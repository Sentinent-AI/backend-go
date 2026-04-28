package services

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"sentinent-backend/database"
	"sentinent-backend/models"

	"golang.org/x/oauth2"
)

var (
	jiraOAuthConfig *oauth2.Config
)

// AtlassianResource represents an accessible Atlassian Cloud site
type AtlassianResource struct {
	ID        string   `json:"id"`
	URL       string   `json:"url"`
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes"`
	AvatarURL string   `json:"avatarUrl"`
}

// JiraProject represents a project visible on a Jira Cloud site.
type JiraProject struct {
	ID        string `json:"id"`
	Key       string `json:"key"`
	Name      string `json:"name"`
	AvatarURL string `json:"avatarUrl,omitempty"`
	SiteID    string `json:"siteId"`
	SiteName  string `json:"siteName"`
	SiteURL   string `json:"siteUrl"`
}

// JiraIssue represents an issue retrieved from Jira REST API
type JiraIssue struct {
	ID     string `json:"id"`
	Key    string `json:"key"`
	Fields struct {
		Summary     string      `json:"summary"`
		Description interface{} `json:"description"`
		Status      struct {
			Name string `json:"name"`
		} `json:"status"`
		Project struct {
			Key  string `json:"key"`
			Name string `json:"name"`
		} `json:"project"`
		Priority *struct {
			Name string `json:"name"`
		} `json:"priority"`
		Issuetype struct {
			Name string `json:"name"`
		} `json:"issuetype"`
		Assignee *struct {
			DisplayName string `json:"displayName"`
		} `json:"assignee"`
		Reporter *struct {
			DisplayName string `json:"displayName"`
		} `json:"reporter"`
		Updated string `json:"updated"`
		Created string `json:"created"`
	} `json:"fields"`
}

// InitJiraService initializes the Jira OAuth configuration
func InitJiraService() error {
	clientID := strings.TrimSpace(os.Getenv("JIRA_CLIENT_ID"))
	clientSecret := strings.TrimSpace(os.Getenv("JIRA_CLIENT_SECRET"))
	baseURL := strings.TrimSpace(os.Getenv("API_BASE_URL"))
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}

	if clientID == "" || clientSecret == "" {
		return fmt.Errorf("JIRA_CLIENT_ID and JIRA_CLIENT_SECRET must be set")
	}
	if err := initTokenEncryptionKey(); err != nil {
		return err
	}

	jiraOAuthConfig = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  baseURL + "/api/integrations/jira/callback",
		Scopes:       []string{"read:jira-work", "read:jira-user", "offline_access"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://auth.atlassian.com/authorize",
			TokenURL: "https://auth.atlassian.com/oauth/token",
		},
	}

	return nil
}

// IsJiraConfigured checks if Jira OAuth is configured
func IsJiraConfigured() bool {
	return jiraOAuthConfig != nil
}

// GetJiraAuthURL returns the OAuth authorization URL
func GetJiraAuthURL(state string) string {
	if jiraOAuthConfig == nil {
		return ""
	}
	return jiraOAuthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("audience", "api.atlassian.com"), oauth2.SetAuthURLParam("prompt", "consent"))
}

// ExchangeJiraCode exchanges the authorization code for an access token
func ExchangeJiraCode(code string) (*oauth2.Token, error) {
	if jiraOAuthConfig == nil {
		return nil, fmt.Errorf("Jira OAuth not initialized")
	}
	return jiraOAuthConfig.Exchange(context.Background(), code)
}

// SaveJiraIntegration saves the Jira integration for a user
func SaveJiraIntegration(userID, workspaceID int, token *oauth2.Token) error {
	encryptedToken, err := EncryptToken(token.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to encrypt access token: %w", err)
	}

	var encryptedRefreshToken string
	if token.RefreshToken != "" {
		encryptedRefreshToken, err = EncryptToken(token.RefreshToken)
		if err != nil {
			return fmt.Errorf("failed to encrypt refresh token: %w", err)
		}
	}

	result, err := database.DB.Exec(
		`UPDATE external_integrations
		 SET access_token = ?, refresh_token = ?, expires_at = ?, updated_at = CURRENT_TIMESTAMP
		 WHERE user_id = ? AND provider = 'jira' AND workspace_id = ?`,
		encryptedToken, encryptedRefreshToken, token.Expiry, userID, workspaceID,
	)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected > 0 {
		return nil
	}

	_, err = database.DB.Exec(
		`INSERT INTO external_integrations
		 (user_id, workspace_id, provider, access_token, refresh_token, expires_at, metadata, updated_at)
		 VALUES (?, ?, 'jira', ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		userID, workspaceID, encryptedToken, encryptedRefreshToken, token.Expiry, "{}",
	)
	return err
}

// GetJiraIntegration retrieves the Jira integration for a user
func GetJiraIntegration(userID, workspaceID int) (*models.ExternalIntegration, error) {
	var integration models.ExternalIntegration
	var storedWorkspaceID sql.NullInt64
	var metadata sql.NullString
	var expiresAt *time.Time

	err := database.DB.QueryRow(
		`SELECT id, user_id, workspace_id, provider, access_token, refresh_token, expires_at, metadata, created_at, updated_at
		FROM external_integrations
		WHERE user_id = ? AND provider = 'jira' AND workspace_id = ?`,
		userID, workspaceID,
	).Scan(
		&integration.ID,
		&integration.UserID,
		&storedWorkspaceID,
		&integration.Provider,
		&integration.AccessToken,
		&integration.RefreshToken,
		&expiresAt,
		&metadata,
		&integration.CreatedAt,
		&integration.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	if storedWorkspaceID.Valid {
		integration.WorkspaceID = int(storedWorkspaceID.Int64)
	}
	if metadata.Valid {
		integration.Metadata = metadata.String
	}
	integration.ExpiresAt = expiresAt
	return &integration, nil
}

// DeleteJiraIntegration removes the Jira integration
func DeleteJiraIntegration(userID, workspaceID int) error {
	_, err := database.DB.Exec(
		"DELETE FROM external_integrations WHERE user_id = ? AND provider = 'jira' AND workspace_id = ?",
		userID, workspaceID,
	)
	return err
}

// GetJiraClient creates an HTTP client with the user's Jira token, refreshing if necessary
func GetJiraClient(userID, workspaceID int) (*http.Client, *oauth2.Token, error) {
	if jiraOAuthConfig == nil {
		return nil, nil, fmt.Errorf("Jira OAuth not initialized")
	}

	integration, err := GetJiraIntegration(userID, workspaceID)
	if err != nil {
		return nil, nil, fmt.Errorf("Jira integration not found: %w", err)
	}

	accessToken, err := DecryptToken(integration.AccessToken)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt access token: %w", err)
	}

	refreshToken := ""
	if integration.RefreshToken != "" {
		refreshToken, err = DecryptToken(integration.RefreshToken)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decrypt refresh token: %w", err)
		}
	}

	token := &oauth2.Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
	if integration.ExpiresAt != nil {
		token.Expiry = *integration.ExpiresAt
	}

	tokenSource := jiraOAuthConfig.TokenSource(context.Background(), token)
	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get/refresh token: %w", err)
	}

	// Update token in DB if it was refreshed
	if newToken.AccessToken != token.AccessToken {
		err = SaveJiraIntegration(userID, workspaceID, newToken)
		if err != nil {
			fmt.Printf("Warning: failed to save refreshed Jira token: %v\n", err)
		}
	}

	return oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(newToken)), newToken, nil
}

// FetchAtlassianResources gets the accessible Cloud IDs for the user
func FetchAtlassianResources(client *http.Client) ([]AtlassianResource, error) {
	req, err := http.NewRequest("GET", "https://api.atlassian.com/oauth/token/accessible-resources", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Atlassian API error: %d - %s", resp.StatusCode, string(body))
	}

	var resources []AtlassianResource
	if err := json.NewDecoder(resp.Body).Decode(&resources); err != nil {
		return nil, err
	}

	return resources, nil
}

// FetchJiraIssues requests issues from a specific Jira cloud site
func FetchJiraIssues(client *http.Client, cloudId string, jql string) ([]JiraIssue, error) {
	apiURL := fmt.Sprintf("https://api.atlassian.com/ex/jira/%s/rest/api/3/search/jql", cloudId)
	fields := []string{
		"summary",
		"description",
		"status",
		"project",
		"priority",
		"issuetype",
		"assignee",
		"reporter",
		"updated",
		"created",
	}

	issues := make([]JiraIssue, 0)
	nextPageToken := ""
	for {
		requestBody := map[string]interface{}{
			"jql":        jql,
			"maxResults": 50,
			"fields":     fields,
		}
		if nextPageToken != "" {
			requestBody["nextPageToken"] = nextPageToken
		}

		body, err := json.Marshal(requestBody)
		if err != nil {
			return nil, err
		}

		req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("Jira API error: %d - %s", resp.StatusCode, string(body))
		}

		var result struct {
			Issues        []JiraIssue `json:"issues"`
			NextPageToken string      `json:"nextPageToken"`
		}
		decodeErr := json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()
		if decodeErr != nil {
			return nil, decodeErr
		}

		issues = append(issues, result.Issues...)
		if result.NextPageToken == "" {
			break
		}
		nextPageToken = result.NextPageToken
	}

	return issues, nil
}

// formatDescription extracts text from Jira ADF (Atlassian Document Format)
func formatDescription(desc interface{}) string {
	if desc == nil {
		return ""
	}

	text := strings.TrimSpace(extractADFText(desc))
	if text != "" {
		if len(text) > 500 {
			return text[:500] + "..."
		}
		return text
	}

	body, err := json.Marshal(desc)
	if err != nil {
		return ""
	}
	str := string(body)
	if len(str) > 500 {
		return str[:500] + "..."
	}
	return str
}

func extractADFText(value interface{}) string {
	switch typed := value.(type) {
	case string:
		return typed
	case map[string]interface{}:
		parts := make([]string, 0)
		if text, ok := typed["text"].(string); ok {
			parts = append(parts, text)
		}
		if content, ok := typed["content"].([]interface{}); ok {
			for _, child := range content {
				childText := strings.TrimSpace(extractADFText(child))
				if childText != "" {
					parts = append(parts, childText)
				}
			}
		}
		return strings.Join(parts, " ")
	case []interface{}:
		parts := make([]string, 0, len(typed))
		for _, child := range typed {
			childText := strings.TrimSpace(extractADFText(child))
			if childText != "" {
				parts = append(parts, childText)
			}
		}
		return strings.Join(parts, " ")
	default:
		return ""
	}
}

func parseJiraDate(dateStr string) time.Time {
	t, err := time.Parse("2006-01-02T15:04:05.000-0700", dateStr)
	if err != nil {
		return time.Now()
	}
	return t
}

// SyncJiraSignals fetches and saves Jira issues
func SyncJiraSignals(userID, workspaceID int) error {
	client, _, err := GetJiraClient(userID, workspaceID)
	if err != nil {
		return fmt.Errorf("failed to get Jira client: %w", err)
	}

	resources, err := FetchAtlassianResources(client)
	if err != nil || len(resources) == 0 {
		return fmt.Errorf("no accessible Atlassian resources found: %v", err)
	}

	// We'll sync from the first accessible Jira site for simplicity
	cloudId := resources[0].ID
	cloudURL := resources[0].URL

	// JQL: assigned to currentUser() OR creator = currentUser() OR updated >= -30d
	jql := "assignee = currentUser() OR reporter = currentUser() ORDER BY updated DESC"
	issues, err := FetchJiraIssues(client, cloudId, jql)
	if err != nil {
		return fmt.Errorf("failed to fetch Jira issues: %w", err)
	}

	for _, issue := range issues {
		if err := saveJiraIssueAsSignal(userID, workspaceID, issue, cloudURL); err != nil {
			fmt.Printf("Failed to save Jira signal: %v\n", err)
		}
	}

	return nil
}

func saveJiraIssueAsSignal(userID, workspaceID int, issue JiraIssue, cloudURL string) error {
	priorityName := ""
	if issue.Fields.Priority != nil {
		priorityName = issue.Fields.Priority.Name
	}

	assigneeName := ""
	if issue.Fields.Assignee != nil {
		assigneeName = issue.Fields.Assignee.DisplayName
	}

	reporterName := ""
	if issue.Fields.Reporter != nil {
		reporterName = issue.Fields.Reporter.DisplayName
	}

	metadata := models.JiraMetadata{
		ProjectKey:   issue.Fields.Project.Key,
		IssueType:    issue.Fields.Issuetype.Name,
		Priority:     priorityName,
		Status:       issue.Fields.Status.Name,
		IssueKey:     issue.Key,
		AssigneeName: assigneeName,
	}

	metadataJSON, _ := json.Marshal(metadata)

	url := fmt.Sprintf("%s/browse/%s", cloudURL, issue.Key)
	createdAt := parseJiraDate(issue.Fields.Created)

	_, err := database.DB.Exec(
		`INSERT INTO signals
		(user_id, workspace_id, source_type, source_id, external_id, title, content, body, url, author, status, source_metadata, received_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(user_id, source_type, source_id) DO UPDATE SET
		external_id = excluded.external_id,
		title = excluded.title,
		content = excluded.content,
		body = excluded.body,
		url = excluded.url,
		author = excluded.author,
		source_metadata = excluded.source_metadata,
		received_at = excluded.received_at,
		updated_at = CURRENT_TIMESTAMP`,
		userID,
		workspaceID,
		models.SourceTypeJira,
		issue.ID,
		issue.Key,
		fmt.Sprintf("[%s] %s", issue.Key, issue.Fields.Summary),
		formatDescription(issue.Fields.Description),
		formatDescription(issue.Fields.Description),
		url,
		reporterName,
		models.SignalStatusUnread,
		string(metadataJSON),
		createdAt, // Setting received_at to creation date or we can use updated_at
	)

	return err
}

// FetchJiraProjects returns visible projects across all accessible Jira sites.
func FetchJiraProjects(client *http.Client) ([]JiraProject, error) {
	resources, err := FetchAtlassianResources(client)
	if err != nil {
		return nil, err
	}

	projects := make([]JiraProject, 0)
	for _, resource := range resources {
		siteProjects, err := fetchJiraProjectsForResource(client, resource)
		if err != nil {
			return nil, err
		}
		projects = append(projects, siteProjects...)
	}

	return projects, nil
}

func fetchJiraProjectsForResource(client *http.Client, resource AtlassianResource) ([]JiraProject, error) {
	apiURL := fmt.Sprintf("https://api.atlassian.com/ex/jira/%s/rest/api/3/project/search?maxResults=50", resource.ID)
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Jira API error: %d - %s", resp.StatusCode, string(body))
	}

	var result struct {
		Values []struct {
			ID         string            `json:"id"`
			Key        string            `json:"key"`
			Name       string            `json:"name"`
			AvatarURLs map[string]string `json:"avatarUrls"`
		} `json:"values"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	projects := make([]JiraProject, 0, len(result.Values))
	for _, project := range result.Values {
		projects = append(projects, JiraProject{
			ID:        project.ID,
			Key:       project.Key,
			Name:      project.Name,
			AvatarURL: project.AvatarURLs["48x48"],
			SiteID:    resource.ID,
			SiteName:  resource.Name,
			SiteURL:   resource.URL,
		})
	}
	return projects, nil
}
