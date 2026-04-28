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

// SaveJiraIntegration saves the Jira integration for a user.
// It also cleans up any orphan records (e.g., NULL workspace_id) to prevent
// duplicate integration entries that confuse the GetIntegrations query.
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

	// Clean up any orphan Jira records for this user that don't match the target workspace.
	// This handles historical records with NULL workspace_id or records from other workspaces
	// that were created by bugs in older code.
	if workspaceID > 0 {
		_, _ = database.DB.Exec(
			`DELETE FROM external_integrations
			 WHERE user_id = ? AND provider = 'jira' AND (workspace_id IS NULL OR workspace_id = 0)
			   AND workspace_id != ?`,
			userID, workspaceID,
		)
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

	requestBody, _ := json.Marshal(map[string]interface{}{
		"jql":        jql,
		"maxResults": 50,
		"fields": []string{
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
		},
	})

	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
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
		Issues []JiraIssue `json:"issues"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Issues, nil
}

// parseADFToText recursively extracts raw text from an Atlassian Document Format (ADF) object
func parseADFToText(node interface{}) string {
	if node == nil {
		return ""
	}

	m, ok := node.(map[string]interface{})
	if !ok {
		// Attempt to handle slices if it's an array of nodes
		if arr, isArr := node.([]interface{}); isArr {
			var sb strings.Builder
			for _, child := range arr {
				childText := parseADFToText(child)
				if childText != "" {
					sb.WriteString(childText)
				}
			}
			return sb.String()
		}
		return ""
	}

	nodeType, _ := m["type"].(string)

	var sb strings.Builder

	if nodeType == "text" {
		if text, ok := m["text"].(string); ok {
			sb.WriteString(text)
		}
	}

	if contentObj, exists := m["content"]; exists {
		if contentArr, ok := contentObj.([]interface{}); ok {
			for _, child := range contentArr {
				childText := parseADFToText(child)
				if childText != "" {
					sb.WriteString(childText)
				}
			}
		}
	}

	// Add newlines after block elements for readability
	if nodeType == "paragraph" || nodeType == "heading" || nodeType == "listItem" || nodeType == "codeBlock" {
		sb.WriteString("\n")
	}

	return sb.String()
}

// formatDescription extracts text from Jira ADF (Atlassian Document Format)
func formatDescription(desc interface{}) string {
	if desc == nil {
		return ""
	}

	text := strings.TrimSpace(parseADFToText(desc))

	if len(text) > 500 {
		return text[:500] + "..."
	}
	if text == "" {
		// Fallback to JSON if parsing failed completely
		bytes, err := json.Marshal(desc)
		if err == nil {
			str := string(bytes)
			if len(str) > 500 {
				return str[:500] + "..."
			}
			return str
		}
	}
	return text
}

// GetJiraCloudID returns the first accessible cloud ID
func GetJiraCloudID(client *http.Client) (string, error) {
	resources, err := FetchAtlassianResources(client)
	if err != nil {
		return "", err
	}
	if len(resources) == 0 {
		return "", fmt.Errorf("no accessible Atlassian resources found")
	}
	return resources[0].ID, nil
}

// JiraTransition represents an available transition for a Jira issue
type JiraTransition struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	To   struct {
		Name string `json:"name"`
	} `json:"to"`
}

// GetAvailableTransitions fetches transitions for a specific issue
func GetAvailableTransitions(client *http.Client, cloudId string, issueKey string) ([]JiraTransition, error) {
	apiURL := fmt.Sprintf("https://api.atlassian.com/ex/jira/%s/rest/api/3/issue/%s/transitions", cloudId, issueKey)

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
		Transitions []JiraTransition `json:"transitions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Transitions, nil
}

// PerformTransition executes a status change on a specific issue
func PerformTransition(client *http.Client, cloudId string, issueKey string, transitionID string) error {
	apiURL := fmt.Sprintf("https://api.atlassian.com/ex/jira/%s/rest/api/3/issue/%s/transitions", cloudId, issueKey)

	requestBody, _ := json.Marshal(map[string]interface{}{
		"transition": map[string]string{
			"id": transitionID,
		},
	})

	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(requestBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// 204 No Content is expected for successful transition
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Jira API error: %d - %s", resp.StatusCode, string(body))
	}

	return nil
}

// AddJiraComment adds a comment to a specific issue
func AddJiraComment(client *http.Client, cloudId string, issueKey string, commentText string) error {
	apiURL := fmt.Sprintf("https://api.atlassian.com/ex/jira/%s/rest/api/3/issue/%s/comment", cloudId, issueKey)

	// Jira API v3 expects ADF for comments.
	requestBody, _ := json.Marshal(map[string]interface{}{
		"body": map[string]interface{}{
			"version": 1,
			"type":    "doc",
			"content": []map[string]interface{}{
				{
					"type": "paragraph",
					"content": []map[string]interface{}{
						{
							"type": "text",
							"text": commentText,
						},
					},
				},
			},
		},
	})

	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(requestBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Jira API error: %d - %s", resp.StatusCode, string(body))
	}

	return nil
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
		saveJiraIssueAsSignal(userID, workspaceID, issue, cloudURL)
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
	updatedAt := parseJiraDate(issue.Fields.Updated)

	// Since SourceMetadata in models.Signal is strongly typed to GitHubMetadata for now,
	// we will likely store Jira metadata in a new field or JSON encode it into the body to be generic.
	// Wait, the model update we applied added JiraMetadata but didn't modify Signal struct's SourceMetadata type!
	// We might need to change it to interface{} or add JiraMetadata *JiraMetadata

	// But let's just save it.
	_, err := database.DB.Exec(
		`INSERT INTO signals
		(user_id, workspace_id, source_type, source_id, external_id, title, content, body, url, author, status, source_metadata, received_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(user_id, source_type, source_id) DO UPDATE SET
		external_id = excluded.external_id,
		title = excluded.title,
		content = excluded.content,
		url = excluded.url,
		author = excluded.author,
		status = excluded.status,
		source_metadata = excluded.source_metadata,
		updated_at = ?`,
		userID,
		workspaceID,
		models.SourceTypeJira,
		issue.ID,
		issue.Key,
		fmt.Sprintf("[%s] %s", issue.Key, issue.Fields.Summary),
		formatDescription(issue.Fields.Description),
		"", // body used for different things
		url,
		reporterName,
		issue.Fields.Status.Name,
		string(metadataJSON),
		createdAt, // Setting received_at to creation date or we can use updated_at
		updatedAt,
	)

	return err
}
