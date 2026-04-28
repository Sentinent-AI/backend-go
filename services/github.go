package services

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"sentinent-backend/database"
	"sentinent-backend/models"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

var (
	githubOAuthConfig  *oauth2.Config
	tokenEncryptionKey []byte
)

func IsGitHubConfigured() bool {
	return githubOAuthConfig != nil && len(tokenEncryptionKey) > 0
}

// GitHubIssue represents a GitHub issue or PR
// We use a single struct since the API response is similar
type GitHubIssue struct {
	ID        int64     `json:"id"`
	Number    int       `json:"number"`
	Title     string    `json:"title"`
	Body      string    `json:"body"`
	State     string    `json:"state"`
	HTMLURL   string    `json:"html_url"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Labels    []struct {
		Name string `json:"name"`
	} `json:"labels"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	PullRequest *struct {
		URL string `json:"url"`
	} `json:"pull_request,omitempty"`
}

// InitGitHubService initializes the GitHub OAuth configuration
func InitGitHubService() error {
	clientID := strings.TrimSpace(os.Getenv("GITHUB_CLIENT_ID"))
	clientSecret := strings.TrimSpace(os.Getenv("GITHUB_CLIENT_SECRET"))
	encryptionKey := strings.TrimSpace(os.Getenv("TOKEN_ENCRYPTION_KEY"))

	if encryptionKey != "" {
		// Ensure key is 32 bytes for AES-256
		tokenEncryptionKey = []byte(encryptionKey)
		if len(tokenEncryptionKey) < 32 {
			// Pad key to 32 bytes
			paddedKey := make([]byte, 32)
			copy(paddedKey, tokenEncryptionKey)
			tokenEncryptionKey = paddedKey
		} else if len(tokenEncryptionKey) > 32 {
			tokenEncryptionKey = tokenEncryptionKey[:32]
		}
	}

	if clientID == "" || clientSecret == "" {
		return fmt.Errorf("GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET must be set")
	}

	if encryptionKey == "" {
		return fmt.Errorf("TOKEN_ENCRYPTION_KEY must be set")
	}

	githubOAuthConfig = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       []string{"read:user", "read:org", "repo"},
		Endpoint:     github.Endpoint,
	}

	return nil
}

// GetGitHubAuthURL returns the OAuth authorization URL
func GetGitHubAuthURL(state string) string {
	if githubOAuthConfig == nil {
		return ""
	}
	return githubOAuthConfig.AuthCodeURL(state, oauth2.AccessTypeOnline)
}

// ExchangeGitHubCode exchanges the authorization code for an access token
func ExchangeGitHubCode(code string) (*oauth2.Token, error) {
	if githubOAuthConfig == nil {
		return nil, fmt.Errorf("GitHub OAuth not initialized")
	}
	return githubOAuthConfig.Exchange(context.Background(), code)
}

// EncryptToken encrypts a token using AES-GCM
func EncryptToken(plaintext string) (string, error) {
	block, err := aes.NewCipher(tokenEncryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptToken decrypts a token using AES-GCM
func DecryptToken(ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(tokenEncryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// SaveGitHubIntegration saves the GitHub integration for a user
func SaveGitHubIntegration(userID, workspaceID int, token *oauth2.Token) error {
	encryptedToken, err := EncryptToken(token.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to encrypt token: %w", err)
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
		 WHERE user_id = ? AND provider = 'github' AND workspace_id = ?`,
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
		 VALUES (?, ?, 'github', ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		userID, workspaceID, encryptedToken, encryptedRefreshToken, token.Expiry, "",
	)
	return err
}

// GetGitHubIntegration retrieves the GitHub integration for a user
func GetGitHubIntegration(userID, workspaceID int) (*models.ExternalIntegration, error) {
	var integration models.ExternalIntegration
	var storedWorkspaceID sql.NullInt64
	var metadata sql.NullString
	var expiresAt *time.Time

	err := database.DB.QueryRow(
		`SELECT id, user_id, workspace_id, provider, access_token, refresh_token, expires_at, metadata, created_at, updated_at
		FROM external_integrations
		WHERE user_id = ? AND provider = 'github' AND workspace_id = ?`,
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

// DeleteGitHubIntegration removes the GitHub integration for a user
func DeleteGitHubIntegration(userID, workspaceID int) error {
	_, err := database.DB.Exec(
		"DELETE FROM external_integrations WHERE user_id = ? AND provider = 'github' AND workspace_id = ?",
		userID, workspaceID,
	)
	return err
}

// GetGitHubClient creates an HTTP client with the user's GitHub token
func GetGitHubClient(userID, workspaceID int) (*http.Client, error) {
	integration, err := GetGitHubIntegration(userID, workspaceID)
	if err != nil {
		return nil, fmt.Errorf("GitHub integration not found: %w", err)
	}

	accessToken, err := DecryptToken(integration.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt token: %w", err)
	}

	// Create a token source
	token := &oauth2.Token{
		AccessToken: accessToken,
	}

	return oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(token)), nil
}

// FetchAssignedIssues fetches issues assigned to the user
func FetchAssignedIssues(userID, workspaceID int) ([]GitHubIssue, error) {
	client, err := GetGitHubClient(userID, workspaceID)
	if err != nil {
		return nil, err
	}

	return fetchGitHubIssues(client, "issues", map[string]string{
		"filter": "assigned",
		"state":  "all",
	})
}

// fetchGitHubIssues fetches issues or PRs from GitHub API with pagination
func fetchGitHubIssues(client *http.Client, endpoint string, params map[string]string) ([]GitHubIssue, error) {
	var allIssues []GitHubIssue
	page := 1
	perPage := 100 // Max per page to reduce API calls

	for {
		u, _ := url.Parse(fmt.Sprintf("https://api.github.com/%s", endpoint))
		q := u.Query()
		for key, value := range params {
			q.Set(key, value)
		}
		q.Set("page", strconv.Itoa(page))
		q.Set("per_page", strconv.Itoa(perPage))
		u.RawQuery = q.Encode()

		req, err := http.NewRequest("GET", u.String(), nil)
		if err != nil {
			return nil, err
		}

		// Add headers for better API behavior
		req.Header.Set("Accept", "application/vnd.github.v3+json")

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("GitHub API error: %d - %s", resp.StatusCode, string(body))
		}

		var issues []GitHubIssue
		decodeErr := json.NewDecoder(resp.Body).Decode(&issues)
		resp.Body.Close()
		if decodeErr != nil {
			return nil, decodeErr
		}

		if len(issues) == 0 {
			break
		}

		allIssues = append(allIssues, issues...)

		// Check if we've reached the last page
		if len(issues) < perPage {
			break
		}

		// Respect rate limits - check remaining requests
		remaining := resp.Header.Get("X-RateLimit-Remaining")
		if remaining != "" {
			remainingInt, _ := strconv.Atoi(remaining)
			if remainingInt < 10 {
				// Slow down if we're running low on requests
				time.Sleep(time.Second)
			}
		}

		page++
	}

	return allIssues, nil
}

func splitGitHubIssuesAndPullRequests(items []GitHubIssue) ([]GitHubIssue, []GitHubIssue) {
	issues := make([]GitHubIssue, 0, len(items))
	prs := make([]GitHubIssue, 0, len(items))

	for _, item := range items {
		if item.PullRequest != nil {
			prs = append(prs, item)
			continue
		}
		issues = append(issues, item)
	}

	return issues, prs
}

// SyncGitHubSignals syncs GitHub issues and PRs to signals
func SyncGitHubSignals(userID, workspaceID int) error {
	items, err := FetchAssignedIssues(userID, workspaceID)
	if err != nil {
		return fmt.Errorf("failed to fetch issues: %w", err)
	}

	issues, prs := splitGitHubIssuesAndPullRequests(items)

	// Save issues as signals
	for _, issue := range issues {
		if err := saveGitHubSignal(userID, workspaceID, issue, "issue"); err != nil {
			// Log error but continue with other items
			fmt.Printf("Failed to save issue signal: %v\n", err)
		}
	}

	// Save PRs as signals
	for _, pr := range prs {
		if err := saveGitHubSignal(userID, workspaceID, pr, "pull_request"); err != nil {
			fmt.Printf("Failed to save PR signal: %v\n", err)
		}
	}

	return nil
}

// saveGitHubSignal saves a GitHub issue/PR as a signal
func saveGitHubSignal(userID, workspaceID int, issue GitHubIssue, issueType string) error {
	// Extract labels
	labels := make([]string, 0, len(issue.Labels))
	for _, label := range issue.Labels {
		labels = append(labels, label.Name)
	}

	metadata := models.GitHubMetadata{
		Repository: issue.Repository.FullName,
		Number:     issue.Number,
		State:      issue.State,
		Labels:     labels,
		Type:       issueType,
	}

	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return err
	}

	_, err = database.DB.Exec(
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
		status = excluded.status,
		source_metadata = excluded.source_metadata,
		received_at = excluded.received_at,
		updated_at = CURRENT_TIMESTAMP`,
		userID,
		workspaceID,
		models.SourceTypeGitHub,
		strconv.FormatInt(issue.ID, 10),
		strconv.FormatInt(issue.ID, 10),
		issue.Title,
		issue.Body,
		issue.Body,
		issue.HTMLURL,
		"",
		issue.State,
		string(metadataJSON),
		issue.UpdatedAt,
	)

	return err
}

// GetUserSignals retrieves signals for a user with optional filtering
func GetUserSignals(userID int, filter *models.SignalFilter) ([]models.Signal, error) {
	query := `SELECT s.id, s.user_id, s.workspace_id, s.source_type, s.source_id, s.external_id,
		s.title, s.content, s.author, s.body, s.url, COALESCE(ss.status, s.status) as status,
		s.source_metadata, s.received_at, s.created_at, s.updated_at
		FROM signals s
		LEFT JOIN signal_status ss ON s.id = ss.signal_id AND ss.user_id = ?
		WHERE s.user_id = ?`
	args := []interface{}{userID, userID}

	if filter != nil && filter.SourceType != "" {
		query += " AND s.source_type = ?"
		args = append(args, filter.SourceType)
	}

	if filter != nil && filter.Status != "" {
		query += " AND COALESCE(ss.status, s.status) = ?"
		args = append(args, filter.Status)
	}

	query += " ORDER BY s.updated_at DESC"

	rows, err := database.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	signals := make([]models.Signal, 0)
	for rows.Next() {
		var signal models.Signal
		var workspaceID sql.NullInt64
		var externalID sql.NullString
		var content sql.NullString
		var author sql.NullString
		var body sql.NullString
		var url sql.NullString
		var metadataJSON sql.NullString
		var receivedAt sql.NullTime

		err := rows.Scan(
			&signal.ID,
			&signal.UserID,
			&workspaceID,
			&signal.SourceType,
			&signal.SourceID,
			&externalID,
			&signal.Title,
			&content,
			&author,
			&body,
			&url,
			&signal.Status,
			&metadataJSON,
			&receivedAt,
			&signal.CreatedAt,
			&signal.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		if workspaceID.Valid {
			signal.WorkspaceID = int(workspaceID.Int64)
		}
		if externalID.Valid {
			signal.ExternalID = externalID.String
		}
		if content.Valid {
			signal.Content = content.String
		}
		if author.Valid {
			signal.Author = author.String
		}
		if body.Valid {
			signal.Body = body.String
		}
		if url.Valid {
			signal.URL = url.String
		}
		if receivedAt.Valid {
			signal.ReceivedAt = receivedAt.Time
		}
		if metadataJSON.Valid && metadataJSON.String != "" {
			var metadata models.GitHubMetadata
			if err := json.Unmarshal([]byte(metadataJSON.String), &metadata); err == nil {
				signal.SourceMetadata = &metadata
			}
		}

		signals = append(signals, signal)
	}

	return signals, rows.Err()
}

// ListAccessibleRepos lists repositories accessible to the user
func ListAccessibleRepos(userID, workspaceID int) ([]map[string]interface{}, error) {
	client, err := GetGitHubClient(userID, workspaceID)
	if err != nil {
		return nil, err
	}

	var allRepos []map[string]interface{}
	page := 1
	perPage := 100

	for {
		u := fmt.Sprintf("https://api.github.com/user/repos?page=%d&per_page=%d", page, perPage)

		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			return nil, err
		}

		req.Header.Set("Accept", "application/vnd.github.v3+json")

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("GitHub API error: %d - %s", resp.StatusCode, string(body))
		}

		var repos []map[string]interface{}
		if err := json.Unmarshal(body, &repos); err != nil {
			return nil, err
		}

		if len(repos) == 0 {
			break
		}

		allRepos = append(allRepos, repos...)

		if len(repos) < perPage {
			break
		}

		page++
	}

	return allRepos, nil
}
