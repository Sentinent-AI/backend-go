package services

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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

	if clientID == "" || clientSecret == "" {
		return fmt.Errorf("GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET must be set")
	}

	if encryptionKey == "" {
		return fmt.Errorf("TOKEN_ENCRYPTION_KEY must be set")
	}

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
	return githubOAuthConfig.Exchange(oauth2.NoContext, code)
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
func SaveGitHubIntegration(userID int, token *oauth2.Token) error {
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

	_, err = database.DB.Exec(
		`INSERT INTO external_integrations (user_id, provider, access_token, refresh_token, expires_at, updated_at)
		VALUES (?, 'github', ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(user_id, provider) DO UPDATE SET
		access_token = excluded.access_token,
		refresh_token = excluded.refresh_token,
		expires_at = excluded.expires_at,
		updated_at = CURRENT_TIMESTAMP`,
		userID, encryptedToken, encryptedRefreshToken, token.Expiry,
	)

	return err
}

// GetGitHubIntegration retrieves the GitHub integration for a user
func GetGitHubIntegration(userID int) (*models.ExternalIntegration, error) {
	var integration models.ExternalIntegration
	var expiresAt *time.Time

	err := database.DB.QueryRow(
		`SELECT id, user_id, provider, access_token, refresh_token, expires_at, created_at, updated_at
		FROM external_integrations WHERE user_id = ? AND provider = 'github'`,
		userID,
	).Scan(&integration.ID, &integration.UserID, &integration.Provider, &integration.AccessToken, &integration.RefreshToken, &expiresAt, &integration.CreatedAt, &integration.UpdatedAt)

	if err != nil {
		return nil, err
	}

	integration.ExpiresAt = expiresAt
	return &integration, nil
}

// DeleteGitHubIntegration removes the GitHub integration for a user
func DeleteGitHubIntegration(userID int) error {
	_, err := database.DB.Exec(
		"DELETE FROM external_integrations WHERE user_id = ? AND provider = 'github'",
		userID,
	)
	return err
}

// GetGitHubClient creates an HTTP client with the user's GitHub token
func GetGitHubClient(userID int) (*http.Client, error) {
	integration, err := GetGitHubIntegration(userID)
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

	return oauth2.NewClient(oauth2.NoContext, oauth2.StaticTokenSource(token)), nil
}

// FetchAssignedIssues fetches issues assigned to the user
func FetchAssignedIssues(userID int) ([]GitHubIssue, error) {
	client, err := GetGitHubClient(userID)
	if err != nil {
		return nil, err
	}

	return fetchGitHubIssues(client, "issues", map[string]string{
		"filter": "assigned",
		"state":  "all",
	})
}

// FetchAssignedPullRequests fetches pull requests assigned to the user
func FetchAssignedPullRequests(userID int) ([]GitHubIssue, error) {
	client, err := GetGitHubClient(userID)
	if err != nil {
		return nil, err
	}

	return fetchGitHubIssues(client, "pulls", map[string]string{
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
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("GitHub API error: %d - %s", resp.StatusCode, string(body))
		}

		var issues []GitHubIssue
		if err := json.NewDecoder(resp.Body).Decode(&issues); err != nil {
			return nil, err
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

// SyncGitHubSignals syncs GitHub issues and PRs to signals
func SyncGitHubSignals(userID int) error {
	// Fetch issues
	issues, err := FetchAssignedIssues(userID)
	if err != nil {
		return fmt.Errorf("failed to fetch issues: %w", err)
	}

	// Fetch PRs
	prs, err := FetchAssignedPullRequests(userID)
	if err != nil {
		return fmt.Errorf("failed to fetch PRs: %w", err)
	}

	// Save issues as signals
	for _, issue := range issues {
		// Skip if it's a PR (GitHub API returns PRs in issues endpoint too)
		if issue.PullRequest != nil {
			continue
		}

		if err := saveGitHubSignal(userID, issue, "issue"); err != nil {
			// Log error but continue with other items
			fmt.Printf("Failed to save issue signal: %v\n", err)
		}
	}

	// Save PRs as signals
	for _, pr := range prs {
		if err := saveGitHubSignal(userID, pr, "pull_request"); err != nil {
			fmt.Printf("Failed to save PR signal: %v\n", err)
		}
	}

	return nil
}

// saveGitHubSignal saves a GitHub issue/PR as a signal
func saveGitHubSignal(userID int, issue GitHubIssue, issueType string) error {
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
		`INSERT INTO signals (user_id, source_type, source_id, title, body, url, status, source_metadata, updated_at)
		VALUES (?, 'github', ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(user_id, source_type, source_id) DO UPDATE SET
		title = excluded.title,
		body = excluded.body,
		url = excluded.url,
		status = excluded.status,
		source_metadata = excluded.source_metadata,
		updated_at = CURRENT_TIMESTAMP`,
		userID, strconv.FormatInt(issue.ID, 10), issue.Title, issue.Body, issue.HTMLURL, issue.State, string(metadataJSON),
	)

	return err
}

// GetUserSignals retrieves signals for a user with optional filtering
func GetUserSignals(userID int, filter *models.SignalFilter) ([]models.Signal, error) {
	query := `SELECT id, user_id, source_type, source_id, title, body, url, status, source_metadata, created_at, updated_at
		FROM signals WHERE user_id = ?`
	args := []interface{}{userID}

	if filter != nil && filter.SourceType != "" {
		query += " AND source_type = ?"
		args = append(args, filter.SourceType)
	}

	if filter != nil && filter.Status != "" {
		query += " AND status = ?"
		args = append(args, filter.Status)
	}

	query += " ORDER BY updated_at DESC"

	rows, err := database.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var signals []models.Signal
	for rows.Next() {
		var signal models.Signal
		var metadataJSON string

		err := rows.Scan(&signal.ID, &signal.UserID, &signal.SourceType, &signal.SourceID, &signal.Title, &signal.Body, &signal.URL, &signal.Status, &metadataJSON, &signal.CreatedAt, &signal.UpdatedAt)
		if err != nil {
			return nil, err
		}

		if metadataJSON != "" {
			var metadata models.GitHubMetadata
			if err := json.Unmarshal([]byte(metadataJSON), &metadata); err == nil {
				signal.SourceMetadata = &metadata
			}
		}

		signals = append(signals, signal)
	}

	return signals, rows.Err()
}

// ListAccessibleRepos lists repositories accessible to the user
func ListAccessibleRepos(userID int) ([]map[string]interface{}, error) {
	client, err := GetGitHubClient(userID)
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
