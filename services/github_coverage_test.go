package services

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sentinent-backend/database"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/oauth2"
)

func setupGitHubCoverageTestDB(t *testing.T) func() {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "github-coverage.db")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("failed to open sqlite db: %v", err)
	}

	if _, err := db.Exec(`
		CREATE TABLE external_integrations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			workspace_id INTEGER,
			provider TEXT NOT NULL,
			access_token TEXT NOT NULL,
			refresh_token TEXT,
			expires_at DATETIME,
			metadata TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`); err != nil {
		t.Fatalf("failed to prepare schema: %v", err)
	}

	originalDB := database.DB
	database.DB = db

	return func() {
		database.DB = originalDB
		_ = db.Close()
	}
}

type githubRewriteTransport struct {
	base   http.RoundTripper
	target *url.URL
}

func (t githubRewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = t.target.Scheme
	clone.URL.Host = t.target.Host
	clone.Host = t.target.Host
	return t.base.RoundTrip(clone)
}

func TestGitHubTokenEncryptionAndIntegrationCRUD(t *testing.T) {
	cleanup := setupGitHubCoverageTestDB(t)
	defer cleanup()

	originalConfig := githubOAuthConfig
	originalKey := tokenEncryptionKey
	t.Setenv("GITHUB_CLIENT_ID", "client-id")
	t.Setenv("GITHUB_CLIENT_SECRET", "client-secret")
	t.Setenv("TOKEN_ENCRYPTION_KEY", "test-encryption-key-32-bytes-long!")
	t.Cleanup(func() {
		githubOAuthConfig = originalConfig
		tokenEncryptionKey = originalKey
	})

	if err := InitGitHubService(); err != nil {
		t.Fatalf("failed to initialize GitHub service: %v", err)
	}

	ciphertext, err := EncryptToken("github-access-token")
	if err != nil {
		t.Fatalf("failed to encrypt token: %v", err)
	}
	plaintext, err := DecryptToken(ciphertext)
	if err != nil {
		t.Fatalf("failed to decrypt token: %v", err)
	}
	if plaintext != "github-access-token" {
		t.Fatalf("expected decrypted token to round-trip, got %q", plaintext)
	}

	firstToken := &oauth2.Token{
		AccessToken:  "access-token-1",
		RefreshToken: "refresh-token-1",
		Expiry:       time.Now().Add(time.Hour),
	}
	if err := SaveGitHubIntegration(1, 7, firstToken); err != nil {
		t.Fatalf("failed to save integration: %v", err)
	}

	integration, err := GetGitHubIntegration(1, 7)
	if err != nil {
		t.Fatalf("failed to read integration: %v", err)
	}
	if integration.Provider != "github" || integration.WorkspaceID != 7 {
		t.Fatalf("unexpected saved integration: %+v", integration)
	}

	decryptedAccess, err := DecryptToken(integration.AccessToken)
	if err != nil {
		t.Fatalf("failed to decrypt saved access token: %v", err)
	}
	if decryptedAccess != "access-token-1" {
		t.Fatalf("expected access-token-1, got %q", decryptedAccess)
	}

	decryptedRefresh, err := DecryptToken(integration.RefreshToken)
	if err != nil {
		t.Fatalf("failed to decrypt saved refresh token: %v", err)
	}
	if decryptedRefresh != "refresh-token-1" {
		t.Fatalf("expected refresh-token-1, got %q", decryptedRefresh)
	}

	updatedToken := &oauth2.Token{
		AccessToken:  "access-token-2",
		RefreshToken: "refresh-token-2",
		Expiry:       time.Now().Add(2 * time.Hour),
	}
	if err := SaveGitHubIntegration(1, 7, updatedToken); err != nil {
		t.Fatalf("failed to update integration: %v", err)
	}

	var rowCount int
	if err := database.DB.QueryRow(
		"SELECT COUNT(*) FROM external_integrations WHERE user_id = ? AND workspace_id = ? AND provider = 'github'",
		1, 7,
	).Scan(&rowCount); err != nil {
		t.Fatalf("failed to count integrations: %v", err)
	}
	if rowCount != 1 {
		t.Fatalf("expected a single integration row, got %d", rowCount)
	}

	if err := DeleteGitHubIntegration(1, 7); err != nil {
		t.Fatalf("failed to delete integration: %v", err)
	}
	if err := database.DB.QueryRow(
		"SELECT COUNT(*) FROM external_integrations WHERE user_id = ? AND workspace_id = ? AND provider = 'github'",
		1, 7,
	).Scan(&rowCount); err != nil {
		t.Fatalf("failed to count deleted integrations: %v", err)
	}
	if rowCount != 0 {
		t.Fatalf("expected integration row to be deleted, got %d", rowCount)
	}
}

func TestFetchAssignedIssuesAndListAccessibleReposWithLocalGitHubServer(t *testing.T) {
	cleanup := setupGitHubCoverageTestDB(t)
	defer cleanup()

	originalConfig := githubOAuthConfig
	originalKey := tokenEncryptionKey
	originalDefaultTransport := http.DefaultTransport
	originalDefaultClientTransport := http.DefaultClient.Transport
	t.Setenv("GITHUB_CLIENT_ID", "client-id")
	t.Setenv("GITHUB_CLIENT_SECRET", "client-secret")
	t.Setenv("TOKEN_ENCRYPTION_KEY", "test-encryption-key-32-bytes-long!")
	t.Cleanup(func() {
		githubOAuthConfig = originalConfig
		tokenEncryptionKey = originalKey
		http.DefaultTransport = originalDefaultTransport
		http.DefaultClient.Transport = originalDefaultClientTransport
	})

	if err := InitGitHubService(); err != nil {
		t.Fatalf("failed to initialize GitHub service: %v", err)
	}

	if err := SaveGitHubIntegration(1, 7, &oauth2.Token{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		Expiry:       time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("failed to seed integration: %v", err)
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		switch r.URL.Path {
		case "/issues":
			switch page {
			case "1":
				items := make([]GitHubIssue, 0, 100)
				for i := 1; i <= 100; i++ {
					items = append(items, GitHubIssue{
						ID:     int64(i),
						Number: i,
						Title:  fmt.Sprintf("Issue %d", i),
						Body:   "Assigned issue",
						State:  "open",
						Repository: struct {
							FullName string `json:"full_name"`
						}{FullName: "octo/repo"},
					})
				}
				_ = json.NewEncoder(w).Encode(items)
			case "2":
				_ = json.NewEncoder(w).Encode([]GitHubIssue{
					{
						ID:     101,
						Number: 101,
						Title:  "Issue 101",
						Body:   "Assigned issue",
						State:  "open",
						Repository: struct {
							FullName string `json:"full_name"`
						}{FullName: "octo/repo"},
					},
				})
			default:
				_ = json.NewEncoder(w).Encode([]GitHubIssue{})
			}
		case "/user/repos":
			switch page {
			case "1":
				_ = json.NewEncoder(w).Encode([]map[string]any{
					{"id": 1, "name": "repo-1"},
					{"id": 2, "name": "repo-2"},
				})
			default:
				_ = json.NewEncoder(w).Encode([]map[string]any{})
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	targetURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("failed to parse server url: %v", err)
	}

	rewriteTransport := githubRewriteTransport{
		base:   server.Client().Transport,
		target: targetURL,
	}
	http.DefaultTransport = rewriteTransport
	http.DefaultClient.Transport = rewriteTransport

	issues, err := FetchAssignedIssues(1, 7)
	if err != nil {
		t.Fatalf("FetchAssignedIssues returned error: %v", err)
	}
	if len(issues) != 101 {
		t.Fatalf("expected 101 fetched issues, got %d", len(issues))
	}

	repos, err := ListAccessibleRepos(1, 7)
	if err != nil {
		t.Fatalf("ListAccessibleRepos returned error: %v", err)
	}
	if len(repos) != 2 {
		t.Fatalf("expected 2 accessible repos, got %d", len(repos))
	}
	if repos[0]["name"] != "repo-1" {
		t.Fatalf("unexpected repo payload: %+v", repos[0])
	}
}
