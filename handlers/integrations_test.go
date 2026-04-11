package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sentinent-backend/database"
	"sentinent-backend/middleware"
	"sentinent-backend/models"
	"sentinent-backend/services"
	"sentinent-backend/utils"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestSlackAuthHandlerSetsSignedState(t *testing.T) {
	setupTestDB()
	defer database.DB.Close()

	if _, err := database.DB.Exec(
		"INSERT INTO users (email, password) VALUES (?, ?)",
		"octo@example.com", "hashed-password",
	); err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}

	originalSlackClientID := slackClientID
	originalSlackClientSecret := slackClientSecret
	originalTokenEncryptor := tokenEncryptor
	t.Setenv("TOKEN_ENCRYPTION_KEY", "test-encryption-key-32-bytes-long!")

	encryptor, err := utils.NewTokenEncryptor()
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	slackClientID = "client-id"
	slackClientSecret = "client-secret"
	tokenEncryptor = encryptor
	t.Cleanup(func() {
		slackClientID = originalSlackClientID
		slackClientSecret = originalSlackClientSecret
		tokenEncryptor = originalTokenEncryptor
	})

	req := httptest.NewRequest(http.MethodGet, "/api/integrations/slack/auth?workspace_id=7", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserEmailKey, "octo@example.com"))
	rr := httptest.NewRecorder()

	SlackAuth(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var payload map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&payload); err != nil {
		t.Fatalf("expected JSON response: %v", err)
	}

	authURL, err := url.Parse(payload["auth_url"])
	if err != nil {
		t.Fatalf("failed to parse auth URL: %v", err)
	}

	userID, workspaceID, err := validateSlackOAuthState(authURL.Query().Get("state"))
	if err != nil {
		t.Fatalf("expected signed state to validate: %v", err)
	}
	if userID != 1 || workspaceID != 7 {
		t.Fatalf("expected user 1 workspace 7, got user %d workspace %d", userID, workspaceID)
	}
}

func TestValidateSlackOAuthStateRejectsExpiredState(t *testing.T) {
	setupTestDB()
	defer database.DB.Close()

	state, err := createSlackOAuthState(1, 7, time.Now().Add(-slackOAuthStateTTL-time.Minute))
	if err != nil {
		t.Fatalf("failed to create expired state: %v", err)
	}

	if _, _, err := validateSlackOAuthState(state); err == nil {
		t.Fatal("expected expired state to be rejected")
	}
}

func TestSlackCallbackHandlerAcceptsValidStateWithoutCookie(t *testing.T) {
	setupTestDB()
	defer database.DB.Close()

	if _, err := database.DB.Exec(`
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
		)`); err != nil {
		t.Fatalf("failed to create external_integrations table: %v", err)
	}

	if _, err := database.DB.Exec(
		"INSERT INTO users (email, password) VALUES (?, ?)",
		"octo@example.com", "hashed-password",
	); err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}

	originalSlackClientID := slackClientID
	originalSlackClientSecret := slackClientSecret
	originalTokenEncryptor := tokenEncryptor
	originalSlackExchangeCodeFunc := slackExchangeCodeFunc
	t.Setenv("TOKEN_ENCRYPTION_KEY", "test-encryption-key-32-bytes-long!")
	t.Setenv("SLACK_REDIRECT_URI", "https://example.ngrok.app/api/integrations/slack/callback")

	encryptor, err := utils.NewTokenEncryptor()
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	slackClientID = "client-id"
	slackClientSecret = "client-secret"
	tokenEncryptor = encryptor
	slackExchangeCodeFunc = func(clientID, clientSecret, code, redirectURI string) (*services.SlackOAuthResponse, error) {
		if clientID != "client-id" || clientSecret != "client-secret" {
			t.Fatalf("unexpected Slack client credentials: %q %q", clientID, clientSecret)
		}
		if code != "test-code" {
			t.Fatalf("expected code test-code, got %q", code)
		}
		if redirectURI != "https://example.ngrok.app/api/integrations/slack/callback" {
			t.Fatalf("unexpected redirect URI: %q", redirectURI)
		}

		resp := &services.SlackOAuthResponse{
			OK:          true,
			AccessToken: "slack-test-token",
			Scope:       "channels:read,groups:read",
			BotUserID:   "B123",
			AppID:       "A123",
		}
		resp.Team.ID = "T123"
		resp.Team.Name = "Workspace"
		return resp, nil
	}
	t.Cleanup(func() {
		slackClientID = originalSlackClientID
		slackClientSecret = originalSlackClientSecret
		tokenEncryptor = originalTokenEncryptor
		slackExchangeCodeFunc = originalSlackExchangeCodeFunc
	})

	state, err := createSlackOAuthState(1, 7, time.Now())
	if err != nil {
		t.Fatalf("failed to create state: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/integrations/slack/callback?code=test-code&state="+url.QueryEscape(state), nil)
	rr := httptest.NewRecorder()

	SlackCallback(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var count int
	if err := database.DB.QueryRow(
		"SELECT count(*) FROM external_integrations WHERE user_id = ? AND workspace_id = ? AND provider = 'slack'",
		1, 7,
	).Scan(&count); err != nil {
		t.Fatalf("failed to query saved integration: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 saved slack integration, got %d", count)
	}
}

func TestGitHubAuthHandlerSetsSignedStateCookie(t *testing.T) {
	setupTestDB()
	defer database.DB.Close()

	originalGitHubAuthURLFunc := githubAuthURLFunc
	t.Cleanup(func() {
		githubAuthURLFunc = originalGitHubAuthURLFunc
	})

	var capturedState string
	githubAuthURLFunc = func(state string) string {
		capturedState = state
		return "https://github.com/login/oauth/authorize?state=" + url.QueryEscape(state)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/integrations/github/auth", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserEmailKey, "octo@example.com"))
	rr := httptest.NewRecorder()

	GitHubAuthHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}
	if capturedState == "" {
		t.Fatal("expected GitHub auth URL to receive a state value")
	}

	email, err := validateGitHubOAuthState(capturedState)
	if err != nil {
		t.Fatalf("expected signed state to validate: %v", err)
	}
	if email != "octo@example.com" {
		t.Fatalf("expected state to be bound to octo@example.com, got %q", email)
	}

	var stateCookie *http.Cookie
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == githubOAuthStateCookieName {
			stateCookie = cookie
			break
		}
	}
	if stateCookie == nil {
		t.Fatal("expected GitHub OAuth state cookie to be set")
	}
	if stateCookie.Value != capturedState {
		t.Fatal("expected cookie state to match auth URL state")
	}
	if !stateCookie.HttpOnly {
		t.Fatal("expected GitHub OAuth state cookie to be HttpOnly")
	}
	if stateCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("expected SameSite=Lax, got %v", stateCookie.SameSite)
	}

	var payload map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&payload); err != nil {
		t.Fatalf("expected JSON response: %v", err)
	}
	if payload["auth_url"] == "" {
		t.Fatal("expected auth_url in response")
	}
}

func TestGitHubCallbackHandlerRejectsMissingStateCookie(t *testing.T) {
	setupTestDB()
	defer database.DB.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/integrations/github/callback?code=test-code&state=test-state", nil)
	rr := httptest.NewRecorder()

	GitHubCallbackHandler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rr.Code)
	}
}

func TestGitHubCallbackHandlerRejectsTamperedState(t *testing.T) {
	setupTestDB()
	defer database.DB.Close()

	state, err := createGitHubOAuthState("octo@example.com", time.Now())
	if err != nil {
		t.Fatalf("failed to create state: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/integrations/github/callback?code=test-code&state="+url.QueryEscape(state+"tampered"), nil)
	req.AddCookie(&http.Cookie{Name: githubOAuthStateCookieName, Value: state})
	rr := httptest.NewRecorder()

	GitHubCallbackHandler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rr.Code)
	}
}

func TestValidateGitHubOAuthStateRejectsExpiredState(t *testing.T) {
	setupTestDB()
	defer database.DB.Close()

	state, err := createGitHubOAuthState("octo@example.com", time.Now().Add(-githubOAuthStateTTL-time.Minute))
	if err != nil {
		t.Fatalf("failed to create expired state: %v", err)
	}

	if _, err := validateGitHubOAuthState(state); err == nil {
		t.Fatal("expected expired state to be rejected")
	}
}

func TestGitHubCallbackHandlerAcceptsValidState(t *testing.T) {
	setupTestDB()
	defer database.DB.Close()

	if _, err := database.DB.Exec(
		"INSERT INTO users (email, password) VALUES (?, ?)",
		"octo@example.com", "hashed-password",
	); err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}

	originalGitHubExchangeCodeFunc := githubExchangeCodeFunc
	originalGitHubSaveIntegrationFunc := githubSaveIntegrationFunc
	originalGitHubSyncSignalsFunc := githubSyncSignalsFunc
	t.Cleanup(func() {
		githubExchangeCodeFunc = originalGitHubExchangeCodeFunc
		githubSaveIntegrationFunc = originalGitHubSaveIntegrationFunc
		githubSyncSignalsFunc = originalGitHubSyncSignalsFunc
	})

	githubExchangeCodeFunc = func(code string) (*oauth2.Token, error) {
		if code != "test-code" {
			t.Fatalf("expected code test-code, got %q", code)
		}
		return &oauth2.Token{AccessToken: "test-token"}, nil
	}

	var savedUserID int
	githubSaveIntegrationFunc = func(userID int, token *oauth2.Token) error {
		savedUserID = userID
		if token.AccessToken != "test-token" {
			t.Fatalf("expected access token test-token, got %q", token.AccessToken)
		}
		return nil
	}

	syncUserIDs := make(chan int, 1)
	githubSyncSignalsFunc = func(userID int) error {
		syncUserIDs <- userID
		return nil
	}

	state, err := createGitHubOAuthState("octo@example.com", time.Now())
	if err != nil {
		t.Fatalf("failed to create state: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/integrations/github/callback?code=test-code&state="+url.QueryEscape(state), nil)
	req.AddCookie(&http.Cookie{Name: githubOAuthStateCookieName, Value: state})
	rr := httptest.NewRecorder()

	GitHubCallbackHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}
	if savedUserID == 0 {
		t.Fatal("expected integration save to use a real user ID")
	}

	select {
	case syncedUserID := <-syncUserIDs:
		if syncedUserID != savedUserID {
			t.Fatalf("expected sync user ID %d, got %d", savedUserID, syncedUserID)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected GitHub sync to be triggered")
	}
}

func TestGmailAuthHandlerSetsSignedStateCookie(t *testing.T) {
	setupTestDB()
	defer database.DB.Close()

	originalGmailClientID := gmailClientID
	originalGmailClientSecret := gmailClientSecret
	originalTokenEncryptor := tokenEncryptor
	t.Setenv("TOKEN_ENCRYPTION_KEY", "test-encryption-key-32-bytes-long!")

	encryptor, err := utils.NewTokenEncryptor()
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	gmailClientID = "gmail-client"
	gmailClientSecret = "gmail-secret"
	tokenEncryptor = encryptor
	t.Cleanup(func() {
		gmailClientID = originalGmailClientID
		gmailClientSecret = originalGmailClientSecret
		tokenEncryptor = originalTokenEncryptor
	})

	req := httptest.NewRequest(http.MethodGet, "/api/integrations/gmail/auth?redirect_url="+url.QueryEscape("http://localhost:4200/workspaces/7/settings/integrations"), nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserEmailKey, "octo@example.com"))
	rr := httptest.NewRecorder()

	GmailAuthHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var payload map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&payload); err != nil {
		t.Fatalf("expected JSON response: %v", err)
	}

	authURL, err := url.Parse(payload["auth_url"])
	if err != nil {
		t.Fatalf("failed to parse auth URL: %v", err)
	}

	email, redirectURL, err := validateGmailOAuthState(authURL.Query().Get("state"))
	if err != nil {
		t.Fatalf("expected signed state to validate: %v", err)
	}
	if email != "octo@example.com" {
		t.Fatalf("expected state to be bound to octo@example.com, got %q", email)
	}
	if redirectURL != "http://localhost:4200/workspaces/7/settings/integrations" {
		t.Fatalf("unexpected redirect URL in state: %q", redirectURL)
	}

	var stateCookie *http.Cookie
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == gmailOAuthStateCookieName {
			stateCookie = cookie
			break
		}
	}
	if stateCookie == nil {
		t.Fatal("expected Gmail OAuth state cookie to be set")
	}
}

func TestGmailCallbackHandlerAcceptsValidState(t *testing.T) {
	setupIntegrationsTestDB(t)
	defer database.DB.Close()

	originalGmailClientID := gmailClientID
	originalGmailClientSecret := gmailClientSecret
	originalTokenEncryptor := tokenEncryptor
	originalGmailExchangeCodeFunc := gmailExchangeCodeFunc
	originalGmailFetchProfileFunc := gmailFetchProfileFunc

	t.Setenv("TOKEN_ENCRYPTION_KEY", "test-encryption-key-32-bytes-long!")
	t.Setenv("GOOGLE_REDIRECT_URI", "https://example.ngrok.app/api/integrations/gmail/callback")

	encryptor, err := utils.NewTokenEncryptor()
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	gmailClientID = "gmail-client"
	gmailClientSecret = "gmail-secret"
	tokenEncryptor = encryptor
	gmailExchangeCodeFunc = func(code, redirectURI string) (*oauth2.Token, error) {
		if code != "test-code" {
			t.Fatalf("expected code test-code, got %q", code)
		}
		if redirectURI != "https://example.ngrok.app/api/integrations/gmail/callback" {
			t.Fatalf("unexpected redirect URI: %q", redirectURI)
		}
		return &oauth2.Token{
			AccessToken:  "gmail-access-token",
			RefreshToken: "gmail-refresh-token",
			Expiry:       time.Now().Add(time.Hour),
		}, nil
	}
	gmailFetchProfileFunc = func(token *oauth2.Token) (*gmailProfile, error) {
		if token.AccessToken != "gmail-access-token" {
			t.Fatalf("expected gmail access token, got %q", token.AccessToken)
		}
		return &gmailProfile{
			Email:         "mailbox@example.com",
			Name:          "Mailbox User",
			VerifiedEmail: true,
		}, nil
	}
	t.Cleanup(func() {
		gmailClientID = originalGmailClientID
		gmailClientSecret = originalGmailClientSecret
		tokenEncryptor = originalTokenEncryptor
		gmailExchangeCodeFunc = originalGmailExchangeCodeFunc
		gmailFetchProfileFunc = originalGmailFetchProfileFunc
	})

	state, err := createGmailOAuthState("reader@example.com", "", time.Now())
	if err != nil {
		t.Fatalf("failed to create state: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/integrations/gmail/callback?code=test-code&state="+url.QueryEscape(state), nil)
	req.AddCookie(&http.Cookie{Name: gmailOAuthStateCookieName, Value: state})
	rr := httptest.NewRecorder()

	GmailCallbackHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var accessToken, refreshToken, metadata string
	if err := database.DB.QueryRow(
		`SELECT access_token, refresh_token, metadata FROM external_integrations
		 WHERE user_id = ? AND provider = 'gmail' AND workspace_id IS NULL`,
		1,
	).Scan(&accessToken, &refreshToken, &metadata); err != nil {
		t.Fatalf("failed to query saved gmail integration: %v", err)
	}

	decryptedAccessToken, err := tokenEncryptor.Decrypt(accessToken)
	if err != nil {
		t.Fatalf("failed to decrypt saved access token: %v", err)
	}
	if decryptedAccessToken != "gmail-access-token" {
		t.Fatalf("unexpected decrypted access token %q", decryptedAccessToken)
	}

	decryptedRefreshToken, err := tokenEncryptor.Decrypt(refreshToken)
	if err != nil {
		t.Fatalf("failed to decrypt saved refresh token: %v", err)
	}
	if decryptedRefreshToken != "gmail-refresh-token" {
		t.Fatalf("unexpected decrypted refresh token %q", decryptedRefreshToken)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(metadata), &payload); err != nil {
		t.Fatalf("failed to decode integration metadata: %v", err)
	}
	if payload["email"] != "mailbox@example.com" {
		t.Fatalf("expected connected gmail email in metadata, got %#v", payload["email"])
	}
}

func setupIntegrationsTestDB(t *testing.T) {
	t.Helper()

	setupTestDB()

	if _, err := database.DB.Exec(`
		CREATE TABLE IF NOT EXISTS external_integrations (
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
		)`); err != nil {
		t.Fatalf("failed to create external_integrations table: %v", err)
	}

	if _, err := database.DB.Exec(
		"INSERT INTO users (id, email, password) VALUES (1, 'reader@example.com', 'hashed-password')",
	); err != nil {
		t.Fatalf("failed to seed primary integration user: %v", err)
	}

	if _, err := database.DB.Exec(
		"INSERT INTO users (id, email, password) VALUES (2, 'other@example.com', 'hashed-password')",
	); err != nil {
		t.Fatalf("failed to seed secondary integration user: %v", err)
	}
}

func integrationRequestWithUser(method, target, email string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	return req.WithContext(context.WithValue(req.Context(), middleware.UserEmailKey, email))
}

func TestGetIntegrationsFiltersByWorkspaceAndIncludesGlobalIntegrations(t *testing.T) {
	setupIntegrationsTestDB(t)
	defer database.DB.Close()

	if _, err := database.DB.Exec(
		`INSERT INTO external_integrations
			(id, user_id, workspace_id, provider, access_token, metadata)
		 VALUES
			(1, 1, 9, 'slack', 'token-1', '{"team":"workspace-9"}'),
			(2, 1, NULL, 'github', 'token-2', '{"scope":"global"}'),
			(3, 1, 10, 'slack', 'token-3', '{"team":"workspace-10"}'),
			(4, 2, 9, 'slack', 'token-4', '{"team":"other-user"}')`,
	); err != nil {
		t.Fatalf("failed to seed integrations: %v", err)
	}

	req := integrationRequestWithUser(http.MethodGet, "/api/integrations?workspace_id=9", "reader@example.com")
	rr := httptest.NewRecorder()

	GetIntegrations(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var integrations []models.ExternalIntegration
	if err := json.NewDecoder(rr.Body).Decode(&integrations); err != nil {
		t.Fatalf("failed to decode integrations response: %v", err)
	}

	if len(integrations) != 2 {
		t.Fatalf("expected 2 integrations, got %d", len(integrations))
	}

	var workspaceScoped, globalScoped bool
	for _, integration := range integrations {
		if integration.Provider == "slack" && integration.WorkspaceID == 9 {
			workspaceScoped = true
		}
		if integration.Provider == "github" && integration.Metadata == `{"scope":"global"}` {
			globalScoped = true
		}
	}

	if !workspaceScoped || !globalScoped {
		t.Fatalf("expected one workspace-scoped and one global integration, got %+v", integrations)
	}
}

func TestDeleteIntegrationDeletesOwnedIntegration(t *testing.T) {
	setupIntegrationsTestDB(t)
	defer database.DB.Close()

	if _, err := database.DB.Exec(
		`INSERT INTO external_integrations
			(id, user_id, workspace_id, provider, access_token, metadata)
		 VALUES (5, 1, 9, 'slack', 'token-5', '{"team":"workspace-9"}')`,
	); err != nil {
		t.Fatalf("failed to seed integration: %v", err)
	}

	req := integrationRequestWithUser(http.MethodDelete, "/api/integrations/5", "reader@example.com")
	rr := httptest.NewRecorder()

	DeleteIntegration(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d", rr.Code)
	}

	var count int
	if err := database.DB.QueryRow("SELECT COUNT(*) FROM external_integrations WHERE id = 5").Scan(&count); err != nil {
		t.Fatalf("failed to verify delete: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected integration to be deleted, found %d rows", count)
	}
}

func TestDeleteIntegrationRejectsDifferentOwner(t *testing.T) {
	setupIntegrationsTestDB(t)
	defer database.DB.Close()

	if _, err := database.DB.Exec(
		`INSERT INTO external_integrations
			(id, user_id, workspace_id, provider, access_token, metadata)
		 VALUES (6, 2, 9, 'slack', 'token-6', '{"team":"workspace-9"}')`,
	); err != nil {
		t.Fatalf("failed to seed foreign integration: %v", err)
	}

	req := integrationRequestWithUser(http.MethodDelete, "/api/integrations/6", "reader@example.com")
	rr := httptest.NewRecorder()

	DeleteIntegration(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rr.Code)
	}
}

func TestIntegrationStatusHandlerReturnsConnectionState(t *testing.T) {
	setupIntegrationsTestDB(t)
	defer database.DB.Close()

	if _, err := database.DB.Exec(
		`INSERT INTO external_integrations
			(id, user_id, workspace_id, provider, access_token, metadata)
		 VALUES
			(7, 1, 9, 'slack', 'token-7', '{"team":"workspace-9"}'),
			(8, 1, NULL, 'github', 'token-8', '{"scope":"global"}'),
			(9, 1, NULL, 'gmail', 'token-9', '{"email":"mailbox@example.com"}')`,
	); err != nil {
		t.Fatalf("failed to seed integration statuses: %v", err)
	}

	originalSlackClientID := slackClientID
	originalSlackClientSecret := slackClientSecret
	originalGmailClientID := gmailClientID
	originalGmailClientSecret := gmailClientSecret
	originalTokenEncryptor := tokenEncryptor
	t.Cleanup(func() {
		slackClientID = originalSlackClientID
		slackClientSecret = originalSlackClientSecret
		gmailClientID = originalGmailClientID
		gmailClientSecret = originalGmailClientSecret
		tokenEncryptor = originalTokenEncryptor
	})

	t.Setenv("TOKEN_ENCRYPTION_KEY", "test-encryption-key-32-bytes-long!")
	encryptor, err := utils.NewTokenEncryptor()
	if err != nil {
		t.Fatalf("failed to create token encryptor: %v", err)
	}
	slackClientID = "slack-client"
	slackClientSecret = "slack-secret"
	gmailClientID = "gmail-client"
	gmailClientSecret = "gmail-secret"
	tokenEncryptor = encryptor

	req := integrationRequestWithUser(http.MethodGet, "/api/integrations/status?workspace_id=9", "reader@example.com")
	rr := httptest.NewRecorder()

	IntegrationStatusHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var statuses []models.IntegrationStatus
	if err := json.NewDecoder(rr.Body).Decode(&statuses); err != nil {
		t.Fatalf("failed to decode integration statuses: %v", err)
	}

	if len(statuses) != 3 {
		t.Fatalf("expected 3 statuses, got %d", len(statuses))
	}

	var slackStatus, githubStatus, gmailStatus *models.IntegrationStatus
	for i := range statuses {
		switch statuses[i].Provider {
		case "slack":
			slackStatus = &statuses[i]
		case "github":
			githubStatus = &statuses[i]
		case "gmail":
			gmailStatus = &statuses[i]
		}
	}

	if slackStatus == nil || !slackStatus.Configured || !slackStatus.Connected {
		t.Fatalf("expected configured and connected slack status, got %+v", slackStatus)
	}
	if githubStatus == nil || !githubStatus.Connected {
		t.Fatalf("expected connected github status, got %+v", githubStatus)
	}
	if gmailStatus == nil || !gmailStatus.Configured || !gmailStatus.Connected {
		t.Fatalf("expected configured and connected gmail status, got %+v", gmailStatus)
	}
}
