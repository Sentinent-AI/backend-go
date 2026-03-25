package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sentinent-backend/database"
	"sentinent-backend/middleware"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

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
