package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sentinent-backend/database"
	"sentinent-backend/middleware"
	"sentinent-backend/services"
	"sentinent-backend/utils"
	"testing"
	"time"
)

func TestJiraAuthHandlerSetsSignedStateCookie(t *testing.T) {
	setupIntegrationsTestDB(t)
	defer database.DB.Close()

	originalJwtKey := utils.JwtKey
	utils.JwtKey = []byte("test-jwt-secret")
	t.Cleanup(func() {
		utils.JwtKey = originalJwtKey
	})

	t.Setenv("JIRA_CLIENT_ID", "jira-client")
	t.Setenv("JIRA_CLIENT_SECRET", "jira-secret")
	t.Setenv("API_BASE_URL", "https://api.example.com")
	if err := services.InitJiraService(); err != nil {
		t.Fatalf("failed to initialize Jira service: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/integrations/jira/auth?workspace_id=9&redirect_url=https://app.example.com/settings", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserEmailKey, "reader@example.com"))
	rr := httptest.NewRecorder()

	JiraAuthHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var payload map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&payload); err != nil {
		t.Fatalf("failed to decode Jira auth response: %v", err)
	}

	authURL, err := url.Parse(payload["auth_url"])
	if err != nil {
		t.Fatalf("failed to parse auth URL: %v", err)
	}

	email, workspaceID, redirectURL, err := validateJiraOAuthState(authURL.Query().Get("state"))
	if err != nil {
		t.Fatalf("expected Jira state to validate: %v", err)
	}
	if email != "reader@example.com" || workspaceID != 9 || redirectURL != "https://app.example.com/settings" {
		t.Fatalf("unexpected state values: email=%q workspace=%d redirect=%q", email, workspaceID, redirectURL)
	}

	cookie := rr.Result().Cookies()[0]
	if cookie.Name != jiraOAuthStateCookieName || !cookie.HttpOnly {
		t.Fatalf("expected HttpOnly Jira state cookie, got %+v", cookie)
	}
}

func TestValidateJiraOAuthStateRejectsExpiredState(t *testing.T) {
	originalJwtKey := utils.JwtKey
	utils.JwtKey = []byte("test-jwt-secret")
	t.Cleanup(func() {
		utils.JwtKey = originalJwtKey
	})

	state, err := createJiraOAuthState("reader@example.com", 9, "", time.Now().Add(-jiraOAuthStateTTL-time.Minute))
	if err != nil {
		t.Fatalf("failed to create expired state: %v", err)
	}

	if _, _, _, err := validateJiraOAuthState(state); err == nil {
		t.Fatal("expected expired Jira state to be rejected")
	}
}
