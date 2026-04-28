package handlers

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"sentinent-backend/database"
	"sentinent-backend/middleware"
	"sentinent-backend/services"
	"sentinent-backend/utils"

	"github.com/golang-jwt/jwt/v5"
)

const (
	jiraOAuthStateCookieName = "jira_oauth_state"
	jiraOAuthStateTTL        = 10 * time.Minute
)

type jiraOAuthStateClaims struct {
	Email       string `json:"email"`
	WorkspaceID int    `json:"workspace_id"`
	RedirectURL string `json:"redirect_url,omitempty"`
	jwt.RegisteredClaims
}

func createJiraOAuthState(email string, workspaceID int, redirectURL string, now time.Time) (string, error) {
	if len(utils.JwtKey) == 0 {
		return "", http.ErrNoCookie
	}

	claims := &jiraOAuthStateClaims{
		Email:       email,
		WorkspaceID: workspaceID,
		RedirectURL: sanitizeRedirectURL(redirectURL),
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   email,
			ExpiresAt: jwt.NewNumericDate(now.Add(jiraOAuthStateTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(utils.JwtKey)
}

func validateJiraOAuthState(state string) (string, int, string, error) {
	if state == "" || len(utils.JwtKey) == 0 {
		return "", 0, "", http.ErrNoCookie
	}

	claims := &jiraOAuthStateClaims{}
	token, err := jwt.ParseWithClaims(state, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, http.ErrNoCookie
		}
		return utils.JwtKey, nil
	})
	if err != nil {
		return "", 0, "", err
	}
	if !token.Valid || claims.Subject == "" {
		return "", 0, "", http.ErrNoCookie
	}

	return claims.Subject, claims.WorkspaceID, sanitizeRedirectURL(claims.RedirectURL), nil
}

func JiraAuthHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("JiraAuthHandler called: %s", r.URL.String())
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, err := getUserIDFromContext(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	email, ok := r.Context().Value(middleware.UserEmailKey).(string)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	workspaceID, statusCode, err := getAuthorizedWorkspaceID(r, userID)
	if err != nil {
		http.Error(w, err.Error(), statusCode)
		return
	}

	redirectURL := sanitizeRedirectURL(r.URL.Query().Get("redirect_url"))

	state, err := createJiraOAuthState(email, workspaceID, redirectURL, time.Now())
	if err != nil {
		http.Error(w, "Jira integration state error", http.StatusInternalServerError)
		return
	}

	authURL := services.GetJiraAuthURL(state)
	if authURL == "" {
		http.Error(w, "Jira integration not configured", http.StatusServiceUnavailable)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     jiraOAuthStateCookieName,
		Value:    state,
		Expires:  time.Now().Add(jiraOAuthStateTTL),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isProductionEnv(),
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"auth_url": authURL})
}

func JiraCallbackHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stateCookie, err := r.Cookie(jiraOAuthStateCookieName)
	if err != nil {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	state := r.URL.Query().Get("state")
	if subtle.ConstantTimeCompare([]byte(state), []byte(stateCookie.Value)) != 1 {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	userEmail, workspaceID, redirectURL, err := validateJiraOAuthState(state)
	if err != nil {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		if redirectOAuthResultIfPossible(w, r, redirectURL, "jira", "failed") {
			return
		}
		http.Error(w, "Authorization code not provided", http.StatusBadRequest)
		return
	}

	token, err := services.ExchangeJiraCode(code)
	if err != nil {
		if redirectOAuthResultIfPossible(w, r, redirectURL, "jira", "failed") {
			return
		}
		http.Error(w, "Failed to exchange code: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var userID int
	err = database.DB.QueryRow("SELECT id FROM users WHERE email = ?", userEmail).Scan(&userID)
	if err != nil {
		if redirectOAuthResultIfPossible(w, r, redirectURL, "jira", "failed") {
			return
		}
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	role, err := middleware.GetWorkspaceRole(userID, workspaceID)
	if err != nil {
		if redirectOAuthResultIfPossible(w, r, redirectURL, "jira", "failed") {
			return
		}
		http.Error(w, "Failed to verify workspace access", http.StatusInternalServerError)
		return
	}
	if role == "" {
		if redirectOAuthResultIfPossible(w, r, redirectURL, "jira", "failed") {
			return
		}
		http.Error(w, "Forbidden: Not a member of this workspace", http.StatusForbidden)
		return
	}

	if err := services.SaveJiraIntegration(userID, workspaceID, token); err != nil {
		if redirectOAuthResultIfPossible(w, r, redirectURL, "jira", "failed") {
			return
		}
		http.Error(w, "Failed to save integration: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     jiraOAuthStateCookieName,
		Value:    "",
		Expires:  time.Unix(0, 0),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isProductionEnv(),
	})

	go func() {
		if err := services.SyncJiraSignals(userID, workspaceID); err != nil {
			log.Printf("Sync error: %v", err)
		}
	}()

	if redirectOAuthResultIfPossible(w, r, redirectURL, "jira", "connected") {
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(`<html><body style="font-family: sans-serif; text-align: center; margin-top: 50px;"><h2>Jira Connected Successfully!</h2><p>You can close this window to return to Sentinent.</p><script>setTimeout(function() { window.close(); }, 1000);</script></body></html>`))
}

func JiraSyncHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, err := getUserIDFromContext(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	workspaceID, statusCode, err := getAuthorizedWorkspaceID(r, userID)
	if err != nil {
		http.Error(w, err.Error(), statusCode)
		return
	}

	go func() {
		if err := services.SyncJiraSignals(userID, workspaceID); err != nil {
			log.Printf("Sync error: %v", err)
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "sync_started"})
}

func JiraDisconnectHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, err := getUserIDFromContext(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	workspaceID, statusCode, err := getAuthorizedWorkspaceID(r, userID)
	if err != nil {
		http.Error(w, err.Error(), statusCode)
		return
	}

	if err := services.DeleteJiraIntegration(userID, workspaceID); err != nil {
		http.Error(w, "Failed to disconnect: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "disconnected"})
}

// JiraProjectsHandler returns Jira projects visible to the connected account.
func JiraProjectsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, err := getUserIDFromContext(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	workspaceID, statusCode, err := getAuthorizedWorkspaceID(r, userID)
	if err != nil {
		http.Error(w, err.Error(), statusCode)
		return
	}

	client, _, err := services.GetJiraClient(userID, workspaceID)
	if err != nil {
		http.Error(w, "Failed to get Jira client: "+err.Error(), http.StatusInternalServerError)
		return
	}

	projects, err := services.FetchJiraProjects(client)
	if err != nil {
		http.Error(w, "Failed to fetch Jira projects: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(projects)
}
