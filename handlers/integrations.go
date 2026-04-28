package handlers

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"sentinent-backend/database"
	"sentinent-backend/middleware"
	"sentinent-backend/models"
	"sentinent-backend/services"
	"sentinent-backend/utils"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

var (
	slackClient           = services.NewSlackClient()
	tokenEncryptor        *utils.TokenEncryptor
	slackClientID         string
	slackClientSecret     string
	gmailClientID         string
	gmailClientSecret     string
	slackExchangeCodeFunc = func(clientID, clientSecret, code, redirectURI string) (*services.SlackOAuthResponse, error) {
		return slackClient.ExchangeCodeForToken(clientID, clientSecret, code, redirectURI)
	}
	githubAuthURLFunc         = services.GetGitHubAuthURL
	githubExchangeCodeFunc    = services.ExchangeGitHubCode
	githubSaveIntegrationFunc = services.SaveGitHubIntegration
	githubSyncSignalsFunc     = services.SyncGitHubSignals
	gmailExchangeCodeFunc     = exchangeGmailCode
	gmailFetchProfileFunc     = fetchGmailProfile
)

const (
	githubOAuthStateCookieName = "github_oauth_state"
	gmailOAuthStateCookieName  = "gmail_oauth_state"
	githubOAuthStateTTL        = 10 * time.Minute
	gmailOAuthStateTTL         = 10 * time.Minute
	slackOAuthStateTTL         = 10 * time.Minute
)

type githubOAuthStateClaims struct {
	Email       string `json:"email"`
	WorkspaceID int    `json:"workspace_id"`
	RedirectURL string `json:"redirect_url,omitempty"`
	jwt.RegisteredClaims
}

type slackOAuthStateClaims struct {
	UserID      int `json:"user_id"`
	WorkspaceID int `json:"workspace_id"`
	jwt.RegisteredClaims
}

type gmailOAuthStateClaims struct {
	Email       string `json:"email"`
	RedirectURL string `json:"redirect_url,omitempty"`
	jwt.RegisteredClaims
}

type gmailProfile struct {
	Email         string `json:"email"`
	Name          string `json:"name"`
	VerifiedEmail bool   `json:"verified_email"`
}

func InitIntegrationHandlers() error {
	slackClientID = os.Getenv("SLACK_CLIENT_ID")
	slackClientSecret = os.Getenv("SLACK_CLIENT_SECRET")
	gmailClientID = strings.TrimSpace(os.Getenv("GOOGLE_CLIENT_ID"))
	gmailClientSecret = strings.TrimSpace(os.Getenv("GOOGLE_CLIENT_SECRET"))

	needsTokenEncryptor := (slackClientID != "" && slackClientSecret != "") || (gmailClientID != "" && gmailClientSecret != "")
	if !needsTokenEncryptor {
		return nil
	}

	encryptor, err := utils.NewTokenEncryptor()
	if err != nil {
		return err
	}
	tokenEncryptor = encryptor
	return nil
}

func SlackAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isSlackConfigured() {
		http.Error(w, "Slack integration not configured", http.StatusServiceUnavailable)
		return
	}

	userID, err := getUserIDFromContext(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	workspaceIDStr := r.URL.Query().Get("workspace_id")
	if workspaceIDStr == "" {
		http.Error(w, "workspace_id is required", http.StatusBadRequest)
		return
	}

	workspaceID, err := strconv.Atoi(workspaceIDStr)
	if err != nil {
		http.Error(w, "Invalid workspace_id", http.StatusBadRequest)
		return
	}

	state, err := createSlackOAuthState(userID, workspaceID, time.Now())
	if err != nil {
		http.Error(w, "Failed to create OAuth state", http.StatusInternalServerError)
		return
	}
	redirectURI := getSlackRedirectURI(r)
	authURL := "https://slack.com/oauth/v2/authorize?" +
		"client_id=" + slackClientID +
		"&scope=channels:history,channels:read,chat:write,users:read,groups:read,im:history,groups:history" +
		"&redirect_uri=" + redirectURI +
		"&state=" + state

	http.SetCookie(w, &http.Cookie{
		Name:     "slack_oauth_state",
		Value:    state,
		Expires:  time.Now().Add(10 * time.Minute),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"auth_url": authURL})
}

func SlackCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isSlackConfigured() {
		http.Error(w, "Slack integration not configured", http.StatusServiceUnavailable)
		return
	}

	state := r.URL.Query().Get("state")
	userID, workspaceID, err := validateSlackOAuthState(state)
	if err != nil {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Authorization code not provided", http.StatusBadRequest)
		return
	}

	redirectURI := getSlackRedirectURI(r)
	oauthResp, err := slackExchangeCodeFunc(slackClientID, slackClientSecret, code, redirectURI)
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	encryptedAccessToken, err := tokenEncryptor.Encrypt(oauthResp.AccessToken)
	if err != nil {
		http.Error(w, "Failed to encrypt token", http.StatusInternalServerError)
		return
	}

	metadata := map[string]interface{}{
		"team_id":     oauthResp.Team.ID,
		"team_name":   oauthResp.Team.Name,
		"bot_user_id": oauthResp.BotUserID,
		"app_id":      oauthResp.AppID,
		"scope":       oauthResp.Scope,
	}
	metadataJSON, _ := json.Marshal(metadata)

	var existingID int
	err = database.DB.QueryRow(
		`SELECT id FROM external_integrations
		 WHERE user_id = ? AND workspace_id = ? AND provider = 'slack'`,
		userID, workspaceID,
	).Scan(&existingID)

	switch err {
	case sql.ErrNoRows:
		_, err = database.DB.Exec(
			`INSERT INTO external_integrations
			 (user_id, workspace_id, provider, access_token, metadata, updated_at)
			 VALUES (?, ?, 'slack', ?, ?, CURRENT_TIMESTAMP)`,
			userID, workspaceID, encryptedAccessToken, string(metadataJSON),
		)
	case nil:
		_, err = database.DB.Exec(
			`UPDATE external_integrations
			 SET access_token = ?, metadata = ?, updated_at = CURRENT_TIMESTAMP
			 WHERE id = ?`,
			encryptedAccessToken, string(metadataJSON), existingID,
		)
	}
	if err != nil {
		http.Error(w, "Failed to save integration", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "slack_oauth_state",
		Value:    "",
		Expires:  time.Unix(0, 0),
		Path:     "/",
		HttpOnly: true,
	})

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(`<html><body style="font-family: sans-serif; text-align: center; margin-top: 50px;"><h2>Slack Connected Successfully!</h2><p>You can close this window to return to Sentinent.</p><script>setTimeout(function() { window.close(); }, 1000);</script></body></html>`))
}

func GetIntegrations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, err := getUserIDFromContext(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	query := `SELECT id, user_id, workspace_id, provider, metadata, created_at, updated_at
		FROM external_integrations WHERE user_id = ?`
	args := []interface{}{userID}

	if workspaceIDStr := r.URL.Query().Get("workspace_id"); workspaceIDStr != "" {
		workspaceID, convErr := strconv.Atoi(workspaceIDStr)
		if convErr != nil {
			http.Error(w, "Invalid workspace_id", http.StatusBadRequest)
			return
		}
		query += " AND (workspace_id = ? OR workspace_id IS NULL)"
		args = append(args, workspaceID)
	}

	log.Printf("[GetIntegrations] userID=%d query=%s args=%v", userID, query, args)
	rows, err := database.DB.Query(query, args...)
	if err != nil {
		http.Error(w, "Failed to fetch integrations", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var integrations []models.ExternalIntegration
	for rows.Next() {
		var integration models.ExternalIntegration
		var workspaceID sql.NullInt64
		var metadata sql.NullString
		if err := rows.Scan(
			&integration.ID,
			&integration.UserID,
			&workspaceID,
			&integration.Provider,
			&metadata,
			&integration.CreatedAt,
			&integration.UpdatedAt,
		); err != nil {
			continue
		}
		if workspaceID.Valid {
			integration.WorkspaceID = int(workspaceID.Int64)
		}
		if metadata.Valid {
			integration.Metadata = metadata.String
		}
		integrations = append(integrations, integration)
	}

	// Deduplicate: if both a workspace-scoped and NULL-workspace record exist for
	// the same provider, prefer the workspace-scoped one. This prevents duplicate
	// integration entries from confusing the frontend's connection state logic.
	seen := make(map[string]int) // provider -> index of best record
	for i, integration := range integrations {
		if prev, exists := seen[integration.Provider]; exists {
			// Keep the one with a non-zero workspace_id
			if integrations[prev].WorkspaceID == 0 && integration.WorkspaceID != 0 {
				seen[integration.Provider] = i
			}
		} else {
			seen[integration.Provider] = i
		}
	}
	deduped := make([]models.ExternalIntegration, 0, len(seen))
	for _, idx := range seen {
		deduped = append(deduped, integrations[idx])
	}

	log.Printf("[GetIntegrations] returning %d integrations (from %d raw), providers: %v", len(deduped), len(integrations), func() []string {
		ps := make([]string, len(deduped))
		for i, d := range deduped {
			ps[i] = fmt.Sprintf("%s(ws=%d)", d.Provider, d.WorkspaceID)
		}
		return ps
	}())

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(deduped)
}

func DeleteIntegration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, err := getUserIDFromContext(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	integrationIDStr := r.URL.Path[len("/api/integrations/"):]
	integrationID, err := strconv.Atoi(integrationIDStr)
	if err != nil {
		http.Error(w, "Invalid integration ID", http.StatusBadRequest)
		return
	}

	var ownerID int
	err = database.DB.QueryRow(
		"SELECT user_id FROM external_integrations WHERE id = ?",
		integrationID,
	).Scan(&ownerID)
	if err == sql.ErrNoRows {
		http.Error(w, "Integration not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "Failed to fetch integration", http.StatusInternalServerError)
		return
	}
	if ownerID != userID {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if _, err := database.DB.Exec("DELETE FROM external_integrations WHERE id = ?", integrationID); err != nil {
		http.Error(w, "Failed to delete integration", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func GetSlackChannels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPatch {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isSlackConfigured() {
		http.Error(w, "Slack integration not configured", http.StatusServiceUnavailable)
		return
	}

	userID, err := getUserIDFromContext(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if r.Method == http.MethodPatch {
		updateSlackChannelSelection(w, r, userID)
		return
	}

	integrationIDStr := r.URL.Query().Get("integration_id")
	if integrationIDStr == "" {
		http.Error(w, "integration_id is required", http.StatusBadRequest)
		return
	}

	integrationID, err := strconv.Atoi(integrationIDStr)
	if err != nil {
		http.Error(w, "Invalid integration_id", http.StatusBadRequest)
		return
	}

	var encryptedToken string
	err = database.DB.QueryRow(
		`SELECT access_token FROM external_integrations
		 WHERE id = ? AND user_id = ? AND provider = 'slack'`,
		integrationID, userID,
	).Scan(&encryptedToken)
	if err == sql.ErrNoRows {
		http.Error(w, "Integration not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "Failed to fetch integration", http.StatusInternalServerError)
		return
	}

	accessToken, err := tokenEncryptor.Decrypt(encryptedToken)
	if err != nil {
		http.Error(w, "Failed to decrypt token", http.StatusInternalServerError)
		return
	}

	channels, rateLimit, err := slackClient.GetChannels(accessToken)
	if err != nil {
		if rateLimit != nil && rateLimit.IsRateLimited() {
			http.Error(w, "Rate limited by Slack API", http.StatusTooManyRequests)
			return
		}
		http.Error(w, "Failed to fetch channels: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"channels": channels})
}

func GmailAuthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isGmailConfigured() {
		http.Error(w, "Gmail integration not configured", http.StatusServiceUnavailable)
		return
	}

	email, ok := middleware.GetUserEmail(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	redirectURL := sanitizeRedirectURL(r.URL.Query().Get("redirect_url"))
	state, err := createGmailOAuthState(email, redirectURL, time.Now())
	if err != nil {
		http.Error(w, "Gmail integration not configured", http.StatusServiceUnavailable)
		return
	}

	authURL := buildGmailAuthURL(state, getGmailRedirectURI(r))
	http.SetCookie(w, &http.Cookie{
		Name:     gmailOAuthStateCookieName,
		Value:    state,
		Expires:  time.Now().Add(gmailOAuthStateTTL),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isProductionEnv(),
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"auth_url": authURL})
}

func GmailCallbackHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stateCookie, err := r.Cookie(gmailOAuthStateCookieName)
	if err != nil {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	state := r.URL.Query().Get("state")
	if subtle.ConstantTimeCompare([]byte(state), []byte(stateCookie.Value)) != 1 {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	userEmail, redirectURL, err := validateGmailOAuthState(state)
	if err != nil {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		if redirectOAuthResultIfPossible(w, r, redirectURL, "gmail", "failed") {
			return
		}
		http.Error(w, "Authorization code not provided", http.StatusBadRequest)
		return
	}

	token, err := gmailExchangeCodeFunc(code, getGmailRedirectURI(r))
	if err != nil {
		if redirectOAuthResultIfPossible(w, r, redirectURL, "gmail", "failed") {
			return
		}
		http.Error(w, "Failed to exchange code: "+err.Error(), http.StatusInternalServerError)
		return
	}

	profile, err := gmailFetchProfileFunc(token)
	if err != nil {
		if redirectOAuthResultIfPossible(w, r, redirectURL, "gmail", "failed") {
			return
		}
		http.Error(w, "Failed to fetch Gmail profile: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var userID int
	err = database.DB.QueryRow("SELECT id FROM users WHERE email = ?", userEmail).Scan(&userID)
	if err != nil {
		if redirectOAuthResultIfPossible(w, r, redirectURL, "gmail", "failed") {
			return
		}
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	if err := saveGmailIntegration(userID, token, profile); err != nil {
		if redirectOAuthResultIfPossible(w, r, redirectURL, "gmail", "failed") {
			return
		}
		http.Error(w, "Failed to save integration: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     gmailOAuthStateCookieName,
		Value:    "",
		Expires:  time.Unix(0, 0),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isProductionEnv(),
	})

	if redirectOAuthResultIfPossible(w, r, redirectURL, "gmail", "connected") {
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(`<html><body style="font-family: sans-serif; text-align: center; margin-top: 50px;"><h2>Google Connected Successfully!</h2><p>You can close this window to return to Sentinent.</p><script>setTimeout(function() { window.close(); }, 1000);</script></body></html>`))
}

func GitHubAuthHandler(w http.ResponseWriter, r *http.Request) {
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

	state, err := createGitHubOAuthState(email, workspaceID, redirectURL, time.Now())
	if err != nil {
		http.Error(w, "GitHub integration not configured", http.StatusServiceUnavailable)
		return
	}

	authURL := githubAuthURLFunc(state)
	if authURL == "" {
		http.Error(w, "GitHub integration not configured", http.StatusServiceUnavailable)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     githubOAuthStateCookieName,
		Value:    state,
		Expires:  time.Now().Add(githubOAuthStateTTL),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isProductionEnv(),
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"auth_url": authURL})
}

func GitHubCallbackHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stateCookie, err := r.Cookie(githubOAuthStateCookieName)
	if err != nil {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	state := r.URL.Query().Get("state")
	if subtle.ConstantTimeCompare([]byte(state), []byte(stateCookie.Value)) != 1 {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	userEmail, workspaceID, redirectURL, err := validateGitHubOAuthState(state)
	if err != nil {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		if redirectOAuthResultIfPossible(w, r, redirectURL, "github", "failed") {
			return
		}
		http.Error(w, "Authorization code not provided", http.StatusBadRequest)
		return
	}

	token, err := githubExchangeCodeFunc(code)
	if err != nil {
		if redirectOAuthResultIfPossible(w, r, redirectURL, "github", "failed") {
			return
		}
		http.Error(w, "Failed to exchange code: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var userID int
	err = database.DB.QueryRow("SELECT id FROM users WHERE email = ?", userEmail).Scan(&userID)
	if err != nil {
		if redirectOAuthResultIfPossible(w, r, redirectURL, "github", "failed") {
			return
		}
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	role, err := middleware.GetWorkspaceRole(userID, workspaceID)
	if err != nil {
		if redirectOAuthResultIfPossible(w, r, redirectURL, "github", "failed") {
			return
		}
		http.Error(w, "Failed to verify workspace access", http.StatusInternalServerError)
		return
	}
	if role == "" {
		if redirectOAuthResultIfPossible(w, r, redirectURL, "github", "failed") {
			return
		}
		http.Error(w, "Forbidden: Not a member of this workspace", http.StatusForbidden)
		return
	}

	if err := githubSaveIntegrationFunc(userID, workspaceID, token); err != nil {
		if redirectOAuthResultIfPossible(w, r, redirectURL, "github", "failed") {
			return
		}
		http.Error(w, "Failed to save integration: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     githubOAuthStateCookieName,
		Value:    "",
		Expires:  time.Unix(0, 0),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isProductionEnv(),
	})

	go func() {
		if err := githubSyncSignalsFunc(userID, workspaceID); err != nil {
			log.Printf("Sync error: %v", err)
		}
	}()

	if redirectOAuthResultIfPossible(w, r, redirectURL, "github", "connected") {
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(`<html><body style="font-family: sans-serif; text-align: center; margin-top: 50px;"><h2>GitHub Connected Successfully!</h2><p>You can close this window to return to Sentinent.</p><script>setTimeout(function() { window.close(); }, 1000);</script></body></html>`))
}

func GitHubReposHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPatch {
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

	if r.Method == http.MethodPatch {
		updateGitHubRepoSelection(w, r, userID, workspaceID)
		return
	}

	repos, err := services.ListAccessibleRepos(userID, workspaceID)
	if err != nil {
		http.Error(w, "Failed to fetch repos: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(repos)
}

func GitHubSyncHandler(w http.ResponseWriter, r *http.Request) {
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
		if err := services.SyncGitHubSignals(userID, workspaceID); err != nil {
			log.Printf("Sync error: %v", err)
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "sync_started"})
}

func GitHubDisconnectHandler(w http.ResponseWriter, r *http.Request) {
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

	if err := services.DeleteGitHubIntegration(userID, workspaceID); err != nil {
		http.Error(w, "Failed to disconnect: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "disconnected"})
}

func GitHubAddCommentHandler(w http.ResponseWriter, r *http.Request) {
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

	// URL format: /api/integrations/github/issues/{number}/comments
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 6 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	number, err := strconv.Atoi(pathParts[5])
	if err != nil {
		http.Error(w, "Invalid issue number", http.StatusBadRequest)
		return
	}

	var req struct {
		Repo string `json:"repo"`
		Body string `json:"body"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := services.AddGitHubComment(userID, workspaceID, req.Repo, number, req.Body); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func GitHubUpdateStateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
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

	// URL format: /api/integrations/github/issues/{number}/state
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 6 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	number, err := strconv.Atoi(pathParts[5])
	if err != nil {
		http.Error(w, "Invalid issue number", http.StatusBadRequest)
		return
	}

	var req struct {
		Repo  string `json:"repo"`
		State string `json:"state"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := services.UpdateGitHubIssueState(userID, workspaceID, req.Repo, number, req.State); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func GmailDisconnectHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, err := getUserIDFromContext(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if _, err := database.DB.Exec(
		"DELETE FROM external_integrations WHERE user_id = ? AND provider = 'gmail' AND workspace_id IS NULL",
		userID,
	); err != nil {
		http.Error(w, "Failed to disconnect Gmail", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "disconnected"})
}

func SignalsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, err := getUserIDFromContext(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	filter := &models.SignalFilter{SourceType: r.URL.Query().Get("source_type")}
	if status := r.URL.Query().Get("status"); status != "" {
		filter.Status = status
	}

	signals, err := services.GetUserSignals(userID, filter)
	if err != nil {
		http.Error(w, "Failed to fetch signals: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(signals)
}

func GitHubWebhookHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	eventType := r.Header.Get("X-GitHub-Event")
	if eventType == "" {
		http.Error(w, "Missing event type", http.StatusBadRequest)
		return
	}

	var payload map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	switch eventType {
	case "issues":
		handleIssuesWebhook(payload)
	case "pull_request":
		handlePullRequestWebhook(payload)
	}

	w.WriteHeader(http.StatusOK)
}

func handleIssuesWebhook(payload map[string]interface{}) {
	issue, ok := payload["issue"].(map[string]interface{})
	if !ok {
		return
	}

	action, _ := payload["action"].(string)
	if action != "opened" && action != "closed" && action != "reopened" && action != "edited" {
		return
	}

	_ = issue
}

func handlePullRequestWebhook(payload map[string]interface{}) {
	pr, ok := payload["pull_request"].(map[string]interface{})
	if !ok {
		return
	}

	action, _ := payload["action"].(string)
	if action == "opened" || action == "closed" || action == "reopened" || action == "edited" {
		_ = pr
	}
}

func IntegrationStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, err := getUserIDFromContext(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var workspaceID *int
	if workspaceIDStr := r.URL.Query().Get("workspace_id"); workspaceIDStr != "" {
		value, convErr := strconv.Atoi(workspaceIDStr)
		if convErr != nil {
			http.Error(w, "Invalid workspace_id", http.StatusBadRequest)
			return
		}
		workspaceID = &value
	}

	statuses := []models.IntegrationStatus{
		buildIntegrationStatus(userID, "slack", isSlackConfigured(), workspaceID),
		buildIntegrationStatus(userID, "github", services.IsGitHubConfigured(), workspaceID),
		buildIntegrationStatus(userID, "gmail", isGmailConfigured(), nil),
		buildIntegrationStatus(userID, "jira", services.IsJiraConfigured(), workspaceID),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(statuses)
}

func buildIntegrationStatus(userID int, provider string, configured bool, workspaceID *int) models.IntegrationStatus {
	status := models.IntegrationStatus{
		Provider:   provider,
		Configured: configured,
	}

	var (
		query string
		args  []interface{}
	)

	switch {
	case workspaceID != nil:
		query = `SELECT updated_at FROM external_integrations
			WHERE user_id = ? AND provider = ? AND workspace_id = ?
			ORDER BY updated_at DESC LIMIT 1`
		args = []interface{}{userID, provider, *workspaceID}
	default:
		query = `SELECT updated_at FROM external_integrations
			WHERE user_id = ? AND provider = ?
			ORDER BY updated_at DESC LIMIT 1`
		args = []interface{}{userID, provider}
	}

	if err := database.DB.QueryRow(query, args...).Scan(&status.UpdatedAt); err == nil {
		status.Connected = true
	}

	return status
}

func updateSlackChannelSelection(w http.ResponseWriter, r *http.Request, userID int) {
	workspaceIDStr := r.URL.Query().Get("workspace_id")
	if workspaceIDStr == "" {
		http.Error(w, "workspace_id is required", http.StatusBadRequest)
		return
	}

	workspaceID, err := strconv.Atoi(workspaceIDStr)
	if err != nil {
		http.Error(w, "Invalid workspace_id", http.StatusBadRequest)
		return
	}

	var req struct {
		ChannelIDs []string `json:"channel_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := updateIntegrationMetadata(
		userID,
		"slack",
		&workspaceID,
		func(metadata map[string]interface{}) {
			metadata["selected_channels"] = req.ChannelIDs
		},
	); err != nil {
		writeIntegrationUpdateError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func updateGitHubRepoSelection(w http.ResponseWriter, r *http.Request, userID, workspaceID int) {
	var req struct {
		RepoIDs []int `json:"repo_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := updateIntegrationMetadata(
		userID,
		"github",
		&workspaceID,
		func(metadata map[string]interface{}) {
			metadata["selected_repo_ids"] = req.RepoIDs
		},
	); err != nil {
		writeIntegrationUpdateError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func updateIntegrationMetadata(
	userID int,
	provider string,
	workspaceID *int,
	mutate func(metadata map[string]interface{}),
) error {
	var (
		query    string
		args     []interface{}
		rowID    int
		metadata sql.NullString
	)

	switch {
	case workspaceID != nil:
		query = `SELECT id, metadata FROM external_integrations
			WHERE user_id = ? AND provider = ? AND workspace_id = ?`
		args = []interface{}{userID, provider, *workspaceID}
	default:
		query = `SELECT id, metadata FROM external_integrations
			WHERE user_id = ? AND provider = ? AND workspace_id IS NULL`
		args = []interface{}{userID, provider}
	}

	if err := database.DB.QueryRow(query, args...).Scan(&rowID, &metadata); err != nil {
		return err
	}

	payload := map[string]interface{}{}
	if metadata.Valid && metadata.String != "" {
		if err := json.Unmarshal([]byte(metadata.String), &payload); err != nil {
			return err
		}
	}
	mutate(payload)

	metadataJSON, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	_, err = database.DB.Exec(
		`UPDATE external_integrations
		 SET metadata = ?, updated_at = CURRENT_TIMESTAMP
		 WHERE id = ?`,
		string(metadataJSON), rowID,
	)
	return err
}

func writeIntegrationUpdateError(w http.ResponseWriter, err error) {
	switch err {
	case sql.ErrNoRows:
		http.Error(w, "Integration not found", http.StatusNotFound)
	default:
		http.Error(w, "Failed to update integration", http.StatusInternalServerError)
	}
}

func getUserIDFromContext(r *http.Request) (int, error) {
	if userID, ok := middleware.GetUserID(r.Context()); ok {
		return userID, nil
	}

	email, ok := middleware.GetUserEmail(r.Context())
	if !ok {
		return 0, http.ErrNoCookie
	}
	var userID int
	err := database.DB.QueryRow("SELECT id FROM users WHERE email = ?", email).Scan(&userID)
	if err != nil {
		return 0, err
	}

	return userID, nil
}

func getAuthorizedWorkspaceID(r *http.Request, userID int) (int, int, error) {
	workspaceIDStr := r.URL.Query().Get("workspace_id")
	if workspaceIDStr == "" {
		return 0, http.StatusBadRequest, fmt.Errorf("workspace_id is required")
	}

	workspaceID, err := strconv.Atoi(workspaceIDStr)
	if err != nil {
		return 0, http.StatusBadRequest, fmt.Errorf("invalid workspace_id")
	}

	role, err := middleware.GetWorkspaceRole(userID, workspaceID)
	if err != nil {
		return 0, http.StatusInternalServerError, fmt.Errorf("failed to verify workspace access")
	}
	if role == "" {
		return 0, http.StatusForbidden, fmt.Errorf("forbidden: not a member of this workspace")
	}

	return workspaceID, 0, nil
}

func getSlackRedirectURI(r *http.Request) string {
	if uri := os.Getenv("SLACK_REDIRECT_URI"); uri != "" {
		return uri
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + "/api/integrations/slack/callback"
}

func isSlackConfigured() bool {
	return slackClientID != "" && slackClientSecret != "" && tokenEncryptor != nil
}

func getGmailRedirectURI(r *http.Request) string {
	if uri := strings.TrimSpace(os.Getenv("GOOGLE_REDIRECT_URI")); uri != "" {
		return uri
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + "/api/integrations/gmail/callback"
}

func isGmailConfigured() bool {
	return gmailClientID != "" && gmailClientSecret != "" && tokenEncryptor != nil
}

func createGitHubOAuthState(email string, workspaceID int, redirectURL string, now time.Time) (string, error) {
	if len(utils.JwtKey) == 0 {
		return "", http.ErrNoCookie
	}

	claims := &githubOAuthStateClaims{
		Email:       email,
		WorkspaceID: workspaceID,
		RedirectURL: sanitizeRedirectURL(redirectURL),
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   email,
			ExpiresAt: jwt.NewNumericDate(now.Add(githubOAuthStateTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(utils.JwtKey)
}

func validateGitHubOAuthState(state string) (string, int, string, error) {
	if state == "" || len(utils.JwtKey) == 0 {
		return "", 0, "", http.ErrNoCookie
	}

	claims := &githubOAuthStateClaims{}
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

func createGmailOAuthState(email, redirectURL string, now time.Time) (string, error) {
	if len(utils.JwtKey) == 0 {
		return "", http.ErrNoCookie
	}

	claims := &gmailOAuthStateClaims{
		Email:       email,
		RedirectURL: sanitizeRedirectURL(redirectURL),
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   email,
			ExpiresAt: jwt.NewNumericDate(now.Add(gmailOAuthStateTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(utils.JwtKey)
}

func validateGmailOAuthState(state string) (string, string, error) {
	if state == "" || len(utils.JwtKey) == 0 {
		return "", "", http.ErrNoCookie
	}

	claims := &gmailOAuthStateClaims{}
	token, err := jwt.ParseWithClaims(state, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, http.ErrNoCookie
		}
		return utils.JwtKey, nil
	})
	if err != nil {
		return "", "", err
	}
	if !token.Valid || claims.Subject == "" {
		return "", "", http.ErrNoCookie
	}

	return claims.Subject, sanitizeRedirectURL(claims.RedirectURL), nil
}

func createSlackOAuthState(userID, workspaceID int, now time.Time) (string, error) {
	if len(utils.JwtKey) == 0 {
		return "", http.ErrNoCookie
	}

	claims := &slackOAuthStateClaims{
		UserID:      userID,
		WorkspaceID: workspaceID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(slackOAuthStateTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(utils.JwtKey)
}

func validateSlackOAuthState(state string) (int, int, error) {
	if state == "" || len(utils.JwtKey) == 0 {
		return 0, 0, http.ErrNoCookie
	}

	claims := &slackOAuthStateClaims{}
	token, err := jwt.ParseWithClaims(state, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, http.ErrNoCookie
		}
		return utils.JwtKey, nil
	})
	if err != nil {
		return 0, 0, err
	}
	if !token.Valid {
		return 0, 0, http.ErrNoCookie
	}

	return claims.UserID, claims.WorkspaceID, nil
}

func buildGmailAuthURL(state, redirectURI string) string {
	config := &oauth2.Config{
		ClientID:     gmailClientID,
		ClientSecret: gmailClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://accounts.google.com/o/oauth2/auth",
			TokenURL: "https://oauth2.googleapis.com/token",
		},
		RedirectURL: redirectURI,
		Scopes: []string{
			"https://www.googleapis.com/auth/gmail.readonly",
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
	}
	return config.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("prompt", "consent"))
}

func exchangeGmailCode(code, redirectURI string) (*oauth2.Token, error) {
	config := &oauth2.Config{
		ClientID:     gmailClientID,
		ClientSecret: gmailClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://accounts.google.com/o/oauth2/auth",
			TokenURL: "https://oauth2.googleapis.com/token",
		},
		RedirectURL: redirectURI,
		Scopes: []string{
			"https://www.googleapis.com/auth/gmail.readonly",
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
	}
	return config.Exchange(context.Background(), code)
}

func fetchGmailProfile(token *oauth2.Token) (*gmailProfile, error) {
	if token == nil || token.AccessToken == "" {
		return nil, fmt.Errorf("missing access token")
	}

	client := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(token))
	req, err := http.NewRequest(http.MethodGet, "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gmail userinfo request failed with status %d", resp.StatusCode)
	}

	var profile gmailProfile
	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		return nil, err
	}
	if strings.TrimSpace(profile.Email) == "" {
		return nil, fmt.Errorf("gmail profile did not include an email address")
	}
	return &profile, nil
}

func saveGmailIntegration(userID int, token *oauth2.Token, profile *gmailProfile) error {
	if tokenEncryptor == nil {
		return fmt.Errorf("token encryption is not configured")
	}

	encryptedAccessToken, err := tokenEncryptor.Encrypt(token.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to encrypt access token: %w", err)
	}

	var encryptedRefreshToken string
	if token.RefreshToken != "" {
		encryptedRefreshToken, err = tokenEncryptor.Encrypt(token.RefreshToken)
		if err != nil {
			return fmt.Errorf("failed to encrypt refresh token: %w", err)
		}
	}

	metadata := map[string]interface{}{
		"email":          profile.Email,
		"name":           profile.Name,
		"verified_email": profile.VerifiedEmail,
	}
	if scope, ok := token.Extra("scope").(string); ok && scope != "" {
		metadata["scope"] = scope
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return err
	}

	result, err := database.DB.Exec(
		`UPDATE external_integrations
		 SET access_token = ?, refresh_token = ?, expires_at = ?, metadata = ?, updated_at = CURRENT_TIMESTAMP
		 WHERE user_id = ? AND provider = 'gmail' AND workspace_id IS NULL`,
		encryptedAccessToken, encryptedRefreshToken, token.Expiry, string(metadataJSON), userID,
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
		 VALUES (?, NULL, 'gmail', ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		userID, encryptedAccessToken, encryptedRefreshToken, token.Expiry, string(metadataJSON),
	)
	return err
}

func sanitizeRedirectURL(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	switch parsed.Scheme {
	case "http", "https":
		return parsed.String()
	default:
		return ""
	}
}

func redirectOAuthResultIfPossible(w http.ResponseWriter, r *http.Request, redirectURL, provider, status string) bool {
	redirectURL = sanitizeRedirectURL(redirectURL)
	if redirectURL == "" {
		return false
	}

	parsed, err := url.Parse(redirectURL)
	if err != nil {
		return false
	}

	query := parsed.Query()
	query.Set(provider, status)
	parsed.RawQuery = query.Encode()
	http.Redirect(w, r, parsed.String(), http.StatusFound)
	return true
}
