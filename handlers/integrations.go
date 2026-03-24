package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"sentinent-backend/database"
	"sentinent-backend/middleware"
	"sentinent-backend/models"
	"sentinent-backend/services"
	"sentinent-backend/utils"
	"strconv"
	"time"
)

var (
	slackClient     *services.SlackClient
	tokenEncryptor  *utils.TokenEncryptor
	slackClientID   string
	slackClientSecret string
)

func init() {
	slackClient = services.NewSlackClient()
}

// InitIntegrationHandlers initializes the integration handlers with dependencies
func InitIntegrationHandlers() error {
	var err error
	tokenEncryptor, err = utils.NewTokenEncryptor()
	if err != nil {
		return err
	}

	slackClientID = os.Getenv("SLACK_CLIENT_ID")
	slackClientSecret = os.Getenv("SLACK_CLIENT_SECRET")

	if slackClientID == "" || slackClientSecret == "" {
		return nil // OAuth will be disabled, but don't fail startup
	}

	return nil
}

// SlackAuth initiates the Slack OAuth flow
func SlackAuth(w http.ResponseWriter, r *http.Request) {
	if slackClientID == "" {
		http.Error(w, "Slack integration not configured", http.StatusServiceUnavailable)
		return
	}

	userID, err := getUserIDFromContext(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Get workspace_id from query parameter
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

	// Store state in a cookie or session (simplified: using cookie)
	state := generateState(userID, workspaceID)

	// Build OAuth URL
	redirectURI := getRedirectURI(r)
	authURL := "https://slack.com/oauth/v2/authorize?" +
		"client_id=" + slackClientID +
		"&scope=channels:history,channels:read,chat:write,users:read,im:history,groups:history" +
		"&redirect_uri=" + redirectURI +
		"&state=" + state

	// Set state cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "slack_oauth_state",
		Value:    state,
		Expires:  time.Now().Add(10 * time.Minute),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"auth_url": authURL,
	})
}

// SlackCallback handles the OAuth callback from Slack
func SlackCallback(w http.ResponseWriter, r *http.Request) {
	if slackClientID == "" || slackClientSecret == "" {
		http.Error(w, "Slack integration not configured", http.StatusServiceUnavailable)
		return
	}

	// Verify state
	stateCookie, err := r.Cookie("slack_oauth_state")
	if err != nil {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	state := r.URL.Query().Get("state")
	if state != stateCookie.Value {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Authorization code not provided", http.StatusBadRequest)
		return
	}

	// Exchange code for token
	redirectURI := getRedirectURI(r)
	oauthResp, err := slackClient.ExchangeCodeForToken(slackClientID, slackClientSecret, code, redirectURI)
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Extract userID and workspaceID from state
	userID, workspaceID, err := parseState(state)
	if err != nil {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	// Encrypt tokens
	encryptedAccessToken, err := tokenEncryptor.Encrypt(oauthResp.AccessToken)
	if err != nil {
		http.Error(w, "Failed to encrypt token", http.StatusInternalServerError)
		return
	}

	// Prepare metadata
	metadata := map[string]interface{}{
		"team_id":      oauthResp.Team.ID,
		"team_name":    oauthResp.Team.Name,
		"bot_user_id":  oauthResp.BotUserID,
		"app_id":       oauthResp.AppID,
		"scope":        oauthResp.Scope,
	}
	metadataJSON, _ := json.Marshal(metadata)

	// Check if integration already exists
	var existingID int
	err = database.DB.QueryRow(
		"SELECT id FROM external_integrations WHERE user_id = ? AND workspace_id = ? AND provider = ?",
		userID, workspaceID, "slack",
	).Scan(&existingID)

	if err == sql.ErrNoRows {
		// Insert new integration
		_, err = database.DB.Exec(
			"INSERT INTO external_integrations (user_id, workspace_id, provider, access_token, metadata) VALUES (?, ?, ?, ?, ?)",
			userID, workspaceID, "slack", encryptedAccessToken, string(metadataJSON),
		)
	} else if err == nil {
		// Update existing integration
		_, err = database.DB.Exec(
			"UPDATE external_integrations SET access_token = ?, metadata = ?, updated_at = ? WHERE id = ?",
			encryptedAccessToken, string(metadataJSON), time.Now(), existingID,
		)
	}

	if err != nil {
		http.Error(w, "Failed to save integration", http.StatusInternalServerError)
		return
	}

	// Clear state cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "slack_oauth_state",
		Value:    "",
		Expires:  time.Unix(0, 0),
		Path:     "/",
		HttpOnly: true,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Slack integration connected successfully",
	})
}

// GetIntegrations lists all integrations for a workspace
func GetIntegrations(w http.ResponseWriter, r *http.Request) {
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

	rows, err := database.DB.Query(
		"SELECT id, user_id, workspace_id, provider, metadata, created_at, updated_at FROM external_integrations WHERE user_id = ? AND workspace_id = ?",
		userID, workspaceID,
	)
	if err != nil {
		http.Error(w, "Failed to fetch integrations", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var integrations []models.ExternalIntegration
	for rows.Next() {
		var i models.ExternalIntegration
		if err := rows.Scan(&i.ID, &i.UserID, &i.WorkspaceID, &i.Provider, &i.Metadata, &i.CreatedAt, &i.UpdatedAt); err != nil {
			continue
		}
		integrations = append(integrations, i)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(integrations)
}

// DeleteIntegration removes an integration
func DeleteIntegration(w http.ResponseWriter, r *http.Request) {
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

	// Verify ownership
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

	_, err = database.DB.Exec("DELETE FROM external_integrations WHERE id = ?", integrationID)
	if err != nil {
		http.Error(w, "Failed to delete integration", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetSlackChannels retrieves channels from Slack for a given integration
func GetSlackChannels(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromContext(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
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

	// Get the integration and verify ownership
	var encryptedToken string
	err = database.DB.QueryRow(
		"SELECT access_token FROM external_integrations WHERE id = ? AND user_id = ? AND provider = ?",
		integrationID, userID, "slack",
	).Scan(&encryptedToken)

	if err == sql.ErrNoRows {
		http.Error(w, "Integration not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "Failed to fetch integration", http.StatusInternalServerError)
		return
	}

	// Decrypt token
	accessToken, err := tokenEncryptor.Decrypt(encryptedToken)
	if err != nil {
		http.Error(w, "Failed to decrypt token", http.StatusInternalServerError)
		return
	}

	// Fetch channels from Slack
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
	json.NewEncoder(w).Encode(map[string]interface{}{
		"channels": channels,
	})
}

// Helper functions

func getUserIDFromContext(r *http.Request) (int, error) {
	email, ok := r.Context().Value(middleware.UserEmailKey).(string)
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

func generateState(userID, workspaceID int) string {
	// Simple state generation - in production use a more secure method
	return strconv.Itoa(userID) + ":" + strconv.Itoa(workspaceID) + ":" + strconv.FormatInt(time.Now().Unix(), 10)
}

func parseState(state string) (userID, workspaceID int, err error) {
	// Simple state parsing
	parts := make([]string, 0)
	current := ""
	for _, c := range state {
		if c == ':' {
			parts = append(parts, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	parts = append(parts, current)

	if len(parts) < 2 {
		return 0, 0, http.ErrNoCookie
	}

	userID, err = strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, err
	}

	workspaceID, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, err
	}

	return userID, workspaceID, nil
}

func getRedirectURI(r *http.Request) string {
	// Use environment variable if set, otherwise construct from request
	if uri := os.Getenv("SLACK_REDIRECT_URI"); uri != "" {
		return uri
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + "/api/integrations/slack/callback"
}
