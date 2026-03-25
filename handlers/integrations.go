package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"time"

	"sentinent-backend/database"
	"sentinent-backend/middleware"
	"sentinent-backend/models"
	"sentinent-backend/services"
	"sentinent-backend/utils"
)

var (
	slackClient       = services.NewSlackClient()
	tokenEncryptor    *utils.TokenEncryptor
	slackClientID     string
	slackClientSecret string
)

func InitIntegrationHandlers() error {
	slackClientID = os.Getenv("SLACK_CLIENT_ID")
	slackClientSecret = os.Getenv("SLACK_CLIENT_SECRET")

	if slackClientID == "" || slackClientSecret == "" {
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

	state := generateState(userID, workspaceID)
	redirectURI := getSlackRedirectURI(r)
	authURL := "https://slack.com/oauth/v2/authorize?" +
		"client_id=" + slackClientID +
		"&scope=channels:history,channels:read,chat:write,users:read,im:history,groups:history" +
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

	redirectURI := getSlackRedirectURI(r)
	oauthResp, err := slackClient.ExchangeCodeForToken(slackClientID, slackClientSecret, code, redirectURI)
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	userID, workspaceID, err := parseState(state)
	if err != nil {
		http.Error(w, "Invalid state", http.StatusBadRequest)
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

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Slack integration connected successfully",
	})
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

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(integrations)
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

func GitHubAuthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email, ok := r.Context().Value(middleware.UserEmailKey).(string)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	authURL := services.GetGitHubAuthURL(email)
	if authURL == "" {
		http.Error(w, "GitHub integration not configured", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"auth_url": authURL})
}

func GitHubCallbackHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Authorization code not provided", http.StatusBadRequest)
		return
	}

	token, err := services.ExchangeGitHubCode(code)
	if err != nil {
		http.Error(w, "Failed to exchange code: "+err.Error(), http.StatusInternalServerError)
		return
	}

	userEmail := r.URL.Query().Get("state")
	var userID int
	err = database.DB.QueryRow("SELECT id FROM users WHERE email = ?", userEmail).Scan(&userID)
	if err != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	if err := services.SaveGitHubIntegration(userID, token); err != nil {
		http.Error(w, "Failed to save integration: "+err.Error(), http.StatusInternalServerError)
		return
	}

	go services.SyncGitHubSignals(userID)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "connected"})
}

func GitHubReposHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, err := getUserIDFromContext(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	repos, err := services.ListAccessibleRepos(userID)
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

	go func() {
		if err := services.SyncGitHubSignals(userID); err != nil {
			println("Sync error:", err.Error())
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

	if err := services.DeleteGitHubIntegration(userID); err != nil {
		http.Error(w, "Failed to disconnect: "+err.Error(), http.StatusInternalServerError)
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
	if _, ok := payload["issue"].(map[string]interface{}); !ok {
		return
	}

	action, _ := payload["action"].(string)
	if action == "opened" || action == "closed" || action == "reopened" || action == "edited" {
		return
	}
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
		buildIntegrationStatus(userID, "github", services.IsGitHubConfigured(), nil),
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
	return strconv.Itoa(userID) + ":" + strconv.Itoa(workspaceID) + ":" + strconv.FormatInt(time.Now().Unix(), 10)
}

func parseState(state string) (userID, workspaceID int, err error) {
	parts := make([]string, 0)
	current := ""
	for _, c := range state {
		if c == ':' {
			parts = append(parts, current)
			current = ""
			continue
		}
		current += string(c)
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
