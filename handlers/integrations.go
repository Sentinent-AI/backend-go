package handlers

import (
	"encoding/json"
	"net/http"

	"sentinent-backend/database"
	"sentinent-backend/middleware"
	"sentinent-backend/models"
	"sentinent-backend/services"
)

// GitHubAuthHandler initiates the GitHub OAuth flow
func GitHubAuthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get user email from context (must be authenticated)
	email, ok := r.Context().Value(middleware.UserEmailKey).(string)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Generate state parameter (should include user identifier for security)
	state := email

	authURL := services.GetGitHubAuthURL(state)
	if authURL == "" {
		http.Error(w, "GitHub integration not configured", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"auth_url": authURL,
	})
}

// GitHubCallbackHandler handles the OAuth callback from GitHub
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

	// Exchange code for token
	token, err := services.ExchangeGitHubCode(code)
	if err != nil {
		http.Error(w, "Failed to exchange code: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// For now, we need to get the user ID from the state or a session
	// In a production app, you'd use a secure state parameter with user ID
	// For this implementation, we'll require the user to be authenticated via cookie
	userEmail := r.URL.Query().Get("state")

	// Get user ID from database
	var userID int
	err = database.DB.QueryRow("SELECT id FROM users WHERE email = ?", userEmail).Scan(&userID)
	if err != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	// Save the integration
	if err := services.SaveGitHubIntegration(userID, token); err != nil {
		http.Error(w, "Failed to save integration: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Trigger initial sync
	go services.SyncGitHubSignals(userID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "connected",
	})
}

// GitHubReposHandler lists accessible repositories
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
	json.NewEncoder(w).Encode(repos)
}

// GitHubSyncHandler triggers a manual sync of GitHub issues and PRs
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

	// Run sync in background
	go func() {
		if err := services.SyncGitHubSignals(userID); err != nil {
			// Log error - in production, use proper logging
			println("Sync error:", err.Error())
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "sync_started",
	})
}

// GitHubDisconnectHandler disconnects the GitHub integration
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
	json.NewEncoder(w).Encode(map[string]string{
		"status": "disconnected",
	})
}

// SignalsHandler retrieves signals for the authenticated user
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

	// Parse filter parameters
	filter := &models.SignalFilter{}
	sourceType := r.URL.Query().Get("source_type")
	if sourceType != "" {
		filter.SourceType = sourceType
	}

	signals, err := services.GetUserSignals(userID, filter)
	if err != nil {
		http.Error(w, "Failed to fetch signals: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(signals)
}

// getUserIDFromContext extracts user ID from the request context
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

// GitHubWebhookHandler handles GitHub webhook events
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

	// Parse the webhook payload
	var payload map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	// Handle different event types
	switch eventType {
	case "issues":
		handleIssuesWebhook(payload)
	case "pull_request":
		handlePullRequestWebhook(payload)
	default:
		// Ignore other events
	}

	w.WriteHeader(http.StatusOK)
}

// handleIssuesWebhook processes issues events from GitHub
func handleIssuesWebhook(payload map[string]interface{}) {
	// Extract issue data from payload
	_, ok := payload["issue"].(map[string]interface{})
	if !ok {
		return
	}

	action, _ := payload["action"].(string)
	if action == "opened" || action == "closed" || action == "reopened" || action == "edited" {
		// In a real implementation, you'd find the user(s) this issue is assigned to
		// and sync the signal for each of them
		// For now, we'll skip this as it requires more complex user mapping
	}
}

// handlePullRequestWebhook processes pull request events from GitHub
func handlePullRequestWebhook(payload map[string]interface{}) {
	pr, ok := payload["pull_request"].(map[string]interface{})
	if !ok {
		return
	}

	action, _ := payload["action"].(string)
	if action == "opened" || action == "closed" || action == "reopened" || action == "edited" {
		// Similar to issues webhook
		_ = pr
	}
}

// IntegrationStatusHandler returns the status of integrations for the user
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

	// Get GitHub integration status
	integration, err := services.GetGitHubIntegration(userID)
	githubStatus := models.IntegrationStatus{
		Provider:  "github",
		Connected: err == nil,
	}
	if err == nil {
		githubStatus.UpdatedAt = integration.UpdatedAt
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode([]models.IntegrationStatus{githubStatus})
}
