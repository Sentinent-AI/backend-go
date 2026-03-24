package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sentinent-backend/database"
	"sentinent-backend/middleware"
	"sentinent-backend/models"
	"sentinent-backend/utils"
	"strconv"
	"strings"
	"time"
)

const invitationExpirationDays = 7

// generateSecureToken generates a cryptographically secure random token
func generateSecureToken() (string, error) {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// CreateInvitation handles POST /api/workspaces/:id/invitations
func CreateInvitation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Extract workspace ID from URL
	workspaceID, err := extractWorkspaceIDFromPath(r.URL.Path)
	if err != nil {
		http.Error(w, "Invalid workspace ID", http.StatusBadRequest)
		return
	}

	// Verify user is owner
	isOwner, err := middleware.IsWorkspaceOwner(userID, workspaceID)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if !isOwner {
		http.Error(w, "Forbidden: Only owners can invite members", http.StatusForbidden)
		return
	}

	var req models.CreateInvitationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if !utils.IsEmailValid(req.Email) {
		http.Error(w, "Invalid email format", http.StatusBadRequest)
		return
	}

	// Validate role (default to member if not specified or invalid)
	if req.Role != models.RoleViewer {
		req.Role = models.RoleMember
	}

	// Check if user is already a member
	var existingCount int
	err = database.DB.QueryRow(
		"SELECT COUNT(*) FROM workspace_members wm JOIN users u ON wm.user_id = u.id WHERE wm.workspace_id = ? AND u.email = ?",
		workspaceID, req.Email,
	).Scan(&existingCount)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if existingCount > 0 {
		http.Error(w, "User is already a member of this workspace", http.StatusConflict)
		return
	}

	// Check for existing active invitation
	var existingInvitationID int
	err = database.DB.QueryRow(
		"SELECT id FROM invitations WHERE workspace_id = ? AND email = ? AND expires_at > ? AND accepted_at IS NULL",
		workspaceID, req.Email, time.Now(),
	).Scan(&existingInvitationID)
	if err == nil {
		http.Error(w, "Active invitation already exists for this email", http.StatusConflict)
		return
	}

	// Generate secure token
	token, err := generateSecureToken()
	if err != nil {
		http.Error(w, "Failed to generate invitation token", http.StatusInternalServerError)
		return
	}

	expiresAt := time.Now().AddDate(0, 0, invitationExpirationDays)

	result, err := database.DB.Exec(
		"INSERT INTO invitations (workspace_id, email, token, role, expires_at, created_by) VALUES (?, ?, ?, ?, ?, ?)",
		workspaceID, req.Email, token, req.Role, expiresAt, userID,
	)
	if err != nil {
		http.Error(w, "Failed to create invitation", http.StatusInternalServerError)
		return
	}

	invitationID, _ := result.LastInsertId()

	// TODO: Send email with invitation link
	// For now, just log it (mock implementation)
	// In production, this would send an actual email with the join link

	response := models.InvitationResponse{
		ID:          int(invitationID),
		WorkspaceID: workspaceID,
		Email:       req.Email,
		Role:        req.Role,
		ExpiresAt:   expiresAt,
		CreatedAt:   time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// ValidateInvitation handles GET /api/invitations/:token
func ValidateInvitation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := extractTokenFromPath(r.URL.Path)
	if token == "" {
		http.Error(w, "Invalid invitation token", http.StatusBadRequest)
		return
	}

	var invitation models.Invitation
	err := database.DB.QueryRow(
		"SELECT id, workspace_id, email, role, expires_at, created_at FROM invitations WHERE token = ? AND accepted_at IS NULL",
		token,
	).Scan(&invitation.ID, &invitation.WorkspaceID, &invitation.Email, &invitation.Role, &invitation.ExpiresAt, &invitation.CreatedAt)

	if err != nil {
		http.Error(w, "Invalid or expired invitation", http.StatusNotFound)
		return
	}

	if time.Now().After(invitation.ExpiresAt) {
		http.Error(w, "Invitation has expired", http.StatusGone)
		return
	}

	// Get workspace name
	var workspaceName string
	err = database.DB.QueryRow("SELECT name FROM workspaces WHERE id = ?", invitation.WorkspaceID).Scan(&workspaceName)
	if err != nil {
		http.Error(w, "Workspace not found", http.StatusNotFound)
		return
	}

	response := map[string]interface{}{
		"id":             invitation.ID,
		"workspace_id":   invitation.WorkspaceID,
		"workspace_name": workspaceName,
		"email":          invitation.Email,
		"role":           invitation.Role,
		"expires_at":     invitation.ExpiresAt,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// AcceptInvitation handles POST /api/invitations/:token/accept
func AcceptInvitation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	userEmail, ok := middleware.GetUserEmail(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	token := extractTokenFromPath(r.URL.Path)
	if token == "" {
		http.Error(w, "Invalid invitation token", http.StatusBadRequest)
		return
	}

	var invitation models.Invitation
	err := database.DB.QueryRow(
		"SELECT id, workspace_id, email, role, expires_at FROM invitations WHERE token = ? AND accepted_at IS NULL",
		token,
	).Scan(&invitation.ID, &invitation.WorkspaceID, &invitation.Email, &invitation.Role, &invitation.ExpiresAt)

	if err != nil {
		http.Error(w, "Invalid or expired invitation", http.StatusNotFound)
		return
	}

	if time.Now().After(invitation.ExpiresAt) {
		http.Error(w, "Invitation has expired", http.StatusGone)
		return
	}

	// Verify the accepting user's email matches the invitation
	if userEmail != invitation.Email {
		http.Error(w, "Forbidden: This invitation is for a different email address", http.StatusForbidden)
		return
	}

	// Check if user is already a member
	var existingRole string
	err = database.DB.QueryRow(
		"SELECT role FROM workspace_members WHERE workspace_id = ? AND user_id = ?",
		invitation.WorkspaceID, userID,
	).Scan(&existingRole)
	if err == nil {
		http.Error(w, "You are already a member of this workspace", http.StatusConflict)
		return
	}

	// Begin transaction
	tx, err := database.DB.Begin()
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	// Add user to workspace
	_, err = tx.Exec(
		"INSERT INTO workspace_members (workspace_id, user_id, role) VALUES (?, ?, ?)",
		invitation.WorkspaceID, userID, invitation.Role,
	)
	if err != nil {
		http.Error(w, "Failed to add member to workspace", http.StatusInternalServerError)
		return
	}

	// Mark invitation as accepted
	_, err = tx.Exec(
		"UPDATE invitations SET accepted_at = ?, accepted_by = ? WHERE id = ?",
		time.Now(), userID, invitation.ID,
	)
	if err != nil {
		http.Error(w, "Failed to update invitation", http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(); err != nil {
		http.Error(w, "Failed to complete invitation acceptance", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Invitation accepted successfully",
		"role":    string(invitation.Role),
	})
}

// extractWorkspaceIDFromPath extracts workspace ID from /api/workspaces/:id/... paths
func extractWorkspaceIDFromPath(path string) (int, error) {
	// Path format: /api/workspaces/{id}/invitations
	parts := splitPath(path)
	if len(parts) >= 3 && parts[0] == "api" && parts[1] == "workspaces" {
		return strconv.Atoi(parts[2])
	}
	return 0, strconv.ErrSyntax
}

// extractTokenFromPath extracts token from /api/invitations/:token/... paths
func extractTokenFromPath(path string) string {
	// Path format: /api/invitations/{token} or /api/invitations/{token}/accept
	parts := splitPath(path)
	if len(parts) >= 3 && parts[0] == "api" && parts[1] == "invitations" {
		return parts[2]
	}
	return ""
}

// splitPath splits a URL path into components
func splitPath(path string) []string {
	var parts []string
	for _, p := range strings.Split(path, "/") {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}
