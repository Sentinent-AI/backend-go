package handlers

import (
	"crypto/rand"
	"database/sql"
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

	workspaceID, err := extractWorkspaceIDFromPath(r.URL.Path)
	if err != nil {
		http.Error(w, "Invalid workspace ID", http.StatusBadRequest)
		return
	}

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

	if req.Role != models.RoleViewer {
		req.Role = models.RoleMember
	}

	var existingCount int
	err = database.DB.QueryRow(
		`SELECT COUNT(*)
		 FROM workspace_members wm
		 JOIN users u ON u.id = wm.user_id
		 WHERE wm.workspace_id = ? AND lower(u.email) = lower(?)`,
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

	var existingInvitationID int
	err = database.DB.QueryRow(
		`SELECT id
		 FROM invitations
		 WHERE workspace_id = ?
		   AND lower(email) = lower(?)
		   AND expires_at > ?
		   AND accepted_at IS NULL`,
		workspaceID, req.Email, time.Now(),
	).Scan(&existingInvitationID)
	if err == nil {
		http.Error(w, "Active invitation already exists for this email", http.StatusConflict)
		return
	}
	if err != nil && err != sql.ErrNoRows {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	token, err := generateSecureToken()
	if err != nil {
		http.Error(w, "Failed to generate invitation token", http.StatusInternalServerError)
		return
	}

	expiresAt := time.Now().AddDate(0, 0, invitationExpirationDays)
	result, err := database.DB.Exec(
		`INSERT INTO invitations (workspace_id, email, token, role, expires_at, created_by)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		workspaceID, req.Email, token, req.Role, expiresAt, userID,
	)
	if err != nil {
		http.Error(w, "Failed to create invitation", http.StatusInternalServerError)
		return
	}

	invitationID, _ := result.LastInsertId()
	response := models.InvitationResponse{
		ID:          int(invitationID),
		WorkspaceID: workspaceID,
		Email:       req.Email,
		Token:       token,
		Role:        req.Role,
		ExpiresAt:   expiresAt,
		CreatedAt:   time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(response)
}

func ListInvitations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	workspaceID, err := extractWorkspaceIDFromPath(r.URL.Path)
	if err != nil {
		http.Error(w, "Invalid workspace ID", http.StatusBadRequest)
		return
	}

	isOwner, err := middleware.IsWorkspaceOwner(userID, workspaceID)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if !isOwner {
		http.Error(w, "Forbidden: Only owners can view invitations", http.StatusForbidden)
		return
	}

	rows, err := database.DB.Query(
		`SELECT id, workspace_id, email, token, role, expires_at, created_by, created_at, updated_at
		 FROM invitations
		 WHERE workspace_id = ? AND accepted_at IS NULL AND expires_at > ?
		 ORDER BY created_at DESC`,
		workspaceID, time.Now(),
	)
	if err != nil {
		http.Error(w, "Failed to fetch invitations", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	invitations := make([]models.Invitation, 0)
	for rows.Next() {
		var invitation models.Invitation
		if err := rows.Scan(
			&invitation.ID,
			&invitation.WorkspaceID,
			&invitation.Email,
			&invitation.Token,
			&invitation.Role,
			&invitation.ExpiresAt,
			&invitation.CreatedBy,
			&invitation.CreatedAt,
			&invitation.UpdatedAt,
		); err != nil {
			http.Error(w, "Failed to scan invitation", http.StatusInternalServerError)
			return
		}
		invitations = append(invitations, invitation)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(invitations)
}

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
	var createdBy int
	err := database.DB.QueryRow(
		`SELECT id, workspace_id, email, role, expires_at, created_at, created_by
		 FROM invitations
		 WHERE token = ? AND accepted_at IS NULL`,
		token,
	).Scan(
		&invitation.ID,
		&invitation.WorkspaceID,
		&invitation.Email,
		&invitation.Role,
		&invitation.ExpiresAt,
		&invitation.CreatedAt,
		&createdBy,
	)
	if err != nil {
		http.Error(w, "Invalid or expired invitation", http.StatusNotFound)
		return
	}
	if time.Now().After(invitation.ExpiresAt) {
		http.Error(w, "Invitation has expired", http.StatusGone)
		return
	}

	var workspaceName string
	err = database.DB.QueryRow("SELECT name FROM workspaces WHERE id = ?", invitation.WorkspaceID).Scan(&workspaceName)
	if err != nil {
		http.Error(w, "Workspace not found", http.StatusNotFound)
		return
	}

	var invitedByEmail string
	if err := database.DB.QueryRow("SELECT email FROM users WHERE id = ?", createdBy).Scan(&invitedByEmail); err != nil {
		http.Error(w, "Invitation owner not found", http.StatusNotFound)
		return
	}

	response := map[string]interface{}{
		"valid": true,
		"workspace": map[string]interface{}{
			"id":   invitation.WorkspaceID,
			"name": workspaceName,
		},
		"invited_by": map[string]string{
			"email": invitedByEmail,
		},
		"role":       invitation.Role,
		"expires_at": invitation.ExpiresAt,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

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
		`SELECT id, workspace_id, email, role, expires_at
		 FROM invitations
		 WHERE token = ? AND accepted_at IS NULL`,
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
	if !strings.EqualFold(userEmail, invitation.Email) {
		http.Error(w, "Forbidden: This invitation is for a different email address", http.StatusForbidden)
		return
	}

	var existingRole string
	err = database.DB.QueryRow(
		"SELECT role FROM workspace_members WHERE workspace_id = ? AND user_id = ?",
		invitation.WorkspaceID, userID,
	).Scan(&existingRole)
	if err == nil {
		http.Error(w, "You are already a member of this workspace", http.StatusConflict)
		return
	}
	if err != nil && err != sql.ErrNoRows {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	tx, err := database.DB.Begin()
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	if _, err = tx.Exec(
		"INSERT INTO workspace_members (workspace_id, user_id, role) VALUES (?, ?, ?)",
		invitation.WorkspaceID, userID, invitation.Role,
	); err != nil {
		http.Error(w, "Failed to add member to workspace", http.StatusInternalServerError)
		return
	}
	if _, err = tx.Exec(
		"UPDATE invitations SET accepted_at = ?, accepted_by = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
		time.Now(), userID, invitation.ID,
	); err != nil {
		http.Error(w, "Failed to update invitation", http.StatusInternalServerError)
		return
	}
	if err := tx.Commit(); err != nil {
		http.Error(w, "Failed to complete invitation acceptance", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"workspace_id": invitation.WorkspaceID,
		"role":         invitation.Role,
	})
}

func CancelInvitation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	invitationID, err := extractInvitationIDFromPath(r.URL.Path)
	if err != nil {
		http.Error(w, "Invalid invitation ID", http.StatusBadRequest)
		return
	}

	var workspaceID int
	err = database.DB.QueryRow(
		"SELECT workspace_id FROM invitations WHERE id = ? AND accepted_at IS NULL",
		invitationID,
	).Scan(&workspaceID)
	if err == sql.ErrNoRows {
		http.Error(w, "Invitation not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	isOwner, err := middleware.IsWorkspaceOwner(userID, workspaceID)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if !isOwner {
		http.Error(w, "Forbidden: Only owners can cancel invitations", http.StatusForbidden)
		return
	}

	if _, err := database.DB.Exec("DELETE FROM invitations WHERE id = ?", invitationID); err != nil {
		http.Error(w, "Failed to cancel invitation", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func generateSecureToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func extractWorkspaceIDFromPath(path string) (int, error) {
	parts := splitPath(path)
	if len(parts) >= 3 && parts[0] == "api" && parts[1] == "workspaces" {
		return strconv.Atoi(parts[2])
	}
	return 0, strconv.ErrSyntax
}

func extractTokenFromPath(path string) string {
	parts := splitPath(path)
	if len(parts) >= 3 && parts[0] == "api" && parts[1] == "invitations" {
		return parts[2]
	}
	return ""
}

func extractInvitationIDFromPath(path string) (int, error) {
	parts := splitPath(path)
	if len(parts) >= 3 && parts[0] == "api" && parts[1] == "invitations" {
		return strconv.Atoi(parts[2])
	}
	if len(parts) >= 5 && parts[0] == "api" && parts[1] == "workspaces" && parts[3] == "invitations" {
		return strconv.Atoi(parts[4])
	}
	return 0, strconv.ErrSyntax
}

func splitPath(path string) []string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}
