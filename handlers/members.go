package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"sentinent-backend/database"
	"sentinent-backend/middleware"
	"sentinent-backend/models"
	"strconv"
)

// ListMembers handles GET /api/workspaces/:id/members
func ListMembers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
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

	// Verify user is a member (any role)
	role, err := middleware.GetWorkspaceRole(userID, workspaceID)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if role == "" {
		http.Error(w, "Forbidden: Not a member of this workspace", http.StatusForbidden)
		return
	}

	rows, err := database.DB.Query(
		`SELECT wm.id, wm.workspace_id, wm.user_id, wm.role, wm.joined_at, u.email
		 FROM workspace_members wm
		 JOIN users u ON wm.user_id = u.id
		 WHERE wm.workspace_id = ?
		 ORDER BY
			CASE wm.role
				WHEN 'owner' THEN 1
				WHEN 'member' THEN 2
				WHEN 'viewer' THEN 3
				ELSE 4
			END,
			wm.joined_at`,
		workspaceID,
	)
	if err != nil {
		http.Error(w, "Failed to fetch members", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var members []models.WorkspaceMember
	for rows.Next() {
		var m models.WorkspaceMember
		err := rows.Scan(&m.ID, &m.WorkspaceID, &m.UserID, &m.Role, &m.JoinedAt, &m.Email)
		if err != nil {
			http.Error(w, "Failed to scan member", http.StatusInternalServerError)
			return
		}
		members = append(members, m)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(members)
}

// RemoveMember handles DELETE /api/workspaces/:id/members/:userId
func RemoveMember(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	currentUserID, ok := middleware.GetUserID(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Extract workspace ID and target user ID from URL
	workspaceID, targetUserID, err := extractWorkspaceAndUserIDs(r.URL.Path)
	if err != nil {
		http.Error(w, "Invalid workspace or user ID", http.StatusBadRequest)
		return
	}

	// Verify current user is owner
	isOwner, err := middleware.IsWorkspaceOwner(currentUserID, workspaceID)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if !isOwner {
		http.Error(w, "Forbidden: Only owners can remove members", http.StatusForbidden)
		return
	}

	// Prevent owner from removing themselves
	if currentUserID == targetUserID {
		http.Error(w, "Cannot remove yourself as owner. Transfer ownership first.", http.StatusBadRequest)
		return
	}

	// Check if target user is actually a member
	var targetRole string
	err = database.DB.QueryRow(
		"SELECT role FROM workspace_members WHERE workspace_id = ? AND user_id = ?",
		workspaceID, targetUserID,
	).Scan(&targetRole)
	if err == sql.ErrNoRows {
		http.Error(w, "User is not a member of this workspace", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Cannot remove another owner
	if targetRole == string(models.RoleOwner) {
		http.Error(w, "Cannot remove another owner", http.StatusForbidden)
		return
	}

	_, err = database.DB.Exec(
		"DELETE FROM workspace_members WHERE workspace_id = ? AND user_id = ?",
		workspaceID, targetUserID,
	)
	if err != nil {
		http.Error(w, "Failed to remove member", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// UpdateMemberRole handles PATCH /api/workspaces/:id/members/:userId
func UpdateMemberRole(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	currentUserID, ok := middleware.GetUserID(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Extract workspace ID and target user ID from URL
	workspaceID, targetUserID, err := extractWorkspaceAndUserIDs(r.URL.Path)
	if err != nil {
		http.Error(w, "Invalid workspace or user ID", http.StatusBadRequest)
		return
	}

	// Verify current user is owner
	isOwner, err := middleware.IsWorkspaceOwner(currentUserID, workspaceID)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if !isOwner {
		http.Error(w, "Forbidden: Only owners can change member roles", http.StatusForbidden)
		return
	}

	var req struct {
		Role models.WorkspaceMemberRole `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate role
	if req.Role != models.RoleMember && req.Role != models.RoleViewer && req.Role != models.RoleOwner {
		http.Error(w, "Invalid role. Must be 'owner', 'member', or 'viewer'", http.StatusBadRequest)
		return
	}

	// Check if target user is actually a member
	var targetRole string
	err = database.DB.QueryRow(
		"SELECT role FROM workspace_members WHERE workspace_id = ? AND user_id = ?",
		workspaceID, targetUserID,
	).Scan(&targetRole)
	if err == sql.ErrNoRows {
		http.Error(w, "User is not a member of this workspace", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Handle ownership transfer
	if req.Role == models.RoleOwner {
		// If promoting someone to owner, demote current owner to member
		if targetRole != string(models.RoleOwner) {
			_, err = database.DB.Exec(
				"UPDATE workspace_members SET role = ? WHERE workspace_id = ? AND user_id = ?",
				models.RoleMember, workspaceID, currentUserID,
			)
			if err != nil {
				http.Error(w, "Failed to transfer ownership", http.StatusInternalServerError)
				return
			}
		}
	}

	// Prevent changing own role unless transferring ownership (handled above)
	if currentUserID == targetUserID && req.Role != models.RoleOwner {
		http.Error(w, "Cannot change your own role. Transfer ownership to another user first.", http.StatusBadRequest)
		return
	}

	_, err = database.DB.Exec(
		"UPDATE workspace_members SET role = ? WHERE workspace_id = ? AND user_id = ?",
		req.Role, workspaceID, targetUserID,
	)
	if err != nil {
		http.Error(w, "Failed to update member role", http.StatusInternalServerError)
		return
	}

	// Return updated member info
	var member models.WorkspaceMember
	err = database.DB.QueryRow(
		`SELECT wm.id, wm.workspace_id, wm.user_id, wm.role, wm.joined_at, u.email
		 FROM workspace_members wm
		 JOIN users u ON wm.user_id = u.id
		 WHERE wm.workspace_id = ? AND wm.user_id = ?`,
		workspaceID, targetUserID,
	).Scan(&member.ID, &member.WorkspaceID, &member.UserID, &member.Role, &member.JoinedAt, &member.Email)
	if err != nil {
		http.Error(w, "Failed to fetch updated member", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(member)
}

// extractWorkspaceAndUserIDs extracts workspace ID and user ID from /api/workspaces/:id/members/:userId paths
func extractWorkspaceAndUserIDs(path string) (workspaceID int, userID int, err error) {
	// Path format: /api/workspaces/{workspaceId}/members/{userId}
	parts := splitPath(path)
	if len(parts) >= 5 && parts[0] == "api" && parts[1] == "workspaces" && parts[3] == "members" {
		workspaceID, err = strconv.Atoi(parts[2])
		if err != nil {
			return 0, 0, err
		}
		userID, err = strconv.Atoi(parts[4])
		if err != nil {
			return 0, 0, err
		}
		return workspaceID, userID, nil
	}
	return 0, 0, strconv.ErrSyntax
}
