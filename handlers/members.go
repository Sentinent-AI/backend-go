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

func WorkspacesRouter(w http.ResponseWriter, r *http.Request) {
	parts := splitPath(r.URL.Path)
	if len(parts) < 4 || parts[0] != "api" || parts[1] != "workspaces" {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	switch {
	case len(parts) == 4 && parts[3] == "signals" && r.Method == http.MethodGet:
		GetSignals(w, r)
	case len(parts) == 4 && parts[3] == "invitations" && r.Method == http.MethodPost:
		CreateInvitation(w, r)
	case len(parts) == 4 && parts[3] == "invitations" && r.Method == http.MethodGet:
		ListInvitations(w, r)
	case len(parts) == 4 && parts[3] == "members" && r.Method == http.MethodGet:
		ListMembers(w, r)
	case len(parts) == 5 && parts[3] == "members" && r.Method == http.MethodPatch:
		UpdateMemberRole(w, r)
	case len(parts) == 5 && parts[3] == "members" && r.Method == http.MethodDelete:
		RemoveMember(w, r)
	default:
		http.Error(w, "Not found", http.StatusNotFound)
	}
}

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

	workspaceID, err := extractWorkspaceIDFromPath(r.URL.Path)
	if err != nil {
		http.Error(w, "Invalid workspace ID", http.StatusBadRequest)
		return
	}

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
		`SELECT wm.id, wm.workspace_id, wm.user_id, wm.role, wm.joined_at, wm.updated_at, u.email
		 FROM workspace_members wm
		 JOIN users u ON u.id = wm.user_id
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

	members := make([]models.WorkspaceMember, 0)
	for rows.Next() {
		var member models.WorkspaceMember
		if err := rows.Scan(
			&member.ID,
			&member.WorkspaceID,
			&member.UserID,
			&member.Role,
			&member.JoinedAt,
			&member.UpdatedAt,
			&member.Email,
		); err != nil {
			http.Error(w, "Failed to scan member", http.StatusInternalServerError)
			return
		}
		members = append(members, member)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(members)
}

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

	workspaceID, targetUserID, err := extractWorkspaceAndUserIDs(r.URL.Path)
	if err != nil {
		http.Error(w, "Invalid workspace or user ID", http.StatusBadRequest)
		return
	}

	isOwner, err := middleware.IsWorkspaceOwner(currentUserID, workspaceID)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if !isOwner {
		http.Error(w, "Forbidden: Only owners can remove members", http.StatusForbidden)
		return
	}
	if currentUserID == targetUserID {
		http.Error(w, "Cannot remove yourself as owner. Transfer ownership first.", http.StatusBadRequest)
		return
	}

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
	if targetRole == string(models.RoleOwner) {
		http.Error(w, "Cannot remove another owner", http.StatusForbidden)
		return
	}

	if _, err := database.DB.Exec(
		"DELETE FROM workspace_members WHERE workspace_id = ? AND user_id = ?",
		workspaceID, targetUserID,
	); err != nil {
		http.Error(w, "Failed to remove member", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

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

	workspaceID, targetUserID, err := extractWorkspaceAndUserIDs(r.URL.Path)
	if err != nil {
		http.Error(w, "Invalid workspace or user ID", http.StatusBadRequest)
		return
	}

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
	if req.Role != models.RoleOwner && req.Role != models.RoleMember && req.Role != models.RoleViewer {
		http.Error(w, "Invalid role. Must be 'owner', 'member', or 'viewer'", http.StatusBadRequest)
		return
	}

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

	if currentUserID == targetUserID && req.Role != models.RoleOwner {
		http.Error(w, "Cannot change your own role. Transfer ownership to another user first.", http.StatusBadRequest)
		return
	}

	tx, err := database.DB.Begin()
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	if req.Role == models.RoleOwner && targetRole != string(models.RoleOwner) {
		if _, err := tx.Exec(
			"UPDATE workspaces SET owner_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
			targetUserID, workspaceID,
		); err != nil {
			http.Error(w, "Failed to transfer ownership", http.StatusInternalServerError)
			return
		}
		if _, err := tx.Exec(
			"UPDATE workspace_members SET role = ?, updated_at = CURRENT_TIMESTAMP WHERE workspace_id = ? AND user_id = ?",
			models.RoleMember, workspaceID, currentUserID,
		); err != nil {
			http.Error(w, "Failed to transfer ownership", http.StatusInternalServerError)
			return
		}
	}

	if _, err := tx.Exec(
		"UPDATE workspace_members SET role = ?, updated_at = CURRENT_TIMESTAMP WHERE workspace_id = ? AND user_id = ?",
		req.Role, workspaceID, targetUserID,
	); err != nil {
		http.Error(w, "Failed to update member role", http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(); err != nil {
		http.Error(w, "Failed to update member role", http.StatusInternalServerError)
		return
	}

	var member models.WorkspaceMember
	err = database.DB.QueryRow(
		`SELECT wm.id, wm.workspace_id, wm.user_id, wm.role, wm.joined_at, wm.updated_at, u.email
		 FROM workspace_members wm
		 JOIN users u ON u.id = wm.user_id
		 WHERE wm.workspace_id = ? AND wm.user_id = ?`,
		workspaceID, targetUserID,
	).Scan(
		&member.ID,
		&member.WorkspaceID,
		&member.UserID,
		&member.Role,
		&member.JoinedAt,
		&member.UpdatedAt,
		&member.Email,
	)
	if err != nil {
		http.Error(w, "Failed to fetch updated member", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(member)
}

func extractWorkspaceAndUserIDs(path string) (workspaceID int, userID int, err error) {
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
