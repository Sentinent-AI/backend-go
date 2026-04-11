package handlers

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"sentinent-backend/database"
	"sentinent-backend/middleware"
	"sentinent-backend/models"
	"strings"
)

func ListWorkspaces(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	rows, err := database.DB.Query(
		`SELECT DISTINCT w.id, w.name, COALESCE(w.description, ''), w.owner_id, w.created_at, w.updated_at
		 FROM workspaces w
		 JOIN workspace_members wm ON wm.workspace_id = w.id
		 WHERE wm.user_id = ?
		 ORDER BY w.updated_at DESC, w.id DESC`,
		userID,
	)
	if err != nil {
		http.Error(w, "Failed to fetch workspaces", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	workspaces := make([]models.Workspace, 0)
	for rows.Next() {
		var workspace models.Workspace
		if err := rows.Scan(
			&workspace.ID,
			&workspace.Name,
			&workspace.Description,
			&workspace.OwnerID,
			&workspace.CreatedAt,
			&workspace.UpdatedAt,
		); err != nil {
			http.Error(w, "Failed to scan workspace", http.StatusInternalServerError)
			return
		}
		workspaces = append(workspaces, workspace)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(workspaces)
}

func CreateWorkspace(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req models.WorkspaceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	req.Description = strings.TrimSpace(req.Description)
	if req.Name == "" {
		http.Error(w, "Workspace name is required", http.StatusBadRequest)
		return
	}

	tx, err := database.DB.Begin()
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	result, err := tx.Exec(
		`INSERT INTO workspaces (name, description, owner_id, updated_at)
		 VALUES (?, ?, ?, CURRENT_TIMESTAMP)`,
		req.Name, req.Description, userID,
	)
	if err != nil {
		http.Error(w, "Failed to create workspace", http.StatusInternalServerError)
		return
	}

	workspaceID64, err := result.LastInsertId()
	if err != nil {
		http.Error(w, "Failed to create workspace", http.StatusInternalServerError)
		return
	}
	workspaceID := int(workspaceID64)

	if _, err := tx.Exec(
		`INSERT INTO workspace_members (workspace_id, user_id, role)
		 VALUES (?, ?, ?)`,
		workspaceID, userID, models.RoleOwner,
	); err != nil {
		http.Error(w, "Failed to create workspace membership", http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(); err != nil {
		http.Error(w, "Failed to create workspace", http.StatusInternalServerError)
		return
	}

	workspace, err := getWorkspaceByID(workspaceID)
	if err != nil {
		http.Error(w, "Failed to fetch workspace", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(workspace)
}

func GetWorkspace(w http.ResponseWriter, r *http.Request) {
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

	workspace, err := getWorkspaceByID(workspaceID)
	if err == sql.ErrNoRows {
		http.Error(w, "Workspace not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "Failed to fetch workspace", http.StatusInternalServerError)
		return
	}

	log.Printf("Successfully fetched workspace %d", workspaceID)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(workspace)
}

func UpdateWorkspace(w http.ResponseWriter, r *http.Request) {
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
		http.Error(w, "Forbidden: Only owners can update workspaces", http.StatusForbidden)
		return
	}

	var req models.WorkspaceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	req.Description = strings.TrimSpace(req.Description)
	if req.Name == "" {
		http.Error(w, "Workspace name is required", http.StatusBadRequest)
		return
	}

	result, err := database.DB.Exec(
		`UPDATE workspaces
		 SET name = ?, description = ?, updated_at = CURRENT_TIMESTAMP
		 WHERE id = ?`,
		req.Name, req.Description, workspaceID,
	)
	if err != nil {
		http.Error(w, "Failed to update workspace", http.StatusInternalServerError)
		return
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Workspace not found", http.StatusNotFound)
		return
	}

	workspace, err := getWorkspaceByID(workspaceID)
	if err != nil {
		http.Error(w, "Failed to fetch workspace", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(workspace)
}

func DeleteWorkspace(w http.ResponseWriter, r *http.Request) {
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
		http.Error(w, "Forbidden: Only owners can delete workspaces", http.StatusForbidden)
		return
	}

	tx, err := database.DB.Begin()
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	statements := []string{
		`DELETE FROM signal_status WHERE signal_id IN (SELECT id FROM signals WHERE workspace_id = ?)`,
		`DELETE FROM signals WHERE workspace_id = ?`,
		`DELETE FROM invitations WHERE workspace_id = ?`,
		`DELETE FROM workspace_members WHERE workspace_id = ?`,
		`DELETE FROM external_integrations WHERE workspace_id = ?`,
		`DELETE FROM decisions WHERE workspace_id = ?`,
		`DELETE FROM workspaces WHERE id = ?`,
	}

	for _, statement := range statements {
		if _, err := tx.Exec(statement, workspaceID); err != nil {
			http.Error(w, "Failed to delete workspace", http.StatusInternalServerError)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		http.Error(w, "Failed to delete workspace", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func getWorkspaceByID(workspaceID int) (*models.Workspace, error) {
	var workspace models.Workspace
	err := database.DB.QueryRow(
		`SELECT id, name, COALESCE(description, ''), owner_id, created_at, updated_at
		 FROM workspaces
		 WHERE id = ?`,
		workspaceID,
	).Scan(
		&workspace.ID,
		&workspace.Name,
		&workspace.Description,
		&workspace.OwnerID,
		&workspace.CreatedAt,
		&workspace.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &workspace, nil
}
