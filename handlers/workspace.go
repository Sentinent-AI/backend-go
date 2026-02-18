package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"sentinent-backend/database"
	"sentinent-backend/models"
	"strconv"
	"strings"
)

type createWorkspaceRequest struct {
	Name string `json:"name"`
}

type addWorkspaceMemberRequest struct {
	Email string `json:"email"`
}

type createWorkspaceDecisionRequest struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Status      string `json:"status"`
}

func CreateWorkspace(w http.ResponseWriter, r *http.Request, userEmail string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req createWorkspaceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		http.Error(w, "Workspace name is required", http.StatusBadRequest)
		return
	}

	ownerID, err := getUserIDByEmail(userEmail)
	if err == sql.ErrNoRows {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if err != nil {
		http.Error(w, "Failed to identify user", http.StatusInternalServerError)
		return
	}

	result, err := database.DB.Exec(
		"INSERT INTO workspaces (name, owner_id) VALUES (?, ?)",
		req.Name,
		ownerID,
	)
	if err != nil {
		http.Error(w, "Failed to create workspace", http.StatusInternalServerError)
		return
	}

	workspaceID, err := result.LastInsertId()
	if err != nil {
		http.Error(w, "Failed to create workspace", http.StatusInternalServerError)
		return
	}

	_, err = database.DB.Exec(
		"INSERT INTO workspace_members (workspace_id, user_id, role) VALUES (?, ?, 'owner')",
		workspaceID,
		ownerID,
	)
	if err != nil {
		http.Error(w, "Failed to create workspace membership", http.StatusInternalServerError)
		return
	}

	var workspace models.Workspace
	err = database.DB.QueryRow(
		"SELECT id, name, owner_id, created_at FROM workspaces WHERE id = ?",
		workspaceID,
	).Scan(&workspace.ID, &workspace.Name, &workspace.OwnerID, &workspace.CreatedAt)
	if err != nil {
		http.Error(w, "Failed to fetch workspace", http.StatusInternalServerError)
		return
	}
	workspace.OwnerEmail = userEmail

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(workspace)
}

func WorkspaceSubresourceHandler(w http.ResponseWriter, r *http.Request, userEmail string) {
	workspaceID, resource, err := parseWorkspaceSubresourcePath(r.URL.Path)
	if err != nil {
		http.Error(w, "Invalid workspace path", http.StatusBadRequest)
		return
	}

	switch resource {
	case "members":
		addWorkspaceMember(w, r, userEmail, workspaceID)
	case "decisions":
		createDecisionInWorkspace(w, r, userEmail, workspaceID)
	default:
		http.Error(w, "Not found", http.StatusNotFound)
	}
}

func addWorkspaceMember(w http.ResponseWriter, r *http.Request, requesterEmail string, workspaceID int64) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	requesterID, err := getUserIDByEmail(requesterEmail)
	if err == sql.ErrNoRows {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if err != nil {
		http.Error(w, "Failed to identify user", http.StatusInternalServerError)
		return
	}

	var ownerID int
	err = database.DB.QueryRow("SELECT owner_id FROM workspaces WHERE id = ?", workspaceID).Scan(&ownerID)
	if err == sql.ErrNoRows {
		http.Error(w, "Workspace not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "Failed to fetch workspace", http.StatusInternalServerError)
		return
	}

	if ownerID != requesterID {
		http.Error(w, "Only workspace owner can add members", http.StatusForbidden)
		return
	}

	var req addWorkspaceMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" {
		http.Error(w, "Member email is required", http.StatusBadRequest)
		return
	}

	memberID, err := getUserIDByEmail(req.Email)
	if err == sql.ErrNoRows {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "Failed to fetch user", http.StatusInternalServerError)
		return
	}

	_, err = database.DB.Exec(
		`INSERT INTO workspace_members (workspace_id, user_id, role)
		 VALUES (?, ?, 'member')
		 ON CONFLICT(workspace_id, user_id) DO NOTHING`,
		workspaceID,
		memberID,
	)
	if err != nil {
		http.Error(w, "Failed to add workspace member", http.StatusInternalServerError)
		return
	}

	var membership models.WorkspaceMember
	err = database.DB.QueryRow(
		`SELECT wm.workspace_id, wm.user_id, wm.role, wm.created_at
		 FROM workspace_members wm
		 WHERE wm.workspace_id = ? AND wm.user_id = ?`,
		workspaceID,
		memberID,
	).Scan(&membership.WorkspaceID, &membership.UserID, &membership.Role, &membership.CreatedAt)
	if err != nil {
		http.Error(w, "Failed to fetch workspace member", http.StatusInternalServerError)
		return
	}
	membership.Email = req.Email

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(membership)
}

func createDecisionInWorkspace(w http.ResponseWriter, r *http.Request, userEmail string, workspaceID int64) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ownerID, err := getUserIDByEmail(userEmail)
	if err == sql.ErrNoRows {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if err != nil {
		http.Error(w, "Failed to identify user", http.StatusInternalServerError)
		return
	}

	if !workspaceExists(workspaceID) {
		http.Error(w, "Workspace not found", http.StatusNotFound)
		return
	}

	if !isWorkspaceMember(workspaceID, ownerID) {
		http.Error(w, "User is not a member of workspace", http.StatusForbidden)
		return
	}

	var req createWorkspaceDecisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	req.Title = strings.TrimSpace(req.Title)
	req.Description = strings.TrimSpace(req.Description)
	req.Status = strings.TrimSpace(req.Status)
	if req.Title == "" || req.Description == "" || req.Status == "" {
		http.Error(w, "Title, description, and status are required", http.StatusBadRequest)
		return
	}

	result, err := database.DB.Exec(
		`INSERT INTO decisions (title, description, status, workspace_id, owner_id)
		 VALUES (?, ?, ?, ?, ?)`,
		req.Title,
		req.Description,
		req.Status,
		workspaceID,
		ownerID,
	)
	if err != nil {
		http.Error(w, "Failed to create decision", http.StatusInternalServerError)
		return
	}

	decisionID, err := result.LastInsertId()
	if err != nil {
		http.Error(w, "Failed to create decision", http.StatusInternalServerError)
		return
	}

	var decision models.Decision
	err = database.DB.QueryRow(
		`SELECT id, title, description, status, workspace_id, owner_id, created_at, updated_at
		 FROM decisions
		 WHERE id = ?`,
		decisionID,
	).Scan(
		&decision.ID,
		&decision.Title,
		&decision.Description,
		&decision.Status,
		&decision.WorkspaceID,
		&decision.OwnerID,
		&decision.CreatedAt,
		&decision.UpdatedAt,
	)
	if err != nil {
		http.Error(w, "Failed to fetch decision", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(decision)
}

func parseWorkspaceSubresourcePath(path string) (int64, string, error) {
	const prefix = "/api/workspaces/"
	if !strings.HasPrefix(path, prefix) {
		return 0, "", fmt.Errorf("invalid path")
	}

	trimmed := strings.Trim(strings.TrimPrefix(path, prefix), "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 2 {
		return 0, "", fmt.Errorf("invalid path")
	}

	workspaceID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || workspaceID <= 0 {
		return 0, "", fmt.Errorf("invalid workspace id")
	}

	return workspaceID, parts[1], nil
}

func isWorkspaceMember(workspaceID int64, userID int) bool {
	var exists int
	err := database.DB.QueryRow(
		"SELECT 1 FROM workspace_members WHERE workspace_id = ? AND user_id = ?",
		workspaceID,
		userID,
	).Scan(&exists)
	return err == nil && exists == 1
}

func workspaceExists(workspaceID int64) bool {
	var exists int
	err := database.DB.QueryRow(
		"SELECT 1 FROM workspaces WHERE id = ?",
		workspaceID,
	).Scan(&exists)
	return err == nil && exists == 1
}
