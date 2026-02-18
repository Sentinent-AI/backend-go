package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"sentinent-backend/database"
	"sentinent-backend/models"
	"strings"
)

type createWorkspaceRequest struct {
	Name string `json:"name"`
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

	var ownerID int
	err := database.DB.QueryRow("SELECT id FROM users WHERE email = ?", userEmail).Scan(&ownerID)
	if err == sql.ErrNoRows {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if err != nil {
		http.Error(w, "Failed to look up user", http.StatusInternalServerError)
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
