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

type updateDecisionRequest struct {
	Title       *string `json:"title"`
	Description *string `json:"description"`
	Status      *string `json:"status"`
}

func UpdateDecision(w http.ResponseWriter, r *http.Request, userEmail string) {
	if r.Method != http.MethodPut && r.Method != http.MethodPatch {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	decisionID, err := parseDecisionID(r.URL.Path)
	if err != nil {
		http.Error(w, "Invalid decision ID", http.StatusBadRequest)
		return
	}

	var req updateDecisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	setClauses := make([]string, 0, 3)
	args := make([]any, 0, 5)

	if req.Title != nil {
		title := strings.TrimSpace(*req.Title)
		if title == "" {
			http.Error(w, "Title cannot be empty", http.StatusBadRequest)
			return
		}
		setClauses = append(setClauses, "title = ?")
		args = append(args, title)
	}

	if req.Description != nil {
		description := strings.TrimSpace(*req.Description)
		if description == "" {
			http.Error(w, "Description cannot be empty", http.StatusBadRequest)
			return
		}
		setClauses = append(setClauses, "description = ?")
		args = append(args, description)
	}

	if req.Status != nil {
		status := strings.TrimSpace(*req.Status)
		if status == "" {
			http.Error(w, "Status cannot be empty", http.StatusBadRequest)
			return
		}
		setClauses = append(setClauses, "status = ?")
		args = append(args, status)
	}

	if len(setClauses) == 0 {
		http.Error(w, "At least one field is required", http.StatusBadRequest)
		return
	}

	ownerID, err := getUserIDByEmail(userEmail)
	if err == sql.ErrNoRows {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if err != nil {
		http.Error(w, "Failed to authorize user", http.StatusInternalServerError)
		return
	}

	updateQuery := fmt.Sprintf(
		"UPDATE decisions SET %s, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND owner_id = ?",
		strings.Join(setClauses, ", "),
	)
	args = append(args, decisionID, ownerID)

	result, err := database.DB.Exec(updateQuery, args...)
	if err != nil {
		http.Error(w, "Failed to update decision", http.StatusInternalServerError)
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		http.Error(w, "Failed to update decision", http.StatusInternalServerError)
		return
	}
	if rowsAffected == 0 {
		http.Error(w, "Decision not found", http.StatusNotFound)
		return
	}

	var decision models.Decision
	err = database.DB.QueryRow(
		`SELECT id, title, description, status, owner_id, created_at, updated_at
		 FROM decisions
		 WHERE id = ?`,
		decisionID,
	).Scan(
		&decision.ID,
		&decision.Title,
		&decision.Description,
		&decision.Status,
		&decision.OwnerID,
		&decision.CreatedAt,
		&decision.UpdatedAt,
	)
	if err != nil {
		http.Error(w, "Failed to fetch updated decision", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(decision)
}

func parseDecisionID(path string) (int64, error) {
	const prefix = "/api/decisions/"
	if !strings.HasPrefix(path, prefix) {
		return 0, fmt.Errorf("invalid path")
	}

	idPart := strings.TrimPrefix(path, prefix)
	if idPart == "" || strings.Contains(idPart, "/") {
		return 0, fmt.Errorf("invalid decision id")
	}

	id, err := strconv.ParseInt(idPart, 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("invalid decision id")
	}

	return id, nil
}

func getUserIDByEmail(email string) (int, error) {
	var ownerID int
	err := database.DB.QueryRow("SELECT id FROM users WHERE email = ?", email).Scan(&ownerID)
	if err != nil {
		return 0, err
	}
	return ownerID, nil
}
