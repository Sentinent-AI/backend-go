package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"sentinent-backend/database"
	"sentinent-backend/middleware"
	"sentinent-backend/models"
	"strconv"
	"strings"
)

func ListDecisions(w http.ResponseWriter, r *http.Request) {
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
		`SELECT id, workspace_id, user_id, title, COALESCE(description, ''), status, due_date, created_at, updated_at
		 FROM decisions
		 WHERE workspace_id = ?
		 ORDER BY updated_at DESC, id DESC`,
		workspaceID,
	)
	if err != nil {
		http.Error(w, "Failed to fetch decisions", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	decisions := make([]models.Decision, 0)
	for rows.Next() {
		decision, err := scanDecision(rows)
		if err != nil {
			http.Error(w, "Failed to scan decision", http.StatusInternalServerError)
			return
		}
		decisions = append(decisions, *decision)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(decisions)
}

func CreateDecision(w http.ResponseWriter, r *http.Request) {
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
	if role != models.RoleOwner && role != models.RoleMember {
		http.Error(w, "Forbidden: Only members can manage decisions", http.StatusForbidden)
		return
	}

	req, err := decodeDecisionRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	result, err := database.DB.Exec(
		`INSERT INTO decisions (workspace_id, user_id, title, description, status, due_date, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		workspaceID, userID, req.Title, req.Description, req.Status, req.DueDate,
	)
	if err != nil {
		http.Error(w, "Failed to create decision", http.StatusInternalServerError)
		return
	}

	decisionID64, err := result.LastInsertId()
	if err != nil {
		http.Error(w, "Failed to create decision", http.StatusInternalServerError)
		return
	}

	decision, err := getDecisionByID(workspaceID, int(decisionID64))
	if err != nil {
		http.Error(w, "Failed to fetch decision", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(decision)
}

func GetDecision(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	workspaceID, decisionID, err := extractDecisionIDs(r.URL.Path)
	if err != nil {
		http.Error(w, "Invalid workspace or decision ID", http.StatusBadRequest)
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

	decision, err := getDecisionByID(workspaceID, decisionID)
	if err == sql.ErrNoRows {
		http.Error(w, "Decision not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "Failed to fetch decision", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(decision)
}

func UpdateDecision(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	workspaceID, decisionID, err := extractDecisionIDs(r.URL.Path)
	if err != nil {
		http.Error(w, "Invalid workspace or decision ID", http.StatusBadRequest)
		return
	}

	role, err := middleware.GetWorkspaceRole(userID, workspaceID)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if role != models.RoleOwner && role != models.RoleMember {
		http.Error(w, "Forbidden: Only members can manage decisions", http.StatusForbidden)
		return
	}

	req, err := decodeDecisionRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	result, err := database.DB.Exec(
		`UPDATE decisions
		 SET title = ?, description = ?, status = ?, due_date = ?, updated_at = CURRENT_TIMESTAMP
		 WHERE id = ? AND workspace_id = ?`,
		req.Title, req.Description, req.Status, req.DueDate, decisionID, workspaceID,
	)
	if err != nil {
		http.Error(w, "Failed to update decision", http.StatusInternalServerError)
		return
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Decision not found", http.StatusNotFound)
		return
	}

	decision, err := getDecisionByID(workspaceID, decisionID)
	if err != nil {
		http.Error(w, "Failed to fetch decision", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(decision)
}

func DeleteDecision(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	workspaceID, decisionID, err := extractDecisionIDs(r.URL.Path)
	if err != nil {
		http.Error(w, "Invalid workspace or decision ID", http.StatusBadRequest)
		return
	}

	role, err := middleware.GetWorkspaceRole(userID, workspaceID)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if role != models.RoleOwner && role != models.RoleMember {
		http.Error(w, "Forbidden: Only members can manage decisions", http.StatusForbidden)
		return
	}

	result, err := database.DB.Exec(
		`DELETE FROM decisions WHERE id = ? AND workspace_id = ?`,
		decisionID, workspaceID,
	)
	if err != nil {
		http.Error(w, "Failed to delete decision", http.StatusInternalServerError)
		return
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Decision not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func decodeDecisionRequest(r *http.Request) (*models.DecisionRequest, error) {
	var req models.DecisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, err
	}

	req.Title = strings.TrimSpace(req.Title)
	req.Description = strings.TrimSpace(req.Description)
	if req.Title == "" {
		return nil, errors.New("Decision title is required")
	}
	if req.Status == "" {
		req.Status = models.DecisionStatusDraft
	}
	switch req.Status {
	case models.DecisionStatusDraft, models.DecisionStatusOpen, models.DecisionStatusClosed:
	default:
		return nil, errors.New("Invalid decision status")
	}

	return &req, nil
}

func getDecisionByID(workspaceID, decisionID int) (*models.Decision, error) {
	row := database.DB.QueryRow(
		`SELECT id, workspace_id, user_id, title, COALESCE(description, ''), status, due_date, created_at, updated_at
		 FROM decisions
		 WHERE workspace_id = ? AND id = ?`,
		workspaceID, decisionID,
	)
	return scanDecision(row)
}

type decisionScanner interface {
	Scan(dest ...interface{}) error
}

func scanDecision(scanner decisionScanner) (*models.Decision, error) {
	var (
		decision models.Decision
		dueDate  sql.NullTime
	)

	err := scanner.Scan(
		&decision.ID,
		&decision.WorkspaceID,
		&decision.UserID,
		&decision.Title,
		&decision.Description,
		&decision.Status,
		&dueDate,
		&decision.CreatedAt,
		&decision.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if dueDate.Valid {
		decision.DueDate = &dueDate.Time
	}
	return &decision, nil
}

func extractDecisionIDs(path string) (workspaceID int, decisionID int, err error) {
	parts := splitPath(path)
	if len(parts) < 5 || parts[0] != "api" || parts[1] != "workspaces" || parts[3] != "decisions" {
		return 0, 0, strconv.ErrSyntax
	}

	workspaceID, err = strconv.Atoi(parts[2])
	if err != nil {
		return 0, 0, err
	}

	decisionID, err = strconv.Atoi(parts[4])
	if err != nil {
		return 0, 0, err
	}

	return workspaceID, decisionID, nil
}
