package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"sentinent-backend/database"
	"sentinent-backend/models"
	"strconv"
	"strings"
	"time"
)

// GetSignals lists signals for a workspace with optional filtering
func GetSignals(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromContext(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Extract workspace_id from path
	path := r.URL.Path
	prefix := "/api/workspaces/"
	if len(path) <= len(prefix)+len("/signals") {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	// Parse workspace ID from /api/workspaces/:id/signals
	pathWithoutPrefix := path[len(prefix):]
	parts := make([]string, 0)
	current := ""
	for _, c := range pathWithoutPrefix {
		if c == '/' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}

	if len(parts) < 2 || parts[1] != "signals" {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	workspaceID, err := strconv.Atoi(parts[0])
	if err != nil {
		http.Error(w, "Invalid workspace ID", http.StatusBadRequest)
		return
	}

	// Parse query filters
	filter := models.SignalFilter{
		SourceType: r.URL.Query().Get("source_type"),
		Status:     r.URL.Query().Get("status"),
	}

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		filter.Limit, _ = strconv.Atoi(limitStr)
	}
	if filter.Limit <= 0 || filter.Limit > 100 {
		filter.Limit = 50 // Default limit
	}

	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		filter.Offset, _ = strconv.Atoi(offsetStr)
	}

	// Build query
	query := `
		SELECT s.id, s.user_id, s.workspace_id, s.source_type, s.source_id, s.external_id,
		       s.title, s.content, s.author, COALESCE(ss.status, s.status) as status,
		       s.received_at, s.created_at
		FROM signals s
		LEFT JOIN signal_status ss ON s.id = ss.signal_id AND ss.user_id = ?
		WHERE s.workspace_id = ? AND s.user_id = ?`
	args := []interface{}{userID, workspaceID, userID}

	if filter.SourceType != "" {
		query += " AND s.source_type = ?"
		args = append(args, filter.SourceType)
	}

	if filter.Status != "" {
		query += " AND COALESCE(ss.status, s.status) = ?"
		args = append(args, filter.Status)
	}

	query += " ORDER BY s.received_at DESC LIMIT ? OFFSET ?"
	args = append(args, filter.Limit, filter.Offset)

	rows, err := database.DB.Query(query, args...)
	if err != nil {
		http.Error(w, "Failed to fetch signals", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var signals []models.Signal
	for rows.Next() {
		var s models.Signal
		var content sql.NullString
		var author sql.NullString
		var sourceID sql.NullString

		err := rows.Scan(
			&s.ID, &s.UserID, &s.WorkspaceID, &s.SourceType, &sourceID, &s.ExternalID,
			&s.Title, &content, &author, &s.Status, &s.ReceivedAt, &s.CreatedAt,
		)
		if err != nil {
			continue
		}
		s.Content = content.String
		s.Author = author.String
		s.SourceID = sourceID.String
		signals = append(signals, s)
	}

	// Get total count
	countQuery := "SELECT COUNT(*) FROM signals WHERE workspace_id = ? AND user_id = ?"
	countArgs := []interface{}{workspaceID, userID}

	if filter.SourceType != "" {
		countQuery += " AND source_type = ?"
		countArgs = append(countArgs, filter.SourceType)
	}

	var total int
	err = database.DB.QueryRow(countQuery, countArgs...).Scan(&total)
	if err != nil {
		total = len(signals)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.SignalListResponse{
		Signals: signals,
		Total:   total,
	})
}

// GetSignal retrieves a single signal by ID
func GetSignal(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromContext(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Extract signal ID from path /api/signals/:id
	path := r.URL.Path
	prefix := "/api/signals/"
	if len(path) <= len(prefix) {
		http.Error(w, "Invalid signal ID", http.StatusBadRequest)
		return
	}

	signalIDStr := path[len(prefix):]
	signalID, err := strconv.Atoi(signalIDStr)
	if err != nil {
		http.Error(w, "Invalid signal ID", http.StatusBadRequest)
		return
	}

	var s models.Signal
	var content sql.NullString
	var author sql.NullString
	var sourceID sql.NullString

	err = database.DB.QueryRow(`
		SELECT s.id, s.user_id, s.workspace_id, s.source_type, s.source_id, s.external_id,
		       s.title, s.content, s.author, COALESCE(ss.status, s.status) as status,
		       s.received_at, s.created_at
		FROM signals s
		LEFT JOIN signal_status ss ON s.id = ss.signal_id AND ss.user_id = ?
		WHERE s.id = ? AND s.user_id = ?`,
		userID, signalID, userID,
	).Scan(
		&s.ID, &s.UserID, &s.WorkspaceID, &s.SourceType, &sourceID, &s.ExternalID,
		&s.Title, &content, &author, &s.Status, &s.ReceivedAt, &s.CreatedAt,
	)

	if err == sql.ErrNoRows {
		http.Error(w, "Signal not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "Failed to fetch signal", http.StatusInternalServerError)
		return
	}

	s.Content = content.String
	s.Author = author.String
	s.SourceID = sourceID.String

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s)
}

// MarkSignalAsRead marks a signal as read
func MarkSignalAsRead(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromContext(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Extract signal ID from path /api/signals/:id/read
	path := r.URL.Path
	prefix := "/api/signals/"
	suffix := "/read"

	if !strings.HasSuffix(path, suffix) || len(path) <= len(prefix)+len(suffix) {
		http.Error(w, "Invalid signal ID", http.StatusBadRequest)
		return
	}

	signalIDStr := path[len(prefix) : len(path)-len(suffix)]
	signalID, err := strconv.Atoi(signalIDStr)
	if err != nil {
		http.Error(w, "Invalid signal ID", http.StatusBadRequest)
		return
	}

	// Verify signal exists and belongs to user
	var exists bool
	err = database.DB.QueryRow(
		"SELECT EXISTS(SELECT 1 FROM signals WHERE id = ? AND user_id = ?)",
		signalID, userID,
	).Scan(&exists)

	if err != nil || !exists {
		http.Error(w, "Signal not found", http.StatusNotFound)
		return
	}

	// Upsert signal status
	_, err = database.DB.Exec(`
		INSERT INTO signal_status (signal_id, user_id, status, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(signal_id, user_id) DO UPDATE SET
			status = excluded.status,
			updated_at = excluded.updated_at`,
		signalID, userID, models.SignalStatusRead, time.Now(),
	)

	if err != nil {
		http.Error(w, "Failed to update signal status", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ArchiveSignal archives a signal
func ArchiveSignal(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromContext(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Extract signal ID from path /api/signals/:id/archive
	path := r.URL.Path
	prefix := "/api/signals/"
	suffix := "/archive"

	if !strings.HasSuffix(path, suffix) || len(path) <= len(prefix)+len(suffix) {
		http.Error(w, "Invalid signal ID", http.StatusBadRequest)
		return
	}

	signalIDStr := path[len(prefix) : len(path)-len(suffix)]
	signalID, err := strconv.Atoi(signalIDStr)
	if err != nil {
		http.Error(w, "Invalid signal ID", http.StatusBadRequest)
		return
	}

	// Verify signal exists and belongs to user
	var exists bool
	err = database.DB.QueryRow(
		"SELECT EXISTS(SELECT 1 FROM signals WHERE id = ? AND user_id = ?)",
		signalID, userID,
	).Scan(&exists)

	if err != nil || !exists {
		http.Error(w, "Signal not found", http.StatusNotFound)
		return
	}

	// Upsert signal status
	_, err = database.DB.Exec(`
		INSERT INTO signal_status (signal_id, user_id, status, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(signal_id, user_id) DO UPDATE SET
			status = excluded.status,
			updated_at = excluded.updated_at`,
		signalID, userID, models.SignalStatusArchived, time.Now(),
	)

	if err != nil {
		http.Error(w, "Failed to archive signal", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
