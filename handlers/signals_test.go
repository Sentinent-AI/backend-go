package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sentinent-backend/database"
	"sentinent-backend/middleware"
	"sentinent-backend/models"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func setupSignalsTestDB(t *testing.T) {
	t.Helper()

	var err error
	database.DB, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}

	statements := []string{
		`CREATE TABLE users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email TEXT NOT NULL UNIQUE,
			password TEXT NOT NULL
		);`,
		`CREATE TABLE signals (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			workspace_id INTEGER,
			source_type TEXT NOT NULL,
			source_id TEXT NOT NULL,
			external_id TEXT,
			title TEXT NOT NULL,
			content TEXT,
			author TEXT,
			body TEXT,
			url TEXT,
			status TEXT DEFAULT 'unread',
			source_metadata TEXT,
			received_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE signal_status (
			signal_id INTEGER NOT NULL,
			user_id INTEGER NOT NULL,
			status TEXT NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (signal_id, user_id)
		);`,
	}

	for _, statement := range statements {
		if _, err := database.DB.Exec(statement); err != nil {
			t.Fatalf("failed to prepare test schema: %v", err)
		}
	}

	if _, err := database.DB.Exec(
		`INSERT INTO users (id, email, password) VALUES (1, 'reader@example.com', 'hashed-password')`,
	); err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}

	if _, err := database.DB.Exec(
		`INSERT INTO signals
			(id, user_id, workspace_id, source_type, source_id, external_id, title, content, status)
		 VALUES
			(1, 1, 7, 'github', 'sig-1', 'external-1', 'Signal One', 'Body', 'unread'),
			(2, 1, 7, 'github', 'sig-2', 'external-2', 'Signal Two', 'Body', 'unread')`,
	); err != nil {
		t.Fatalf("failed to seed signals: %v", err)
	}

	if _, err := database.DB.Exec(
		`INSERT INTO signal_status (signal_id, user_id, status) VALUES (1, 1, ?)`,
		models.SignalStatusRead,
	); err != nil {
		t.Fatalf("failed to seed signal status: %v", err)
	}
}

func signalRequestWithUser(method, target string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	return req.WithContext(context.WithValue(req.Context(), middleware.UserEmailKey, "reader@example.com"))
}

func TestSignalsHandlerUsesResolvedSignalStatus(t *testing.T) {
	setupSignalsTestDB(t)
	defer database.DB.Close()

	req := signalRequestWithUser(http.MethodGet, "/api/signals?status=read")
	rr := httptest.NewRecorder()

	SignalsHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var signals []models.Signal
	if err := json.NewDecoder(rr.Body).Decode(&signals); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(signals) != 1 {
		t.Fatalf("expected 1 signal, got %d", len(signals))
	}
	if signals[0].ID != 1 {
		t.Fatalf("expected signal 1, got %d", signals[0].ID)
	}
	if signals[0].Status != models.SignalStatusRead {
		t.Fatalf("expected resolved status %q, got %q", models.SignalStatusRead, signals[0].Status)
	}
}

func TestWorkspaceSignalsStatusFilterUsesResolvedStatusForResultsAndTotal(t *testing.T) {
	setupSignalsTestDB(t)
	defer database.DB.Close()

	req := signalRequestWithUser(http.MethodGet, "/api/workspaces/7/signals?status=read")
	rr := httptest.NewRecorder()

	GetSignals(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var response models.SignalListResponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(response.Signals) != 1 {
		t.Fatalf("expected 1 signal, got %d", len(response.Signals))
	}
	if response.Total != 1 {
		t.Fatalf("expected total 1, got %d", response.Total)
	}
	if response.Signals[0].ID != 1 {
		t.Fatalf("expected signal 1, got %d", response.Signals[0].ID)
	}
	if response.Signals[0].Status != models.SignalStatusRead {
		t.Fatalf("expected resolved status %q, got %q", models.SignalStatusRead, response.Signals[0].Status)
	}
}
