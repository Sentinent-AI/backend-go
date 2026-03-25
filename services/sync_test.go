package services

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sentinent-backend/database"
	"sentinent-backend/models"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func setupSyncTestDB(t *testing.T) {
	t.Helper()

	var err error
	database.DB, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}

	statements := []string{
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
		`CREATE UNIQUE INDEX idx_signals_user_source ON signals(user_id, source_type, source_id);`,
		`CREATE TABLE external_integrations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			workspace_id INTEGER,
			provider TEXT NOT NULL,
			access_token TEXT NOT NULL,
			metadata TEXT,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
	}

	for _, statement := range statements {
		if _, err := database.DB.Exec(statement); err != nil {
			t.Fatalf("failed to prepare sync test schema: %v", err)
		}
	}

	if _, err := database.DB.Exec(
		`INSERT INTO external_integrations (id, user_id, workspace_id, provider, access_token, metadata)
		 VALUES (1, 42, 7, 'slack', 'encrypted-token', '{"selected_channels":["C123"]}')`,
	); err != nil {
		t.Fatalf("failed to seed integration: %v", err)
	}
}

func TestSyncSlackIntegrationStoresMultipleMessagesPerChannelWithoutDuplicates(t *testing.T) {
	setupSyncTestDB(t)
	defer database.DB.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/conversations.history":
			_ = json.NewEncoder(w).Encode(SlackMessagesResponse{
				OK: true,
				Messages: []SlackMessage{
					{Type: "message", User: "U1", Text: "First message", TS: "1710000000.000100"},
					{Type: "message", User: "U2", Text: "Second message", TS: "1710000001.000200"},
				},
			})
		case "/users.info":
			userID := r.URL.Query().Get("user")
			name := "Unknown"
			if userID == "U1" {
				name = "Alice"
			}
			if userID == "U2" {
				name = "Bob"
			}
			_ = json.NewEncoder(w).Encode(SlackUserResponse{
				OK: true,
				User: struct {
					ID       string `json:"id"`
					Name     string `json:"name"`
					RealName string `json:"real_name"`
				}{
					ID:       userID,
					RealName: name,
				},
			})
		default:
			t.Fatalf("unexpected Slack API path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	service := &SyncService{
		slackClient: &SlackClient{
			HTTPClient: server.Client(),
			BaseURL:    server.URL,
		},
	}

	integration := &models.ExternalIntegration{
		ID:          1,
		UserID:      42,
		WorkspaceID: 7,
		Provider:    "slack",
		Metadata:    `{"selected_channels":["C123"]}`,
	}

	service.syncSlackIntegration(integration, "test-token")
	service.syncSlackIntegration(integration, "test-token")

	var total int
	if err := database.DB.QueryRow(
		`SELECT COUNT(*) FROM signals WHERE user_id = ? AND workspace_id = ? AND source_type = ?`,
		42, 7, models.SourceTypeSlack,
	).Scan(&total); err != nil {
		t.Fatalf("failed to count synced signals: %v", err)
	}
	if total != 2 {
		t.Fatalf("expected 2 synced signals, got %d", total)
	}

	rows, err := database.DB.Query(
		`SELECT source_id, external_id FROM signals WHERE user_id = ? AND source_type = ? ORDER BY source_id`,
		42, models.SourceTypeSlack,
	)
	if err != nil {
		t.Fatalf("failed to query synced signals: %v", err)
	}
	defer rows.Close()

	var rowsRead int
	for rows.Next() {
		var sourceID string
		var externalID string
		if err := rows.Scan(&sourceID, &externalID); err != nil {
			t.Fatalf("failed to scan synced signal: %v", err)
		}
		rowsRead++
		if sourceID != buildSlackSignalSourceID("C123", externalID) {
			t.Fatalf("expected source_id to include channel and message ts, got %q for external_id %q", sourceID, externalID)
		}
	}
	if rowsRead != 2 {
		t.Fatalf("expected to inspect 2 rows, got %d", rowsRead)
	}
}
