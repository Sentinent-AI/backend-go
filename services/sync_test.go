package services

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sentinent-backend/database"
	"sentinent-backend/models"
	"sentinent-backend/utils"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

type mockSlackSyncClient struct {
	channels []SlackChannel
	messages []SlackMessage
	msgErr   error
}

func (m *mockSlackSyncClient) GetChannels(accessToken string) ([]SlackChannel, *RateLimitInfo, error) {
	return m.channels, nil, nil
}

func (m *mockSlackSyncClient) GetMessages(accessToken, channelID string, limit int, oldest string) ([]SlackMessage, *RateLimitInfo, error) {
	return m.messages, nil, m.msgErr
}

func (m *mockSlackSyncClient) GetUserInfo(accessToken, userID string) (*SlackUserResponse, *RateLimitInfo, error) {
	return nil, nil, nil
}

func setupSyncTestDB(t *testing.T) func() {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "sync-test.db")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("failed to open sqlite db: %v", err)
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
			refresh_token TEXT,
			expires_at DATETIME,
			metadata TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
	}

	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("failed to prepare sync test schema: %v", err)
		}
	}

	originalDB := database.DB
	database.DB = db

	return func() {
		database.DB = originalDB
		_ = db.Close()
	}
}

func TestSyncSlackIntegrationStoresMultipleMessagesPerChannelWithoutDuplicates(t *testing.T) {
	cleanup := setupSyncTestDB(t)
	defer cleanup()

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

func TestSyncAllIntegrationsUpdatesSlackMetadata(t *testing.T) {
	cleanup := setupSyncTestDB(t)
	defer cleanup()

	t.Setenv("TOKEN_ENCRYPTION_KEY", "test-encryption-key-32-bytes-long!")
	encryptor, err := utils.NewTokenEncryptor()
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	encryptedToken, err := encryptor.Encrypt("slack-token")
	if err != nil {
		t.Fatalf("failed to encrypt token: %v", err)
	}

	if _, err := database.DB.Exec(
		`INSERT INTO external_integrations (user_id, workspace_id, provider, access_token, metadata)
		 VALUES (?, ?, 'slack', ?, '{}')`,
		1, 1, encryptedToken,
	); err != nil {
		t.Fatalf("failed to seed integration: %v", err)
	}

	service := NewSyncService(encryptor)
	service.slackClient = &mockSlackSyncClient{
		channels: []SlackChannel{{ID: "C123", Name: "general"}},
	}

	service.syncAllIntegrations()

	var metadataJSON string
	if err := database.DB.QueryRow(
		"SELECT metadata FROM external_integrations WHERE provider = 'slack'",
	).Scan(&metadataJSON); err != nil {
		t.Fatalf("failed to query integration metadata: %v", err)
	}

	var metadata map[string]any
	if err := json.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
		t.Fatalf("failed to unmarshal metadata: %v", err)
	}
	if _, ok := metadata["last_sync"]; !ok {
		t.Fatalf("expected last_sync in metadata, got %s", metadataJSON)
	}
}

func TestSyncSlackIntegrationSkipsNotInChannelErrors(t *testing.T) {
	cleanup := setupSyncTestDB(t)
	defer cleanup()

	t.Setenv("TOKEN_ENCRYPTION_KEY", "test-encryption-key-32-bytes-long!")
	encryptor, err := utils.NewTokenEncryptor()
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	if _, err := database.DB.Exec(
		`INSERT INTO external_integrations (id, user_id, workspace_id, provider, access_token, metadata)
		 VALUES (?, ?, ?, 'slack', ?, '{}')`,
		1, 1, 1, "ignored",
	); err != nil {
		t.Fatalf("failed to seed integration: %v", err)
	}

	service := NewSyncService(encryptor)
	service.slackClient = &mockSlackSyncClient{
		channels: []SlackChannel{{ID: "C123", Name: "general"}},
		msgErr:   &SlackAPIError{Code: "not_in_channel"},
	}

	integration := &models.ExternalIntegration{
		ID:          1,
		UserID:      1,
		WorkspaceID: 1,
		Provider:    "slack",
		Metadata:    "{}",
	}

	service.syncSlackIntegration(integration, "slack-token")

	var metadataJSON string
	if err := database.DB.QueryRow(
		"SELECT metadata FROM external_integrations WHERE id = 1",
	).Scan(&metadataJSON); err != nil {
		t.Fatalf("failed to query integration metadata: %v", err)
	}

	var metadata map[string]any
	if err := json.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
		t.Fatalf("failed to unmarshal metadata: %v", err)
	}
	if _, ok := metadata["last_sync"]; !ok {
		t.Fatalf("expected last_sync after skipping inaccessible channel, got %s", metadataJSON)
	}
	if !IsSlackAPIError(service.slackClient.(*mockSlackSyncClient).msgErr, "not_in_channel") {
		t.Fatal("expected not_in_channel to be recognized as a Slack API error")
	}
}
