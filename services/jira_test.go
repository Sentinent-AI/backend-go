package services

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sentinent-backend/database"
	"sentinent-backend/models"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func setupJiraTestDB(t *testing.T) func() {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "jira-test.db")
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
		`CREATE TABLE signal_status (
			signal_id INTEGER NOT NULL,
			user_id INTEGER NOT NULL,
			status TEXT NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (signal_id, user_id)
		);`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("failed to prepare jira test schema: %v", err)
		}
	}

	originalDB := database.DB
	database.DB = db
	return func() {
		database.DB = originalDB
		_ = db.Close()
	}
}

func TestFormatDescriptionExtractsADFText(t *testing.T) {
	description := map[string]interface{}{
		"type": "doc",
		"content": []interface{}{
			map[string]interface{}{
				"type": "paragraph",
				"content": []interface{}{
					map[string]interface{}{"type": "text", "text": "Fix dashboard"},
					map[string]interface{}{"type": "text", "text": "filters"},
				},
			},
		},
	}

	got := formatDescription(description)
	if got != "Fix dashboard filters" {
		t.Fatalf("expected ADF text extraction, got %q", got)
	}
}

func TestSaveJiraIssueAsSignalStoresUnreadSignalWithMetadata(t *testing.T) {
	cleanup := setupJiraTestDB(t)
	defer cleanup()

	issue := JiraIssue{
		ID:  "10001",
		Key: "SEN-17",
	}
	issue.Fields.Summary = "Investigate sync failure"
	issue.Fields.Description = map[string]interface{}{
		"content": []interface{}{
			map[string]interface{}{"content": []interface{}{
				map[string]interface{}{"text": "Webhook delivery failed"},
			}},
		},
	}
	issue.Fields.Status.Name = "In Progress"
	issue.Fields.Project.Key = "SEN"
	issue.Fields.Project.Name = "Sentinent"
	issue.Fields.Issuetype.Name = "Bug"
	issue.Fields.Priority = &struct {
		Name string `json:"name"`
	}{Name: "High"}
	issue.Fields.Assignee = &struct {
		DisplayName string `json:"displayName"`
	}{DisplayName: "Yash"}
	issue.Fields.Reporter = &struct {
		DisplayName string `json:"displayName"`
	}{DisplayName: "Reporter"}
	issue.Fields.Created = "2026-04-27T12:30:00.000-0400"

	if err := saveJiraIssueAsSignal(1, 7, issue, "https://sentinent.atlassian.net"); err != nil {
		t.Fatalf("failed to save jira signal: %v", err)
	}

	signals, err := GetUserSignals(1, &models.SignalFilter{SourceType: models.SourceTypeJira})
	if err != nil {
		t.Fatalf("failed to load signals: %v", err)
	}
	if len(signals) != 1 {
		t.Fatalf("expected one signal, got %d", len(signals))
	}

	signal := signals[0]
	if signal.Status != models.SignalStatusUnread {
		t.Fatalf("expected signal status unread, got %q", signal.Status)
	}
	if signal.Title != "[SEN-17] Investigate sync failure" {
		t.Fatalf("unexpected title %q", signal.Title)
	}
	if signal.Content != "Webhook delivery failed" {
		t.Fatalf("unexpected content %q", signal.Content)
	}
	if signal.URL != "https://sentinent.atlassian.net/browse/SEN-17" {
		t.Fatalf("unexpected Jira URL %q", signal.URL)
	}

	metadata, ok := signal.SourceMetadata.(*models.JiraMetadata)
	if !ok {
		t.Fatalf("expected Jira metadata, got %#v", signal.SourceMetadata)
	}
	if metadata.ProjectKey != "SEN" || metadata.IssueType != "Bug" || metadata.Priority != "High" {
		t.Fatalf("unexpected Jira metadata: %+v", metadata)
	}
	if metadata.Status != "In Progress" || metadata.IssueKey != "SEN-17" || metadata.AssigneeName != "Yash" {
		t.Fatalf("unexpected Jira issue details: %+v", metadata)
	}
}

func TestFetchJiraIssuesUsesSearchJQLPagination(t *testing.T) {
	originalDefaultTransport := http.DefaultTransport
	originalDefaultClientTransport := http.DefaultClient.Transport
	t.Cleanup(func() {
		http.DefaultTransport = originalDefaultTransport
		http.DefaultClient.Transport = originalDefaultClientTransport
	})

	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ex/jira/cloud-123/rest/api/3/search/jql" {
			t.Fatalf("unexpected Jira API path: %s", r.URL.Path)
		}

		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}
		requests++

		switch requests {
		case 1:
			if _, ok := payload["nextPageToken"]; ok {
				t.Fatal("first request should not include nextPageToken")
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"issues":        []JiraIssue{{ID: "1", Key: "SEN-1"}},
				"nextPageToken": "page-2",
			})
		case 2:
			if payload["nextPageToken"] != "page-2" {
				t.Fatalf("expected nextPageToken page-2, got %#v", payload["nextPageToken"])
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"issues": []JiraIssue{{ID: "2", Key: "SEN-2"}},
			})
		default:
			t.Fatalf("unexpected extra request %d", requests)
		}
	}))
	defer server.Close()

	targetURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("failed to parse server URL: %v", err)
	}
	rewriteTransport := githubRewriteTransport{
		base:   server.Client().Transport,
		target: targetURL,
	}
	client := &http.Client{Transport: rewriteTransport}
	http.DefaultTransport = rewriteTransport
	http.DefaultClient.Transport = rewriteTransport

	issues, err := FetchJiraIssues(client, "cloud-123", "assignee = currentUser()")
	if err != nil {
		t.Fatalf("FetchJiraIssues returned error: %v", err)
	}
	if len(issues) != 2 {
		t.Fatalf("expected 2 issues, got %d", len(issues))
	}
	if issues[0].Key != "SEN-1" || issues[1].Key != "SEN-2" {
		t.Fatalf("unexpected issues: %+v", issues)
	}
}
