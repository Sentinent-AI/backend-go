package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sentinent-backend/database"
	"sentinent-backend/middleware"
	"sentinent-backend/models"
	"sentinent-backend/utils"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestWorkspaceReadUpdateAndMemberRoutes(t *testing.T) {
	setupCollaborationTestDB(t)
	seedWorkspaceCollaborationData(t)

	getReq := requestWithUser(http.MethodGet, "/api/workspaces/10", nil, 1, "owner@example.com")
	getRR := httptest.NewRecorder()
	WorkspacesRouter(getRR, getReq)

	if getRR.Code != http.StatusOK {
		t.Fatalf("expected 200 from GetWorkspace, got %d: %s", getRR.Code, getRR.Body.String())
	}

	var workspace models.Workspace
	if err := json.Unmarshal(getRR.Body.Bytes(), &workspace); err != nil {
		t.Fatalf("failed to decode workspace response: %v", err)
	}
	if workspace.ID != 10 || workspace.Name != "Sentinent" {
		t.Fatalf("unexpected workspace response: %+v", workspace)
	}

	updateBody, _ := json.Marshal(models.WorkspaceRequest{
		Name:        "Sentinent Platform",
		Description: "Updated workspace description",
	})
	updateReq := requestWithUser(http.MethodPatch, "/api/workspaces/10", updateBody, 1, "owner@example.com")
	updateRR := httptest.NewRecorder()
	WorkspacesRouter(updateRR, updateReq)

	if updateRR.Code != http.StatusOK {
		t.Fatalf("expected 200 from UpdateWorkspace, got %d: %s", updateRR.Code, updateRR.Body.String())
	}

	var updated models.Workspace
	if err := json.Unmarshal(updateRR.Body.Bytes(), &updated); err != nil {
		t.Fatalf("failed to decode updated workspace response: %v", err)
	}
	if updated.Name != "Sentinent Platform" {
		t.Fatalf("expected updated workspace name, got %q", updated.Name)
	}

	var storedName, storedDescription string
	if err := database.DB.QueryRow(
		"SELECT name, description FROM workspaces WHERE id = ?",
		10,
	).Scan(&storedName, &storedDescription); err != nil {
		t.Fatalf("failed to verify workspace update: %v", err)
	}
	if storedName != "Sentinent Platform" || storedDescription != "Updated workspace description" {
		t.Fatalf("unexpected stored workspace values: %q %q", storedName, storedDescription)
	}

	listReq := requestWithUser(http.MethodGet, "/api/workspaces/10/members", nil, 1, "owner@example.com")
	listRR := httptest.NewRecorder()
	WorkspacesRouter(listRR, listReq)

	if listRR.Code != http.StatusOK {
		t.Fatalf("expected 200 from ListMembers, got %d: %s", listRR.Code, listRR.Body.String())
	}

	var members []models.WorkspaceMember
	if err := json.Unmarshal(listRR.Body.Bytes(), &members); err != nil {
		t.Fatalf("failed to decode members response: %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("expected 2 members before removal, got %d", len(members))
	}

	removeReq := requestWithUser(http.MethodDelete, "/api/workspaces/10/members/3", nil, 1, "owner@example.com")
	removeRR := httptest.NewRecorder()
	WorkspacesRouter(removeRR, removeReq)

	if removeRR.Code != http.StatusNoContent {
		t.Fatalf("expected 204 from RemoveMember, got %d: %s", removeRR.Code, removeRR.Body.String())
	}

	var memberCount int
	if err := database.DB.QueryRow(
		"SELECT COUNT(*) FROM workspace_members WHERE workspace_id = 10",
	).Scan(&memberCount); err != nil {
		t.Fatalf("failed to verify removed member: %v", err)
	}
	if memberCount != 1 {
		t.Fatalf("expected 1 remaining member, got %d", memberCount)
	}
}

func TestSignalLifecycleHandlers(t *testing.T) {
	setupSignalsTestDB(t)
	defer database.DB.Close()

	getReq := signalRequestWithUser(http.MethodGet, "/api/signals/1")
	getRR := httptest.NewRecorder()
	GetSignal(getRR, getReq)

	if getRR.Code != http.StatusOK {
		t.Fatalf("expected 200 from GetSignal, got %d: %s", getRR.Code, getRR.Body.String())
	}

	var signal models.Signal
	if err := json.NewDecoder(getRR.Body).Decode(&signal); err != nil {
		t.Fatalf("failed to decode signal response: %v", err)
	}
	if signal.ID != 1 || signal.Status != models.SignalStatusRead {
		t.Fatalf("unexpected signal response: %+v", signal)
	}

	readReq := signalRequestWithUser(http.MethodPost, "/api/signals/2/read")
	readRR := httptest.NewRecorder()
	MarkSignalAsRead(readRR, readReq)

	if readRR.Code != http.StatusNoContent {
		t.Fatalf("expected 204 from MarkSignalAsRead, got %d", readRR.Code)
	}

	archiveReq := signalRequestWithUser(http.MethodPost, "/api/signals/2/archive")
	archiveRR := httptest.NewRecorder()
	ArchiveSignal(archiveRR, archiveReq)

	if archiveRR.Code != http.StatusNoContent {
		t.Fatalf("expected 204 from ArchiveSignal, got %d", archiveRR.Code)
	}

	var status string
	if err := database.DB.QueryRow(
		"SELECT status FROM signal_status WHERE signal_id = ? AND user_id = ?",
		2, 1,
	).Scan(&status); err != nil {
		t.Fatalf("failed to fetch final signal status: %v", err)
	}
	if status != models.SignalStatusArchived {
		t.Fatalf("expected archived status, got %q", status)
	}
}

func TestIntegrationMetadataRoutesAndDisconnectHandlers(t *testing.T) {
	setupIntegrationsTestDB(t)
	defer database.DB.Close()

	originalSlackClientID := slackClientID
	originalSlackClientSecret := slackClientSecret
	originalTokenEncryptor := tokenEncryptor
	t.Setenv("TOKEN_ENCRYPTION_KEY", "test-encryption-key-32-bytes-long!")

	encryptor, err := utils.NewTokenEncryptor()
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	slackClientID = "slack-client"
	slackClientSecret = "slack-secret"
	tokenEncryptor = encryptor
	t.Cleanup(func() {
		slackClientID = originalSlackClientID
		slackClientSecret = originalSlackClientSecret
		tokenEncryptor = originalTokenEncryptor
	})

	if _, err := database.DB.Exec(
		`INSERT INTO external_integrations
			(id, user_id, workspace_id, provider, access_token, metadata)
		 VALUES
			(11, 1, 9, 'slack', 'slack-token', '{"existing":true}'),
			(12, 1, 9, 'github', 'github-token', '{"existing":true}'),
			(13, 1, NULL, 'gmail', 'gmail-token', '{"existing":true}')`,
	); err != nil {
		t.Fatalf("failed to seed integrations: %v", err)
	}

	slackUpdateBody := []byte(`{"channel_ids":["C1","C2"]}`)
	slackUpdateReq := integrationRequestWithBody(http.MethodPatch, "/api/integrations/slack/channels?workspace_id=9", "reader@example.com", slackUpdateBody)
	slackUpdateRR := httptest.NewRecorder()
	GetSlackChannels(slackUpdateRR, slackUpdateReq)

	if slackUpdateRR.Code != http.StatusNoContent {
		t.Fatalf("expected 204 from Slack metadata update, got %d: %s", slackUpdateRR.Code, slackUpdateRR.Body.String())
	}

	githubUpdateBody := []byte(`{"repo_ids":[101,202]}`)
	githubUpdateReq := integrationRequestWithBody(http.MethodPatch, "/api/integrations/github/repos?workspace_id=9", "reader@example.com", githubUpdateBody)
	githubUpdateRR := httptest.NewRecorder()
	GitHubReposHandler(githubUpdateRR, githubUpdateReq)

	if githubUpdateRR.Code != http.StatusNoContent {
		t.Fatalf("expected 204 from GitHub metadata update, got %d: %s", githubUpdateRR.Code, githubUpdateRR.Body.String())
	}

	var slackMetadata, githubMetadata string
	if err := database.DB.QueryRow(
		"SELECT metadata FROM external_integrations WHERE id = 11",
	).Scan(&slackMetadata); err != nil {
		t.Fatalf("failed to fetch slack metadata: %v", err)
	}
	if err := database.DB.QueryRow(
		"SELECT metadata FROM external_integrations WHERE id = 12",
	).Scan(&githubMetadata); err != nil {
		t.Fatalf("failed to fetch github metadata: %v", err)
	}
	var slackPayload map[string]interface{}
	if err := json.Unmarshal([]byte(slackMetadata), &slackPayload); err != nil {
		t.Fatalf("failed to decode slack metadata: %v", err)
	}
	if got := slackPayload["selected_channels"]; got == nil {
		t.Fatalf("expected selected_channels in slack metadata, got %v", slackPayload)
	}

	var githubPayload map[string]interface{}
	if err := json.Unmarshal([]byte(githubMetadata), &githubPayload); err != nil {
		t.Fatalf("failed to decode github metadata: %v", err)
	}
	if got := githubPayload["selected_repo_ids"]; got == nil {
		t.Fatalf("expected selected_repo_ids in github metadata, got %v", githubPayload)
	}

	syncReq := integrationRequestWithUser(http.MethodPost, "/api/integrations/github/sync?workspace_id=bad", "reader@example.com")
	syncRR := httptest.NewRecorder()
	GitHubSyncHandler(syncRR, syncReq)

	if syncRR.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 from GitHubSyncHandler validation path, got %d: %s", syncRR.Code, syncRR.Body.String())
	}

	githubDisconnectReq := integrationRequestWithUser(http.MethodDelete, "/api/integrations/github?workspace_id=9", "reader@example.com")
	githubDisconnectRR := httptest.NewRecorder()
	GitHubDisconnectHandler(githubDisconnectRR, githubDisconnectReq)

	if githubDisconnectRR.Code != http.StatusOK {
		t.Fatalf("expected 200 from GitHubDisconnectHandler, got %d: %s", githubDisconnectRR.Code, githubDisconnectRR.Body.String())
	}

	gmailDisconnectReq := integrationRequestWithUser(http.MethodDelete, "/api/integrations/gmail", "reader@example.com")
	gmailDisconnectRR := httptest.NewRecorder()
	GmailDisconnectHandler(gmailDisconnectRR, gmailDisconnectReq)

	if gmailDisconnectRR.Code != http.StatusOK {
		t.Fatalf("expected 200 from GmailDisconnectHandler, got %d: %s", gmailDisconnectRR.Code, gmailDisconnectRR.Body.String())
	}

	var remaining int
	if err := database.DB.QueryRow(
		"SELECT COUNT(*) FROM external_integrations WHERE provider = 'github' AND workspace_id = 9",
	).Scan(&remaining); err != nil {
		t.Fatalf("failed to verify github disconnect: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("expected github integration to be removed, got %d rows", remaining)
	}
	if err := database.DB.QueryRow(
		"SELECT COUNT(*) FROM external_integrations WHERE provider = 'gmail' AND workspace_id IS NULL",
	).Scan(&remaining); err != nil {
		t.Fatalf("failed to verify gmail disconnect: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("expected gmail integration to be removed, got %d rows", remaining)
	}
}

func TestGitHubWebhookHandlerHandlesIssueAndPullRequestEvents(t *testing.T) {
	setupIntegrationsTestDB(t)
	defer database.DB.Close()

	issueReq := httptest.NewRequest(http.MethodPost, "/api/webhooks/github", bytes.NewBufferString(`{"action":"opened","issue":{"id":1,"title":"Issue"}}`))
	issueReq.Header.Set("X-GitHub-Event", "issues")
	issueRR := httptest.NewRecorder()
	GitHubWebhookHandler(issueRR, issueReq)

	if issueRR.Code != http.StatusOK {
		t.Fatalf("expected 200 from issues webhook, got %d: %s", issueRR.Code, issueRR.Body.String())
	}

	prReq := httptest.NewRequest(http.MethodPost, "/api/webhooks/github", bytes.NewBufferString(`{"action":"opened","pull_request":{"id":2,"title":"PR"}}`))
	prReq.Header.Set("X-GitHub-Event", "pull_request")
	prRR := httptest.NewRecorder()
	GitHubWebhookHandler(prRR, prReq)

	if prRR.Code != http.StatusOK {
		t.Fatalf("expected 200 from pull request webhook, got %d: %s", prRR.Code, prRR.Body.String())
	}
}

func integrationRequestWithBody(method, target, email string, body []byte) *http.Request {
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	return req.WithContext(context.WithValue(req.Context(), middleware.UserEmailKey, email))
}
