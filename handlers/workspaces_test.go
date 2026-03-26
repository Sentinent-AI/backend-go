package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sentinent-backend/database"
	"sentinent-backend/models"
	"testing"
)

func TestWorkspaceCRUDLifecycle(t *testing.T) {
	setupCollaborationTestDB(t)
	seedWorkspaceCollaborationData(t)

	body, _ := json.Marshal(models.WorkspaceRequest{
		Name:        "Platform",
		Description: "Shared engineering decisions",
	})

	createReq := requestWithUser(http.MethodPost, "/api/workspaces", body, 1, "owner@example.com")
	createRR := httptest.NewRecorder()
	WorkspacesRouter(createRR, createReq)

	if createRR.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", createRR.Code, createRR.Body.String())
	}

	var created models.Workspace
	if err := json.Unmarshal(createRR.Body.Bytes(), &created); err != nil {
		t.Fatalf("failed to parse workspace response: %v", err)
	}
	if created.Name != "Platform" {
		t.Fatalf("expected created workspace name Platform, got %q", created.Name)
	}

	listReq := requestWithUser(http.MethodGet, "/api/workspaces", nil, 1, "owner@example.com")
	listRR := httptest.NewRecorder()
	WorkspacesRouter(listRR, listReq)

	if listRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", listRR.Code, listRR.Body.String())
	}

	var workspaces []models.Workspace
	if err := json.Unmarshal(listRR.Body.Bytes(), &workspaces); err != nil {
		t.Fatalf("failed to parse workspace list: %v", err)
	}
	if len(workspaces) != 2 {
		t.Fatalf("expected 2 workspaces, got %d", len(workspaces))
	}

	deleteReq := requestWithUser(http.MethodDelete, "/api/workspaces/"+strconvFormatInt(int64(created.ID)), nil, 1, "owner@example.com")
	deleteRR := httptest.NewRecorder()
	WorkspacesRouter(deleteRR, deleteReq)

	if deleteRR.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", deleteRR.Code, deleteRR.Body.String())
	}

	var count int
	if err := database.DB.QueryRow("SELECT COUNT(*) FROM workspaces WHERE id = ?", created.ID).Scan(&count); err != nil {
		t.Fatalf("failed to count workspaces: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected deleted workspace to be removed, got count=%d", count)
	}
}

func TestDecisionLifecycle(t *testing.T) {
	setupCollaborationTestDB(t)
	seedWorkspaceCollaborationData(t)

	body := []byte(`{"title":"Choose auth provider","description":"Compare Slack and Google","status":"OPEN"}`)

	createReq := requestWithUser(http.MethodPost, "/api/workspaces/10/decisions", body, 3, "member@example.com")
	createRR := httptest.NewRecorder()
	WorkspacesRouter(createRR, createReq)

	if createRR.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", createRR.Code, createRR.Body.String())
	}

	var created models.Decision
	if err := json.Unmarshal(createRR.Body.Bytes(), &created); err != nil {
		t.Fatalf("failed to parse decision response: %v", err)
	}
	if created.Title != "Choose auth provider" {
		t.Fatalf("expected decision title to round-trip, got %q", created.Title)
	}

	listReq := requestWithUser(http.MethodGet, "/api/workspaces/10/decisions", nil, 1, "owner@example.com")
	listRR := httptest.NewRecorder()
	WorkspacesRouter(listRR, listReq)

	if listRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", listRR.Code, listRR.Body.String())
	}

	var decisions []models.Decision
	if err := json.Unmarshal(listRR.Body.Bytes(), &decisions); err != nil {
		t.Fatalf("failed to parse decision list: %v", err)
	}
	if len(decisions) != 1 {
		t.Fatalf("expected 1 decision, got %d", len(decisions))
	}

	deleteReq := requestWithUser(http.MethodDelete, "/api/workspaces/10/decisions/"+strconvFormatInt(int64(created.ID)), nil, 3, "member@example.com")
	deleteRR := httptest.NewRecorder()
	WorkspacesRouter(deleteRR, deleteReq)

	if deleteRR.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", deleteRR.Code, deleteRR.Body.String())
	}
}
