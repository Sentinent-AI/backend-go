package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sentinent-backend/database"
	"sentinent-backend/models"
	"testing"
)

func TestUpdateDecision(t *testing.T) {
	setupCollaborationTestDB(t)
	seedWorkspaceCollaborationData(t)

	// 1. Create a decision first
	_, err := database.DB.Exec(`
		INSERT INTO decisions (id, workspace_id, user_id, title, description, status)
		VALUES (1, 10, 3, 'Initial Title', 'Initial Description', 'DRAFT')
	`)
	if err != nil {
		t.Fatalf("failed to seed decision: %v", err)
	}

	// 2. Update the decision as the owner (user 3 is a member, but we'll assume they own this decision)
	updateBody := []byte(`{"title":"Updated Title","description":"Updated Description","status":"OPEN"}`)
	updateReq := requestWithUser(http.MethodPatch, "/api/workspaces/10/decisions/1", updateBody, 3, "member@example.com")
	updateRR := httptest.NewRecorder()
	WorkspacesRouter(updateRR, updateReq)

	if updateRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", updateRR.Code, updateRR.Body.String())
	}

	var updated models.Decision
	if err := json.Unmarshal(updateRR.Body.Bytes(), &updated); err != nil {
		t.Fatalf("failed to parse updated decision: %v", err)
	}

	if updated.Title != "Updated Title" || updated.Status != models.DecisionStatusOpen {
		t.Fatalf("unexpected updated decision: %+v", updated)
	}

	// 3. Verify in DB
	var title, status string
	err = database.DB.QueryRow("SELECT title, status FROM decisions WHERE id = 1").Scan(&title, &status)
	if err != nil {
		t.Fatalf("failed to query decision: %v", err)
	}
	if title != "Updated Title" || status != "OPEN" {
		t.Fatalf("db values not updated: title=%s, status=%s", title, status)
	}
}

func TestUpdateDecisionForbidden(t *testing.T) {
	setupCollaborationTestDB(t)
	seedWorkspaceCollaborationData(t)

	// Create user 4 who is NOT in workspace 10
	_, _ = database.DB.Exec("INSERT INTO users (id, email, password) VALUES (4, 'stranger@example.com', 'pw')")

	_, _ = database.DB.Exec(`
		INSERT INTO decisions (id, workspace_id, user_id, title, description, status)
		VALUES (1, 10, 3, 'Initial Title', 'Initial Description', 'DRAFT')
	`)

	updateBody := []byte(`{"title":"Hacked"}`)
	updateReq := requestWithUser(http.MethodPatch, "/api/workspaces/10/decisions/1", updateBody, 4, "stranger@example.com")
	updateRR := httptest.NewRecorder()
	WorkspacesRouter(updateRR, updateReq)

	if updateRR.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", updateRR.Code)
	}
}
