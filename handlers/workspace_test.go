package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sentinent-backend/database"
	"testing"
)

func TestCreateWorkspaceAllowsMultiplePerUser(t *testing.T) {
	setupTestDB()
	defer database.DB.Close()

	ownerEmail := "owner@example.com"
	ownerID := insertDecisionTestUser(t, ownerEmail)

	firstReq := httptest.NewRequest(http.MethodPost, "/api/workspaces", bytes.NewBufferString(`{"name":"Product"}`))
	firstRR := httptest.NewRecorder()
	CreateWorkspace(firstRR, firstReq, ownerEmail)
	if firstRR.Code != http.StatusCreated {
		t.Fatalf("expected first workspace create status 201, got %d", firstRR.Code)
	}

	secondReq := httptest.NewRequest(http.MethodPost, "/api/workspaces", bytes.NewBufferString(`{"name":"Operations"}`))
	secondRR := httptest.NewRecorder()
	CreateWorkspace(secondRR, secondReq, ownerEmail)
	if secondRR.Code != http.StatusCreated {
		t.Fatalf("expected second workspace create status 201, got %d", secondRR.Code)
	}

	var count int
	err := database.DB.QueryRow("SELECT COUNT(*) FROM workspaces WHERE owner_id = ?", ownerID).Scan(&count)
	if err != nil {
		t.Fatalf("failed to count workspaces: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 workspaces for owner, got %d", count)
	}
}

func TestUserCanBeMemberOfMultipleWorkspaces(t *testing.T) {
	setupTestDB()
	defer database.DB.Close()

	owner1Email := "owner1@example.com"
	owner2Email := "owner2@example.com"
	memberEmail := "member@example.com"

	owner1ID := insertDecisionTestUser(t, owner1Email)
	owner2ID := insertDecisionTestUser(t, owner2Email)
	memberID := insertDecisionTestUser(t, memberEmail)

	workspace1ID := insertWorkspace(t, owner1ID, "Workspace One")
	workspace2ID := insertWorkspace(t, owner2ID, "Workspace Two")

	req1 := httptest.NewRequest(
		http.MethodPost,
		"/api/workspaces/"+toString(workspace1ID)+"/members",
		bytes.NewBufferString(`{"email":"`+memberEmail+`"}`),
	)
	rr1 := httptest.NewRecorder()
	WorkspaceSubresourceHandler(rr1, req1, owner1Email)
	if rr1.Code != http.StatusCreated {
		t.Fatalf("expected add member to workspace1 status 201, got %d", rr1.Code)
	}

	req2 := httptest.NewRequest(
		http.MethodPost,
		"/api/workspaces/"+toString(workspace2ID)+"/members",
		bytes.NewBufferString(`{"email":"`+memberEmail+`"}`),
	)
	rr2 := httptest.NewRecorder()
	WorkspaceSubresourceHandler(rr2, req2, owner2Email)
	if rr2.Code != http.StatusCreated {
		t.Fatalf("expected add member to workspace2 status 201, got %d", rr2.Code)
	}

	var count int
	err := database.DB.QueryRow(
		"SELECT COUNT(*) FROM workspace_members WHERE user_id = ? AND role = 'member'",
		memberID,
	).Scan(&count)
	if err != nil {
		t.Fatalf("failed to count workspace memberships: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected member to belong to 2 workspaces, got %d", count)
	}
}

func TestUserCanCreateMultipleDecisionsInSingleWorkspace(t *testing.T) {
	setupTestDB()
	defer database.DB.Close()

	userEmail := "maker@example.com"
	userID := insertDecisionTestUser(t, userEmail)
	workspaceID := insertWorkspace(t, userID, "Strategy")

	req1 := httptest.NewRequest(
		http.MethodPost,
		"/api/workspaces/"+toString(workspaceID)+"/decisions",
		bytes.NewBufferString(`{"title":"D1","description":"First","status":"draft"}`),
	)
	rr1 := httptest.NewRecorder()
	WorkspaceSubresourceHandler(rr1, req1, userEmail)
	if rr1.Code != http.StatusCreated {
		t.Fatalf("expected first decision status 201, got %d", rr1.Code)
	}

	req2 := httptest.NewRequest(
		http.MethodPost,
		"/api/workspaces/"+toString(workspaceID)+"/decisions",
		bytes.NewBufferString(`{"title":"D2","description":"Second","status":"approved"}`),
	)
	rr2 := httptest.NewRecorder()
	WorkspaceSubresourceHandler(rr2, req2, userEmail)
	if rr2.Code != http.StatusCreated {
		t.Fatalf("expected second decision status 201, got %d", rr2.Code)
	}

	var count int
	err := database.DB.QueryRow(
		"SELECT COUNT(*) FROM decisions WHERE workspace_id = ? AND owner_id = ?",
		workspaceID,
		userID,
	).Scan(&count)
	if err != nil {
		t.Fatalf("failed to count decisions: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 decisions by user in same workspace, got %d", count)
	}

	var decisionResponse map[string]any
	if err := json.Unmarshal(rr2.Body.Bytes(), &decisionResponse); err != nil {
		t.Fatalf("expected JSON response: %v", err)
	}
	if decisionResponse["workspaceId"] == nil {
		t.Fatalf("expected workspaceId in decision response")
	}
}
