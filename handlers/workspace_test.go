package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sentinent-backend/database"
	"testing"
)

func createUserForWorkspaceTest(t *testing.T, email string) {
	t.Helper()
	_, err := database.DB.Exec(
		"INSERT INTO users (email, password) VALUES (?, ?)",
		email,
		"hashed-password",
	)
	if err != nil {
		t.Fatalf("failed to insert user: %v", err)
	}
}

func TestCreateWorkspaceSuccess(t *testing.T) {
	setupTestDB()
	defer database.DB.Close()

	email := "owner@example.com"
	createUserForWorkspaceTest(t, email)

	body := bytes.NewBufferString(`{"name":"Product Decisions"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/workspaces", body)
	rr := httptest.NewRecorder()

	CreateWorkspace(rr, req, email)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", rr.Code)
	}

	var workspaceResponse map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &workspaceResponse); err != nil {
		t.Fatalf("expected JSON response: %v", err)
	}

	if workspaceResponse["name"] != "Product Decisions" {
		t.Fatalf("expected workspace name Product Decisions, got %v", workspaceResponse["name"])
	}

	if workspaceResponse["createdAt"] == "" {
		t.Fatalf("expected createdAt to be set")
	}

	if workspaceResponse["ownerEmail"] != email {
		t.Fatalf("expected ownerEmail %s, got %v", email, workspaceResponse["ownerEmail"])
	}
}

func TestCreateWorkspaceRequiresName(t *testing.T) {
	setupTestDB()
	defer database.DB.Close()

	email := "owner@example.com"
	createUserForWorkspaceTest(t, email)

	body := bytes.NewBufferString(`{"name":"   "}`)
	req := httptest.NewRequest(http.MethodPost, "/api/workspaces", body)
	rr := httptest.NewRecorder()

	CreateWorkspace(rr, req, email)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rr.Code)
	}
}

func TestCreateWorkspaceAssignsOwner(t *testing.T) {
	setupTestDB()
	defer database.DB.Close()

	email := "owner@example.com"
	createUserForWorkspaceTest(t, email)

	body := bytes.NewBufferString(`{"name":"Architecture Board"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/workspaces", body)
	rr := httptest.NewRecorder()

	CreateWorkspace(rr, req, email)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", rr.Code)
	}

	var ownerID int
	err := database.DB.QueryRow(`
		SELECT w.owner_id
		FROM workspaces w
		JOIN users u ON u.id = w.owner_id
		WHERE w.name = ? AND u.email = ?
	`, "Architecture Board", email).Scan(&ownerID)
	if err != nil {
		t.Fatalf("expected workspace owner relationship to exist: %v", err)
	}
	if ownerID <= 0 {
		t.Fatalf("expected a valid owner_id, got %d", ownerID)
	}
}
