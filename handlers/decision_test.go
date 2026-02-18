package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sentinent-backend/database"
	"strconv"
	"testing"
)

func insertDecisionTestUser(t *testing.T, email string) int {
	t.Helper()

	result, err := database.DB.Exec(
		"INSERT INTO users (email, password) VALUES (?, ?)",
		email,
		"hashed-password",
	)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("failed to get user id: %v", err)
	}
	return int(id)
}

func insertDecision(t *testing.T, ownerID int, title, description, status, createdAt, updatedAt string) int64 {
	t.Helper()

	result, err := database.DB.Exec(
		`INSERT INTO decisions (title, description, status, owner_id, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		title,
		description,
		status,
		ownerID,
		createdAt,
		updatedAt,
	)
	if err != nil {
		t.Fatalf("failed to insert decision: %v", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("failed to get decision id: %v", err)
	}
	return id
}

func TestUpdateDecisionSuccess(t *testing.T) {
	setupTestDB()
	defer database.DB.Close()

	ownerEmail := "owner@example.com"
	ownerID := insertDecisionTestUser(t, ownerEmail)
	oldUpdatedAt := "2000-01-01 00:00:00"
	decisionID := insertDecision(
		t,
		ownerID,
		"Initial Title",
		"Initial Description",
		"draft",
		"2000-01-01 00:00:00",
		oldUpdatedAt,
	)

	body := bytes.NewBufferString(`{
		"title":"Updated Title",
		"description":"Updated Description",
		"status":"approved"
	}`)
	req := httptest.NewRequest(http.MethodPut, "/api/decisions/"+toString(decisionID), body)
	rr := httptest.NewRecorder()

	UpdateDecision(rr, req, ownerEmail)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var response map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("expected JSON response: %v", err)
	}

	if response["title"] != "Updated Title" {
		t.Fatalf("expected updated title, got %v", response["title"])
	}
	if response["description"] != "Updated Description" {
		t.Fatalf("expected updated description, got %v", response["description"])
	}
	if response["status"] != "approved" {
		t.Fatalf("expected updated status, got %v", response["status"])
	}

	updatedAt, _ := response["updatedAt"].(string)
	if updatedAt == "" {
		t.Fatalf("expected updatedAt to be set")
	}
	if updatedAt == oldUpdatedAt {
		t.Fatalf("expected updatedAt to change automatically")
	}
}

func TestUpdateDecisionRequiresAtLeastOneField(t *testing.T) {
	setupTestDB()
	defer database.DB.Close()

	ownerEmail := "owner@example.com"
	ownerID := insertDecisionTestUser(t, ownerEmail)
	decisionID := insertDecision(
		t,
		ownerID,
		"Initial Title",
		"Initial Description",
		"draft",
		"2000-01-01 00:00:00",
		"2000-01-01 00:00:00",
	)

	body := bytes.NewBufferString(`{}`)
	req := httptest.NewRequest(http.MethodPut, "/api/decisions/"+toString(decisionID), body)
	rr := httptest.NewRecorder()

	UpdateDecision(rr, req, ownerEmail)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rr.Code)
	}
}

func TestUpdateDecisionNotOwner(t *testing.T) {
	setupTestDB()
	defer database.DB.Close()

	ownerID := insertDecisionTestUser(t, "owner@example.com")
	insertDecisionTestUser(t, "another@example.com")
	decisionID := insertDecision(
		t,
		ownerID,
		"Initial Title",
		"Initial Description",
		"draft",
		"2000-01-01 00:00:00",
		"2000-01-01 00:00:00",
	)

	body := bytes.NewBufferString(`{"status":"approved"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/decisions/"+toString(decisionID), body)
	rr := httptest.NewRecorder()

	UpdateDecision(rr, req, "another@example.com")

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", rr.Code)
	}
}

func toString(id int64) string {
	return strconv.FormatInt(id, 10)
}
