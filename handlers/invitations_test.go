package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sentinent-backend/database"
	"sentinent-backend/middleware"
	"sentinent-backend/models"
	"strconv"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func setupCollaborationTestDB(t *testing.T) {
	t.Helper()

	var err error
	database.DB, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	database.DB.SetMaxOpenConns(1)

	statements := []string{
		`CREATE TABLE users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email TEXT NOT NULL UNIQUE,
			password TEXT NOT NULL
		);`,
		`CREATE TABLE workspaces (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			description TEXT DEFAULT '',
			owner_id INTEGER NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE decisions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			workspace_id INTEGER NOT NULL,
			user_id INTEGER NOT NULL,
			title TEXT NOT NULL,
			description TEXT,
			status TEXT NOT NULL,
			due_date DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE external_integrations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			workspace_id INTEGER,
			provider TEXT NOT NULL,
			access_token TEXT NOT NULL,
			metadata TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE signals (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			workspace_id INTEGER,
			source_type TEXT NOT NULL,
			source_id TEXT NOT NULL,
			title TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'unread',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE signal_status (
			signal_id INTEGER NOT NULL,
			user_id INTEGER NOT NULL,
			status TEXT NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE workspace_members (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			workspace_id INTEGER NOT NULL,
			user_id INTEGER NOT NULL,
			role TEXT NOT NULL,
			joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(workspace_id, user_id)
		);`,
		`CREATE TABLE invitations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			workspace_id INTEGER NOT NULL,
			email TEXT NOT NULL,
			token TEXT NOT NULL UNIQUE,
			role TEXT NOT NULL,
			expires_at DATETIME NOT NULL,
			created_by INTEGER NOT NULL,
			accepted_at DATETIME,
			accepted_by INTEGER,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
	}

	for _, statement := range statements {
		if _, err := database.DB.Exec(statement); err != nil {
			t.Fatalf("failed to create schema: %v", err)
		}
	}

	t.Cleanup(func() {
		_ = database.DB.Close()
	})
}

func seedWorkspaceCollaborationData(t *testing.T) {
	t.Helper()

	_, err := database.DB.Exec(`
		INSERT INTO users (id, email, password) VALUES
			(1, 'owner@example.com', 'pw'),
			(2, 'invitee@example.com', 'pw'),
			(3, 'member@example.com', 'pw')
	`)
	if err != nil {
		t.Fatalf("failed to seed users: %v", err)
	}

	_, err = database.DB.Exec(
		"INSERT INTO workspaces (id, name, owner_id) VALUES (10, 'Sentinent', 1)",
	)
	if err != nil {
		t.Fatalf("failed to seed workspace: %v", err)
	}

	_, err = database.DB.Exec(`
		INSERT INTO workspace_members (workspace_id, user_id, role) VALUES
			(10, 1, 'owner'),
			(10, 3, 'member')
	`)
	if err != nil {
		t.Fatalf("failed to seed members: %v", err)
	}
}

func requestWithUser(method, target string, body []byte, userID int, email string) *http.Request {
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	ctx := context.WithValue(req.Context(), middleware.UserIDKey, userID)
	ctx = context.WithValue(ctx, middleware.UserEmailKey, email)
	return req.WithContext(ctx)
}

func TestInvitationLifecycle(t *testing.T) {
	setupCollaborationTestDB(t)
	seedWorkspaceCollaborationData(t)

	body, _ := json.Marshal(models.CreateInvitationRequest{
		Email: "invitee@example.com",
		Role:  models.RoleViewer,
	})

	createReq := requestWithUser(http.MethodPost, "/api/workspaces/10/invitations", body, 1, "owner@example.com")
	createRR := httptest.NewRecorder()
	CreateInvitation(createRR, createReq)

	if createRR.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", createRR.Code, createRR.Body.String())
	}

	var token string
	if err := database.DB.QueryRow("SELECT token FROM invitations WHERE workspace_id = 10 AND email = 'invitee@example.com'").Scan(&token); err != nil {
		t.Fatalf("failed to fetch token: %v", err)
	}

	validateReq := httptest.NewRequest(http.MethodGet, "/api/invitations/"+token, nil)
	validateRR := httptest.NewRecorder()
	ValidateInvitation(validateRR, validateReq)

	if validateRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", validateRR.Code, validateRR.Body.String())
	}
	var validation map[string]interface{}
	if err := json.Unmarshal(validateRR.Body.Bytes(), &validation); err != nil {
		t.Fatalf("failed to parse validation response: %v", err)
	}
	if validation["email"] != "invitee@example.com" {
		t.Fatalf("expected validation response to include invited email, got %#v", validation["email"])
	}

	acceptReq := requestWithUser(http.MethodPost, "/api/invitations/"+token+"/accept", nil, 2, "invitee@example.com")
	acceptRR := httptest.NewRecorder()
	AcceptInvitation(acceptRR, acceptReq)

	if acceptRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", acceptRR.Code, acceptRR.Body.String())
	}

	var role string
	if err := database.DB.QueryRow(
		"SELECT role FROM workspace_members WHERE workspace_id = 10 AND user_id = 2",
	).Scan(&role); err != nil {
		t.Fatalf("failed to fetch accepted membership: %v", err)
	}
	if role != string(models.RoleViewer) {
		t.Fatalf("expected viewer role, got %s", role)
	}

	var acceptedAt sql.NullTime
	if err := database.DB.QueryRow(
		"SELECT accepted_at FROM invitations WHERE token = ?",
		token,
	).Scan(&acceptedAt); err != nil {
		t.Fatalf("failed to fetch invitation acceptance: %v", err)
	}
	if !acceptedAt.Valid {
		t.Fatal("expected invitation to be marked accepted")
	}
}

func TestListAndCancelInvitation(t *testing.T) {
	setupCollaborationTestDB(t)
	seedWorkspaceCollaborationData(t)

	expiresAt := time.Now().Add(24 * time.Hour)
	acceptedAt := time.Now().Add(-time.Hour)
	result, err := database.DB.Exec(
		`INSERT INTO invitations (workspace_id, email, token, role, expires_at, created_by)
		 VALUES (10, 'invitee@example.com', 'token-1', 'member', ?, 1)`,
		expiresAt,
	)
	if err != nil {
		t.Fatalf("failed to seed invitation: %v", err)
	}
	invitationID, _ := result.LastInsertId()

	if _, err := database.DB.Exec(
		`INSERT INTO invitations (workspace_id, email, token, role, expires_at, created_by, accepted_at, accepted_by)
		 VALUES (10, 'joined@example.com', 'token-accepted', 'viewer', ?, 1, ?, 2)`,
		expiresAt, acceptedAt,
	); err != nil {
		t.Fatalf("failed to seed accepted invitation: %v", err)
	}

	listReq := requestWithUser(http.MethodGet, "/api/workspaces/10/invitations", nil, 1, "owner@example.com")
	listRR := httptest.NewRecorder()
	ListInvitations(listRR, listReq)

	if listRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", listRR.Code, listRR.Body.String())
	}

	var invitations []models.Invitation
	if err := json.Unmarshal(listRR.Body.Bytes(), &invitations); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if len(invitations) != 2 {
		t.Fatalf("expected pending and accepted invitations, got %d", len(invitations))
	}
	var sawAccepted bool
	for _, invitation := range invitations {
		if invitation.Email == "joined@example.com" {
			sawAccepted = invitation.AcceptedAt != nil
		}
	}
	if !sawAccepted {
		t.Fatal("expected list response to include accepted invitation with accepted_at")
	}

	cancelReq := requestWithUser(http.MethodDelete, "/api/invitations/"+strconvFormatInt(invitationID), nil, 1, "owner@example.com")
	cancelRR := httptest.NewRecorder()
	CancelInvitation(cancelRR, cancelReq)

	if cancelRR.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", cancelRR.Code, cancelRR.Body.String())
	}

	var count int
	if err := database.DB.QueryRow("SELECT COUNT(*) FROM invitations WHERE id = ?", invitationID).Scan(&count); err != nil {
		t.Fatalf("failed to count invitations: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected invitation to be deleted, got count=%d", count)
	}
}

func TestResendInvitationAllowsOwnerForPendingInvite(t *testing.T) {
	setupCollaborationTestDB(t)
	seedWorkspaceCollaborationData(t)

	if _, err := database.DB.Exec(
		`INSERT INTO invitations (workspace_id, email, token, role, expires_at, created_by)
		 VALUES (10, 'invitee@example.com', 'token-resend', 'member', ?, 1)`,
		time.Now().Add(24*time.Hour),
	); err != nil {
		t.Fatalf("failed to seed invitation: %v", err)
	}

	req := requestWithUser(http.MethodPost, "/api/invitations/token-resend/resend", nil, 1, "owner@example.com")
	rr := httptest.NewRecorder()
	ResendInvitation(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var response map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse resend response: %v", err)
	}
	if response["status"] != "sent" {
		t.Fatalf("expected sent status, got %#v", response)
	}
}

func TestResendInvitationRejectsAcceptedInvite(t *testing.T) {
	setupCollaborationTestDB(t)
	seedWorkspaceCollaborationData(t)

	if _, err := database.DB.Exec(
		`INSERT INTO invitations (workspace_id, email, token, role, expires_at, created_by, accepted_at, accepted_by)
		 VALUES (10, 'invitee@example.com', 'token-accepted', 'member', ?, 1, ?, 2)`,
		time.Now().Add(24*time.Hour), time.Now(),
	); err != nil {
		t.Fatalf("failed to seed accepted invitation: %v", err)
	}

	req := requestWithUser(http.MethodPost, "/api/invitations/token-accepted/resend", nil, 1, "owner@example.com")
	rr := httptest.NewRecorder()
	ResendInvitation(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for accepted invite resend, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestUpdateMemberRoleTransfersOwnership(t *testing.T) {
	setupCollaborationTestDB(t)
	seedWorkspaceCollaborationData(t)

	_, err := database.DB.Exec(
		"INSERT INTO workspace_members (workspace_id, user_id, role) VALUES (10, 2, 'viewer')",
	)
	if err != nil {
		t.Fatalf("failed to seed target member: %v", err)
	}

	body := []byte(`{"role":"owner"}`)
	req := requestWithUser(http.MethodPatch, "/api/workspaces/10/members/2", body, 1, "owner@example.com")
	rr := httptest.NewRecorder()
	UpdateMemberRole(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var ownerID int
	if err := database.DB.QueryRow("SELECT owner_id FROM workspaces WHERE id = 10").Scan(&ownerID); err != nil {
		t.Fatalf("failed to fetch owner_id: %v", err)
	}
	if ownerID != 2 {
		t.Fatalf("expected owner transfer to user 2, got %d", ownerID)
	}

	var previousOwnerRole string
	if err := database.DB.QueryRow(
		"SELECT role FROM workspace_members WHERE workspace_id = 10 AND user_id = 1",
	).Scan(&previousOwnerRole); err != nil {
		t.Fatalf("failed to fetch previous owner role: %v", err)
	}
	if previousOwnerRole != string(models.RoleMember) {
		t.Fatalf("expected previous owner to become member, got %s", previousOwnerRole)
	}
}

func TestGenerateSecureToken(t *testing.T) {
	token, err := generateSecureToken()
	if err != nil {
		t.Fatalf("generateSecureToken() returned error: %v", err)
	}
	if token == "" {
		t.Fatal("expected token to be non-empty")
	}

	second, err := generateSecureToken()
	if err != nil {
		t.Fatalf("generateSecureToken() second call returned error: %v", err)
	}
	if token == second {
		t.Fatal("expected generated tokens to be unique")
	}
	if len(token) != 64 {
		t.Fatalf("expected 64-char token, got %d", len(token))
	}
}

func TestExtractPathHelpers(t *testing.T) {
	workspaceID, err := extractWorkspaceIDFromPath("/api/workspaces/123/invitations")
	if err != nil || workspaceID != 123 {
		t.Fatalf("expected workspace 123, got %d err=%v", workspaceID, err)
	}

	if token := extractTokenFromPath("/api/invitations/token123/accept"); token != "token123" {
		t.Fatalf("expected token123, got %q", token)
	}

	parsedWorkspaceID, parsedUserID, err := extractWorkspaceAndUserIDs("/api/workspaces/5/members/8")
	if err != nil || parsedWorkspaceID != 5 || parsedUserID != 8 {
		t.Fatalf("unexpected parsed ids: workspace=%d user=%d err=%v", parsedWorkspaceID, parsedUserID, err)
	}
}

func strconvFormatInt(value int64) string {
	return strconv.FormatInt(value, 10)
}
