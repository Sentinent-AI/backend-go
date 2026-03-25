package middleware

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"sentinent-backend/database"
	"sentinent-backend/models"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func setupRolesTestDB(t *testing.T) {
	t.Helper()

	var err error
	database.DB, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}

	statements := []string{
		`CREATE TABLE workspaces (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			owner_id INTEGER NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
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
	}
	for _, statement := range statements {
		if _, err := database.DB.Exec(statement); err != nil {
			t.Fatalf("failed to create schema: %v", err)
		}
	}

	if _, err := database.DB.Exec("INSERT INTO workspaces (id, name, owner_id) VALUES (9, 'Sentinent', 1)"); err != nil {
		t.Fatalf("failed to insert workspace: %v", err)
	}
	if _, err := database.DB.Exec(
		"INSERT INTO workspace_members (workspace_id, user_id, role) VALUES (9, 2, 'member'), (9, 3, 'viewer')",
	); err != nil {
		t.Fatalf("failed to insert members: %v", err)
	}

	t.Cleanup(func() {
		_ = database.DB.Close()
	})
}

func TestGetWorkspaceRoleFallsBackToOwnerID(t *testing.T) {
	setupRolesTestDB(t)

	role, err := GetWorkspaceRole(1, 9)
	if err != nil {
		t.Fatalf("GetWorkspaceRole returned error: %v", err)
	}
	if role != models.RoleOwner {
		t.Fatalf("expected owner role, got %q", role)
	}
}

func TestRequireOwnerRejectsNonOwner(t *testing.T) {
	setupRolesTestDB(t)

	called := false
	handler := RequireOwner(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/workspaces/9/members", nil)
	req = req.WithContext(context.WithValue(req.Context(), UserIDKey, 2))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
	if called {
		t.Fatal("expected downstream handler not to be called")
	}
}

func TestRequireViewerAllowsViewer(t *testing.T) {
	setupRolesTestDB(t)

	called := false
	handler := RequireViewer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/workspaces/9/members", nil)
	req = req.WithContext(context.WithValue(req.Context(), UserIDKey, 3))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
	if !called {
		t.Fatal("expected downstream handler to be called")
	}
}
