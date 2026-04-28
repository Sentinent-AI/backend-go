package database

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInitDBWithPathCreatesSchemaAndConfiguresSQLite(t *testing.T) {
	originalDB := DB
	dbPath := filepath.Join(t.TempDir(), "sentinent.db")

	if err := InitDBWithPath(dbPath); err != nil {
		t.Fatalf("InitDBWithPath returned error: %v", err)
	}
	t.Cleanup(func() {
		_ = DB.Close()
		DB = originalDB
	})

	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("expected database file to be created: %v", err)
	}

	var userTable string
	if err := DB.QueryRow("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'users'").Scan(&userTable); err != nil {
		t.Fatalf("expected users table to exist: %v", err)
	}

	var foreignKeys int
	if err := DB.QueryRow("PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
		t.Fatalf("failed to read foreign_keys pragma: %v", err)
	}
	if foreignKeys != 1 {
		t.Fatalf("expected foreign_keys pragma to be enabled, got %d", foreignKeys)
	}

	var busyTimeout int
	if err := DB.QueryRow("PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
		t.Fatalf("failed to read busy_timeout pragma: %v", err)
	}
	if busyTimeout < 5000 {
		t.Fatalf("expected busy_timeout to be at least 5000, got %d", busyTimeout)
	}
}

func TestInitDBUsesConfiguredDatabasePath(t *testing.T) {
	originalDB := DB
	dbPath := filepath.Join(t.TempDir(), "configured.db")
	t.Setenv("DATABASE_PATH", dbPath)

	if err := InitDB(); err != nil {
		t.Fatalf("InitDB returned error: %v", err)
	}
	t.Cleanup(func() {
		_ = DB.Close()
		DB = originalDB
	})

	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("expected configured database file to be created: %v", err)
	}
}
