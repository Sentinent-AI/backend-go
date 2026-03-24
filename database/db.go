package database

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

var DB *sql.DB

func InitDB() {
	var err error
	DB, err = sql.Open("sqlite3", "./sentinent.db")
	if err != nil {
		log.Fatal(err)
	}

	createTables := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS workspaces (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		description TEXT,
		created_by INTEGER NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (created_by) REFERENCES users(id)
	);

	CREATE TABLE IF NOT EXISTS workspace_members (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		workspace_id INTEGER NOT NULL,
		user_id INTEGER NOT NULL,
		role TEXT NOT NULL CHECK(role IN ('owner', 'member', 'viewer')),
		joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(workspace_id, user_id),
		FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS invitations (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		workspace_id INTEGER NOT NULL,
		email TEXT NOT NULL,
		token TEXT NOT NULL UNIQUE,
		role TEXT NOT NULL DEFAULT 'member' CHECK(role IN ('member', 'viewer')),
		expires_at DATETIME NOT NULL,
		created_by INTEGER NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		accepted_at DATETIME,
		accepted_by INTEGER,
		FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
		FOREIGN KEY (created_by) REFERENCES users(id),
		FOREIGN KEY (accepted_by) REFERENCES users(id)
	);

	CREATE INDEX IF NOT EXISTS idx_invitations_token ON invitations(token);
	CREATE INDEX IF NOT EXISTS idx_workspace_members_workspace ON workspace_members(workspace_id);
	CREATE INDEX IF NOT EXISTS idx_workspace_members_user ON workspace_members(user_id);
	`

	_, err = DB.Exec(createTables)
	if err != nil {
		log.Fatal(err)
	}
}
