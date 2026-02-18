package database

import (
	"database/sql"
	"fmt"
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

	createTable := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL
	);`

	_, err = DB.Exec(createTable)
	if err != nil {
		log.Fatal(err)
	}

	createWorkspacesTable := `
	CREATE TABLE IF NOT EXISTS workspaces (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		owner_id INTEGER NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (owner_id) REFERENCES users(id)
	);`

	_, err = DB.Exec(createWorkspacesTable)
	if err != nil {
		log.Fatal(err)
	}

	createWorkspaceMembersTable := `
	CREATE TABLE IF NOT EXISTS workspace_members (
		workspace_id INTEGER NOT NULL,
		user_id INTEGER NOT NULL,
		role TEXT NOT NULL DEFAULT 'member',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (workspace_id, user_id),
		FOREIGN KEY (workspace_id) REFERENCES workspaces(id),
		FOREIGN KEY (user_id) REFERENCES users(id)
	);`

	_, err = DB.Exec(createWorkspaceMembersTable)
	if err != nil {
		log.Fatal(err)
	}

	createDecisionsTable := `
	CREATE TABLE IF NOT EXISTS decisions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		title TEXT NOT NULL,
		description TEXT NOT NULL,
		status TEXT NOT NULL,
		workspace_id INTEGER NOT NULL,
		owner_id INTEGER NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (workspace_id) REFERENCES workspaces(id),
		FOREIGN KEY (owner_id) REFERENCES users(id)
	);`

	_, err = DB.Exec(createDecisionsTable)
	if err != nil {
		log.Fatal(err)
	}

	if err := ensureDecisionsWorkspaceColumn(); err != nil {
		log.Fatal(err)
	}
}

func ensureDecisionsWorkspaceColumn() error {
	rows, err := DB.Query("PRAGMA table_info(decisions)")
	if err != nil {
		return err
	}
	defer rows.Close()

	var (
		cid       int
		name      string
		colType   string
		notNull   int
		defaultV  sql.NullString
		pk        int
		hasColumn bool
	)
	for rows.Next() {
		if err := rows.Scan(&cid, &name, &colType, &notNull, &defaultV, &pk); err != nil {
			return err
		}
		if name == "workspace_id" {
			hasColumn = true
			break
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	if hasColumn {
		return nil
	}

	if _, err := DB.Exec("ALTER TABLE decisions ADD COLUMN workspace_id INTEGER"); err != nil {
		return fmt.Errorf("add decisions.workspace_id: %w", err)
	}

	return nil
}
