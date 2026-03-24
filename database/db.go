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
		owner_id INTEGER NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (owner_id) REFERENCES users(id)
	);

	CREATE TABLE IF NOT EXISTS external_integrations (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		workspace_id INTEGER NOT NULL,
		provider TEXT NOT NULL,
		access_token TEXT NOT NULL,
		refresh_token TEXT,
		metadata TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id),
		FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
	);

	CREATE TABLE IF NOT EXISTS signals (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		workspace_id INTEGER NOT NULL,
		source_type TEXT NOT NULL,
		source_id TEXT,
		external_id TEXT NOT NULL,
		title TEXT NOT NULL,
		content TEXT,
		author TEXT,
		status TEXT DEFAULT 'unread',
		received_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id),
		FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
	);

	CREATE TABLE IF NOT EXISTS signal_status (
		signal_id INTEGER NOT NULL,
		user_id INTEGER NOT NULL,
		status TEXT NOT NULL,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (signal_id, user_id),
		FOREIGN KEY (signal_id) REFERENCES signals(id),
		FOREIGN KEY (user_id) REFERENCES users(id)
	);

	CREATE INDEX IF NOT EXISTS idx_signals_user_id ON signals(user_id);
	CREATE INDEX IF NOT EXISTS idx_signals_workspace_id ON signals(workspace_id);
	CREATE INDEX IF NOT EXISTS idx_signals_source_type ON signals(source_type);
	CREATE INDEX IF NOT EXISTS idx_signals_status ON signals(status);
	CREATE INDEX IF NOT EXISTS idx_integrations_user_id ON external_integrations(user_id);
	CREATE INDEX IF NOT EXISTS idx_integrations_workspace_id ON external_integrations(workspace_id);
	`

	_, err = DB.Exec(createTables)
	if err != nil {
		log.Fatal(err)
	}
}
