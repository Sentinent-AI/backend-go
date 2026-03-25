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

	createExternalIntegrationsTable := `
	CREATE TABLE IF NOT EXISTS external_integrations (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		provider TEXT NOT NULL,
		access_token TEXT NOT NULL,
		refresh_token TEXT,
		expires_at DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id),
		UNIQUE(user_id, provider)
	);`

	_, err = DB.Exec(createExternalIntegrationsTable)
	if err != nil {
		log.Fatal(err)
	}

	createSignalsTable := `
	CREATE TABLE IF NOT EXISTS signals (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		source_type TEXT NOT NULL,
		source_id TEXT NOT NULL,
		title TEXT NOT NULL,
		body TEXT,
		url TEXT,
		status TEXT,
		source_metadata TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id),
		UNIQUE(user_id, source_type, source_id)
	);`

	_, err = DB.Exec(createSignalsTable)
	if err != nil {
		log.Fatal(err)
	}
}
