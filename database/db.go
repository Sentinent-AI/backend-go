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

	createWorkspaceTable := `
	CREATE TABLE IF NOT EXISTS workspaces (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		owner_id INTEGER NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (owner_id) REFERENCES users(id)
	);`

	_, err = DB.Exec(createWorkspaceTable)
	if err != nil {
		log.Fatal(err)
	}
}
