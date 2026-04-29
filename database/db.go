package database

import (
	"database/sql"
	"fmt"
	"os"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

var DB *sql.DB

const defaultDBPath = "./sentinent.db"

func InitDB() error {
	return InitDBWithPath(strings.TrimSpace(os.Getenv("DATABASE_PATH")))
}

func buildDSN(path string) string {
	// Embed SQLite pragmas in the DSN so they apply to every connection in the
	// pool, not just the one used during initialisation.  Without this,
	// busy_timeout only applies to the first connection; background goroutines
	// that hold a write lock can block other connections indefinitely.
	if strings.Contains(path, ":memory:") || strings.Contains(path, "?") {
		return path // already has params, or in-memory test db – leave as-is
	}
	return path + "?_busy_timeout=5000&_journal_mode=wal&_foreign_keys=on"
}

func InitDBWithPath(path string) error {
	if strings.TrimSpace(path) == "" {
		path = defaultDBPath
	}

	db, err := sql.Open("sqlite3", buildDSN(path))
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}

	previousDB := DB
	DB = db
	if err := configureSQLite(); err != nil {
		DB = previousDB
		_ = db.Close()
		return err
	}

	statements := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email TEXT NOT NULL UNIQUE,
			password TEXT NOT NULL,
			full_name TEXT DEFAULT '',
			job_title TEXT DEFAULT '',
			organization TEXT DEFAULT '',
			timezone TEXT DEFAULT '',
			bio TEXT DEFAULT '',
			role_label TEXT DEFAULT ''
		);`,
		`CREATE TABLE IF NOT EXISTS workspaces (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			description TEXT DEFAULT '',
			owner_id INTEGER NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (owner_id) REFERENCES users(id)
		);`,
		`CREATE TABLE IF NOT EXISTS decisions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			workspace_id INTEGER NOT NULL,
			user_id INTEGER NOT NULL,
			title TEXT NOT NULL,
			description TEXT,
			status TEXT NOT NULL CHECK (status IN ('DRAFT', 'OPEN', 'CLOSED')),
			due_date DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (workspace_id) REFERENCES workspaces(id),
			FOREIGN KEY (user_id) REFERENCES users(id)
		);`,
		`CREATE TABLE IF NOT EXISTS workspace_members (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			workspace_id INTEGER NOT NULL,
			user_id INTEGER NOT NULL,
			role TEXT NOT NULL CHECK (role IN ('owner', 'member', 'viewer')),
			joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(workspace_id, user_id),
			FOREIGN KEY (workspace_id) REFERENCES workspaces(id),
			FOREIGN KEY (user_id) REFERENCES users(id)
		);`,
		`CREATE TABLE IF NOT EXISTS invitations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			workspace_id INTEGER NOT NULL,
			email TEXT NOT NULL,
			token TEXT NOT NULL UNIQUE,
			role TEXT NOT NULL CHECK (role IN ('member', 'viewer')),
			expires_at DATETIME NOT NULL,
			created_by INTEGER NOT NULL,
			accepted_at DATETIME,
			accepted_by INTEGER,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (workspace_id) REFERENCES workspaces(id),
			FOREIGN KEY (created_by) REFERENCES users(id),
			FOREIGN KEY (accepted_by) REFERENCES users(id)
		);`,
		`CREATE TABLE IF NOT EXISTS external_integrations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			workspace_id INTEGER,
			provider TEXT NOT NULL,
			access_token TEXT NOT NULL,
			refresh_token TEXT,
			expires_at DATETIME,
			metadata TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id),
			FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
		);`,
		`CREATE TABLE IF NOT EXISTS signals (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			workspace_id INTEGER,
			source_type TEXT NOT NULL,
			source_id TEXT NOT NULL,
			external_id TEXT,
			title TEXT NOT NULL,
			content TEXT,
			author TEXT,
			body TEXT,
			url TEXT,
			status TEXT DEFAULT 'unread',
			source_metadata TEXT,
			received_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id),
			FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
		);`,
		`CREATE TABLE IF NOT EXISTS signal_status (
			signal_id INTEGER NOT NULL,
			user_id INTEGER NOT NULL,
			status TEXT NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (signal_id, user_id),
			FOREIGN KEY (signal_id) REFERENCES signals(id),
			FOREIGN KEY (user_id) REFERENCES users(id)
		);`,
		`CREATE TABLE IF NOT EXISTS password_reset_tokens (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			token_hash TEXT NOT NULL UNIQUE,
			expires_at DATETIME NOT NULL,
			used_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id)
		);`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_external_integrations_user_provider_workspace
			ON external_integrations(user_id, provider, COALESCE(workspace_id, 0));`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_signals_user_source
			ON signals(user_id, source_type, source_id);`,
		`CREATE INDEX IF NOT EXISTS idx_signals_user_id ON signals(user_id);`,
		`CREATE INDEX IF NOT EXISTS idx_signals_workspace_id ON signals(workspace_id);`,
		`CREATE INDEX IF NOT EXISTS idx_signals_received_at ON signals(received_at);`,
		`CREATE INDEX IF NOT EXISTS idx_integrations_user_id ON external_integrations(user_id);`,
		`CREATE INDEX IF NOT EXISTS idx_integrations_workspace_id ON external_integrations(workspace_id);`,
		`CREATE INDEX IF NOT EXISTS idx_workspace_members_workspace_id ON workspace_members(workspace_id);`,
		`CREATE INDEX IF NOT EXISTS idx_workspace_members_user_id ON workspace_members(user_id);`,
		`CREATE INDEX IF NOT EXISTS idx_invitations_workspace_id ON invitations(workspace_id);`,
		`CREATE INDEX IF NOT EXISTS idx_invitations_email ON invitations(email);`,
		`CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);`,
		`CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_expires_at ON password_reset_tokens(expires_at);`,
	}

	for _, statement := range statements {
		if _, err := DB.Exec(statement); err != nil {
			DB = previousDB
			_ = db.Close()
			return fmt.Errorf("run schema statement: %w", err)
		}
	}

	columns := []struct {
		table      string
		name       string
		definition string
	}{
		{"external_integrations", "workspace_id", "INTEGER"},
		{"external_integrations", "refresh_token", "TEXT"},
		{"external_integrations", "expires_at", "DATETIME"},
		{"external_integrations", "metadata", "TEXT"},
		{"workspaces", "description", "TEXT DEFAULT ''"},
		{"users", "full_name", "TEXT DEFAULT ''"},
		{"users", "job_title", "TEXT DEFAULT ''"},
		{"users", "organization", "TEXT DEFAULT ''"},
		{"users", "timezone", "TEXT DEFAULT ''"},
		{"users", "bio", "TEXT DEFAULT ''"},
		{"users", "role_label", "TEXT DEFAULT ''"},
		{"signals", "workspace_id", "INTEGER"},
		{"signals", "external_id", "TEXT"},
		{"signals", "content", "TEXT"},
		{"signals", "author", "TEXT"},
		{"signals", "body", "TEXT"},
		{"signals", "url", "TEXT"},
		{"signals", "source_metadata", "TEXT"},
		{"signals", "received_at", "DATETIME DEFAULT CURRENT_TIMESTAMP"},
		{"signals", "updated_at", "DATETIME DEFAULT CURRENT_TIMESTAMP"},
	}
	for _, column := range columns {
		if err := ensureColumn(column.table, column.name, column.definition); err != nil {
			DB = previousDB
			_ = db.Close()
			return err
		}
	}

	if _, err := DB.Exec(`CREATE INDEX IF NOT EXISTS idx_decisions_workspace_id ON decisions(workspace_id);`); err != nil {
		DB = previousDB
		_ = db.Close()
		return fmt.Errorf("create decisions workspace index: %w", err)
	}
	if _, err := DB.Exec(`CREATE INDEX IF NOT EXISTS idx_decisions_user_id ON decisions(user_id);`); err != nil {
		DB = previousDB
		_ = db.Close()
		return fmt.Errorf("create decisions user index: %w", err)
	}

	if err := ensureWorkspaceOwnerMemberships(); err != nil {
		DB = previousDB
		_ = db.Close()
		return err
	}
	if err := cleanupOrphanIntegrations(); err != nil {
		DB = previousDB
		_ = db.Close()
		return err
	}

	return nil
}

func configureSQLite() error {
	statements := []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA busy_timeout = 5000",
		"PRAGMA journal_mode = WAL",
	}
	for _, statement := range statements {
		if _, err := DB.Exec(statement); err != nil {
			return fmt.Errorf("configure sqlite %q: %w", statement, err)
		}
	}
	return nil
}

func ensureColumn(tableName, columnName, columnDefinition string) error {
	rows, err := DB.Query(fmt.Sprintf("PRAGMA table_info(%s)", tableName))
	if err != nil {
		return fmt.Errorf("inspect table %s: %w", tableName, err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			cid        int
			name       string
			columnType string
			notNull    int
			defaultVal sql.NullString
			pk         int
		)
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultVal, &pk); err != nil {
			return fmt.Errorf("scan table %s column info: %w", tableName, err)
		}
		if name == columnName {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate table %s columns: %w", tableName, err)
	}

	statement := fmt.Sprintf(
		"ALTER TABLE %s ADD COLUMN %s %s",
		tableName,
		columnName,
		columnDefinition,
	)
	if _, err := DB.Exec(statement); err != nil {
		return fmt.Errorf("add column %s.%s: %w", tableName, columnName, err)
	}
	return nil
}

func ensureWorkspaceOwnerMemberships() error {
	if _, err := DB.Exec(`
		INSERT INTO workspace_members (workspace_id, user_id, role, updated_at)
		SELECT w.id, w.owner_id, 'owner', CURRENT_TIMESTAMP
		FROM workspaces w
		WHERE NOT EXISTS (
			SELECT 1 FROM workspace_members wm 
			WHERE wm.workspace_id = w.id AND wm.user_id = w.owner_id
		)
	`); err != nil {
		return fmt.Errorf("ensure owner memberships: %w", err)
	}

	if _, err := DB.Exec(`
		UPDATE workspace_members SET role = 'owner', updated_at = CURRENT_TIMESTAMP
		WHERE workspace_id IN (
			SELECT w.id FROM workspaces w
			WHERE w.owner_id = workspace_members.user_id
		)
		AND role != 'owner'
	`); err != nil {
		return fmt.Errorf("restore owner roles: %w", err)
	}

	if _, err := DB.Exec(`
		UPDATE workspace_members
		SET role = 'member', updated_at = CURRENT_TIMESTAMP
		WHERE role = 'owner'
		  AND EXISTS (
			  SELECT 1
			  FROM workspaces w
			  WHERE w.id = workspace_members.workspace_id
			    AND w.owner_id <> workspace_members.user_id
		  )
	`); err != nil {
		return fmt.Errorf("demote stale owner roles: %w", err)
	}
	return nil
}

// cleanupOrphanIntegrations removes integration records with NULL or 0 workspace_id
// when a valid workspace-scoped record exists for the same user and provider.
// This prevents duplicate records from confusing the GetIntegrations query which
// includes `workspace_id IS NULL` results alongside workspace-scoped ones.
func cleanupOrphanIntegrations() error {
	result, err := DB.Exec(`
		DELETE FROM external_integrations
		WHERE (workspace_id IS NULL OR workspace_id = 0)
		  AND provider IN ('jira', 'github')
		  AND EXISTS (
		      SELECT 1 FROM external_integrations ei2
		      WHERE ei2.user_id = external_integrations.user_id
		        AND ei2.provider = external_integrations.provider
		        AND ei2.workspace_id IS NOT NULL
		        AND ei2.workspace_id != 0
		  )
	`)
	if err != nil {
		return fmt.Errorf("clean up orphan integrations: %w", err)
	}
	_, _ = result.RowsAffected()
	return nil
}
