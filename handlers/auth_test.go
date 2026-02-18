package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sentinent-backend/database"
	"sentinent-backend/models"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func setupTestDB() {
	var err error
	database.DB, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}

	createTable := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL
	);`

	_, err = database.DB.Exec(createTable)
	if err != nil {
		panic(err)
	}

	createDecisionsTable := `
	CREATE TABLE IF NOT EXISTS workspaces (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		owner_id INTEGER NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (owner_id) REFERENCES users(id)
	);

	CREATE TABLE IF NOT EXISTS workspace_members (
		workspace_id INTEGER NOT NULL,
		user_id INTEGER NOT NULL,
		role TEXT NOT NULL DEFAULT 'member',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (workspace_id, user_id),
		FOREIGN KEY (workspace_id) REFERENCES workspaces(id),
		FOREIGN KEY (user_id) REFERENCES users(id)
	);

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

	_, err = database.DB.Exec(createDecisionsTable)
	if err != nil {
		panic(err)
	}

	JwtKey = []byte("test-jwt-secret")
}

func TestSignup(t *testing.T) {
	setupTestDB()
	defer database.DB.Close()

	user := models.User{
		Email:    "test@example.com",
		Password: "password123",
	}
	body, _ := json.Marshal(user)

	req, _ := http.NewRequest("POST", "/signup", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()

	Signup(rr, req)

	if status := rr.Code; status != http.StatusCreated {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusCreated)
	}

	// Verify user is in DB
	var count int
	err := database.DB.QueryRow("SELECT count(*) FROM users WHERE email = ?", user.Email).Scan(&count)
	if err != nil {
		t.Errorf("error querying db: %v", err)
	}
	if count != 1 {
		t.Errorf("user not created in db")
	}
}

func TestSignin(t *testing.T) {
	setupTestDB()
	defer database.DB.Close()
	t.Setenv("APP_ENV", "development")

	// Create user first
	Signup(httptest.NewRecorder(), httptest.NewRequest("POST", "/signup", bytes.NewBuffer([]byte(`{"email":"test@example.com","password":"password123"}`))))

	user := models.User{
		Email:    "test@example.com",
		Password: "password123",
	}
	body, _ := json.Marshal(user)

	req, _ := http.NewRequest("POST", "/signin", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()

	Signin(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check for token in cookie
	var tokenCookie *http.Cookie
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == "token" {
			tokenCookie = cookie
			break
		}
	}
	if tokenCookie == nil {
		t.Errorf("token cookie not found")
	}
	if !tokenCookie.HttpOnly {
		t.Errorf("expected token cookie to be HttpOnly")
	}
	if tokenCookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("expected token cookie to use SameSite=Lax")
	}
	if tokenCookie.Secure {
		t.Errorf("expected token cookie Secure=false in development mode")
	}
}

func TestSigninCookieSecureInProduction(t *testing.T) {
	setupTestDB()
	defer database.DB.Close()
	t.Setenv("APP_ENV", "production")

	Signup(httptest.NewRecorder(), httptest.NewRequest("POST", "/signup", bytes.NewBuffer([]byte(`{"email":"test@example.com","password":"password123"}`))))

	body, _ := json.Marshal(models.User{
		Email:    "test@example.com",
		Password: "password123",
	})

	req, _ := http.NewRequest("POST", "/signin", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()
	Signin(rr, req)

	var tokenCookie *http.Cookie
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == "token" {
			tokenCookie = cookie
			break
		}
	}
	if tokenCookie == nil {
		t.Fatalf("token cookie not found")
	}
	if !tokenCookie.Secure {
		t.Errorf("expected token cookie Secure=true in production mode")
	}
}
