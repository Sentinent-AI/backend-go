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
