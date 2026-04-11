package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sentinent-backend/database"
	"sentinent-backend/models"
	"sentinent-backend/utils"
	"strings"
	"testing"
	"time"

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

	resetTable := `
	CREATE TABLE IF NOT EXISTS password_reset_tokens (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		token_hash TEXT NOT NULL UNIQUE,
		expires_at DATETIME NOT NULL,
		used_at DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`
	_, err = database.DB.Exec(resetTable)
	if err != nil {
		panic(err)
	}

	workspaceTable := `
	CREATE TABLE IF NOT EXISTS workspaces (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		description TEXT DEFAULT '',
		owner_id INTEGER NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`
	_, err = database.DB.Exec(workspaceTable)
	if err != nil {
		panic(err)
	}

	workspaceMembersTable := `
	CREATE TABLE IF NOT EXISTS workspace_members (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		workspace_id INTEGER NOT NULL,
		user_id INTEGER NOT NULL,
		role TEXT NOT NULL,
		joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(workspace_id, user_id)
	);`
	_, err = database.DB.Exec(workspaceMembersTable)
	if err != nil {
		panic(err)
	}

	utils.JwtKey = []byte("test-jwt-secret")
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

func TestSignupInvalidEmail(t *testing.T) {
	setupTestDB()
	defer database.DB.Close()

	user := models.User{
		Email:    "invalid-email",
		Password: "password123",
	}
	body, _ := json.Marshal(user)

	req, _ := http.NewRequest("POST", "/signup", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()

	Signup(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusBadRequest)
	}
}

func TestSigninInvalidEmail(t *testing.T) {
	setupTestDB()
	defer database.DB.Close()

	user := models.User{
		Email:    "invalid-email",
		Password: "password123",
	}
	body, _ := json.Marshal(user)

	req, _ := http.NewRequest("POST", "/signin", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()

	Signin(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusBadRequest)
	}
}

func TestForgotPasswordGeneratesResetTokenForExistingUser(t *testing.T) {
	setupTestDB()
	defer database.DB.Close()
	t.Setenv("FRONTEND_BASE_URL", "http://localhost:4200")

	Signup(httptest.NewRecorder(), httptest.NewRequest("POST", "/signup", bytes.NewBuffer([]byte(`{"email":"test@example.com","password":"password123"}`))))

	req, _ := http.NewRequest("POST", "/forgot-password", bytes.NewBuffer([]byte(`{"email":"test@example.com"}`)))
	rr := httptest.NewRecorder()

	ForgotPassword(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var response map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if response["reset_url"] == "" {
		t.Fatal("expected reset_url in forgot password response")
	}

	var count int
	if err := database.DB.QueryRow("SELECT COUNT(*) FROM password_reset_tokens").Scan(&count); err != nil {
		t.Fatalf("failed to query reset tokens: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 reset token, got %d", count)
	}
}

func TestForgotPasswordSendsResetEmailWhenMailerConfigured(t *testing.T) {
	setupTestDB()
	defer database.DB.Close()
	t.Setenv("FRONTEND_BASE_URL", "https://app.example.com")
	t.Setenv("SMTP_HOST", "smtp.example.com")
	t.Setenv("SMTP_PORT", "587")
	t.Setenv("SMTP_USERNAME", "mailer")
	t.Setenv("SMTP_PASSWORD", "secret")
	t.Setenv("SMTP_FROM_EMAIL", "no-reply@example.com")

	originalSendPasswordResetEmailFunc := sendPasswordResetEmailFunc
	t.Cleanup(func() {
		sendPasswordResetEmailFunc = originalSendPasswordResetEmailFunc
	})

	var deliveredTo string
	var deliveredURL string
	sendPasswordResetEmailFunc = func(toEmail, resetURL string) error {
		deliveredTo = toEmail
		deliveredURL = resetURL
		return nil
	}

	Signup(httptest.NewRecorder(), httptest.NewRequest("POST", "/signup", bytes.NewBuffer([]byte(`{"email":"test@example.com","password":"password123"}`))))

	req, _ := http.NewRequest("POST", "/forgot-password", bytes.NewBuffer([]byte(`{"email":"test@example.com"}`)))
	rr := httptest.NewRecorder()

	ForgotPassword(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var response map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if response["reset_url"] != "" {
		t.Fatal("expected reset_url to be hidden when mail delivery is configured")
	}
	if deliveredTo != "test@example.com" {
		t.Fatalf("expected email to be sent to test@example.com, got %q", deliveredTo)
	}
	if !strings.HasPrefix(deliveredURL, "https://app.example.com/reset-password/") {
		t.Fatalf("expected reset URL to use frontend base URL, got %q", deliveredURL)
	}

	var count int
	if err := database.DB.QueryRow("SELECT COUNT(*) FROM password_reset_tokens").Scan(&count); err != nil {
		t.Fatalf("failed to query reset tokens: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 reset token, got %d", count)
	}
}

func TestForgotPasswordDoesNotRevealMissingEmail(t *testing.T) {
	setupTestDB()
	defer database.DB.Close()

	req, _ := http.NewRequest("POST", "/forgot-password", bytes.NewBuffer([]byte(`{"email":"missing@example.com"}`)))
	rr := httptest.NewRecorder()

	ForgotPassword(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var count int
	if err := database.DB.QueryRow("SELECT COUNT(*) FROM password_reset_tokens").Scan(&count); err != nil {
		t.Fatalf("failed to query reset tokens: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 reset tokens, got %d", count)
	}
}

func TestForgotPasswordFailsInProductionWithoutMailer(t *testing.T) {
	setupTestDB()
	defer database.DB.Close()
	t.Setenv("APP_ENV", "production")

	Signup(httptest.NewRecorder(), httptest.NewRequest("POST", "/signup", bytes.NewBuffer([]byte(`{"email":"test@example.com","password":"password123"}`))))

	req, _ := http.NewRequest("POST", "/forgot-password", bytes.NewBuffer([]byte(`{"email":"test@example.com"}`)))
	rr := httptest.NewRecorder()

	ForgotPassword(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", rr.Code)
	}

	var count int
	if err := database.DB.QueryRow("SELECT COUNT(*) FROM password_reset_tokens").Scan(&count); err != nil {
		t.Fatalf("failed to query reset tokens: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 reset tokens, got %d", count)
	}
}

func TestForgotPasswordDeletesTokenWhenEmailDeliveryFails(t *testing.T) {
	setupTestDB()
	defer database.DB.Close()
	t.Setenv("SMTP_HOST", "smtp.example.com")
	t.Setenv("SMTP_PORT", "587")
	t.Setenv("SMTP_USERNAME", "mailer")
	t.Setenv("SMTP_PASSWORD", "secret")
	t.Setenv("SMTP_FROM_EMAIL", "no-reply@example.com")

	originalSendPasswordResetEmailFunc := sendPasswordResetEmailFunc
	t.Cleanup(func() {
		sendPasswordResetEmailFunc = originalSendPasswordResetEmailFunc
	})

	sendPasswordResetEmailFunc = func(toEmail, resetURL string) error {
		return fmt.Errorf("smtp unavailable")
	}

	Signup(httptest.NewRecorder(), httptest.NewRequest("POST", "/signup", bytes.NewBuffer([]byte(`{"email":"test@example.com","password":"password123"}`))))

	req, _ := http.NewRequest("POST", "/forgot-password", bytes.NewBuffer([]byte(`{"email":"test@example.com"}`)))
	rr := httptest.NewRecorder()

	ForgotPassword(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", rr.Code)
	}

	var count int
	if err := database.DB.QueryRow("SELECT COUNT(*) FROM password_reset_tokens").Scan(&count); err != nil {
		t.Fatalf("failed to query reset tokens: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected failed delivery to clean up reset tokens, got %d", count)
	}
}

func TestValidateAndResetPassword(t *testing.T) {
	setupTestDB()
	defer database.DB.Close()

	Signup(httptest.NewRecorder(), httptest.NewRequest("POST", "/signup", bytes.NewBuffer([]byte(`{"email":"test@example.com","password":"password123"}`))))

	resetToken, err := generatePasswordResetToken()
	if err != nil {
		t.Fatalf("failed to create reset token: %v", err)
	}

	if _, err := database.DB.Exec(
		`INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
		 VALUES (1, ?, ?)`,
		hashPasswordResetToken(resetToken), time.Now().Add(time.Hour),
	); err != nil {
		t.Fatalf("failed to seed reset token: %v", err)
	}

	validateReq, _ := http.NewRequest("GET", "/api/reset-password/"+resetToken, nil)
	validateRR := httptest.NewRecorder()
	ValidatePasswordResetToken(validateRR, validateReq)

	if validateRR.Code != http.StatusOK {
		t.Fatalf("expected validate status 200, got %d", validateRR.Code)
	}

	resetReq, _ := http.NewRequest("POST", "/api/reset-password/"+resetToken, bytes.NewBuffer([]byte(`{"password":"newsecret123"}`)))
	resetRR := httptest.NewRecorder()
	ResetPassword(resetRR, resetReq)

	if resetRR.Code != http.StatusNoContent {
		t.Fatalf("expected reset status 204, got %d", resetRR.Code)
	}

	loginReq, _ := http.NewRequest("POST", "/signin", bytes.NewBuffer([]byte(`{"email":"test@example.com","password":"newsecret123"}`)))
	loginRR := httptest.NewRecorder()
	Signin(loginRR, loginReq)

	if loginRR.Code != http.StatusOK {
		t.Fatalf("expected login with new password to succeed, got %d", loginRR.Code)
	}

	validateAgainReq, _ := http.NewRequest("GET", "/api/reset-password/"+resetToken, nil)
	validateAgainRR := httptest.NewRecorder()
	ValidatePasswordResetToken(validateAgainRR, validateAgainReq)

	if validateAgainRR.Code != http.StatusGone {
		t.Fatalf("expected used token to be rejected, got %d", validateAgainRR.Code)
	}
}
