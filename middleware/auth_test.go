package middleware

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"sentinent-backend/database"
	"sentinent-backend/models"
	"sentinent-backend/utils"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
)

func makeAuthTestToken(t *testing.T, email string) string {
	t.Helper()
	return makeAuthTestTokenWithUserID(t, email, 0)
}

func makeAuthTestTokenWithUserID(t *testing.T, email string, userID int) string {
	t.Helper()

	utils.JwtKey = []byte("middleware-test-secret")
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &models.Claims{
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})

	tokenString, err := token.SignedString(utils.JwtKey)
	if err != nil {
		t.Fatalf("failed to sign JWT: %v", err)
	}

	return tokenString
}

func TestAuthMiddlewareAcceptsBearerToken(t *testing.T) {
	tokenString := makeAuthTestToken(t, "reader@example.com")

	req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	rr := httptest.NewRecorder()

	var gotEmail string
	handler := AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		email, _ := r.Context().Value(UserEmailKey).(string)
		gotEmail = email
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}
	if gotEmail != "reader@example.com" {
		t.Fatalf("expected email reader@example.com, got %q", gotEmail)
	}
}

func TestAuthMiddlewareAcceptsCookieToken(t *testing.T) {
	tokenString := makeAuthTestToken(t, "cookie@example.com")

	req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	req.AddCookie(&http.Cookie{Name: "token", Value: tokenString})
	rr := httptest.NewRecorder()

	var gotEmail string
	handler := AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		email, _ := r.Context().Value(UserEmailKey).(string)
		gotEmail = email
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}
	if gotEmail != "cookie@example.com" {
		t.Fatalf("expected email cookie@example.com, got %q", gotEmail)
	}
}

func TestAuthMiddlewareRejectsMissingToken(t *testing.T) {
	utils.JwtKey = []byte("middleware-test-secret")

	req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	rr := httptest.NewRecorder()

	handler := AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rr.Code)
	}
}

func TestAuthMiddlewareRejectsMalformedBearerToken(t *testing.T) {
	utils.JwtKey = []byte("middleware-test-secret")

	req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	rr := httptest.NewRecorder()

	handler := AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rr.Code)
	}
}

func TestAuthMiddlewareRecoversFromStaleTokenUserID(t *testing.T) {
	var err error
	database.DB, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open in-memory db: %v", err)
	}
	t.Cleanup(func() {
		_ = database.DB.Close()
		database.DB = nil
	})

	if _, err := database.DB.Exec(`
		CREATE TABLE users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email TEXT NOT NULL UNIQUE
		);
	`); err != nil {
		t.Fatalf("failed to create users table: %v", err)
	}

	if _, err := database.DB.Exec("INSERT INTO users (id, email) VALUES (?, ?)", 42, "reader@example.com"); err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}

	tokenString := makeAuthTestTokenWithUserID(t, "reader@example.com", 9999)

	req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	rr := httptest.NewRecorder()

	var gotUserID int
	var gotEmail string
	handler := AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, _ := GetUserID(r.Context())
		email, _ := r.Context().Value(UserEmailKey).(string)
		gotUserID = userID
		gotEmail = email
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}
	if gotUserID != 42 {
		t.Fatalf("expected resolved user id 42, got %d", gotUserID)
	}
	if gotEmail != "reader@example.com" {
		t.Fatalf("expected email reader@example.com, got %q", gotEmail)
	}
}
