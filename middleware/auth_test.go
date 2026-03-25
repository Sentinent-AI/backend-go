package middleware

import (
	"net/http"
	"net/http/httptest"
	"sentinent-backend/models"
	"sentinent-backend/utils"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func makeAuthTestToken(t *testing.T, email string) string {
	t.Helper()

	utils.JwtKey = []byte("middleware-test-secret")
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &models.Claims{
		Email: email,
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
