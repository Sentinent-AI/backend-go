package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func testCORSHandler(t *testing.T, origins ...string) http.Handler {
	t.Helper()
	if err := SetAllowedOrigins(origins); err != nil {
		t.Fatalf("failed to configure allowed origins: %v", err)
	}

	return CorsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

func TestCorsMiddlewareAllowsConfiguredOrigin(t *testing.T) {
	handler := testCORSHandler(t, "http://localhost:4200")

	req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	req.Header.Set("Origin", "http://localhost:4200")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:4200" {
		t.Fatalf("expected allowed origin header, got %q", got)
	}
	if got := rr.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("expected credentials header true, got %q", got)
	}
}

func TestCorsMiddlewareDoesNotSetHeadersForDisallowedOrigin(t *testing.T) {
	handler := testCORSHandler(t, "http://localhost:4200")

	req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	req.Header.Set("Origin", "http://evil.example")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("expected no allow-origin header for disallowed origin, got %q", got)
	}
}

func TestCorsMiddlewareRejectsDisallowedPreflight(t *testing.T) {
	handler := testCORSHandler(t, "http://localhost:4200")

	req := httptest.NewRequest(http.MethodOptions, "/api/protected", nil)
	req.Header.Set("Origin", "http://evil.example")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", rr.Code)
	}
}

func TestCorsMiddlewareHandlesAllowedPreflight(t *testing.T) {
	handler := testCORSHandler(t, "http://localhost:4200")

	req := httptest.NewRequest(http.MethodOptions, "/api/protected", nil)
	req.Header.Set("Origin", "http://localhost:4200")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d", rr.Code)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:4200" {
		t.Fatalf("expected allowed origin header, got %q", got)
	}
}

func TestSetAllowedOriginsRejectsInvalidOrigin(t *testing.T) {
	if err := SetAllowedOrigins([]string{"not-an-origin"}); err == nil {
		t.Fatalf("expected invalid origin error")
	}
}
