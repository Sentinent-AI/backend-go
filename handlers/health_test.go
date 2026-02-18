package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthGet(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rr := httptest.NewRecorder()

	Health(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("expected JSON response, got error: %v", err)
	}

	if body["status"] != "ok" {
		t.Fatalf("expected status=ok, got %q", body["status"])
	}
}

func TestHealthMethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/health", nil)
	rr := httptest.NewRecorder()

	Health(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", rr.Code)
	}
}
