package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSPAHandler(t *testing.T) {
	h := spaHandler()

	// Unmatched API paths must return a JSON 404, not the SPA.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/does-not-exist", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("api 404 expected, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "problem+json") {
		t.Fatalf("expected problem+json, got %q", ct)
	}

	// A client-side route falls back to index.html.
	req = httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	rec = httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("spa route expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "TransCircle") {
		t.Fatalf("expected index.html body, got %q", rec.Body.String())
	}

	// Root serves index.html too.
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("root expected 200, got %d", rec.Code)
	}
}
