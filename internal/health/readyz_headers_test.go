package health

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

// readyz 503 path must still carry Content-Type: application/json — headers
// set after WriteHeader are silently dropped by net/http.
func TestHealthServer_ReadyNotReadyHasContentType(t *testing.T) {
	checker := NewSimpleHealthChecker(func() bool { return false }, nil)
	hs := NewHealthServer("127.0.0.1:0", checker, slog.Default())

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	hs.handleReady(rec, req)

	res := rec.Result()
	defer res.Body.Close()
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d; want 503", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q; want application/json", ct)
	}
}
