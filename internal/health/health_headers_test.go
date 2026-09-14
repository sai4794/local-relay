package health

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Degraded responses must still carry Content-Type: application/json —
// headers set after WriteHeader are silently dropped by net/http.
func TestHealthServer_DegradedHasContentType(t *testing.T) {
	checker := NewSimpleHealthChecker(func() bool { return false }, nil)
	hs := NewHealthServer("127.0.0.1:0", checker, slog.Default())

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	hs.handleHealth(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d; want 503", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q; want application/json", ct)
	}
	var status HealthStatus
	if err := json.NewDecoder(res.Body).Decode(&status); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if status.Status != "degraded" {
		t.Errorf("status = %q; want degraded", status.Status)
	}
}

// The build stamp must flow through SetVersion; default stays "dev" so
// output shape is unchanged when main does not wire it.
func TestHealthServer_VersionWiring(t *testing.T) {
	checker := NewSimpleHealthChecker(func() bool { return true }, nil)

	hs := NewHealthServer("127.0.0.1:0", checker, slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	hs.handleHealth(rec, req)
	var def HealthStatus
	if err := json.NewDecoder(rec.Result().Body).Decode(&def); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if def.Version != "dev" {
		t.Fatalf("default version = %q; want dev", def.Version)
	}

	hs2 := NewHealthServer("127.0.0.1:0", checker, slog.Default())
	hs2.SetVersion("v1.2.3-test")
	rec2 := httptest.NewRecorder()
	hs2.handleHealth(rec2, httptest.NewRequest(http.MethodGet, "/health", nil))
	var stamped HealthStatus
	if err := json.NewDecoder(rec2.Result().Body).Decode(&stamped); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if stamped.Version != "v1.2.3-test" {
		t.Fatalf("version = %q; want v1.2.3-test", stamped.Version)
	}
}
