package health

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/local-relay/proxy/internal/auth"
)

// Admin handlers must require the proxy API key when auth is enabled
// (mirroring the proxy-port auth gate, which covers every non-/health path
// including the /healthz alias): topology, exit IPs, and counters must not
// leak without a credential. Without auth (nil) loopback scraping keeps
// working unchanged.
func TestHealthServer_AdminAuthGating(t *testing.T) {
	const key = "test-key-0123456789abcdef"
	checker := NewSimpleHealthChecker(func() bool { return true }, nil)

	hs := NewHealthServer("127.0.0.1:0", checker, slog.Default())
	hs.SetAuth(auth.NewAPIKeyAuth(key))

	for _, path := range []string{"/health", "/healthz", "/readyz"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		switch path {
		case "/readyz":
			hs.handleReady(rec, req)
		default:
			hs.handleHealth(rec, req)
		}
		if res := rec.Result(); res.StatusCode != http.StatusProxyAuthRequired {
			t.Errorf("%s without key: status = %d; want 407", path, res.StatusCode)
		}
		res := rec.Result()
		res.Body.Close()
	}

	// /metrics is gated too (counters leak operational detail).
	hs.SetMetricsEnabled(true)
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	hs.handleMetrics(rec, req)
	if res := rec.Result(); res.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("/metrics without key: status = %d; want 407", res.StatusCode)
	}
	rec.Result().Body.Close()

	// With the key, every handler serves normally (loopback scraping with
	// auth configured keeps working — only the credential is required).
	for _, path := range []string{"/health", "/readyz", "/metrics"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("X-Api-Key", key)
		rec := httptest.NewRecorder()
		switch path {
		case "/readyz":
			hs.handleReady(rec, req)
		case "/metrics":
			hs.handleMetrics(rec, req)
		default:
			hs.handleHealth(rec, req)
		}
		if res := rec.Result(); res.StatusCode != http.StatusOK {
			t.Errorf("%s with key: status = %d; want 200", path, res.StatusCode)
		}
		rec.Result().Body.Close()
	}
}

// Without auth configured (nil, the default) handlers stay open: existing
// loopback scraping and tests are unaffected.
func TestHealthServer_NoAuthStaysOpen(t *testing.T) {
	checker := NewSimpleHealthChecker(func() bool { return true }, nil)
	hs := NewHealthServer("127.0.0.1:0", checker, slog.Default())
	hs.SetMetricsEnabled(true)

	for _, path := range []string{"/health", "/readyz", "/metrics"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		switch path {
		case "/readyz":
			hs.handleReady(rec, req)
		case "/metrics":
			hs.handleMetrics(rec, req)
		default:
			hs.handleHealth(rec, req)
		}
		if res := rec.Result(); res.StatusCode != http.StatusOK {
			t.Errorf("%s without auth configured: status = %d; want 200 (open)", path, res.StatusCode)
		}
		rec.Result().Body.Close()
	}
}
