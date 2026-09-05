package health

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthServer_Endpoints(t *testing.T) {
	checker := NewSimpleHealthChecker(
		func() bool { return true },
		func() map[string]interface{} {
			return map[string]interface{}{
				"backend": map[string]interface{}{
					"total_slots": 3,
				},
			}
		},
	)

	hs := NewHealthServer("127.0.0.1:0", checker, slog.Default())
	hs.SetMetricsEnabled(true)

	// Test /health
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	hs.handleHealth(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("/health status = %d; want %d", res.StatusCode, http.StatusOK)
	}
	var status HealthStatus
	if err := json.NewDecoder(res.Body).Decode(&status); err != nil {
		t.Fatalf("failed to decode health response: %v", err)
	}
	if status.Status != "healthy" {
		t.Errorf("status = %q; want healthy", status.Status)
	}

	// Test /readyz
	req = httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec = httptest.NewRecorder()
	hs.handleReady(rec, req)

	res = rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("/readyz status = %d; want %d", res.StatusCode, http.StatusOK)
	}

	// Test /metrics
	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec = httptest.NewRecorder()
	hs.handleMetrics(rec, req)

	res = rec.Result()
	bodyBytes, _ := io.ReadAll(res.Body)
	body := string(bodyBytes)
	if !strings.Contains(body, "relay_healthy 1") {
		t.Errorf("metrics does not contain relay_healthy 1:\n%s", body)
	}
}

func TestHealthServer_Degraded(t *testing.T) {
	checker := NewSimpleHealthChecker(
		func() bool { return false },
		nil,
	)

	hs := NewHealthServer("127.0.0.1:0", checker, slog.Default())

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	hs.handleHealth(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("/health status = %d; want %d", res.StatusCode, http.StatusServiceUnavailable)
	}

	req = httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec = httptest.NewRecorder()
	hs.handleReady(rec, req)

	res = rec.Result()
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("/readyz status = %d; want %d", res.StatusCode, http.StatusServiceUnavailable)
	}
}
