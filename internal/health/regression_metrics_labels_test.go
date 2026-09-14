package health

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Regression: per-instance /metrics gauges must label instances correctly no
// matter which numeric type the status map carries the id / in_flight in.
// Production Status() builds []map[string]interface{} with int ids, but a map
// built with int64 ids (or after a JSON round-trip: float64, json.Number)
// previously collapsed every instance onto instance="0" and, for non
// int/int64/float64 in_flight types, dropped the gauge entirely.
func TestRegression_MetricsInstanceNumericTypes(t *testing.T) {
	mkChecker := func(id, inflight interface{}) *SimpleHealthChecker {
		return NewSimpleHealthChecker(
			func() bool { return true },
			func() map[string]interface{} {
				return map[string]interface{}{
					"backend": map[string]interface{}{
						"instances": []map[string]interface{}{
							{"id": id, "in_flight": inflight, "exit_ip": "9.9.9.9"},
						},
					},
				}
			},
		)
	}
	for _, tc := range []struct {
		name     string
		id       interface{}
		inflight interface{}
	}{
		{"int", 3, 2},
		{"int64", int64(3), int64(2)},
		{"float64", float64(3), float64(2)},
		{"uint64", uint64(3), uint64(2)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hs := NewHealthServer("127.0.0.1:0", mkChecker(tc.id, tc.inflight), slog.Default())
			hs.SetMetricsEnabled(true)
			rec := httptest.NewRecorder()
			hs.handleMetrics(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
			body := rec.Body.String()
			if !strings.Contains(body, `lano_in_flight{instance="3"} 2`) {
				t.Errorf("%s id/in_flight mislabelled, want lano_in_flight{instance=\"3\"} 2, body:\n%s", tc.name, body)
			}
		})
	}
}

// Regression: the exit_ip label value must be Prometheus-escaped. An
// unescaped '"' in the value breaks the series line and injects a phantom
// label (e.g. ip="1.2.3.4",evil="x"). Exit IPs are operator-remote data, so
// the exporter must not trust them.
func TestRegression_MetricsExitIPEscaped(t *testing.T) {
	checker := NewSimpleHealthChecker(
		func() bool { return true },
		func() map[string]interface{} {
			return map[string]interface{}{
				"backend": map[string]interface{}{
					"instances": []map[string]interface{}{
						{"id": 1, "in_flight": 0, "exit_ip": "1.2.3.4\",evil=\"x"},
					},
				},
			}
		},
	)
	hs := NewHealthServer("127.0.0.1:0", checker, slog.Default())
	hs.SetMetricsEnabled(true)
	rec := httptest.NewRecorder()
	hs.handleMetrics(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	for _, line := range strings.Split(body, "\n") {
		if strings.Contains(line, "lano_exit_ip") {
			if strings.Contains(line, `",evil="`) {
				t.Errorf("exit_ip label injection: unescaped quote in %q", line)
			}
			if !strings.Contains(line, `\"`) {
				t.Errorf("exit_ip label not escaped in %q", line)
			}
		}
	}
	if !strings.Contains(body, "lano_exit_ip") {
		t.Errorf("lano_exit_ip series missing, body:\n%s", body)
	}
}

// Scored-selection gauges render from additive Status keys with the shared
// coercion: dial_ewma_ms (any numeric shape), quality permille (float),
// state code + escaped label. Missing keys skip (cold backends stay quiet);
// a label-injection payload in state is escaped, never emitted raw.
func TestRegression_MetricsScoredSelectionGauges(t *testing.T) {
	mk := func(inst map[string]interface{}) *SimpleHealthChecker {
		return NewSimpleHealthChecker(
			func() bool { return true },
			func() map[string]interface{} {
				return map[string]interface{}{
					"backend": map[string]interface{}{
						"instances": []map[string]interface{}{inst},
					},
				}
			},
		)
	}
	t.Run("gauges-render", func(t *testing.T) {
		hs := NewHealthServer("127.0.0.1:0", mk(map[string]interface{}{
			"id": 1, "in_flight": 0, "exit_ip": "",
			"dial_ewma_ms": int64(1500), "quality": 0.8,
			"state": "quarantined", "consec_fails": 3,
		}), slog.Default())
		hs.SetMetricsEnabled(true)
		rec := httptest.NewRecorder()
		hs.handleMetrics(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		body := rec.Body.String()
		for _, want := range []string{
			`lano_dial_latency_ewma_ms{instance="1"} 1500`,
			`lano_endpoint_quality{instance="1"} 800`,
			`lano_endpoint_state{instance="1",state="quarantined"} 1`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("missing %q, body:\n%s", want, body)
			}
		}
	})
	t.Run("missing-keys-skip", func(t *testing.T) {
		hs := NewHealthServer("127.0.0.1:0", mk(map[string]interface{}{
			"id": 2, "in_flight": 0,
		}), slog.Default())
		hs.SetMetricsEnabled(true)
		rec := httptest.NewRecorder()
		hs.handleMetrics(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		body := rec.Body.String()
		for _, unwanted := range []string{"lano_dial_latency_ewma_ms", "lano_endpoint_quality", "lano_endpoint_state"} {
			if strings.Contains(body, unwanted) {
				t.Errorf("cold backend emitted %q, body:\n%s", unwanted, body)
			}
		}
	})
	t.Run("state-label-escaped", func(t *testing.T) {
		hs := NewHealthServer("127.0.0.1:0", mk(map[string]interface{}{
			"id": 1, "in_flight": 0, "state": "x\",evil=\"y",
		}), slog.Default())
		hs.SetMetricsEnabled(true)
		rec := httptest.NewRecorder()
		hs.handleMetrics(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		body := rec.Body.String()
		for _, line := range strings.Split(body, "\n") {
			if strings.Contains(line, "lano_endpoint_state") && strings.Contains(line, `",evil="`) {
				t.Errorf("state label injection: unescaped quote in %q", line)
			}
		}
	})
	t.Run("nested-backend-shape", func(t *testing.T) {
		// Production shape is single-wrap: the test checker closure returns
		// info["backend"] = multiTor.Status() directly (main.go), and
		// GetStatus nests that under snapshot["backend"] — so the handler
		// sees snapshot.backend.instances with NO further nesting. This
		// subtest pins that contract: instances one level under
		// snapshot["backend"] render.
		checker := NewSimpleHealthChecker(
			func() bool { return true },
			func() map[string]interface{} {
				return map[string]interface{}{
					"instances": []map[string]interface{}{
						{"id": 1, "in_flight": 0, "dial_ewma_ms": 500, "quality": 0.5, "state": "active"},
					},
				}
			},
		)
		hs := NewHealthServer("127.0.0.1:0", checker, slog.Default())
		hs.SetMetricsEnabled(true)
		rec := httptest.NewRecorder()
		hs.handleMetrics(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		if body := rec.Body.String(); !strings.Contains(body, `lano_dial_latency_ewma_ms{instance="1"} 500`) {
			t.Errorf("production backend shape missing ewma gauge, body:\n%s", body)
		}
	})
}
