package health

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/local-relay/proxy/internal/auth"
	"github.com/local-relay/proxy/internal/metrics"
)

type HealthServer struct {
	addr    string
	logger  *slog.Logger
	checker HealthChecker
	server  *http.Server
	// serveMetrics gates the /metrics path served on this admin mux.
	// Production combines it with the standalone Prometheus listener: main
	// passes the same cfg.Metrics.Enabled to SetMetricsEnabled and to
	// startMetricsServer, so metrics-disabled means off on both, and
	// metrics-enabled serves the metrics path in both places.
	serveMetrics bool
	// version is the build stamp shown in /health responses. It defaults to
	// "dev" (matching cmd/relay's Version default); main overrides it via
	// SetVersion so the stamp is wired through without changing the output
	// shape — only the value.
	version string
	// auth, when non-nil, gates every admin handler with the proxy API key
	// (same credential and 407 semantics as the proxy-port auth gate in
	// HTTPProxy.ServeHTTP, which applies to all non-/health paths including
	// the proxy-port /healthz alias). Nil means auth disabled: loopback
	// scraping works unchanged, and successful-start behavior is identical
	// (Bind still pre-binds the same address; only per-request auth changes,
	// and only when the operator enabled auth).
	auth *auth.APIKeyAuth
}

type HealthChecker interface {
	IsHealthy() bool
	GetStatus() map[string]interface{}
}

type HealthStatus struct {
	Status   string                 `json:"status"`
	Version  string                 `json:"version"`
	Uptime   string                 `json:"uptime"`
	Backend  map[string]interface{} `json:"backend"`
	Rotation map[string]interface{} `json:"rotation,omitempty"`
	Warnings []string               `json:"warnings,omitempty"`
}

type SimpleHealthChecker struct {
	backendHealthy func() bool
	backendInfo    func() map[string]interface{}
	startTime      time.Time
}

func NewSimpleHealthChecker(healthyFunc func() bool, infoFunc func() map[string]interface{}) *SimpleHealthChecker {
	return &SimpleHealthChecker{
		backendHealthy: healthyFunc,
		backendInfo:    infoFunc,
		startTime:      time.Now(),
	}
}

func (c *SimpleHealthChecker) IsHealthy() bool {
	return c.backendHealthy()
}

func (c *SimpleHealthChecker) GetStatus() map[string]interface{} {
	status := map[string]interface{}{
		"uptime": time.Since(c.startTime).String(),
	}

	if c.backendInfo != nil {
		status["backend"] = c.backendInfo()
	}

	return status
}

func NewHealthServer(addr string, checker HealthChecker, logger *slog.Logger) *HealthServer {
	return &HealthServer{
		addr:    addr,
		checker: checker,
		logger:  logger,
		version: "dev",
	}
}

// SetVersion overrides the version stamp reported by /health. Called from
// main with the build's Version var (default "dev").
func (hs *HealthServer) SetVersion(v string) {
	if v != "" {
		hs.version = v
	}
}

// SetMetricsEnabled controls whether the health port also serves /metrics.
// Called from main with cfg.Metrics.Enabled.
func (hs *HealthServer) SetMetricsEnabled(on bool) { hs.serveMetrics = on }

// SetAuth installs the proxy API-key gate on every admin handler (health,
// healthz, readyz, metrics). Pass nil to leave the handlers open — main
// passes nil unless auth is enabled, so loopback scraping without auth keeps
// working exactly as before. When set, unauthenticated requests get the same
// 407 Proxy Authentication Required as the proxy-port auth gate.
func (hs *HealthServer) SetAuth(a *auth.APIKeyAuth) { hs.auth = a }

// checkAuth runs the admin per-request gate. It mirrors the proxy-port auth
// precedent (HTTPProxy.ServeHTTP authenticates every non-/health path,
// including the /healthz alias): with auth enabled the admin port must not
// leak topology, exit IPs, or counters without a key. With auth disabled (nil)
// it is a no-op and behavior is unchanged.
func (hs *HealthServer) checkAuth(w http.ResponseWriter, r *http.Request) bool {
	if hs.auth == nil {
		return true
	}
	return hs.auth.Check(w, r)
}

// Start serves the admin mux on a fresh listener (legacy entry point used by
// tests). Production startup uses Bind + StartListener so a taken port fails
// fast before the ready log instead of dying in a background goroutine.
func (hs *HealthServer) Start() error {
	ln, err := hs.Bind()
	if err != nil {
		return err
	}
	return hs.StartListener(ln)
}

// Bind pre-binds the admin listener so startup can fail fast when the port
// is taken, instead of logging readiness and dying in a background goroutine.
// The returned listener is served by StartListener; nil when disabled.
func (hs *HealthServer) Bind() (net.Listener, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", hs.handleHealth)
	mux.HandleFunc("/healthz", hs.handleHealth)
	mux.HandleFunc("/readyz", hs.handleReady)
	if hs.serveMetrics {
		mux.HandleFunc("/metrics", hs.handleMetrics)
	}

	hs.server = &http.Server{
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	ln, err := net.Listen("tcp", hs.addr)
	if err != nil {
		return nil, err
	}
	hs.logger.Info("Health server listening", "addr", hs.addr)
	return ln, nil
}

// StartListener serves an admin listener previously bound by Bind.
func (hs *HealthServer) StartListener(ln net.Listener) error {
	return hs.server.Serve(ln)
}

func (hs *HealthServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Per-request admin auth (no-op unless main installed the API-key gate
	// via SetAuth when auth is enabled). Loopback scraping without auth is
	// unaffected.
	if !hs.checkAuth(w, r) {
		return
	}
	status := HealthStatus{
		Status:  "healthy",
		Version: hs.version,
	}
	if hs.version == "" {
		status.Version = "dev"
	}

	code := http.StatusOK
	if hs.checker != nil {
		if !hs.checker.IsHealthy() {
			status.Status = "degraded"
			code = http.StatusServiceUnavailable
		}
		backendInfo := hs.checker.GetStatus()
		if bi, ok := backendInfo["backend"]; ok {
			if bim, ok := bi.(map[string]interface{}); ok {
				status.Backend = bim
			}
		}
		if rot, ok := backendInfo["rotation"]; ok {
			if rotm, ok := rot.(map[string]interface{}); ok {
				status.Rotation = rotm
			}
		}
		if warn, ok := backendInfo["warnings"]; ok {
			switch wl := warn.(type) {
			case []string:
				status.Warnings = wl
			case []interface{}:
				for _, v := range wl {
					if s, ok := v.(string); ok {
						status.Warnings = append(status.Warnings, s)
					}
				}
			}
		}
		if uptime, ok := backendInfo["uptime"]; ok {
			if ut, ok := uptime.(string); ok {
				status.Uptime = ut
			}
		}
	}

	// Headers precede WriteHeader: net/http snapshots the header map at
	// WriteHeader time, so setting Content-Type after it silently drops the
	// value on the degraded path (which already wrote 503 above).
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(status)
}

func (hs *HealthServer) handleReady(w http.ResponseWriter, r *http.Request) {
	if !hs.checkAuth(w, r) {
		return
	}
	// Content-Type precedes every WriteHeader: net/http snapshots headers at
	// WriteHeader time, so setting it after would drop it on the 503 path.
	w.Header().Set("Content-Type", "application/json")
	if hs.checker != nil && !hs.checker.IsHealthy() {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"status":"not ready"}`))
		return
	}

	w.Write([]byte(`{"status":"ready"}`))
}

func (hs *HealthServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if !hs.checkAuth(w, r) {
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	fmt.Fprintf(w, "# HELP relay_healthy Whether the relay backend is healthy (1=healthy, 0=degraded)\n")
	fmt.Fprintf(w, "# TYPE relay_healthy gauge\n")

	snapshot := map[string]interface{}{}
	if hs.checker != nil {
		if hs.checker.IsHealthy() {
			fmt.Fprintf(w, "relay_healthy 1\n")
		} else {
			fmt.Fprintf(w, "relay_healthy 0\n")
		}
		// Single GetStatus snapshot reused for every section below: the
		// checker closure rebuilds backend status on each call, so calling it
		// repeatedly could report different instances/rotations per section.
		snapshot = hs.checker.GetStatus()
	} else {
		fmt.Fprintf(w, "relay_healthy 0\n")
	}

	// Per-instance gauges from backend status (multi-tor): in-flight load
	// and the observed exit IP exposed as an info-style metric.
	if b, ok := snapshot["backend"]; ok {
		if bm, ok := b.(map[string]interface{}); ok {
			// instances sit directly under snapshot["backend"] (production:
			// the checker closure returns info["backend"] = Status(), and
			// GetStatus nests that under snapshot["backend"]). A legacy
			// backend.backend level is also accepted.
			// level deeper under backend.backend (wrapped by main.go).
			// Status() builds []map[string]interface{} but a JSON
			// round-trip (or any map[string]any producer) yields
			// []interface{} — accept both.
			var insts []map[string]interface{}
			extract := func(m map[string]interface{}) []map[string]interface{} {
				if direct, ok := m["instances"].([]map[string]interface{}); ok {
					return direct
				}
				if generic, ok := m["instances"].([]interface{}); ok {
					var out []map[string]interface{}
					for _, v := range generic {
						if mm, ok := v.(map[string]interface{}); ok {
							out = append(out, mm)
						}
					}
					return out
				}
				return nil
			}
			insts = extract(bm)
			if insts == nil {
				if nested, ok := bm["backend"].(map[string]interface{}); ok {
					insts = extract(nested)
				}
			}
			for _, inst := range insts {
				id, _ := inst["id"].(int)
				if id == 0 {
					// JSON numbers decode as float64. Map values from an
					// int64 producer or a JSON round-trip land here too.
					switch n := inst["id"].(type) {
					case float64:
						id = int(n)
					case int64:
						id = int(n)
					case float32:
						id = int(n)
					case uint:
						id = int(n)
					case uint64:
						id = int(n)
					case int32:
						id = int(n)
					case json.Number:
						if v, err := n.Int64(); err == nil {
							id = int(v)
						}
					}
				}
				if flVal, flSet := coerceInt64(inst["in_flight"]); flSet {
					fmt.Fprintf(w, "lano_in_flight{instance=\"%d\"} %d\n", id, flVal)
				}
				// Scored-selection gauges from the additive Status keys
				// (multitor instances[] += dial_ewma_ms/dial_ok/dial_err/
				// quality/state/consec_fails). Missing keys skip (cold or
				// foreign backends); quality renders permille — the registry
				// is int64-only, while Status JSON carries the float.
				if ewma, ok := coerceInt64(inst["dial_ewma_ms"]); ok {
					fmt.Fprintf(w, "lano_dial_latency_ewma_ms{instance=\"%d\"} %d\n", id, ewma)
				}
				if q, ok := inst["quality"].(float64); ok {
					fmt.Fprintf(w, "lano_endpoint_quality{instance=\"%d\"} %d\n", id, int64(q*1000))
				}
				if st, ok := inst["state"].(string); ok && st != "" {
					fmt.Fprintf(w, "lano_endpoint_state{instance=\"%d\",state=\"%s\"} %d\n", id, escapeMetricLabel(st), endpointStateCode(st))
				}
				if ip, ok := inst["exit_ip"].(string); ok && ip != "" {
					fmt.Fprintf(w, "lano_exit_ip{instance=\"%d\",ip=\"%s\"} 1\n", id, escapeMetricLabel(ip))
				}
			}
		}
	}

	// Counter series recorded by the process-wide metrics registry.
	metrics.Default().Render(w)

	// Pool stats are nested: snapshot["backend"]["backend"] = pool.Status()
	if b, ok := snapshot["backend"]; ok {
		if bm, ok := b.(map[string]interface{}); ok {
			// Try direct fields first, then nested pool stats
			poolFields := []string{"total_slots", "healthy_slots", "total_requests", "nym_backoff"}
			poolLabels := []string{"relay_pool_slots_total", "relay_pool_slots_healthy", "relay_pool_requests_total", "relay_pool_nym_backoff"}
			poolHelp := []string{
				"Total circuit pool slots",
				"Healthy circuit pool slots",
				"Total requests routed through circuit pool",
				"Current NEWNYM backoff multiplier",
			}
			for i, field := range poolFields {
				if val, ok := bm[field]; ok {
					fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %v\n", poolLabels[i], poolHelp[i], poolLabels[i], poolLabels[i], val)
				}
			}
			// Check nested pool status
			if ps, ok := bm["backend"]; ok {
				if psm, ok := ps.(map[string]interface{}); ok {
					for i, field := range poolFields {
						if val, ok := psm[field]; ok {
							fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %v\n", poolLabels[i], poolHelp[i], poolLabels[i], poolLabels[i], val)
						}
					}
				}
			}
		}
	}
	if rot, ok := snapshot["rotation"]; ok {
		if rm, ok := rot.(map[string]interface{}); ok {
			if rc, ok := rm["request_count"]; ok {
				fmt.Fprintf(w, "# HELP relay_rotation_requests Request count since last rotation\n")
				fmt.Fprintf(w, "# TYPE relay_rotation_requests counter\n")
				fmt.Fprintf(w, "relay_rotation_requests %v\n", rc)
			}
		}
	}
}

// coerceInt64 converts the numeric shapes Status maps carry (int family,
// float family, json.Number) to int64. Same behavior as the inline switch it
// replaces — extracted so the scored-selection gauges share it. Missing keys
// and foreign types report ok=false (skip the series).
func coerceInt64(v interface{}) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	case float64:
		return int64(n), true
	case float32:
		return int64(n), true
	case uint:
		return int64(n), true
	case uint64:
		return int64(n), true
	case int32:
		return int64(n), true
	case json.Number:
		if val, err := n.Int64(); err == nil {
			return val, true
		}
	}
	return 0, false
}

// endpointStateCode maps a state name to its gauge code (0..4 in
// EndpointState declaration order; unknown names read -1 and still render,
// so a future state never silently drops).
func endpointStateCode(st string) int64 {
	switch st {
	case "active":
		return 0
	case "quarantined":
		return 1
	case "probation":
		return 2
	case "draining":
		return 3
	case "closed":
		return 4
	default:
		return -1
	}
}

// escapeMetricLabel escapes a label value for the Prometheus text exposition
// format: backslash, double-quote, and newline must be escaped, or a crafted
// value (e.g. an exit-IP string containing '"') breaks the series line and
// can inject a phantom label or line.
func escapeMetricLabel(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	return strings.ReplaceAll(v, "\n", `\n`)
}

func (hs *HealthServer) Stop() {
	if hs.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		hs.server.Shutdown(ctx)
	}
}
