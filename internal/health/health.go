package health

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

type HealthServer struct {
	addr    string
	logger  *slog.Logger
	checker HealthChecker
	server  *http.Server
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
	}
}

func (hs *HealthServer) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", hs.handleHealth)
	mux.HandleFunc("/healthz", hs.handleHealth)
	mux.HandleFunc("/readyz", hs.handleReady)
	mux.HandleFunc("/metrics", hs.handleMetrics)

	hs.server = &http.Server{
		Addr:         hs.addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	hs.logger.Info("Health server listening", "addr", hs.addr)

	return hs.server.ListenAndServe()
}

func (hs *HealthServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	status := HealthStatus{
		Status:  "healthy",
		Version: "dev",
	}

	if hs.checker != nil {
		if !hs.checker.IsHealthy() {
			status.Status = "degraded"
			w.WriteHeader(http.StatusServiceUnavailable)
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
			if wl, ok := warn.([]string); ok {
				status.Warnings = wl
			}
		}
		if uptime, ok := backendInfo["uptime"]; ok {
			if ut, ok := uptime.(string); ok {
				status.Uptime = ut
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (hs *HealthServer) handleReady(w http.ResponseWriter, r *http.Request) {
	if hs.checker != nil && !hs.checker.IsHealthy() {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"status":"not ready"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ready"}`))
}

func (hs *HealthServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	fmt.Fprintf(w, "# HELP relay_healthy Whether the relay backend is healthy (1=healthy, 0=degraded)\n")
	fmt.Fprintf(w, "# TYPE relay_healthy gauge\n")

	healthy := 0
	if hs.checker != nil && hs.checker.IsHealthy() {
		healthy = 1
	}
	fmt.Fprintf(w, "relay_healthy %d\n", healthy)

	if hs.checker != nil {
		info := hs.checker.GetStatus()
		// Pool stats are nested: info["backend"]["backend"] = pool.Status()
		if b, ok := info["backend"]; ok {
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
		if rot, ok := info["rotation"]; ok {
			if rm, ok := rot.(map[string]interface{}); ok {
				if rc, ok := rm["request_count"]; ok {
					fmt.Fprintf(w, "# HELP relay_rotation_requests Request count since last rotation\n")
					fmt.Fprintf(w, "# TYPE relay_rotation_requests counter\n")
					fmt.Fprintf(w, "relay_rotation_requests %v\n", rc)
				}
			}
		}
	}
}

func (hs *HealthServer) Stop() {
	if hs.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		hs.server.Shutdown(ctx)
	}
}
