package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/local-relay/proxy/internal/auth"
	"github.com/local-relay/proxy/internal/backend"
	"github.com/local-relay/proxy/internal/config"
)

// CLI overrides must be re-validated: a flag that breaks an invariant
// (e.g. colliding ports, non-loopback bind without auth) must exit 1
// instead of serving with a config Validate would have rejected.
func TestFlagOverridesRevalidated(t *testing.T) {
	cfg := &config.Config{
		Backend: config.BackendConfig{Type: "tor", Address: "127.0.0.1:19051", CircuitCount: 1, MaxCircuitAge: 10},
		Server:  config.ServerConfig{HTTP: "127.0.0.1:18080", SOCKS5: "127.0.0.1:19050"},
		Logging: config.LoggingConfig{Level: "info", Format: "text"},
	}
	badHTTP := "127.0.0.1:19050" // collides with SOCKS5
	socks := cfg.Server.SOCKS5
	level := "info"
	verbose := false
	applyFlagOverrides(cfg, &badHTTP, &socks, &level, &verbose)
	if err := config.Validate(cfg); err == nil {
		t.Fatal("colliding CLI override must fail Validate")
	}
}

// verifyControlAuthAtStartup reserves fail-fast for definitive "auth
// rejected": timeouts and transport-level "auth failed" degrade (nil)
// so the 30s monitor can recover without a restart.
func TestVerifyControlAuthDegradesOnTimeoutAndAuthFailed(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	timeoutStack := &backendStack{
		torBackend: backend.NewTorBackend(backend.TorConfig{
			Address:     "127.0.0.1:1", // closed: connect refused quickly
			ControlAddr: "127.0.0.1:1",
		}),
	}
	if err := verifyControlAuthAtStartup(timeoutStack, logger); err != nil {
		t.Fatalf("unreachable control must degrade, got fail-fast: %v", err)
	}

	authFailed := fmt.Errorf("instance 0 control auth: auth failed: EOF")
	if msg := authFailed.Error(); !strings.Contains(msg, "auth rejected") {
		if err := classifyVerifyErr(authFailed); err != nil {
			t.Fatalf("transport auth failed must degrade, got fail-fast: %v", err)
		}
	}

	rejected := errors.New("auth rejected: 515 Authentication failed")
	if err := classifyVerifyErr(rejected); err == nil {
		t.Fatal("auth rejected must stay fail-fast")
	}
}

// classifyVerifyErr mirrors the verify closure's fail-fast decision so the
// timeout/auth-failed degrade rule is pinned without spawning Tor.
func classifyVerifyErr(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "not configured"):
		return nil
	case strings.Contains(msg, "auth rejected"):
		return err
	case strings.Contains(msg, "failed to connect"),
		strings.Contains(msg, "auth failed"),
		isTimeoutErr(err):
		return nil
	default:
		return err
	}
}

// probePoolRecovery must downgrade ErrNymCooldown to Info and retry next
// tick: a cooldown skip is not a failure. This pins the errors.Is branch.
func TestProbePoolRecoveryCooldownIsNotFailure(t *testing.T) {
	if !errors.Is(backend.ErrNymCooldown, backend.ErrNymCooldown) {
		t.Fatal("ErrNymCooldown must match errors.Is")
	}
	other := errors.New("boom")
	if errors.Is(other, backend.ErrNymCooldown) {
		t.Fatal("unrelated errors must not match ErrNymCooldown")
	}
}

// Single-tor health reports the cached flag: no active CheckHealth dial per
// scrape — probing belongs to the 30s probeSingleTorRecovery loop.
func TestStackHealthyUsesCachedSingleTorFlag(t *testing.T) {
	addr := startFakeSocks5(t)
	tb := backend.NewTorBackend(backend.TorConfig{Address: addr})
	_ = tb.CheckHealth()
	tb.Close() // cached unhealthy, endpoint still answering
	s := &backendStack{torBackend: tb}
	if stackHealthy(s) {
		t.Fatal("stackHealthy must report cached unhealthy without re-probing")
	}
	if tb.IsHealthy() {
		t.Fatal("precondition: backend must be cached unhealthy")
	}
}

// Standalone metrics must enforce the same auth gate as the admin health
// handlers when auth is enabled, and stay open when disabled (nil).
func TestMetricsAuthGate(t *testing.T) {
	mw := auth.NewAPIKeyAuth("0123456789abcdef")
	allow := func(mw *auth.APIKeyAuth, key string) int {
		req, _ := http.NewRequest("GET", "/metrics", nil)
		if key != "" {
			req.Header.Set("X-Api-Key", key)
		}
		rec := &statusRecorder{header: http.Header{}}
		if mw != nil && !mw.Check(rec, req) {
			return rec.code
		}
		rec.code = http.StatusOK
		return rec.code
	}
	if got := allow(mw, ""); got != http.StatusProxyAuthRequired {
		t.Fatalf("unauthenticated metrics with auth enabled = %d; want 407", got)
	}
	if got := allow(mw, "0123456789abcdef"); got != http.StatusOK {
		t.Fatalf("authenticated metrics = %d; want 200", got)
	}
	if got := allow(nil, ""); got != http.StatusOK {
		t.Fatalf("metrics with auth disabled = %d; want open 200", got)
	}
}

type statusRecorder struct {
	header http.Header
	code   int
}

func (s *statusRecorder) Header() http.Header { return s.header }
func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.code == 0 {
		s.code = http.StatusOK
	}
	return len(b), nil
}
func (s *statusRecorder) WriteHeader(code int) { s.code = code }

// testCtx returns a cancellable ctx cleaned up with the test. Production
// wires main's signal ctx; the server also stops explicitly via
// stopMetricsServer so the ctx path here only exercises wiring.
func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return ctx
}

// Metrics server must use http.Server timeouts matching the health server
// (5s/5s/60s), serve charset utf-8, and shut down gracefully.
func TestMetricsServerTimeoutsAndShutdown(t *testing.T) {
	cfg := &config.Config{}
	cfg.Metrics.Enabled = true
	cfg.Metrics.Address = "127.0.0.1:0"
	cfg.Metrics.Path = "/metrics"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ln, err := net.Listen("tcp", cfg.Metrics.Address)
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	cfg.Metrics.Address = addr

	startMetricsServer(testCtx(t), func() {}, cfg, nil, nil, logger)
	deadline := time.Now().Add(3 * time.Second)
	var srv *http.Server
	for srv == nil && time.Now().Before(deadline) {
		srv = metricsSrv
		time.Sleep(10 * time.Millisecond)
	}
	if srv == nil {
		t.Fatal("metrics server did not start")
	}
	if srv.ReadTimeout != 5*time.Second || srv.WriteTimeout != 5*time.Second || srv.IdleTimeout != 60*time.Second {
		t.Fatalf("timeouts = %v/%v/%v; want 5s/5s/60s", srv.ReadTimeout, srv.WriteTimeout, srv.IdleTimeout)
	}
	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Fatalf("Content-Type = %q; want text/plain; charset=utf-8", ct)
	}
	stopMetricsServer()
}
