package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/local-relay/proxy/internal/auth"
	"github.com/local-relay/proxy/internal/backend"
	"github.com/local-relay/proxy/internal/config"
	"github.com/local-relay/proxy/internal/health"
	"github.com/local-relay/proxy/internal/metrics"
	"github.com/local-relay/proxy/internal/proxy"
	"github.com/local-relay/proxy/internal/rotate"
	"github.com/local-relay/proxy/internal/security"
)

var (
	Version   = "dev"
	Commit    = "none"
	BuildTime = "unknown"
)

// cleanupInterval is the period for DNS-cache and rate-limiter eviction
// across the security components.
const cleanupInterval = 5 * time.Minute

func main() {
	configPath := flag.String("c", "config.yaml", "Path to config file")
	flag.StringVar(configPath, "config", "config.yaml", "Path to config file (alias for -c)")
	showVersion := flag.Bool("version", false, "Print version and exit")
	verbose := flag.Bool("v", false, "Shortcut for --log-level=debug")
	httpAddr := flag.String("http", "", "Override HTTP proxy address")
	socks5Addr := flag.String("socks5", "", "Override SOCKS5 proxy address")
	logLevel := flag.String("log-level", "", "Log level: debug, info, warn, error")
	flag.Parse()

	if *showVersion {
		fmt.Printf("local-relay %s (commit=%s, built=%s, go=%s)\n",
			Version, Commit, BuildTime, runtime.Version())
		os.Exit(0)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}
	applyFlagOverrides(cfg, httpAddr, socks5Addr, logLevel, verbose)
	if err := config.Validate(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid config after CLI overrides: %v\n", err)
		os.Exit(1)
	}

	logger := setupLogger(cfg.Logging.Level, cfg.Logging.Format)
	logger.Info("Starting local-relay",
		"version", Version,
		"http", cfg.Server.HTTP,
		"socks5", cfg.Server.SOCKS5,
		"backend", cfg.Backend.Type,
		"multi_tor", cfg.MultiTor.Enabled,
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	stack := buildBackendStack(ctx, cfg, logger)
	router := buildRouter(stack, cfg, logger)
	firewall, ssrfBlocker := setupSecurity(ctx, cfg, logger)
	rotator := buildRotator(cfg, stack, logger)

	if err := verifyControlAuthAtStartup(stack, logger); err != nil {
		logger.Error("Control-port auth verification failed at startup", "error", err)
		failExit(stack, 1)
	}

	httpProxy, socks5Proxy := buildProxies(router, stack.usePool, cfg, logger,
		authMiddlewareOrNil(cfg), firewall, rotator, ssrfBlocker)

	if stack.multiTor != nil {
		stack.multiTor.OnRotate = func() {
			httpProxy.ClearIdleConns()
			logger.Info("Connection pool cleared after rotation")
		}
	}

	// Fail fast before the ready log: health Bind (real bind via the exported
	// Bind/StartListener split, with SetVersion/SetAuth/SetMetricsEnabled
	// wiring) plus probe-binds for HTTP/SOCKS5/metrics. Every failure path
	// failExits (ShutdownAll Tor daemons, then os.Exit).
	authMw := authMiddlewareOrNil(cfg)
	healthSrv, healthLn, herr := bindHealthServer(cfg, stack, rotator, logger, authMw)
	if herr != nil {
		logger.Error("Health server bind failed", "addr", cfg.Health.Address, "error", herr)
		if healthLn != nil {
			_ = healthLn.Close()
		}
		failExit(stack, 1)
	}
	if perr := preBindProxies(cfg, logger); perr != nil {
		if healthLn != nil {
			_ = healthLn.Close()
		}
		failExit(stack, 1)
	}
	if cfg.Metrics.Enabled {
		if merr := probeBind(cfg.Metrics.Address); merr != nil {
			logger.Error("Metrics server bind failed", "addr", cfg.Metrics.Address, "error", merr)
			if healthLn != nil {
				_ = healthLn.Close()
			}
			failExit(stack, 1)
		}
	}
	// HealthServer.Stop is nil-safe via the server-nil check inside Stop, and
	// the pre-bound health listener closes on shutdown. Proxy shutdown (10s
	// deadline) stays in shutdown(); admin shutdown stays 5s via Stop.
	// Metrics shutdown (5s budget) runs via the signal-ctx goroutine in
	// startMetricsServer plus an explicit stop in shutdown(); both are
	// nil-safe and idempotent.
	if healthSrv != nil {
		defer healthSrv.Stop()
	}
	defer stopMetricsServer()
	if healthLn != nil {
		defer healthLn.Close()
	}

	// Binds already succeeded so no fail-fast path remains past this point.
	startServers(ctx, stop, cfg, logger, stack, httpProxy, socks5Proxy)
	startHealthListener(healthSrv, healthLn, logger)
	startMetricsServer(ctx, cfg, stack.torLifecycle, authMw, logger)

	logger.Info("Local relay is ready")
	if !router.IsHealthy() {
		logger.Warn("degraded: no healthy proxied backend — traffic fails closed until Tor recovers")
	}

	<-ctx.Done()

	shutdown(logger, rotator, socks5Proxy, httpProxy, stack.torLifecycle)
}

// applyFlagOverrides applies CLI flags over file/env-derived config.
func applyFlagOverrides(cfg *config.Config, httpAddr, socks5Addr, logLevel *string, verbose *bool) {
	if *httpAddr != "" {
		cfg.Server.HTTP = *httpAddr
	}
	if *socks5Addr != "" {
		cfg.Server.SOCKS5 = *socks5Addr
	}
	if *logLevel != "" {
		cfg.Logging.Level = *logLevel
	}
	if *verbose {
		cfg.Logging.Level = "debug"
	}
}

// backendStack holds the selected backend topology plus shared security
// components built alongside it.
type backendStack struct {
	usePool      bool
	pool         *backend.CircuitPoolBackend
	torBackend   *backend.TorBackend
	multiTor     *backend.MultiTorBackend
	torLifecycle *backend.TorLifecycle
	ssrfBlocker  *security.SSRFBlocker
}

// buildBackendStack constructs exactly one proxy backend according to config:
// multi-tor > circuit-pool > single-tor. A failed Tor bootstrap degrades to
// direct-only routing with a warning rather than aborting startup.
func buildBackendStack(ctx context.Context, cfg *config.Config, logger *slog.Logger) *backendStack {
	s := &backendStack{}

	switch {
	case cfg.IsMultiTor():
		s.torLifecycle = backend.NewTorLifecycle(backend.TorLifecycleConfig{
			Binary:       cfg.MultiTor.Binary,
			DataDir:      cfg.MultiTor.DataDir,
			BasePort:     cfg.MultiTor.BasePort,
			ControlBase:  cfg.MultiTor.ControlBase,
			MaxInstances: cfg.MultiTor.MaxInstances,
			RotateAfter:  cfg.MultiTor.RotateAfter,
			LibraryPath:  cfg.MultiTor.LibraryPath,
			Logf: func(format string, args ...interface{}) {
				logger.Debug("[tor-lifecycle] "+format, args...)
			},
		})

		s.multiTor = backend.NewMultiTorBackend(s.torLifecycle, cfg.ConnectionTimeout(), func(format string, args ...interface{}) {
			logger.Debug("[multi-tor] "+format, args...)
		})
		applyPoolTuning(s.multiTor, cfg, logger)

		if err := s.torLifecycle.Start(ctx); err != nil {
			logger.Error("Failed to start Tor instances (traffic will fail closed until Tor is healthy)", "error", err)
		} else {
			logger.Info("Multi-Tor backend ready",
				"instances", s.torLifecycle.GetReadyCount(),
			)
			// Prime exit-IP visibility: probe each instance's exit once
			// so /health and metrics show real IPs before the first rotation.
			for _, inst := range s.torLifecycle.GetInstances() {
				go func(i *backend.TorInstance) {
					s.torLifecycle.RefreshExitIP(i, 15*time.Second)
				}(inst)
			}
		}

	case cfg.IsPool():
		s.usePool = true
		s.pool = backend.NewCircuitPoolBackend(backend.PoolConfig{
			TorAddress:        cfg.Backend.Address,
			ControlAddr:       cfg.Backend.ControlAddr,
			ControlPass:       "",
			ControlCookiePath: cfg.Backend.ControlCookie,
			CircuitCount:      cfg.CircuitCount(),
			MaxCircuitAge:     cfg.MaxCircuitAgeVal(),
			MaxFails:          3,
			MaxAnomaly:        2,
			Timeout:           cfg.ConnectionTimeout(),
			Logf: func(format string, args ...interface{}) {
				logger.Debug("[circuit-pool] "+format, args...)
			},
		})

		if !s.pool.IsHealthy() {
			logger.Warn("Circuit pool initial health check failed")
		} else {
			logger.Info("Circuit pool ready",
				"circuits", cfg.CircuitCount(),
				"max_age", cfg.MaxCircuitAgeVal(),
			)
		}

	case cfg.IsTor():
		s.torBackend = backend.NewTorBackend(backend.TorConfig{
			Address:       cfg.Backend.Address,
			ControlAddr:   cfg.Backend.ControlAddr,
			Timeout:       cfg.ConnectionTimeout(),
			MaxCircuitAge: cfg.MaxCircuitAgeVal(),
		})

		if !s.torBackend.CheckHealth() {
			logger.Warn("Tor is not running")
		}
	}

	return s
}

// applyPoolTuning converts cfg.Pool into backend ScoreParams +
// QuarantineConfig and installs them on the multi-tor backend. The
// kill-switch (pool.enabled:false) passes the zero ScoreParams, which
// SetScoreParams reads as "disable steering" — stats still record, so
// re-enabling later starts warm. buildRouter, monitorBackends, and the
// OnRotate→ClearIdleConns wiring are untouched.
func applyPoolTuning(m *backend.MultiTorBackend, cfg *config.Config, logger *slog.Logger) {
	if !cfg.Pool.Enabled {
		m.SetScoreParams(backend.ScoreParams{})
		logger.Info("pool scoring disabled (kill-switch): pure least-inflight selection")
		return
	}
	m.SetScoreParams(backend.ScoreParams{
		Alpha:      cfg.Pool.EWMAAlpha,
		LatencyRef: time.Duration(cfg.Pool.LatencyRefMs) * time.Millisecond,
		MinSamples: cfg.Pool.MinSamples,
		MinQuality: cfg.Pool.MinQuality,
	})
	m.SetQuarantineConfig(backend.QuarantineConfig{
		AfterFails:  int64(cfg.Pool.QuarantineAfterFails),
		Duration:    time.Duration(cfg.Pool.QuarantineSecs) * time.Second,
		MaxDuration: time.Duration(cfg.Pool.MaxQuarantineSecs) * time.Second,
		Probes:      int64(cfg.Pool.ProbationProbes),
	})
	logger.Info("pool scoring enabled",
		"selection", cfg.Pool.Selection,
		"ewma_alpha", cfg.Pool.EWMAAlpha,
		"quarantine_secs", cfg.Pool.QuarantineSecs,
	)
}

// buildRouter wires the direct (bypass) backend with the selected proxied backend.
func buildRouter(s *backendStack, cfg *config.Config, logger *slog.Logger) *backend.Router {
	directBackend := backend.NewDirectBackend(cfg.ConnectionTimeout())

	var router *backend.Router
	switch {
	case s.multiTor != nil:
		router = backend.NewRouter(directBackend, s.multiTor)
	case s.pool != nil:
		router = backend.NewRouter(directBackend, s.pool)
	case s.torBackend != nil:
		router = backend.NewRouter(directBackend, s.torBackend)
	default:
		router = backend.NewRouter(directBackend)
	}

	if len(cfg.Bypass.Hosts) > 0 {
		router.SetBypassHosts(cfg.Bypass.Hosts)
		logger.Info("Bypass hosts configured", "hosts", cfg.Bypass.Hosts)
	}

	return router
}

// setupSecurity constructs SSRF protection and the per-host firewall/rate limiter,
// sharing a single DNS cache and singleflight deduplicator between them.
// Custom blocked_networks are appended to the firewall's defaults (union, never
// weakened); unparseable entries fail validation at load time, and any residual
// AddBlockedRange error is logged instead of silently skipped. FailClosedDNS
// is propagated to both guards; the .onion exemption precedes it inside each
// guard and is preserved.
func setupSecurity(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*security.Firewall, *security.SSRFBlocker) {
	sharedResolver := security.NewResolver()
	sharedResolver.StartCleanup(ctx, cleanupInterval)

	var blocker *security.SSRFBlocker
	if len(cfg.Security.BlockedNetworks) > 0 {
		blocker = security.NewSSRFBlockerWithResolver(cfg.Security.BlockedNetworks, sharedResolver)
		logger.Info("SSRF protection enabled", "blocked_networks", len(cfg.Security.BlockedNetworks))
	}
	if blocker != nil {
		blocker.FailClosedDNS = cfg.Security.FailClosedDNS
	}

	fw := security.NewFirewallWithResolver(security.FirewallConfig{
		RateLimit:     cfg.Security.RateLimit,
		RateBurst:     cfg.Security.RateBurst,
		FailClosedDNS: cfg.Security.FailClosedDNS,
	}, sharedResolver)
	for _, cidr := range cfg.Security.BlockedNetworks {
		if err := fw.AddBlockedRange(cidr); err != nil {
			logger.Error("invalid blocked_networks CIDR skipped by firewall", "cidr", cidr, "error", err)
		}
	}
	if cfg.Security.FailClosedDNS {
		logger.Info("fail-closed DNS enabled: unresolvable hosts are blocked")
	}
	fw.StartCleanup(ctx, cleanupInterval)
	return fw, blocker
}

// failExit shuts down spawned Tor daemons (when any) before exiting with code.
// Nil-safe: a nil stack or nil lifecycle simply skips the shutdown. Callers
// use it only for post-spawn fail-fast exits (bind/auth failures after Tor
// daemons may be running); pre-spawn exits (flags, config load) exit directly.
func failExit(stack *backendStack, code int) {
	if stack != nil && stack.torLifecycle != nil {
		stack.torLifecycle.ShutdownAll()
	}
	os.Exit(code)
}

// verifyControlAuthAtStartup fails fast when a configured control port rejects
// our credentials: without working control auth every later NEWNYM silently
// fails, so surfacing it before serving beats discovering it on first rotation.
// It authenticates only (no SIGNAL, no state change) via the existing
// VerifyControl/VerifyControls exported APIs. Fail-fast is reserved for a
// definitive "auth rejected" reply; "not configured" (no control endpoint),
// "failed to connect" (Tor down at startup), timeouts, and transport-level
// "auth failed" (read errors under a wedged daemon) degrade fail-closed with
// a warning — matching the existing buildBackendStack behavior — and the 30s
// monitor recovers them.
// Direct-only stacks verify nothing.
func verifyControlAuthAtStartup(stack *backendStack, logger *slog.Logger) error {
	if stack == nil {
		return nil
	}
	verify := func(name string, fn func() error) error {
		if err := fn(); err != nil {
			msg := err.Error()
			switch {
			case strings.Contains(msg, "not configured"):
				// No control endpoint (unconfigured backend or zero
				// instances): a bootstrap outcome, not an auth failure —
				// startup already logged it and degrades.
				logger.Warn("Skipping control-auth verification: no control endpoint", "backend", name, "error", err)
				return nil
			case strings.Contains(msg, "auth rejected"):
				// Definitive bad credentials — the only fail-fast case.
				return err
			case strings.Contains(msg, "failed to connect"),
				strings.Contains(msg, "auth failed"),
				isTimeoutErr(err):
				// Tor down or wedged at startup: keep serving degraded
				// (fail-closed) and let the 30s monitor recover it
				// without a restart.
				logger.Warn("Control port unreachable at startup — serving degraded until Tor recovers (fail-closed)",
					"backend", name, "error", err)
				return nil
			default:
				return err
			}
		}
		logger.Info("Control-port auth verified", "backend", name)
		return nil
	}
	switch {
	case stack.multiTor != nil && stack.torLifecycle != nil:
		return verify("multi-tor", stack.torLifecycle.VerifyControls)
	case stack.pool != nil:
		return verify("circuit-pool", stack.pool.VerifyControl)
	case stack.torBackend != nil:
		return verify("single-tor", stack.torBackend.VerifyControl)
	default:
		return nil
	}
}

// isTimeoutErr reports whether err is (or wraps) a network timeout: a wedged
// control daemon that never answers must degrade, not fail fast.
func isTimeoutErr(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// probeSingleTorRecovery re-probes a degraded single-tor backend: CheckHealth
// flips the cached healthy flag when the Tor endpoint answers again. It is a
// no-op when there is no single-tor backend or it is already healthy.
func probeSingleTorRecovery(logger *slog.Logger, stack *backendStack) {
	if stack == nil || stack.torBackend == nil {
		return
	}
	if stack.torBackend.IsHealthy() {
		return
	}
	if stack.torBackend.CheckHealth() {
		logger.Info("Single-Tor backend recovered")
	}
}

// probePoolRecovery re-probes a degraded circuit pool: when Tor is reachable
// again it issues a ForceRotate which resets slots on success. On failure (or
// while Tor stays unreachable) the pool stays degraded, fail-closed. It is a
// no-op when there is no pool or it is already healthy.
func probePoolRecovery(logger *slog.Logger, stack *backendStack) {
	if stack == nil || stack.pool == nil {
		return
	}
	if stack.pool.IsHealthy() {
		return
	}
	if !stack.pool.CheckTorReachable() {
		return
	}
	if err := stack.pool.ForceRotate(); err != nil {
		if errors.Is(err, backend.ErrNymCooldown) {
			// Rotation already happened inside the cooldown window — slots
			// were reset by the in-flight NEWNYM, so this is informational
			// and the pool retries on the next tick.
			logger.Info("Circuit pool recovery skipped — inside NEWNYM cooldown, retrying next tick")
			return
		}
		logger.Warn("Circuit pool recovery rotate failed — staying degraded (fail-closed)", "error", err)
		return
	}
	logger.Info("Circuit pool recovered")
}

// probeBind checks that addr can be bound right now (fail-fast for taken
// ports) by opening and immediately closing a probe listener. It closes the
// probe before returning so the real server's Start remains the single
// Listen+Serve owner — no double-bind, no behavior change on the success path.
//
// There is an inherent probe-vs-serve TOCTOU (another process could grab the
// port between probe and Start), but that race already existed and the serving
// goroutines still cancel the process via stop() on failure; the probe only
// converts the common taken-port case into a fail-fast failExit before the
// ready log.
func probeBind(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return ln.Close()
}

// preBindProxies fail-fasts on taken proxy ports before the ready log. Each
// failure logs and returns the error — the caller then failExits (ShutdownAll
// Tor daemons, then os.Exit).
func preBindProxies(cfg *config.Config, logger *slog.Logger) error {
	if err := probeBind(cfg.Server.HTTP); err != nil {
		logger.Error("HTTP proxy bind failed", "addr", cfg.Server.HTTP, "error", err)
		return err
	}
	if err := probeBind(cfg.Server.SOCKS5); err != nil {
		logger.Error("SOCKS5 proxy bind failed", "addr", cfg.Server.SOCKS5, "error", err)
		return err
	}
	return nil
}

// authMiddlewareOrNil returns nil unless API-key auth is explicitly enabled.
func authMiddlewareOrNil(cfg *config.Config) *auth.APIKeyAuth {
	if !cfg.Auth.Enabled {
		return nil
	}
	return auth.NewAPIKeyAuth(cfg.Auth.APIKey)
}

// buildRotator wires request-count-based rotation into whichever backend is active.
// In multi-Tor mode rotation is driven purely by per-instance anomaly events
// (429/503/dead-tunnel), so no request-count Rotator is created — global churn
// would pound ALL instances on any error and defeats per-instance isolation.
func buildRotator(cfg *config.Config, s *backendStack, logger *slog.Logger) *rotate.Rotator {
	if !cfg.Rotation.Enabled {
		return nil
	}
	if s.multiTor != nil {
		logger.Info("Multi-Tor active: request-count rotator disabled (rotation is per-instance)")
		return nil
	}

	onRotate := func() {}

	switch {
	case s.pool != nil:
		onRotate = func() {
			logger.Info("Rotation triggered — rotating circuit pool")
			// ForceRotate alone: on a successful NEWNYM it resets all
			// slots via resetAll, so no pre-marking is needed.
			if err := s.pool.ForceRotate(); err != nil {
				logger.Error("Failed to force rotate circuit pool", "error", err)
			}
		}
	case s.torBackend != nil:
		onRotate = func() {
			logger.Info("Rotation triggered — requesting new Tor circuit")
			if err := s.torBackend.RequestNewCircuit(); err != nil {
				logger.Error("Failed to request new Tor circuit", "error", err)
			}
		}
	}

	return rotate.NewRotator(cfg.Rotation.Interval, onRotate, logger)
}

// buildProxies constructs both proxy front-ends sharing one router and one
// rotation/security pipeline.
func buildProxies(
	router *backend.Router,
	usePool bool,
	cfg *config.Config,
	logger *slog.Logger,
	authMiddleware *auth.APIKeyAuth,
	firewall *security.Firewall,
	rotator *rotate.Rotator,
	ssrfBlocker *security.SSRFBlocker,
) (*proxy.HTTPProxy, *proxy.SOCKS5Proxy) {

	// SOCKS5 auth: constant-time on both comma forms; cfg.Auth.APIKey is
	// validated to be >=16 chars at load time.
	var socks5Auth proxy.AuthCheck
	if cfg.Auth.Enabled && cfg.Auth.APIKey != "" {
		apiKey := cfg.Auth.APIKey
		socks5Auth = func(username, password string) bool {
			return subtle.ConstantTimeCompare([]byte(username), []byte(apiKey)) == 1 ||
				subtle.ConstantTimeCompare([]byte(password), []byte(apiKey)) == 1
		}
		logger.Info("SOCKS5 authentication enabled")
	}

	httpProxy := proxy.NewHTTPProxy(router, authMiddleware, firewall, rotator, logger, usePool, ssrfBlocker, cfg.MaxBodySizeBytes())
	socks5Proxy := proxy.NewSOCKS5Proxy(router, firewall, rotator, logger, socks5Auth, ssrfBlocker, cfg.MaxBodySizeBytes())
	return httpProxy, socks5Proxy
}

// startServerGoroutine runs a blocking server with panic containment;
// a fatal error stops the whole process via ctx cancellation.
func startServerGoroutine(name string, logger *slog.Logger, stop context.CancelFunc, serve func() error) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("Panic in "+name, "error", r)
			}
		}()
		if err := serve(); err != nil {
			logger.Error(name+" failed", "error", err)
			stop()
		}
	}()
}

// monitorBackends runs the 30s recovery/monitor loop: the existing multi-tor
// CheckHealth + full-restart dead-man's switch, plus single-tor and pool
// recovery probes. Direct-only stacks have no Tor backend and get no goroutine
// (caller guards on hasTorBackend). No Tor fallback, no fail-open: probes only
// flip cached health / reset slots, routing stays fail-closed via Router.
func monitorBackends(
	ctx context.Context,
	logger *slog.Logger,
	stack *backendStack,
) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	// allDownSince escalates to a full Tor stack restart when every
	// instance has been continuously unhealthy.
	var allDownSince time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			probeSingleTorRecovery(logger, stack)
			probePoolRecovery(logger, stack)
			if stack.torLifecycle == nil {
				continue
			}
			restarted := stack.torLifecycle.CheckHealth(ctx)
			if restarted > 0 {
				logger.Info("Restarted dead Tor instances", "count", restarted)
			}
			// Dead-man's switch: if every instance has been down for
			// >2 minutes individual heals aren't cutting it — recycle
			// the whole Tor stack once (guards/consensus preserved).
			ready := stack.torLifecycle.GetReadyCount()
			if ready == 0 {
				if allDownSince.IsZero() {
					allDownSince = time.Now()
				} else if time.Since(allDownSince) > 2*time.Minute {
					logger.Error("FATAL: all Tor instances unhealthy > 2m — full multi-Tor restart",
						"since", allDownSince)
					stack.torLifecycle.ShutdownAll()
					if err := stack.torLifecycle.Start(ctx); err != nil {
						logger.Error("multi-Tor full restart failed", "error", err)
					}
					allDownSince = time.Time{} // re-arm
				}
			} else {
				allDownSince = time.Time{}
			}
		}
	}
}

// hasTorBackend reports whether the stack owns any Tor backend needing the
// monitor goroutine. Direct-only stacks (no torBackend/pool/lifecycle) skip it.
func hasTorBackend(stack *backendStack) bool {
	return stack != nil && (stack.torBackend != nil || stack.pool != nil || stack.torLifecycle != nil)
}

// startServers launches the two proxy listeners via their existing Start
// entry points plus the backend monitor. Proxy binds that fail inside the
// serving goroutines still cancel the process via stop(); the pre-bind probes
// in main convert the common taken-port case into a fail-fast failExit before
// the ready log.
func startServers(
	ctx context.Context,
	stop context.CancelFunc,
	cfg *config.Config,
	logger *slog.Logger,
	stack *backendStack,
	httpProxy *proxy.HTTPProxy,
	socks5Proxy *proxy.SOCKS5Proxy,
) {
	startServerGoroutine("HTTP proxy", logger, stop, func() error { return httpProxy.Start(cfg.Server.HTTP) })
	startServerGoroutine("SOCKS5 proxy", logger, stop, func() error { return socks5Proxy.Start(cfg.Server.SOCKS5) })

	if hasTorBackend(stack) {
		go monitorBackends(ctx, logger, stack)
	}
}

// stackHealthy reports cached backend health for the /health IsHealthy
// probe. Single-tor uses the cached IsHealthy value — active probing is
// owned by the 30s probeSingleTorRecovery loop, so a per-scrape CheckHealth
// dial must not run here (it could flip health under load). Pool and
// multi-tor branches use their own cheap cached-status reads, unchanged.
func stackHealthy(s *backendStack) bool {
	switch {
	case s.multiTor != nil:
		return s.multiTor.IsHealthy()
	case s.pool != nil:
		return s.pool.IsHealthy()
	case s.torBackend != nil:
		return s.torBackend.IsHealthy()
	default:
		return true
	}
}

// bindHealthServer builds the admin health server with version/auth/metrics
// wiring (SetVersion/SetAuth/SetMetricsEnabled). Binding is done by the
// caller via Bind so taken ports fail fast before the ready log; when health
// is disabled it returns (nil, nil, nil).
func bindHealthServer(
	cfg *config.Config,
	s *backendStack,
	rotator *rotate.Rotator,
	logger *slog.Logger,
	authMw *auth.APIKeyAuth,
) (*health.HealthServer, net.Listener, error) {
	if !cfg.Health.Enabled {
		return nil, nil, nil
	}

	checker := health.NewSimpleHealthChecker(
		func() bool { return stackHealthy(s) },
		func() map[string]interface{} {
			info := map[string]interface{}{
				"type": cfg.Backend.Type,
			}
			switch {
			case s.multiTor != nil:
				info["backend"] = s.multiTor.Status()
			case s.pool != nil:
				info["backend"] = s.pool.Status()
			case s.torBackend != nil:
				info["backend"] = map[string]interface{}{
					"type":     "tor",
					"healthy":  s.torBackend.IsHealthy(),
					"address":  cfg.Backend.Address,
					"circuits": 1,
				}
			}
			if rotator != nil {
				info["rotation"] = map[string]interface{}{
					"request_count": rotator.GetCount(),
					"interval":      cfg.Rotation.Interval,
					"enabled":       true,
				}
			}
			info["uptime"] = time.Since(startTime).String()
			return info
		},
	)

	healthSrv := health.NewHealthServer(cfg.Health.Address, checker, logger)
	healthSrv.SetVersion(Version)
	healthSrv.SetAuth(authMw)
	healthSrv.SetMetricsEnabled(cfg.Metrics.Enabled)
	ln, err := healthSrv.Bind()
	if err != nil {
		return nil, nil, err
	}
	return healthSrv, ln, nil
}

// startHealthListener serves a pre-bound admin listener in the background with
// panic containment. Nil-safe: disabled health leaves nil server/listener.
func startHealthListener(healthSrv *health.HealthServer, healthLn net.Listener, logger *slog.Logger) {
	if healthSrv == nil || healthLn == nil {
		return
	}
	go runComponent("health server", logger, func() error { return healthSrv.StartListener(healthLn) })
}

// metricsServer owns the standalone Prometheus listener so shutdown can
// close it gracefully. Nil when metrics is disabled.
var metricsSrv *http.Server

// startMetricsServer optionally serves minimal Prometheus counters. The bind
// is pre-checked by preBindAll so a taken metrics port fails fast before the
// ready log; here a late bind race only logs (metrics must never take down
// serving traffic). Timeouts mirror the admin health server (5s read/write,
// 60s idle); shutdown is graceful via Stop with the same 5s budget.
func startMetricsServer(ctx context.Context, cfg *config.Config, torLifecycle *backend.TorLifecycle, authMw *auth.APIKeyAuth, logger *slog.Logger) {
	if !cfg.Metrics.Enabled {
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc(cfg.Metrics.Path, func(w http.ResponseWriter, r *http.Request) {
		// Same per-request gate as the admin health handlers
		// (health.go checkAuth): when auth is enabled the metrics port
		// must not expose instance counts without a key. When auth is
		// disabled (nil) the handler stays open — local-only behavior
		// unchanged.
		if authMw != nil && !authMw.Check(w, r) {
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "# LANO local-relay metrics\n")
		fmt.Fprintf(w, "lano_up 1\n")
		if torLifecycle != nil {
			fmt.Fprintf(w, "lano_tor_instances %d\n", torLifecycle.GetReadyCount())
		}
		// Both ports agree: the standalone port renders the same shared
		// registry the health-port /metrics path serves (handleMetrics).
		metrics.Default().Render(w)
	})

	metricsSrv = &http.Server{
		Addr:         cfg.Metrics.Address,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("Panic in metrics server", "error", r)
			}
		}()

		logger.Info("Prometheus metrics enabled", "path", cfg.Metrics.Path, "addr", cfg.Metrics.Address)
		if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("Metrics server failed", "error", err)
		}
	}()

	// Context-scoped graceful shutdown (5s budget, same as the admin Stop
	// path). Production wires main's signal ctx; shutdown() also stops the
	// server explicitly for non-signal exits.
	go func() {
		<-ctx.Done()
		stopMetricsServer()
	}()
}

// stopMetricsServer gracefully shuts down the standalone metrics listener.
// Nil-safe: disabled metrics leaves a nil server.
func stopMetricsServer() {
	if metricsSrv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = metricsSrv.Shutdown(ctx)
}

// runComponent runs a blocking component, containing panics so one bad
// handler cannot take down the process.
func runComponent(name string, logger *slog.Logger, serve func() error) {
	defer func() {
		if r := recover(); r != nil {
			logger.Error("Panic in "+name, "error", r)
		}
	}()
	if err := serve(); err != nil {
		logger.Error(name+" failed", "error", err)
	}
}

// shutdown drains proxies and Tor daemons in dependency order.
func shutdown(logger *slog.Logger, rotator *rotate.Rotator, socks5Proxy *proxy.SOCKS5Proxy, httpProxy *proxy.HTTPProxy, torLifecycle *backend.TorLifecycle) {
	logger.Info("Shutting down...")
	if rotator != nil {
		rotator.Wait()
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	socks5Proxy.Stop()
	if err := httpProxy.Stop(shutdownCtx); err != nil {
		logger.Error("HTTP proxy shutdown error", "error", err)
	}

	stopMetricsServer()

	if torLifecycle != nil {
		torLifecycle.ShutdownAll()
	}

	logger.Info("Local relay stopped")
}

var startTime = time.Now()

func setupLogger(level, format string) *slog.Logger {
	var logLevel slog.Level
	switch level {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: logLevel}

	var handler slog.Handler
	if format == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	return slog.New(handler)
}
