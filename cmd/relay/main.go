package main

import (
	"context"
	"crypto/subtle"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/local-relay/proxy/internal/auth"
	"github.com/local-relay/proxy/internal/backend"
	"github.com/local-relay/proxy/internal/config"
	"github.com/local-relay/proxy/internal/health"
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
	firewall := setupSecurity(ctx, cfg, logger)
	rotator := buildRotator(cfg, stack, logger)

	httpProxy, socks5Proxy := buildProxies(router, stack.usePool, cfg, logger,
		authMiddlewareOrNil(cfg), firewall, rotator, stack.ssrfBlocker)

	if stack.multiTor != nil {
		stack.multiTor.OnRotate = func() {
			httpProxy.ClearIdleConns()
			logger.Info("Connection pool cleared after rotation")
		}
	}

	startServers(ctx, stop, cfg, logger, httpProxy, socks5Proxy, stack.torLifecycle)
	healthSrv := startHealthServer(cfg, stack, rotator, logger)
	if healthSrv != nil {
		defer healthSrv.Stop()
	}
	startMetricsServer(ctx, cfg, stack.torLifecycle, logger)

	logger.Info("Local relay is ready")

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

		if err := s.torLifecycle.Start(ctx); err != nil {
			logger.Error("Failed to start Tor instances", "error", err)
			logger.Warn("Continuing with direct connections only")
			s.torLifecycle = nil
		} else {
			s.multiTor = backend.NewMultiTorBackend(s.torLifecycle, cfg.ConnectionTimeout(), func(format string, args ...interface{}) {
				logger.Debug("[multi-tor] "+format, args...)
			})
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

// setupSecurity constructs SSRF protection and the per-host firewall/rate limiter.
func setupSecurity(ctx context.Context, cfg *config.Config, logger *slog.Logger) *security.Firewall {
	if len(cfg.Security.BlockedNetworks) > 0 {
		blocker := security.NewSSRFBlocker(cfg.Security.BlockedNetworks)
		blocker.StartCleanup(ctx, cleanupInterval)
		logger.Info("SSRF protection enabled", "blocked_networks", len(cfg.Security.BlockedNetworks))
	}

	fw := security.NewFirewall(security.FirewallConfig{
		RateLimit: cfg.Security.RateLimit,
		RateBurst: cfg.Security.RateBurst,
	})
	fw.StartCleanup(ctx, cleanupInterval)
	return fw
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
			s.pool.RotateRandomSlot()
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
	case s.torLifecycle != nil:
		onRotate = func() {
			instances := s.torLifecycle.GetInstances()
			if len(instances) > 0 {
				target := instances[0]
				logger.Info("Rotation triggered — rotating Tor instance", "id", target.ID)
				if err := s.torLifecycle.RequestNewCircuit(target); err != nil {
					logger.Error("Failed to rotate instance", "id", target.ID, "error", err)
				}
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

// startServers launches the two proxy listeners plus the multi-tor health monitor.
func startServers(
	ctx context.Context,
	stop context.CancelFunc,
	cfg *config.Config,
	logger *slog.Logger,
	httpProxy *proxy.HTTPProxy,
	socks5Proxy *proxy.SOCKS5Proxy,
	torLifecycle *backend.TorLifecycle,
) {
	startServerGoroutine("HTTP proxy", logger, stop, func() error { return httpProxy.Start(cfg.Server.HTTP) })
	startServerGoroutine("SOCKS5 proxy", logger, stop, func() error { return socks5Proxy.Start(cfg.Server.SOCKS5) })

	if torLifecycle != nil {
		go func() {
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
					restarted := torLifecycle.CheckHealth(ctx)
					if restarted > 0 {
						logger.Info("Restarted dead Tor instances", "count", restarted)
					}
					// Dead-man's switch: if every instance has been down for
					// >2 minutes individual heals aren't cutting it — recycle
					// the whole Tor stack once (guards/consensus preserved).
					ready := torLifecycle.GetReadyCount()
					if ready == 0 {
						if allDownSince.IsZero() {
							allDownSince = time.Now()
						} else if time.Since(allDownSince) > 2*time.Minute {
							logger.Error("FATAL: all Tor instances unhealthy > 2m — full multi-Tor restart",
								"since", allDownSince)
							torLifecycle.ShutdownAll()
							if err := torLifecycle.Start(ctx); err != nil {
								logger.Error("multi-Tor full restart failed", "error", err)
							}
							allDownSince = time.Time{} // re-arm
						}
					} else {
						allDownSince = time.Time{}
					}
				}
			}
		}()
	}
}

// startHealthServer exposes /health, /readyz and Prometheus-style metrics on
// a dedicated admin port. Returns nil when disabled; otherwise the caller
// owns stopping the returned server.
func startHealthServer(cfg *config.Config, s *backendStack, rotator *rotate.Rotator, logger *slog.Logger) *health.HealthServer {
	if !cfg.Health.Enabled {
		return nil
	}

	checker := health.NewSimpleHealthChecker(
		func() bool {
			switch {
			case s.multiTor != nil:
				return s.multiTor.IsHealthy()
			case s.pool != nil:
				return s.pool.IsHealthy()
			case s.torBackend != nil:
				return s.torBackend.CheckHealth()
			default:
				return true
			}
		},
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
	healthSrv.SetMetricsEnabled(cfg.Metrics.Enabled)
	go runComponent("health server", logger, healthSrv.Start)
	return healthSrv
}

// startMetricsServer optionally serves minimal Prometheus counters.
func startMetricsServer(_ context.Context, cfg *config.Config, torLifecycle *backend.TorLifecycle, logger *slog.Logger) {
	if !cfg.Metrics.Enabled {
		return
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("Panic in metrics server", "error", r)
			}
		}()
		mux := http.NewServeMux()
		mux.HandleFunc(cfg.Metrics.Path, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "# LANO local-relay metrics\n")
			fmt.Fprintf(w, "lano_up 1\n")
			if torLifecycle != nil {
				fmt.Fprintf(w, "lano_tor_instances %d\n", torLifecycle.GetReadyCount())
			}
		})

		logger.Info("Prometheus metrics enabled", "path", cfg.Metrics.Path, "addr", cfg.Metrics.Address)
		if err := http.ListenAndServe(cfg.Metrics.Address, mux); err != nil {
			logger.Error("Metrics server failed", "error", err)
		}
	}()
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
