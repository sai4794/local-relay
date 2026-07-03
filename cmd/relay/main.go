package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
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

	// Backend setup
	var pool *backend.CircuitPoolBackend
	var torBackend *backend.TorBackend
	var multiTor *backend.MultiTorBackend
	var torLifecycle *backend.TorLifecycle
	usePool := false

	if cfg.IsMultiTor() {
		// Multi-Tor mode: spawn N Tor daemons
		torLifecycle = backend.NewTorLifecycle(backend.TorLifecycleConfig{
			Binary:       cfg.MultiTor.Binary,
			DataDir:      cfg.MultiTor.DataDir,
			BasePort:     cfg.MultiTor.BasePort,
			ControlBase:  cfg.MultiTor.ControlBase,
			MaxInstances: cfg.MultiTor.MaxInstances,
			RotateAfter:  cfg.MultiTor.RotateAfter,
			Logf: func(format string, args ...interface{}) {
				logger.Debug("[tor-lifecycle] "+format, args...)
			},
		})

		if err := torLifecycle.Start(ctx); err != nil {
			logger.Error("Failed to start Tor instances", "error", err)
			logger.Warn("Continuing with direct connections only")
			torLifecycle = nil
		} else {
			multiTor = backend.NewMultiTorBackend(torLifecycle, cfg.ConnectionTimeout(), func(format string, args ...interface{}) {
				logger.Debug("[multi-tor] "+format, args...)
			})
			logger.Info("Multi-Tor backend ready",
				"instances", torLifecycle.GetReadyCount(),
			)
		}
	} else if cfg.IsPool() {
		usePool = true
		pool = backend.NewCircuitPoolBackend(backend.PoolConfig{
			TorAddress:        cfg.Backend.Address,
			ControlAddr:       "127.0.0.1:9051",
			ControlPass:       "",
			ControlCookiePath: "/home/stb/tor/data/control_auth_cookie",
			CircuitCount:      cfg.CircuitCount(),
			MaxCircuitAge:     cfg.MaxCircuitAgeVal(),
			MaxFails:          3,
			MaxAnomaly:        2,
			Timeout:           cfg.ConnectionTimeout(),
			Logf: func(format string, args ...interface{}) {
				logger.Debug("[circuit-pool] "+format, args...)
			},
		})

		if !pool.IsHealthy() {
			logger.Warn("Circuit pool initial health check failed")
		} else {
			logger.Info("Circuit pool ready",
				"circuits", cfg.CircuitCount(),
				"max_age", cfg.MaxCircuitAgeVal(),
			)
		}
	} else if cfg.IsTor() {
		torBackend = backend.NewTorBackend(backend.TorConfig{
			Address:       cfg.Backend.Address,
			ControlAddr:   "127.0.0.1:9051",
			Timeout:       cfg.ConnectionTimeout(),
			MaxCircuitAge: cfg.MaxCircuitAgeVal(),
		})

		if !torBackend.CheckHealth() {
			logger.Warn("Tor is not running")
		}
	}

	// Router setup
	directBackend := backend.NewDirectBackend(cfg.ConnectionTimeout())

	var router *backend.Router
	if multiTor != nil {
		router = backend.NewRouter(directBackend, multiTor)
	} else if pool != nil {
		router = backend.NewRouter(directBackend, pool)
	} else if torBackend != nil {
		router = backend.NewRouter(directBackend, torBackend)
	} else {
		router = backend.NewRouter(directBackend)
	}

	if len(cfg.Bypass.Hosts) > 0 {
		router.SetBypassHosts(cfg.Bypass.Hosts)
		logger.Info("Bypass hosts configured", "hosts", cfg.Bypass.Hosts)
	}

	// SSRF protection
	var ssrfBlocker *security.SSRFBlocker
	if len(cfg.Security.BlockedNetworks) > 0 {
		ssrfBlocker = security.NewSSRFBlocker(cfg.Security.BlockedNetworks)
		logger.Info("SSRF protection enabled", "blocked_networks", len(cfg.Security.BlockedNetworks))
	}

	// Auth
	var authMiddleware *auth.APIKeyAuth
	if cfg.Auth.Enabled {
		authMiddleware = auth.NewAPIKeyAuth(cfg.Auth.APIKey)
		logger.Info("API key authentication enabled")
	}

	firewall := security.NewFirewall(security.FirewallConfig{
		RateLimit: 50,
		RateBurst: 100,
	})
	firewall.StartCleanup(ctx, 5*time.Minute)
	defer firewall.StopCleanup()

	// Rotator
	var rotator *rotate.Rotator
	if cfg.Rotation.Enabled {
		rotator = rotate.NewRotator(cfg.Rotation.Interval, func() {
			if pool != nil {
				logger.Info("Rotation triggered — rotating circuit pool")
				pool.RotateRandomSlot()
				if err := pool.ForceRotate(); err != nil {
					logger.Error("Failed to force rotate circuit pool", "error", err)
				}
			} else if torBackend != nil {
				logger.Info("Rotation triggered — requesting new Tor circuit")
				if err := torBackend.RequestNewCircuit(); err != nil {
					logger.Error("Failed to request new Tor circuit", "error", err)
				}
			} else if torLifecycle != nil {
				logger.Info("Rotation triggered — rotating Tor instances")
				for _, inst := range torLifecycle.GetInstances() {
					if err := torLifecycle.RequestNewCircuit(inst); err != nil {
						logger.Error("Failed to rotate instance", "id", inst.ID, "error", err)
					}
				}
			}
		}, logger)
	}

	// SOCKS5 auth
	var socks5Auth proxy.AuthCheck
	if cfg.Auth.Enabled && cfg.Auth.APIKey != "" {
		apiKey := cfg.Auth.APIKey
		socks5Auth = func(username, password string) bool {
			return username == apiKey || password == apiKey
		}
		logger.Info("SOCKS5 authentication enabled")
	}

	// Body size limit
	bodyLimit := cfg.MaxBodySizeBytes()

	httpProxy := proxy.NewHTTPProxy(router, authMiddleware, firewall, rotator, logger, usePool, ssrfBlocker, bodyLimit)
	socks5Proxy := proxy.NewSOCKS5Proxy(router, firewall, rotator, logger, socks5Auth, ssrfBlocker, bodyLimit)

	// Wire connection pool clearing after rotation (for instant IP change)
	if multiTor != nil {
		multiTor.OnRotate = func() {
			httpProxy.ClearIdleConns()
			logger.Info("Connection pool cleared after rotation")
		}
	}

	go func() {
		if err := httpProxy.Start(cfg.Server.HTTP); err != nil {
			logger.Error("HTTP proxy failed", "error", err)
			stop()
		}
	}()

	go func() {
		if err := socks5Proxy.Start(cfg.Server.SOCKS5); err != nil {
			logger.Error("SOCKS5 proxy failed", "error", err)
			stop()
		}
	}()

	// Tor health monitor (for multi-tor mode)
	if torLifecycle != nil {
		go func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					restarted := torLifecycle.CheckHealth(ctx)
					if restarted > 0 {
						logger.Info("Restarted dead Tor instances", "count", restarted)
					}
				}
			}
		}()
	}

	// Health endpoint
	if cfg.Health.Enabled {
		checker := health.NewSimpleHealthChecker(
			func() bool {
				if multiTor != nil {
					return multiTor.IsHealthy()
				}
				if pool != nil {
					return pool.IsHealthy()
				}
				if torBackend != nil {
					return torBackend.CheckHealth()
				}
				return true
			},
			func() map[string]interface{} {
				info := map[string]interface{}{
					"type": cfg.Backend.Type,
				}
				if multiTor != nil {
					info["backend"] = multiTor.Status()
				} else if pool != nil {
					info["backend"] = pool.Status()
				} else if torBackend != nil {
					info["backend"] = map[string]interface{}{
						"type":     "tor",
						"healthy":  torBackend.IsHealthy(),
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
		go func() {
			if err := healthSrv.Start(); err != nil {
				logger.Error("Health server failed", "error", err)
			}
		}()
		defer healthSrv.Stop()
	}

	// Prometheus metrics
	if cfg.Metrics.Enabled {
		go func() {
			mux := http.NewServeMux()
			mux.HandleFunc(cfg.Metrics.Path, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprintf(w, "# LANO local-relay metrics\n")
				fmt.Fprintf(w, "lano_up 1\n")
				if multiTor != nil {
					fmt.Fprintf(w, "lano_tor_instances %d\n", torLifecycle.GetReadyCount())
				}
			})
			metricsAddr := net.JoinHostPort("127.0.0.1", "9090")
			logger.Info("Prometheus metrics enabled", "path", cfg.Metrics.Path, "addr", metricsAddr)
			if err := http.ListenAndServe(metricsAddr, mux); err != nil {
				logger.Error("Metrics server failed", "error", err)
			}
		}()
	}

	logger.Info("Local relay is ready")

	<-ctx.Done()

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

	// Shutdown Tor instances
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

	opts := &slog.HandlerOptions{
		Level: logLevel,
	}

	var handler slog.Handler
	if format == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	return slog.New(handler)
}
