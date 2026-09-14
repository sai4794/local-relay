package config

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

func Validate(cfg *Config) error {
	// Only "tor" has a constructed backend (buildBackendStack). socks5/http
	// types would silently fall through to direct-only egress — fail-closed
	// at validation instead of leaking traffic at runtime.
	if cfg.Backend.Type != "tor" {
		return fmt.Errorf("backend.type must be \"tor\" (only implemented backend)")
	}

	if err := validateAddress(cfg.Server.HTTP, "server.http"); err != nil {
		return err
	}
	if err := validateAddress(cfg.Server.SOCKS5, "server.socks5"); err != nil {
		return err
	}

	// Validate backend address (not needed for multi-tor mode)
	if !cfg.MultiTor.Enabled {
		if err := validateAddress(cfg.Backend.Address, "backend.address"); err != nil {
			return err
		}
		if cfg.Server.HTTP == cfg.Backend.Address {
			return fmt.Errorf("server.http and backend.address cannot be the same")
		}
		if cfg.Server.SOCKS5 == cfg.Backend.Address {
			return fmt.Errorf("server.socks5 and backend.address cannot be the same")
		}
	}

	if cfg.Server.HTTP == cfg.Server.SOCKS5 {
		return fmt.Errorf("server.http and server.socks5 cannot use the same address")
	}

	// Validate multi-tor config
	if cfg.MultiTor.Enabled {
		if cfg.MultiTor.Binary == "" {
			return fmt.Errorf("multi_tor.binary must not be empty")
		}
		if cfg.MultiTor.MaxInstances < 1 {
			return fmt.Errorf("multi_tor.max_instances must be >= 1")
		}
		if _, err := exec.LookPath(cfg.MultiTor.Binary); err != nil {
			return fmt.Errorf("multi_tor.binary not found in PATH: %w", err)
		}
	}

	// Validate circuit pool config
	if cfg.Backend.CircuitCount < 1 {
		return fmt.Errorf("backend.circuit_count must be >= 1")
	}
	if cfg.Backend.MaxCircuitAge < 1 {
		return fmt.Errorf("backend.max_circuit_age must be >= 1")
	}

	// Validate pool tuning ([pool] section): ranges only, no ports/binds.
	if cfg.Pool.EWMAAlpha <= 0 || cfg.Pool.EWMAAlpha > 1 {
		return fmt.Errorf("pool.ewma_alpha must be in (0,1]")
	}
	if cfg.Pool.LatencyRefMs < 100 || cfg.Pool.LatencyRefMs > 60000 {
		return fmt.Errorf("pool.latency_ref_ms must be in [100,60000]")
	}
	if cfg.Pool.MinSamples < 1 || cfg.Pool.MinSamples > 1000 {
		return fmt.Errorf("pool.min_samples must be in [1,1000]")
	}
	if cfg.Pool.MinQuality <= 0 || cfg.Pool.MinQuality > 1 {
		return fmt.Errorf("pool.min_quality must be in (0,1]")
	}
	if cfg.Pool.Selection != "weighted" && cfg.Pool.Selection != "po2" {
		return fmt.Errorf("pool.selection must be one of: weighted, po2")
	}
	if cfg.Pool.Po2Samples < 2 || cfg.Pool.Po2Samples > 8 {
		return fmt.Errorf("pool.po2_samples must be in [2,8]")
	}
	if cfg.Pool.QuarantineAfterFails < 1 || cfg.Pool.QuarantineAfterFails > 100 {
		return fmt.Errorf("pool.quarantine_after_fails must be in [1,100]")
	}
	if cfg.Pool.QuarantineSecs < 5 || cfg.Pool.QuarantineSecs > 3600 {
		return fmt.Errorf("pool.quarantine_secs must be in [5,3600]")
	}
	if cfg.Pool.MaxQuarantineSecs < cfg.Pool.QuarantineSecs || cfg.Pool.MaxQuarantineSecs > 3600 {
		return fmt.Errorf("pool.max_quarantine_secs must be in [pool.quarantine_secs,3600]")
	}
	if cfg.Pool.ProbationProbes < 1 || cfg.Pool.ProbationProbes > 5 {
		return fmt.Errorf("pool.probation_probes must be in [1,5]")
	}

	if cfg.Health.Enabled {
		if err := validateAddress(cfg.Health.Address, "health.address"); err != nil {
			return err
		}
	}

	if cfg.Rotation.Enabled && cfg.Rotation.Interval < 1 {
		return fmt.Errorf("rotation.interval must be >= 1")
	}

	if cfg.Auth.Enabled && len(cfg.Auth.APIKey) < 16 {
		return fmt.Errorf("auth.api_key must be at least 16 characters")
	}

	// Non-loopback listeners are reachable off-host and must require auth.
	// Loopback binds (localhost, ::1, 127.x) keep working without auth so
	// local-only 127.0.0.1 configs and existing tests are unaffected.
	if !cfg.Auth.Enabled {
		if !isLoopbackBind(cfg.Server.HTTP) || !isLoopbackBind(cfg.Server.SOCKS5) {
			return fmt.Errorf("auth.enabled must be true when server.http or server.socks5 binds a non-loopback address")
		}
		if cfg.Health.Enabled && !isLoopbackBind(cfg.Health.Address) {
			return fmt.Errorf("auth.enabled must be true when health.address binds a non-loopback address")
		}
		if cfg.Metrics.Enabled && !isLoopbackBind(cfg.Metrics.Address) {
			return fmt.Errorf("auth.enabled must be true when metrics.address binds a non-loopback address")
		}
	}

	// Rate limits: negatives are meaningless; zero falls through to "disabled"
	// (firewall) — anything else must be sane.
	if cfg.Security.RateLimit < 0 || cfg.Security.RateBurst < 0 {
		return fmt.Errorf("security.rate_limit / rate_burst must not be negative")
	}

	// Listener/backend port collisions are checked in every mode (a second
	// ListenAndServe on a taken port fails at runtime with only a log line).
	// Multi-tor instance ranges additionally must not overlap the listeners
	// or each other.
	usedPorts := make(map[int]string)
	if p := parsePort(cfg.Server.HTTP); p > 0 {
		usedPorts[p] = "server.http"
	}
	if p := parsePort(cfg.Server.SOCKS5); p > 0 {
		usedPorts[p] = "server.socks5"
	}
	if cfg.Health.Enabled {
		if p := parsePort(cfg.Health.Address); p > 0 {
			if conflict, exists := usedPorts[p]; exists {
				return fmt.Errorf("port conflict: health.address collides with %s on port %d", conflict, p)
			}
			usedPorts[p] = "health.address"
		}
	}
	if cfg.Metrics.Enabled {
		if err := validateAddress(cfg.Metrics.Address, "metrics.address"); err != nil {
			return err
		}
		// The path is passed to http.ServeMux.HandleFunc, which panics on a
		// malformed pattern (e.g. "/metrics{bad") and treats "/x/{rest...}"
		// as a subtree. Require a plain absolute path so a typo fails
		// validation with exit 1 instead of crashing or over-exposing.
		if cfg.Metrics.Path == "" || cfg.Metrics.Path[0] != '/' {
			return fmt.Errorf("metrics.path must be a non-empty absolute path")
		}
		for _, c := range cfg.Metrics.Path {
			if c == '{' || c == '}' || c == '*' {
				return fmt.Errorf("metrics.path must be a plain path without mux patterns (got %q)", cfg.Metrics.Path)
			}
		}
		if p := parsePort(cfg.Metrics.Address); p > 0 {
			if conflict, exists := usedPorts[p]; exists {
				return fmt.Errorf("port conflict: metrics.address collides with %s on port %d", conflict, p)
			}
			usedPorts[p] = "metrics.address"
		}
	}
	// Listener/backend port collisions are checked in every mode, including
	// multi-tor: a backend address squatting a listener port still fails at
	// runtime with only a log line. Still just a validation error on collision.
	if p := parsePort(cfg.Backend.Address); p > 0 {
		if conflict, exists := usedPorts[p]; exists {
			return fmt.Errorf("port conflict: backend.address collides with %s on port %d", conflict, p)
		}
	}
	if cfg.Backend.ControlAddr != "" {
		if p := parsePort(cfg.Backend.ControlAddr); p > 0 {
			if conflict, exists := usedPorts[p]; exists {
				return fmt.Errorf("port conflict: backend.control_addr collides with %s on port %d", conflict, p)
			}
		}
	}

	if cfg.MultiTor.Enabled {
		for i := 0; i < cfg.MultiTor.MaxInstances; i++ {
			socks := cfg.MultiTor.BasePort + i
			ctrl := cfg.MultiTor.ControlBase + i
			if socks < 1 || socks > 65535 || ctrl < 1 || ctrl > 65535 {
				return fmt.Errorf("multi_tor port out of range (socks=%d ctrl=%d)", socks, ctrl)
			}
			if socks == ctrl {
				return fmt.Errorf("multi_tor port conflict: instance %d socks and control port are identical (%d)", i, socks)
			}
			socksKey := fmt.Sprintf("multi_tor instance %d socks", i)
			if conflict, exists := usedPorts[socks]; exists {
				return fmt.Errorf("multi_tor port conflict: %s collides with %s on port %d", socksKey, conflict, socks)
			}
			usedPorts[socks] = socksKey

			ctrlKey := fmt.Sprintf("multi_tor instance %d control", i)
			if conflict, exists := usedPorts[ctrl]; exists {
				return fmt.Errorf("multi_tor port conflict: %s collides with %s on port %d", ctrlKey, conflict, ctrl)
			}
			usedPorts[ctrl] = ctrlKey
		}
	}

	// Negative/zero-adjacent values that would silently disable or coerce.
	if cfg.MultiTor.RotateAfter < 0 {
		return fmt.Errorf("multi_tor.rotate_after must not be negative (0 disables threshold rotation)")
	}
	if cfg.Security.MaxBodySize < 0 {
		return fmt.Errorf("security.max_body_size must not be negative")
	}

	validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLevels[cfg.Logging.Level] {
		return fmt.Errorf("logging.level must be one of: debug, info, warn, error")
	}

	validFormats := map[string]bool{"json": true, "text": true}
	if !validFormats[cfg.Logging.Format] {
		return fmt.Errorf("logging.format must be one of: json, text")
	}

	// Validate blocked networks
	for _, cidr := range cfg.Security.BlockedNetworks {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("security.blocked_networks: invalid CIDR %q: %w", cidr, err)
		}
	}

	return nil
}

// isLoopbackBind reports whether addr binds a loopback interface. The host
// from SplitHostPort is loopback when it is "localhost", "::1", or an IP in
// 127/8. The 127/8 check requires a successful ParseIP first: a bare
// strings prefix match would treat a DNS hostname like "127.0.0.1.evil.com"
// as loopback, letting it bind an off-host-resolved address with no auth
// (net.Listen resolves the name at bind time). Non-IP, non-localhost names
// are never loopback here — fail closed toward requiring auth.
func isLoopbackBind(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	if host == "localhost" || host == "::1" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
