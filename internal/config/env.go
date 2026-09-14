package config

import (
	"os"
	"strconv"
	"strings"
)

func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("PROXY_HTTP"); v != "" {
		cfg.Server.HTTP = v
	}
	if v := os.Getenv("PROXY_SOCKS5"); v != "" {
		cfg.Server.SOCKS5 = v
	}
	if v := os.Getenv("PROXY_BACKEND_ADDR"); v != "" {
		cfg.Backend.Address = v
	}
	if v := os.Getenv("PROXY_AUTH_KEY"); v != "" {
		cfg.Auth.APIKey = v
		cfg.Auth.Enabled = true
	}
	if v := os.Getenv("PROXY_LOG_LEVEL"); v != "" {
		cfg.Logging.Level = v
	}
	if v := os.Getenv("PROXY_HEALTH_ADDR"); v != "" {
		cfg.Health.Address = v
	}
	if v := os.Getenv("TOR_BINARY"); v != "" {
		cfg.MultiTor.Binary = v
	}
	if v := os.Getenv("TOR_LIBRARY_PATH"); v != "" {
		cfg.MultiTor.LibraryPath = v
	}
	// Pool tuning overrides (lenient-parse: unparseable values keep file/defaults).
	if v := os.Getenv("POOL_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(strings.TrimSpace(v)); err == nil {
			cfg.Pool.Enabled = b
		}
	}
	if v := os.Getenv("POOL_EWMA_ALPHA"); v != "" {
		if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
			cfg.Pool.EWMAAlpha = f
		}
	}
	if v := os.Getenv("POOL_SELECTION"); v != "" {
		cfg.Pool.Selection = strings.TrimSpace(v)
	}
	if v := os.Getenv("POOL_QUARANTINE_SECS"); v != "" {
		if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
			cfg.Pool.QuarantineSecs = n
		}
	}
}
