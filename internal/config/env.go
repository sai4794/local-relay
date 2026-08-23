package config

import (
	"os"
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
}
