package main

import (
	"testing"

	"github.com/local-relay/proxy/internal/config"
)

func TestApplyFlagOverrides(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP:   "127.0.0.1:8080",
			SOCKS5: "127.0.0.1:9050",
		},
		Logging: config.LoggingConfig{
			Level: "info",
		},
	}

	httpAddr := "127.0.0.1:18080"
	socks5Addr := "127.0.0.1:11080"
	logLevel := "warn"
	verbose := false

	applyFlagOverrides(cfg, &httpAddr, &socks5Addr, &logLevel, &verbose)

	if cfg.Server.HTTP != "127.0.0.1:18080" {
		t.Errorf("HTTP = %q; want 127.0.0.1:18080", cfg.Server.HTTP)
	}
	if cfg.Server.SOCKS5 != "127.0.0.1:11080" {
		t.Errorf("SOCKS5 = %q; want 127.0.0.1:11080", cfg.Server.SOCKS5)
	}
	if cfg.Logging.Level != "warn" {
		t.Errorf("LogLevel = %q; want warn", cfg.Logging.Level)
	}

	// Verbose flag forces debug
	verbose = true
	applyFlagOverrides(cfg, &httpAddr, &socks5Addr, &logLevel, &verbose)
	if cfg.Logging.Level != "debug" {
		t.Errorf("LogLevel = %q; want debug when verbose is true", cfg.Logging.Level)
	}
}
