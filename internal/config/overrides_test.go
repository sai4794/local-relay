package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeOverrideTestConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// M-01: high-precedence CLI overrides must be applicable before validation.
// Loading defers validation; main validates once after applying flags.
func TestLoadUnvalidated_DefersValidationUntilOverrides(t *testing.T) {
	path := writeOverrideTestConfig(t, "server:\n  http: \"not-an-address\"\n")

	cfg, err := LoadUnvalidated(path)
	if err != nil {
		t.Fatalf("LoadUnvalidated rejected a config that a CLI override can repair: %v", err)
	}
	if err := Validate(cfg); err == nil {
		t.Fatal("Validate accepted an invalid listener address")
	}

	cfg.Server.HTTP = "127.0.0.1:18081"
	if err := Validate(cfg); err != nil {
		t.Fatalf("Validate rejected config after override: %v", err)
	}
}

// Load keeps validating so existing callers cannot accidentally consume an
// invalid config.
func TestLoad_StillValidates(t *testing.T) {
	path := writeOverrideTestConfig(t, "server:\n  http: \"not-an-address\"\n")
	if _, err := Load(path); err == nil {
		t.Fatal("Load accepted an invalid config, want validation error")
	}
}

// M-02: PROXY_AUTH_KEY supplies the key, PROXY_AUTH_ENABLED explicitly
// controls whether auth is enabled. Without the toggle the legacy behavior
// (key implies enabled) is preserved.
func TestEnvOverrides_AuthEnabledToggle(t *testing.T) {
	t.Setenv("PROXY_AUTH_KEY", "0123456789abcdef")

	// Explicit opt-out must win over the key-implies-enabled default.
	t.Setenv("PROXY_AUTH_ENABLED", "false")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Auth.Enabled {
		t.Error("PROXY_AUTH_ENABLED=false did not disable auth")
	}
	if cfg.Auth.APIKey != "0123456789abcdef" {
		t.Errorf("APIKey = %q, want the env value", cfg.Auth.APIKey)
	}
}

func TestEnvOverrides_KeyStillEnablesAuthByDefault(t *testing.T) {
	t.Setenv("PROXY_AUTH_KEY", "0123456789abcdef")
	t.Setenv("PROXY_AUTH_ENABLED", "")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Auth.Enabled {
		t.Error("PROXY_AUTH_KEY without a toggle must keep enabling auth (legacy behavior)")
	}
}

// M-12: unparseable POOL_* overrides must fail fast rather than silently
// falling back to defaults with no operator-visible signal.
func TestEnvOverrides_RejectUnparseablePoolValues(t *testing.T) {
	for _, tc := range []struct {
		name  string
		key   string
		value string
	}{
		{"alpha", "POOL_EWMA_ALPHA", "garbage"},
		{"quarantine-secs", "POOL_QUARANTINE_SECS", "xyz"},
		{"enabled", "POOL_ENABLED", "notabool"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(tc.key, tc.value)
			if _, err := Load(""); err == nil {
				t.Fatalf("unparseable %s=%q silently accepted", tc.key, tc.value)
			}
		})
	}
}
