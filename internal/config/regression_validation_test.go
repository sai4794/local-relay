package config

import "testing"

// Regression: guards the newer validation rules — negative rotate_after,
// negative max body size, short API keys, bad CIDRs, and metrics path shape.
func TestRegression_ValidationRules(t *testing.T) {
	good := func() *Config {
		c := &Config{}
		loadDefaults(c)
		c.MultiTor.Enabled = true
		c.MultiTor.Binary = "true" // present in PATH
		return c
	}

	if err := Validate(good()); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"negative rotate_after", func(c *Config) { c.MultiTor.RotateAfter = -1 }},
		{"negative max body size", func(c *Config) { c.Security.MaxBodySize = -1 }},
		{"negative rate burst", func(c *Config) { c.Security.RateBurst = -1 }},
		{"short api key", func(c *Config) { c.Auth.Enabled = true; c.Auth.APIKey = "short" }},
		{"invalid CIDR", func(c *Config) { c.Security.BlockedNetworks = []string{"not-a-cidr"} }},
		{"bad log level", func(c *Config) { c.Logging.Level = "verbose" }},
		{"bad log format", func(c *Config) { c.Logging.Format = "yaml" }},
		{"backend circuit_count zero", func(c *Config) { c.Backend.CircuitCount = 0 }},
		{"pool alpha zero", func(c *Config) { c.Pool.EWMAAlpha = 0 }},
		{"pool selection bad", func(c *Config) { c.Pool.Selection = "random" }},
		{"pool quarantine too short", func(c *Config) { c.Pool.QuarantineSecs = 2 }},
		{"pool max below base", func(c *Config) { c.Pool.MaxQuarantineSecs = c.Pool.QuarantineSecs - 1 }},
		{"pool probes zero", func(c *Config) { c.Pool.ProbationProbes = 0 }},
	}
	for _, tc := range cases {
		c := good()
		tc.mutate(c)
		if err := Validate(c); err == nil {
			t.Errorf("%s: expected validation error, got nil", tc.name)
		}
	}

	// Zero rotate_after explicitly disables threshold rotation (valid).
	c := good()
	c.MultiTor.RotateAfter = 0
	if err := Validate(c); err != nil {
		t.Errorf("rotate_after=0 rejected: %v (0 disables threshold rotation)", err)
	}

	// Metrics path must be an absolute path when metrics are enabled.
	c = good()
	c.Metrics.Enabled = true
	c.Metrics.Address = "127.0.0.1:9090"
	c.Metrics.Path = "metrics"
	if err := Validate(c); err == nil {
		t.Error("relative metrics.path: expected validation error, got nil")
	}
	c.Metrics.Path = "/metrics"
	if err := Validate(c); err != nil {
		t.Errorf("absolute metrics.path rejected: %v", err)
	}

	// Mux patterns/braces would panic (HandleFunc) or over-expose (subtree
	// match); only plain absolute paths are accepted.
	for _, bad := range []string{"/metrics{bad", "/metrics/{rest...}", "/m*"} {
		c.Metrics.Path = bad
		if err := Validate(c); err == nil {
			t.Errorf("metrics.path %q: expected validation error, got nil", bad)
		}
	}
}

// A 127.-prefixed DNS hostname is NOT loopback: net.Listen would resolve it
// off-host at bind time, so it must require auth like any other name.
func TestRegression_LoopbackCheckRejectsLookalikeHostnames(t *testing.T) {
	for _, addr := range []string{"127.0.0.1.evil.com:18080", "127.evil.com:18080"} {
		if isLoopbackBind(addr) {
			t.Errorf("isLoopbackBind(%q) = true; want false (DNS name, not 127/8)", addr)
		}
	}
	// True 127/8 literals (and localhost/::1) stay loopback.
	for _, addr := range []string{"127.0.0.1:18080", "127.1.2.3:18080", "localhost:18080", "[::1]:18080"} {
		if !isLoopbackBind(addr) {
			t.Errorf("isLoopbackBind(%q) = false; want true", addr)
		}
	}
}
