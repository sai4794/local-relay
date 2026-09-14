package config

import "testing"

// Regression: the non-loopback-requires-auth rule covers health.address and
// metrics.address too; loopback defaults are unaffected.
func TestRegression_NonLoopbackHealthMetricsRequireAuth(t *testing.T) {
	good := func() *Config {
		c := &Config{}
		loadDefaults(c)
		c.MultiTor.Enabled = true
		c.MultiTor.Binary = "true" // present in PATH
		return c
	}

	// Loopback defaults pass without auth.
	if err := Validate(good()); err != nil {
		t.Fatalf("loopback defaults rejected without auth: %v", err)
	}

	// Non-loopback health address requires auth.
	c := good()
	c.Health.Address = "0.0.0.0:18888"
	if err := Validate(c); err == nil {
		t.Error("non-loopback health.address without auth: expected error, got nil")
	}
	c.Auth.Enabled = true
	c.Auth.APIKey = "0123456789abcdef"
	if err := Validate(c); err != nil {
		t.Errorf("non-loopback health.address with auth rejected: %v", err)
	}

	// Non-loopback metrics address requires auth.
	c = good()
	c.Metrics.Enabled = true
	c.Metrics.Address = "0.0.0.0:9090"
	if err := Validate(c); err == nil {
		t.Error("non-loopback metrics.address without auth: expected error, got nil")
	}
	c.Auth.Enabled = true
	c.Auth.APIKey = "0123456789abcdef"
	if err := Validate(c); err != nil {
		t.Errorf("non-loopback metrics.address with auth rejected: %v", err)
	}

	// Loopback health/metrics stay valid without auth.
	c = good()
	c.Metrics.Enabled = true
	c.Metrics.Address = "127.0.0.1:9090"
	if err := Validate(c); err != nil {
		t.Errorf("loopback health/metrics without auth rejected: %v", err)
	}
}
