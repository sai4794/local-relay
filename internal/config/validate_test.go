package config

import "testing"

// Covers the new validation rules added in the 2026-08-31 audit pass.
func TestValidate_RejectsBadMultiTorPorts(t *testing.T) {
	c := &Config{}
	loadDefaults(c)
	c.MultiTor.Enabled = true
	c.MultiTor.Binary = "true" // present in PATH
	c.Auth.APIKey = "0123456789abcdef"
	c.Auth.Enabled = true

	c.MultiTor.BasePort = -1
	if err := Validate(c); err == nil {
		t.Error("expected port-range error")
	}

	loadDefaults(c)
	c.MultiTor.Enabled = true
	c.MultiTor.Binary = "true"
	c.MultiTor.BasePort = 9150
	c.Security.RateLimit = -5
	if err := Validate(c); err == nil {
		t.Error("expected negative rate-limit error")
	}
}

func TestValidate_AcceptsGoodConfig(t *testing.T) {
	c := &Config{}
	loadDefaults(c)
	c.MultiTor.Enabled = true
	c.MultiTor.Binary = "true"
	if err := Validate(c); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
}
