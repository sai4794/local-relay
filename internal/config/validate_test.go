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

func TestValidate_RejectsPortCollisions(t *testing.T) {
	// SOCKS and Control port overlap within multi_tor instances
	c := &Config{}
	loadDefaults(c)
	c.MultiTor.Enabled = true
	c.MultiTor.Binary = "true"
	c.MultiTor.BasePort = 9050
	c.MultiTor.ControlBase = 9051
	c.MultiTor.MaxInstances = 3 // 9050, 9051, 9052 vs 9051, 9052, 9053
	if err := Validate(c); err == nil {
		t.Error("expected port collision error between socks and control")
	}

	// SOCKS port collides with server.http
	c = &Config{}
	loadDefaults(c)
	c.MultiTor.Enabled = true
	c.MultiTor.Binary = "true"
	c.Server.HTTP = "127.0.0.1:9050"
	c.MultiTor.BasePort = 9050
	if err := Validate(c); err == nil {
		t.Error("expected port collision error between multi_tor and server.http")
	}
}

