package config

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// Proves the production config uses only known fields, so switching Load to
// strict decoding (KnownFields) cannot break it.
func TestStrict_ProductionConfigHasOnlyKnownFields(t *testing.T) {
	path := filepath.Join("..", "..", "config.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	cfg := &Config{}
	if err := loadDefaults(cfg); err != nil {
		t.Fatalf("loading defaults: %v", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		t.Fatalf("config.yaml not strict-clean: %v", err)
	}
}

// Unknown keys must be rejected, not silently dropped.
func TestLoad_RejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := "server:\n  http: \"127.0.0.1:18080\"\nno_such_key: true\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("writing temp config: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected unknown-field error, got nil")
	}
}

// A second YAML document after "---" is rejected: silently loading only the
// first would leave an operator's appended override dead with no signal.
func TestLoad_RejectsSecondDocument(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := "server:\n  http: \"127.0.0.1:18081\"\n---\nserver:\n  http: \"127.0.0.1:19999\"\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("writing temp config: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected multi-document error, got nil")
	}
}

// Valid overlays keep loading with identical values under strict decoding.
func TestLoad_AcceptsKnownFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := "server:\n  http: \"127.0.0.1:18081\"\nlogging:\n  level: debug\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("writing temp config: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if cfg.Server.HTTP != "127.0.0.1:18081" {
		t.Errorf("Server.HTTP = %q; want 127.0.0.1:18081", cfg.Server.HTTP)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("Logging.Level = %q; want debug", cfg.Logging.Level)
	}
}

// Backend listener collisions must be caught in multi-tor mode too.
func TestValidate_BackendCollisionCheckedInMultiTorMode(t *testing.T) {
	c := &Config{}
	loadDefaults(c)
	c.MultiTor.Enabled = true
	c.MultiTor.Binary = "true" // present in PATH
	c.Backend.Address = c.Server.HTTP
	if err := Validate(c); err == nil {
		t.Error("expected backend.address collision error in multi-tor mode, got nil")
	}

	c = &Config{}
	loadDefaults(c)
	c.MultiTor.Enabled = true
	c.MultiTor.Binary = "true"
	c.Backend.ControlAddr = c.Server.SOCKS5
	if err := Validate(c); err == nil {
		t.Error("expected backend.control_addr collision error in multi-tor mode, got nil")
	}
}
