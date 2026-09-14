package config

import (
	"os"
	"path/filepath"
	"testing"
)

// Defaults carry the production pool tuning: enabled weighted selection with
// the Slice 1 constants and the Slice 5 quarantine windows.
func TestPool_Defaults(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load defaults: %v", err)
	}
	p := cfg.Pool
	if !p.Enabled {
		t.Error("pool.enabled default = false, want true")
	}
	if p.EWMAAlpha != 0.2 {
		t.Errorf("pool.ewma_alpha default = %v, want 0.2", p.EWMAAlpha)
	}
	if p.LatencyRefMs != 2000 {
		t.Errorf("pool.latency_ref_ms default = %d, want 2000", p.LatencyRefMs)
	}
	if p.MinSamples != 5 {
		t.Errorf("pool.min_samples default = %d, want 5", p.MinSamples)
	}
	if p.MinQuality != 0.1 {
		t.Errorf("pool.min_quality default = %v, want 0.1", p.MinQuality)
	}
	if p.Selection != "weighted" {
		t.Errorf("pool.selection default = %q, want weighted", p.Selection)
	}
	if p.Po2Samples != 2 {
		t.Errorf("pool.po2_samples default = %d, want 2", p.Po2Samples)
	}
	if p.QuarantineAfterFails != 3 {
		t.Errorf("pool.quarantine_after_fails default = %d, want 3", p.QuarantineAfterFails)
	}
	if p.QuarantineSecs != 60 {
		t.Errorf("pool.quarantine_secs default = %d, want 60", p.QuarantineSecs)
	}
	if p.MaxQuarantineSecs != 300 {
		t.Errorf("pool.max_quarantine_secs default = %d, want 300", p.MaxQuarantineSecs)
	}
	if p.ProbationProbes != 1 {
		t.Errorf("pool.probation_probes default = %d, want 1", p.ProbationProbes)
	}
}

func writePoolConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// Each invalid pool field is rejected with a pool.* error.
func TestPool_RejectsBadValues(t *testing.T) {
	base := "server:\n  http: \"127.0.0.1:18081\"\npool:\n"
	for _, tc := range []struct {
		name  string
		field string
	}{
		{"alpha-zero", "  ewma_alpha: 0\n"},
		{"alpha-over", "  ewma_alpha: 1.5\n"},
		{"ref-low", "  latency_ref_ms: 50\n"},
		{"ref-high", "  latency_ref_ms: 99999\n"},
		{"samples-zero", "  min_samples: 0\n"},
		{"minq-zero", "  min_quality: 0\n"},
		{"selection-bad", "  selection: \"random\"\n"},
		{"po2-low", "  po2_samples: 1\n"},
		{"fails-zero", "  quarantine_after_fails: 0\n"},
		{"quar-low", "  quarantine_secs: 2\n"},
		{"max-below-base", "  quarantine_secs: 60\n  max_quarantine_secs: 30\n"},
		{"probes-zero", "  probation_probes: 0\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Load(writePoolConfig(t, base+tc.field)); err == nil {
				t.Fatalf("pool %s accepted, want rejection", tc.name)
			}
		})
	}
}

// Unknown pool keys stay rejected under strict decoding.
func TestPool_RejectsUnknownField(t *testing.T) {
	path := writePoolConfig(t, "server:\n  http: \"127.0.0.1:18081\"\npool:\n  no_such_key: 1\n")
	if _, err := Load(path); err == nil {
		t.Fatal("unknown pool field accepted, want rejection")
	}
}

// Env overrides apply leniently: parseable values win, garbage keeps file/defaults.
func TestPool_EnvOverrides(t *testing.T) {
	path := writePoolConfig(t, "server:\n  http: \"127.0.0.1:18081\"\n")
	t.Setenv("POOL_ENABLED", "false")
	t.Setenv("POOL_EWMA_ALPHA", "0.5")
	t.Setenv("POOL_SELECTION", "po2")
	t.Setenv("POOL_QUARANTINE_SECS", "120")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Pool.Enabled {
		t.Error("POOL_ENABLED=false not applied")
	}
	if cfg.Pool.EWMAAlpha != 0.5 {
		t.Errorf("POOL_EWMA_ALPHA not applied, got %v", cfg.Pool.EWMAAlpha)
	}
	if cfg.Pool.Selection != "po2" {
		t.Errorf("POOL_SELECTION not applied, got %q", cfg.Pool.Selection)
	}
	if cfg.Pool.QuarantineSecs != 120 {
		t.Errorf("POOL_QUARANTINE_SECS not applied, got %d", cfg.Pool.QuarantineSecs)
	}

	t.Setenv("POOL_EWMA_ALPHA", "garbage")
	t.Setenv("POOL_QUARANTINE_SECS", "garbage")
	cfg2, err := Load(path)
	if err != nil {
		t.Fatalf("Load with garbage env: %v", err)
	}
	if cfg2.Pool.EWMAAlpha != 0.2 {
		t.Errorf("garbage POOL_EWMA_ALPHA overrode default: %v", cfg2.Pool.EWMAAlpha)
	}
	if cfg2.Pool.QuarantineSecs != 60 {
		t.Errorf("garbage POOL_QUARANTINE_SECS overrode default: %d", cfg2.Pool.QuarantineSecs)
	}
}
