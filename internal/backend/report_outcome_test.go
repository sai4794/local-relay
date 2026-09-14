package backend

import (
	"testing"
	"time"
)

// TestReportOutcome_AttributesToServingInstance drives ReportOutcome through
// the real MultiTorBackend against injected instances: success feeds ok+EWMA,
// failure feeds err only, gen-stale drops, unknown IDs drop without panic.
func TestReportOutcome_AttributesToServingInstance(t *testing.T) {
	lc := NewTorLifecycle(TorLifecycleConfig{
		Binary: "true", DataDir: t.TempDir(),
		BasePort: 0, ControlBase: 0, MaxInstances: 2, Logf: func(string, ...interface{}) {},
	})
	lc.instances = append(lc.instances,
		&TorInstance{ID: 1, Ready: true, StartedAt: time.Now()},
		&TorInstance{ID: 2, Ready: true, StartedAt: time.Now()},
	)
	m := NewMultiTorBackend(lc, time.Second, func(string, ...interface{}) {})

	gen1 := lc.instances[0].CircuitGen()
	m.ReportOutcome(Outcome{ID: 1, Gen: gen1, Success: true, Latency: 500 * time.Millisecond, Status: 200})
	if got := lc.instances[0].DialSuccesses(); got != 1 {
		t.Fatalf("inst1 successes = %d, want 1", got)
	}
	if got := lc.instances[0].DialLatencyEWMA(); got != 500*time.Millisecond {
		t.Fatalf("inst1 EWMA = %v, want 500ms", got)
	}
	if got := lc.instances[1].DialSuccesses(); got != 0 {
		t.Fatalf("inst2 successes = %d, want 0 (no cross-talk)", got)
	}

	m.ReportOutcome(Outcome{ID: 1, Gen: gen1, Success: false, Latency: 30 * time.Second, Status: 503})
	if got := lc.instances[0].DialFailures(); got != 1 {
		t.Fatalf("inst1 failures = %d, want 1", got)
	}
	if got := lc.instances[0].DialLatencyEWMA(); got != 500*time.Millisecond {
		t.Fatalf("inst1 EWMA after failure = %v, want 500ms (failures skip EWMA)", got)
	}

	// Gen-stale: rotate the instance twice (fresh default gen is 1, so one
	// bump lands on 2 — still ambiguous with "never rotated"; two bumps to
	// 3 proves the old sample belongs to a dead generation) — must drop.
	lc.instances[0].NextCircuitGen()
	lc.instances[0].NextCircuitGen()
	m.ReportOutcome(Outcome{ID: 1, Gen: gen1, Success: false, Status: 503})
	if got := lc.instances[0].DialFailures(); got != 1 {
		t.Fatalf("inst1 failures after stale outcome = %d, want 1 (dropped)", got)
	}

	// Unknown ID: drop, no panic.
	m.ReportOutcome(Outcome{ID: 99, Success: false, Status: 503})
	// Nil lifecycle: drop, no panic.
	(&MultiTorBackend{}).ReportOutcome(Outcome{ID: 1, Success: true})
}

// TestReportOutcome_RouterFanout verifies Router.ReportOutcome reaches an
// OutcomeReporter backend (and skips backends without the interface).
func TestReportOutcome_RouterFanout(t *testing.T) {
	lc := NewTorLifecycle(TorLifecycleConfig{
		Binary: "true", DataDir: t.TempDir(),
		BasePort: 0, ControlBase: 0, MaxInstances: 1, Logf: func(string, ...interface{}) {},
	})
	lc.instances = append(lc.instances, &TorInstance{ID: 1, Ready: true, StartedAt: time.Now()})
	m := NewMultiTorBackend(lc, time.Second, func(string, ...interface{}) {})
	r := NewRouter(nil, m)
	r.ReportOutcome(Outcome{ID: 1, Gen: lc.instances[0].CircuitGen(), Success: true, Latency: 200 * time.Millisecond, Status: 200})
	if got := lc.instances[0].DialSuccesses(); got != 1 {
		t.Fatalf("fanout successes = %d, want 1", got)
	}
}

// Single-owner rule: a dial followed by its request outcome records exactly
// one success sample (not dial-sample + outcome-sample). Pre-fix DialContext
// recorded the success AND ReportOutcome recorded it again, inflating the
// success rate and passing the MinSamples gate early.
func TestReportOutcome_SingleSamplePerRequest(t *testing.T) {
	lc := NewTorLifecycle(TorLifecycleConfig{
		Binary: "true", DataDir: t.TempDir(),
		BasePort: 0, ControlBase: 0, MaxInstances: 1, Logf: func(string, ...interface{}) {},
	})
	lc.instances = append(lc.instances, &TorInstance{ID: 1, Ready: true, StartedAt: time.Now()})
	m := NewMultiTorBackend(lc, time.Second, func(string, ...interface{}) {})
	m.SetScoreParams(DefaultScoreParams())

	// Simulate one served request: dial path records nothing on success now;
	// the outcome path records the single authoritative sample.
	gen := lc.instances[0].CircuitGen()
	m.ReportOutcome(Outcome{ID: 1, Gen: gen, Success: true, Latency: 400 * time.Millisecond, Status: 200})
	if got := lc.instances[0].DialSuccesses(); got != 1 {
		t.Fatalf("successes after one request = %d, want exactly 1 (single owner)", got)
	}
	if got := lc.instances[0].DialLatencyEWMA(); got != 400*time.Millisecond {
		t.Fatalf("EWMA = %v, want 400ms (single outcome sample)", got)
	}
}
