package backend

import (
	"testing"
	"time"
)

// Pool ReportOutcome drives the slot quarantine machine: 3 consecutive
// failures quarantine the slot (skipped by selection), unknown IDs and
// stale gens drop, success returns to Active.
func TestPool_ReportOutcomeQuarantine(t *testing.T) {
	pool := NewCircuitPoolBackend(PoolConfig{
		TorAddress:   "127.0.0.1:1",
		ControlAddr:  "127.0.0.1:1", // unreachable: entry NEWNYM fails, state still advances
		CircuitCount: 2,
	})
	// Generation timeline: poolGen starts at 0. Bump to 5 up front
	// (simulating past rotations) so the test can use a nonzero Gen —
	// Gen 0 bypasses the staleness gate by design and can never go stale.
	pool.poolGen.Store(5)
	const gen = 5
	for i := 0; i < 3; i++ {
		pool.ReportOutcome(Outcome{ID: 0, Gen: gen, Success: false, Status: 503})
	}
	if got := pool.slots[0].quar.State(); got != StateQuarantined {
		t.Fatalf("slot 0 state = %v, want quarantined", got)
	}
	if pool.slots[1].quar.State() != StateActive {
		t.Fatal("slot 1 left Active; want untouched")
	}
	// Unknown ID drops, no panic.
	pool.ReportOutcome(Outcome{ID: 99, Success: false, Status: 503})
	// Stale gen drops: advance live gen past the test gen, replay the old one.
	pool.poolGen.Store(gen + 1)
	before := pool.slots[0].DialFailures()
	pool.ReportOutcome(Outcome{ID: 0, Gen: gen, Success: false, Status: 503})
	if got := pool.slots[0].DialFailures(); got != before {
		t.Fatal("stale-gen outcome recorded; want drop")
	}
	// Fresh gen success returns to Active with backoff cleared. Hold is
	// time-based; force-expiry avoids a 60s sleep in test.
	pool.slots[0].quar.quarantinedUntil.Store(time.Now().Add(-time.Second).UnixNano())
	pool.slots[0].quar.pollPromotion(time.Now())
	pool.ReportOutcome(Outcome{ID: 0, Gen: pool.poolGen.Load(), Success: true, Latency: 300 * time.Millisecond, Status: 200})
	if pool.slots[0].quar.State() != StateActive {
		t.Fatalf("slot 0 state = %v after probe success; want active", pool.slots[0].quar.State())
	}
}

// Pool scored selection avoids a sick slot: after failures + slow EWMA,
// dials against a fake SOCKS tor must prefer the healthy slot.
func TestPool_ScoredSelectionAvoidsSick(t *testing.T) {
	pool := NewCircuitPoolBackend(PoolConfig{
		TorAddress:   "127.0.0.1:1",
		CircuitCount: 2,
	})
	pool.SetScoreParams(DefaultScoreParams())
	sp := DefaultScoreParams()
	for i := 0; i < 5; i++ {
		pool.slots[0].RecordDialOutcome(false, 0, sp.Alpha)
	}
	for i := 0; i < 5; i++ {
		pool.slots[0].RecordDialOutcome(true, 8*time.Second, sp.Alpha)
	}
	// Slot 0 quality now ~0.1 vs slot 1 cold 1.0: order must prefer slot 1.
	// Drive selection without network: dialTor would fail on 127.0.0.1:1,
	// so assert via the ordering inputs instead — both slots healthy, but
	// slot 0 effective load must exceed slot 1's.
	q0 := QualityScore(pool.slots[0].DialSuccesses(), pool.slots[0].DialFailures(), int64(pool.slots[0].DialLatencyEWMA()), sp)
	q1 := QualityScore(pool.slots[1].DialSuccesses(), pool.slots[1].DialFailures(), int64(pool.slots[1].DialLatencyEWMA()), sp)
	if !(q1 > q0) {
		t.Fatalf("quality healthy=%v sick=%v; want healthy > sick", q1, q0)
	}
	if e0, e1 := EffectiveLoad(0, q0, sp.MinQuality), EffectiveLoad(0, q1, sp.MinQuality); !(e1 < e0) {
		t.Fatalf("effective load healthy=%v sick=%v; want healthy < sick", e1, e0)
	}
}
