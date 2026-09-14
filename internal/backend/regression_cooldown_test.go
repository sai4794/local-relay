package backend

import (
	"errors"
	"testing"
	"time"
)

// Regression: a NEWNYM cooldown skip is a sentinel (ErrNymCooldown), not a
// rotation — callers must be able to distinguish "skipped" from "rotated".
func TestRegression_NEWNYMCooldownSentinel(t *testing.T) {
	lc := NewTorLifecycle(TorLifecycleConfig{
		Binary: "true", DataDir: t.TempDir(),
		BasePort: 0, ControlBase: 0, MaxInstances: 1,
		Logf: func(string, ...interface{}) {},
	})
	inst := &TorInstance{ID: 1, SocksPort: 1, ControlPort: 1, Ready: true, StartedAt: time.Now()}
	inst.SetLastRotated(time.Now()) // inside the 10s cooldown window

	err := lc.RequestNewCircuit(inst)
	if !errors.Is(err, ErrNymCooldown) {
		t.Fatalf("RequestNewCircuit during cooldown = %v; want ErrNymCooldown sentinel", err)
	}

	// Pool-level cooldown surfaces the same sentinel without resetting slots.
	pool := NewCircuitPoolBackend(PoolConfig{TorAddress: "127.0.0.1:1", ControlAddr: "127.0.0.1:1", CircuitCount: 2})
	pool.lastNymTime = time.Now() // force inside minNymGap window
	rotated, err := pool.rateLimitedNEWNYM()
	if rotated {
		t.Fatal("rateLimitedNEWNYM during cooldown reported rotated=true; want false")
	}
	if !errors.Is(err, ErrNymCooldown) {
		t.Fatalf("rateLimitedNEWNYM during cooldown = %v; want ErrNymCooldown", err)
	}
}

// Regression: interleaved cooldown claims must not reopen the window.
// Anomaly T1 claims, health T2 bypass-claims after it, then T1's SIGNAL
// fails: refunding T1's stale claim must NOT roll back T2's window, or a
// third caller would be wrongly admitted inside the cooldown.
func TestRegression_NymRefundKeepsNewerBypassClaim(t *testing.T) {
	lc := NewTorLifecycle(TorLifecycleConfig{
		Binary: "true", DataDir: t.TempDir(),
		BasePort: 0, ControlBase: 0, MaxInstances: 1,
		Logf: func(string, ...interface{}) {},
	})
	inst := &TorInstance{ID: 1, SocksPort: 1, ControlPort: 1, Ready: true, StartedAt: time.Now()}
	inst.SetLastRotated(time.Now().Add(-time.Hour)) // outside cooldown: claimable

	anomalyClaim := lc.claimNymWindow(inst, false)
	if anomalyClaim == 0 {
		t.Fatal("anomaly claim outside cooldown = 0; want owned claim")
	}
	healthClaim := lc.claimNymWindow(inst, true) // dropGuards bypasses the check
	if healthClaim == 0 {
		t.Fatal("dropGuards bypass claim = 0; want owned claim despite anomaly window")
	}
	if healthClaim == anomalyClaim {
		t.Fatal("claims must be distinct monotonic ids")
	}

	lc.refundNymWindow(inst, anomalyClaim) // T1 SIGNAL failed after T2 claimed

	// Window must still be closed: a third anomaly caller is skipped...
	if got := lc.claimNymWindow(inst, false); got != 0 {
		t.Fatalf("third anomaly claim = %d after stale refund; want 0 (window stays closed)", got)
	}
	// ...and the surviving owner is the health claim.
	inst.mu.RLock()
	owner := inst.nymClaim
	inst.mu.RUnlock()
	if owner != healthClaim {
		t.Fatalf("window owner = %d; want health claim %d (bypass claim survives)", owner, healthClaim)
	}
}

// The owning claim refunding must reopen the window exactly like natural
// expiry: a later caller is admitted again.
func TestRegression_NymRefundByOwnerReopens(t *testing.T) {
	lc := NewTorLifecycle(TorLifecycleConfig{
		Binary: "true", DataDir: t.TempDir(),
		BasePort: 0, ControlBase: 0, MaxInstances: 1,
		Logf: func(string, ...interface{}) {},
	})
	inst := &TorInstance{ID: 1, SocksPort: 1, ControlPort: 1, Ready: true, StartedAt: time.Now()}
	inst.SetLastRotated(time.Now().Add(-time.Hour))

	claim := lc.claimNymWindow(inst, false)
	if claim == 0 {
		t.Fatal("claim outside cooldown = 0; want owned claim")
	}
	lc.refundNymWindow(inst, claim)
	if got := lc.claimNymWindow(inst, false); got == 0 {
		t.Fatal("claim after owner refund = 0; want owned claim (window reopened)")
	}
}

// Claim 0 is the cooldown-skip sentinel, never owned: refunding it must not
// stamp a window nobody claimed. State: inside cooldown with no owner
// (LastRotated set directly, zero-value nymClaim).
func TestRegression_NymRefundZeroClaimNoOp(t *testing.T) {
	lc := NewTorLifecycle(TorLifecycleConfig{
		Binary: "true", DataDir: t.TempDir(),
		BasePort: 0, ControlBase: 0, MaxInstances: 1,
		Logf: func(string, ...interface{}) {},
	})
	inst := &TorInstance{ID: 1, SocksPort: 1, ControlPort: 1, Ready: true, StartedAt: time.Now()}
	inst.SetLastRotated(time.Now()) // inside cooldown, nymClaim zero value

	lc.refundNymWindow(inst, 0)
	if got := lc.claimNymWindow(inst, false); got != 0 {
		t.Fatalf("claim after refund(0) = %d; want 0 (sentinel refund must not reopen)", got)
	}
}
