package backend

import (
	"testing"
	"time"
)

// Dial-path readiness must not syscall per dial: after one probe the verdict
// caches for liveTTL (atomics only); expiry re-probes; dial failure pins
// dead immediately. Nil-Cmd instances (tests) probe Ready-flag-only.
func TestLivenessCache_HotPath(t *testing.T) {
	inst := &TorInstance{ID: 1, Ready: true, StartedAt: time.Now()}
	if !inst.IsReadyLive() {
		t.Fatal("cold IsReadyLive = false; want true (nil Cmd, Ready)")
	}
	if got := inst.liveCached.Load(); got != 1 {
		t.Fatalf("liveCached = %d; want 1 after first probe", got)
	}
	// Second call inside TTL: cache hit, no re-probe (liveAt unchanged).
	at := inst.liveAt.Load()
	if !inst.IsReadyLive() {
		t.Fatal("cached IsReadyLive = false; want true")
	}
	if inst.liveAt.Load() != at {
		t.Fatal("cache-hit dial re-probed; want atomics-only hot path")
	}
	// Dead pins fail-closed until refresh.
	inst.MarkLivenessDead()
	if inst.IsReadyLive() {
		t.Fatal("IsReadyLive = true after MarkLivenessDead; want pinned false")
	}
	// Ready=false short-circuits regardless of cache.
	inst.SetReady(false)
	if inst.IsReadyLive() {
		t.Fatal("IsReadyLive = true with Ready=false; want false")
	}
}

// Expiry re-probes: backdate past TTL, next dial refreshes the stamp.
func TestLivenessCache_ExpiryReprobes(t *testing.T) {
	inst := &TorInstance{ID: 1, Ready: true, StartedAt: time.Now()}
	if !inst.IsReadyLive() {
		t.Fatal("cold probe failed")
	}
	inst.liveAt.Store(time.Now().Add(-liveTTL - time.Second).UnixNano())
	before := inst.liveAt.Load()
	if !inst.IsReadyLive() {
		t.Fatal("expired IsReadyLive = false; want re-probe true")
	}
	if inst.liveAt.Load() == before {
		t.Fatal("expiry did not re-probe; want fresh stamp")
	}
}
