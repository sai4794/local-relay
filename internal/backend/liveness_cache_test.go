package backend

import (
	"errors"
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

// Daemon-dead predicate: only TCP-dial-to-daemon failures ("tor socks
// connect: …" from transport Connect) may pin the liveness cache —
// target-dependent handshake failures must not park a healthy daemon
// (one dead-target request would otherwise pin all instances dead).
func TestIsDaemonDeadErr_Predicate(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("tor socks connect: connection refused"), true},
		{errors.New("tor socks connect: dial tcp 127.0.0.1:9150: connect: connection refused"), true},
		{errors.New("greeting read: EOF"), false},
		{errors.New("connect failed: status 5"), false},
		{errors.New("auth rejected: 1"), false},
		{errors.New("SOCKS5 isolation auth downgraded to no-auth by server"), false},
		{errors.New("connection refused"), false}, // bare target error: no daemon prefix
	} {
		if got := isDaemonDeadErr(tc.err); got != tc.want {
			t.Errorf("isDaemonDeadErr(%v) = %v; want %v", tc.err, got, tc.want)
		}
	}
}

// Dial pins liveness ONLY on daemon-dead: a target-dependent failure must
// leave a healthy daemon's cache alive.
func TestLivenessCache_TargetFailureDoesNotPin(t *testing.T) {
	inst := &TorInstance{ID: 1, Ready: true, StartedAt: time.Now()}
	if !inst.IsReadyLive() {
		t.Fatal("cold IsReadyLive = false; want true (nil Cmd, Ready)")
	}
	// Simulate the markDead gate with a handshake error: no pin.
	if err := errors.New("connect failed: status 5"); isDaemonDeadErr(err) {
		inst.MarkLivenessDead()
	}
	if !inst.IsReadyLive() {
		t.Fatal("IsReadyLive = false after target-dependent failure; want true (no pin)")
	}
	// Daemon-dead pins immediately.
	if err := errors.New("tor socks connect: connection refused"); isDaemonDeadErr(err) {
		inst.MarkLivenessDead()
	}
	if inst.IsReadyLive() {
		t.Fatal("IsReadyLive = true after daemon-dead; want pinned false")
	}
}
