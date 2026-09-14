package rotate

import (
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

// Negative intervals must clamp to 0 (disabled), not wrap into a huge
// uint64 that silently re-enables rotation.
func TestRotatorNegativeIntervalDisabled(t *testing.T) {
	r := NewRotator(-5, func() { t.Error("must not fire") }, slog.Default())
	if got := r.interval.Load(); got != 0 {
		t.Fatalf("interval = %d; want 0 (disabled)", got)
	}
	for i := 0; i < 5; i++ {
		if r.ShouldRotate() {
			t.Fatal("negative interval must never fire")
		}
	}
	r.SetInterval(-1)
	if got := r.interval.Load(); got != 0 {
		t.Fatalf("after SetInterval(-1): interval = %d; want 0", got)
	}
}

// ForceRotate storms must collapse onto one rotation per 10s window, same
// RLock-fast-path/write-claim pattern as TorBackend.ReportAnomaly. The
// request-count ShouldRotate path stays unchanged.
func TestForceRotateCooldown(t *testing.T) {
	var fires atomic.Int32
	done := make(chan struct{}, 8)
	r := NewRotator(1000000, func() { fires.Add(1); done <- struct{}{} }, slog.Default())

	r.ForceRotate()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("first ForceRotate did not fire")
	}
	for i := 0; i < 5; i++ {
		r.ForceRotate() // inside cooldown: dropped
	}
	// Let any wrongly-admitted rotation land.
	time.Sleep(200 * time.Millisecond)
	if got := fires.Load(); got != 1 {
		t.Fatalf("fires = %d; want 1 (storm collapsed)", got)
	}
	r.Wait()
}

// ShouldRotate request-count rotation is unaffected by the ForceRotate
// cooldown: interval hits still fire even right after a forced rotation.
func TestShouldRotateUnaffectedByForceCooldown(t *testing.T) {
	var fires atomic.Int32
	done := make(chan struct{}, 8)
	r := NewRotator(2, func() { fires.Add(1); done <- struct{}{} }, slog.Default())

	r.ForceRotate()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ForceRotate did not fire")
	}
	if !r.ShouldRotate() && !r.ShouldRotate() {
		t.Fatal("ShouldRotate interval hits must still fire after ForceRotate")
	}
	deadline := time.Now().Add(2 * time.Second)
	for fires.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := fires.Load(); got < 2 {
		t.Fatalf("fires = %d; want >= 2 (forced + interval)", got)
	}
	r.Wait()
}
