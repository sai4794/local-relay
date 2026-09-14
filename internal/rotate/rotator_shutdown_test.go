package rotate

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Add racing Wait at shutdown must not leak an untracked rotation: after
// Wait returns, no new callback may run.
func TestRotator_WaitGuardsLateAdd(t *testing.T) {
	var fires atomic.Int32
	r := NewRotator(1000000, func() { fires.Add(1) }, slog.Default())

	r.Wait() // arm closing before any trigger

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.ForceRotate()
		}()
	}
	wg.Wait()
	// Allow any wrongly-admitted goroutine a chance to fire.
	time.Sleep(100 * time.Millisecond)
	if got := fires.Load(); got != 0 {
		t.Fatalf("fires after shutdown Wait = %d; want 0 (late Adds dropped)", got)
	}
}

// Normal rotation still fires exactly once per trigger before shutdown.
func TestRotator_TriggerStillFires(t *testing.T) {
	var fires atomic.Int32
	done := make(chan struct{}, 4)
	r := NewRotator(1000000, func() { fires.Add(1); done <- struct{}{} }, slog.Default())

	r.ForceRotate()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("rotation callback did not fire")
	}
	r.Wait()
	if got := fires.Load(); got != 1 {
		t.Fatalf("fires = %d; want 1", got)
	}
}
