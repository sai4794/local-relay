package rotate

import (
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

func TestRotatorTriggersAtInterval(t *testing.T) {
	var fires atomic.Int32
	r := NewRotator(3, func() { fires.Add(1) }, slog.Default())

	for i := 0; i < 2; i++ {
		if r.ShouldRotate() {
			t.Fatalf("fired early at count %d", i+1)
		}
	}
	if !r.ShouldRotate() {
		t.Fatal("did not fire on interval")
	}
	// Callback is async via WaitGroup — let it land.
	deadline := time.Now().Add(2 * time.Second)
	for fires.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if fires.Load() != 1 {
		t.Fatalf("want 1 fire, got %d", fires.Load())
	}
	if r.ShouldRotate() {
		t.Fatal("counter should have restarted (fires again only at next multiple of interval)")
	}
	r.Wait()
}

func TestRotatorZeroIntervalNeverFires(t *testing.T) {
	r := NewRotator(0, func() { t.Error("must not fire") }, slog.Default())
	for i := 0; i < 5; i++ {
		if r.ShouldRotate() {
			t.Fatal("interval=0 must never fire")
		}
	}
}
