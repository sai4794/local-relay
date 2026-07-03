package backend

import (
	"context"
	"testing"
	"time"
)

func TestCircuitSlotHealth(t *testing.T) {
	slot := &CircuitSlot{id: 0, healthy: true, failThreshold: 3}

	if !slot.IsHealthy() {
		t.Fatal("expected slot to start healthy")
	}

	// 1 failure — still healthy
	slot.RecordFailure()
	if !slot.IsHealthy() {
		t.Fatal("expected slot healthy after 1 failure")
	}

	// 2 more failures — now unhealthy
	slot.RecordFailure()
	slot.RecordFailure()
	if slot.IsHealthy() {
		t.Fatal("expected slot unhealthy after 3 failures")
	}

	// Success doesn't auto-heal (intentional — only resetAll does)
	slot.RecordSuccess()
	if slot.IsHealthy() {
		t.Fatal("RecordSuccess should NOT auto-heal — only resetAll does")
	}

	// Reset restores health
	slot.Reset()
	if !slot.IsHealthy() {
		t.Fatal("expected slot healthy after Reset")
	}
}

func TestCircuitSlotMaxAge(t *testing.T) {
	slot := &CircuitSlot{id: 0, healthy: true}
	maxAge := int64(5)

	for i := int64(0); i < 4; i++ {
		slot.RecordSuccess()
		if slot.ShouldRotate(maxAge) {
			t.Fatalf("should not rotate at request %d", i)
		}
	}

	// 5th request triggers ShouldRotate
	slot.RecordSuccess()
	if !slot.ShouldRotate(maxAge) {
		t.Fatal("should rotate after 5 requests")
	}
}

func TestCircuitSlotAnomalies(t *testing.T) {
	slot := &CircuitSlot{id: 0, healthy: true, anomalyThreshold: 2}

	slot.RecordAnomaly()
	if slot.AnomalyCount() != 1 {
		t.Fatal("expected anomaly count 1")
	}

	// Reset on success
	slot.RecordSuccess()
	if slot.AnomalyCount() != 0 {
		t.Fatal("anomaly count should reset on success")
	}

	// Two anomalies then success resets again
	slot.RecordAnomaly()
	slot.RecordAnomaly()
	slot.RecordSuccess()
	if slot.AnomalyCount() != 0 {
		t.Fatal("anomaly count should reset on success (2)")
	}
}

func TestCircuitPoolNew(t *testing.T) {
	pool := NewCircuitPoolBackend(PoolConfig{
		TorAddress:   "127.0.0.1:9050",
		CircuitCount: 3,
		Timeout:      5 * time.Second,
	})

	if !pool.IsHealthy() {
		t.Fatal("pool should start healthy")
	}

	status := pool.Status()
	if status["total_slots"] != 3 {
		t.Fatalf("expected 3 slots, got %v", status["total_slots"])
	}
	if status["healthy_slots"] != 3 {
		t.Fatalf("expected 3 healthy slots, got %v", status["healthy_slots"])
	}
	if status["nym_backoff"] != int64(1) {
		t.Fatalf("expected backoff 1, got %v", status["nym_backoff"])
	}
}

func TestCircuitPoolDialNoTor(t *testing.T) {
	pool := NewCircuitPoolBackend(PoolConfig{
		TorAddress:   "127.0.0.1:1", // no Tor on port 1
		CircuitCount: 2,
		Timeout:      1 * time.Second,
	})

	_, err := pool.DialContext(context.Background(), "tcp", "example.com:80")
	if err == nil {
		t.Fatal("expected dial to fail with no Tor")
	}
	// Should still be healthy (pool has slots, Tor is just down)
	if !pool.IsHealthy() {
		t.Fatal("pool should still report healthy (slots exist)")
	}
}

func TestBackoffMultiplier(t *testing.T) {
	pool := NewCircuitPoolBackend(PoolConfig{
		TorAddress:   "127.0.0.1:9050",
		CircuitCount: 1,
	})

	if pool.BackoffMultiplier() != 1 {
		t.Fatal("expected initial backoff 1")
	}

	// No easy way to test rateLimitedNEWNYM without Tor,
	// but resetErrorBackoff should work
	pool.resetErrorBackoff()
	if pool.BackoffMultiplier() != 1 {
		t.Fatal("expected backoff 1 after reset")
	}
}

func TestCryptoRandInt(t *testing.T) {
	// cryptoRandInt should produce values in [0, max)
	for i := 0; i < 10; i++ {
		val := cryptoRandInt(100)
		if val < 0 || val >= 100 {
			t.Fatalf("cryptoRandInt(100) = %d, want [0,100)", val)
		}
	}
	// Should handle edge cases without panic
	val := cryptoRandInt(1)
	if val != 0 {
		t.Fatalf("cryptoRandInt(1) = %d, want 0", val)
	}
}

func TestResetErrorBackoff(t *testing.T) {
	pool := NewCircuitPoolBackend(PoolConfig{
		TorAddress:   "127.0.0.1:9050",
		CircuitCount: 1,
	})
	if pool.BackoffMultiplier() != 1 {
		t.Fatal("expected start backoff 1")
	}
	// Simulate backoff increase (via rateLimitedNEWNYM directly is hard without Tor,
	// but calling resetErrorBackoff directly should work)
	pool.resetErrorBackoff()
	if pool.BackoffMultiplier() != 1 {
		t.Fatalf("expected backoff 1 after reset, got %d", pool.BackoffMultiplier())
	}
}
