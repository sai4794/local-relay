package backend

import (
	"testing"
)

// Unknown-slot anomalies (-1) must dispatch NEWNYM without marking ANY
// slot: the old lastSlot-guess fallback attributed to the most recent
// dialer under concurrency, churning an innocent slot while the culprit
// escaped. Attributed callers pass their claim slot index instead.
func TestPool_UnknownSlotAnomalyMarksNothing(t *testing.T) {
	pool := NewCircuitPoolBackend(PoolConfig{
		TorAddress:   "127.0.0.1:1",
		CircuitCount: 3,
	})
	for i := 0; i < 10; i++ {
		pool.ReportAnomaly(-1)
	}
	for i, slot := range pool.slots {
		if !slot.IsHealthy() {
			t.Fatalf("slot %d unhealthy after unattributed anomalies; want all healthy", i)
		}
		if got := slot.AnomalyCount(); got != 0 {
			t.Fatalf("slot %d anomalyCount = %d; want 0 (no guessing)", i, got)
		}
	}
	// Attributed anomalies still work and trip at maxAnomaly.
	pool.ReportAnomaly(1)
	pool.ReportAnomaly(1)
	if pool.slots[1].IsHealthy() {
		t.Fatal("slot 1 healthy after 2 attributed anomalies; want unhealthy at maxAnomaly=2")
	}
	if !pool.slots[0].IsHealthy() || !pool.slots[2].IsHealthy() {
		t.Fatal("unattributed slots churned by attributed anomalies on slot 1")
	}
}
