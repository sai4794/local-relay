package backend

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// Regression: ReportAnomaly(-1) on a cold backend (no serving history) must
// still dispatch the rate-limited NEWNYM but WITHOUT marking a random slot
// unhealthy (pool) and WITHOUT the ResetRequests+OnRotate churn (multitor).
// Once anything has been served, existing attribution is unchanged.
func TestRegression_PoolColdAnomalyNoPhantomRotation(t *testing.T) {
	pool := NewCircuitPoolBackend(PoolConfig{
		TorAddress:   "127.0.0.1:1",
		ControlAddr:  "127.0.0.1:1", // unreachable: NEWNYM fails fast, no reset
		CircuitCount: 3,
	})
	// Cold: lastSlot==-1, no dials served.
	if got := pool.lastSlot.Load(); got != -1 {
		t.Fatalf("lastSlot = %d; want -1 (cold backend)", got)
	}
	pool.ReportAnomaly(-1)
	// Give the async NEWNYM goroutine (if any) a chance to run; it must fail
	// on the unreachable control port, so no reset can occur either way.
	deadline := time.Now().Add(10 * time.Second)
	for pool.nymInflight.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	for i, slot := range pool.slots {
		if !slot.IsHealthy() {
			t.Errorf("cold ReportAnomaly(-1) marked slot %d unhealthy; want all healthy (no phantom rotation)", i)
		}
	}
}

func TestRegression_PoolWarmAnomalyKeepsAttribution(t *testing.T) {
	pool := NewCircuitPoolBackend(PoolConfig{
		TorAddress:   "127.0.0.1:1",
		ControlAddr:  "127.0.0.1:1",
		CircuitCount: 3,
		MaxAnomaly:   1, // single anomaly trips the threshold
	})
	// Attributed anomaly (claim slot index from the dial) trips the slot.
	pool.ReportAnomaly(1)
	if got := pool.slots[1].AnomalyCount(); got != 1 {
		t.Fatalf("slot 1 anomaly count = %d; want 1 (attributed to claim slot)", got)
	}
	if pool.slots[1].IsHealthy() {
		t.Error("slot 1 still healthy after reaching anomaly threshold; want unhealthy (existing attribution)")
	}
	if !pool.slots[0].IsHealthy() || !pool.slots[2].IsHealthy() {
		t.Error("non-serving slots changed health; want only the attributed slot affected")
	}
}

func TestRegression_MultiTorColdAnomalyNoChurn(t *testing.T) {
	lc := NewTorLifecycle(TorLifecycleConfig{
		Binary: "true", DataDir: t.TempDir(),
		BasePort: 0, ControlBase: 0, MaxInstances: 2,
		Logf: func(string, ...interface{}) {},
	})
	m := NewMultiTorBackend(lc, time.Second, func(string, ...interface{}) {})
	// Cold backend: no instances served, everServed unset, no LastServed stamps.
	rotated := false
	m.OnRotate = func() { rotated = true }
	m.ReportAnomaly(-1) // no instances: must return without firing OnRotate
	if rotated {
		t.Error("OnRotate fired on cold backend with no instances; want no churn")
	}
}

// Cold backend WITH spawned ready instances must still skip the NEWNYM
// dispatch on a pre-serve anomaly: with no serving history there is no
// culprit to attribute, so no rotation, no counter reset, no OnRotate.
// The empty-lifecycle case above only exercises the early return; this
// exercises the attribution path with real candidates present.
func TestRegression_MultiTorColdAnomalyNoDispatchWithInstances(t *testing.T) {
	// Fake control server: counts SIGNAL NEWNYM attempts.
	newnymSeen := make(chan string, 16)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				reader := bufio.NewReader(c)
				if _, err := reader.ReadString('\n'); err != nil { // AUTHENTICATE
					return
				}
				_, _ = c.Write([]byte("250 OK\r\n"))
				for {
					cmd, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					if strings.HasPrefix(strings.TrimSpace(cmd), "SIGNAL NEWNYM") {
						newnymSeen <- strings.TrimSpace(cmd)
						_, _ = c.Write([]byte("250 OK\r\n"))
						return
					}
					_, _ = c.Write([]byte("250 OK\r\n"))
				}
			}(conn)
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var ctrlPort int
	if _, err := fmt.Sscan(portStr, &ctrlPort); err != nil {
		t.Fatal(err)
	}

	lc := NewTorLifecycle(TorLifecycleConfig{
		Binary: "true", DataDir: t.TempDir(),
		BasePort: 0, ControlBase: 0, MaxInstances: 2,
		Logf: func(string, ...interface{}) {},
	})
	// Two fake ready instances sharing the fake control port. Both are
	// outside the 10s NEWNYM cooldown and have never served (LastServed==0),
	// so a cold ReportAnomaly(-1) must skip the dispatch entirely.
	for _, id := range []int{1, 2} {
		inst := &TorInstance{ID: id, SocksPort: 0, ControlPort: ctrlPort, Ready: true, StartedAt: time.Now()}
		inst.SetLastRotated(time.Now().Add(-time.Hour))
		lc.instances = append(lc.instances, inst)
	}
	m := NewMultiTorBackend(lc, time.Second, func(string, ...interface{}) {})
	rotated := false
	m.OnRotate = func() { rotated = true }

	m.ReportAnomaly(-1)

	// The dispatch is fire-and-forget, so allow a window for a stray NEWNYM
	// to arrive; any arrival is a failure.
	select {
	case cmd := <-newnymSeen:
		t.Fatalf("cold ReportAnomaly(-1) dispatched NEWNYM (%q); want no dispatch before anything served", cmd)
	case <-time.After(300 * time.Millisecond):
	}
	if rotated {
		t.Error("OnRotate fired on cold backend with ready instances; want no churn")
	}
	for _, inst := range lc.GetInstances() {
		if got := inst.GetRequests(); got != 0 {
			t.Errorf("instance %d requests = %d; want 0 (no counter churn on cold anomaly)", inst.ID, got)
		}
	}
}
