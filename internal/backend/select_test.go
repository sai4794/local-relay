package backend

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// selectTestLifecycle builds a 3-instance lifecycle on fake SOCKS5 listeners
// (mirrors TestMultiTor_LeastInflightPicked's fake) with all instances fresh
// (LastRotated zero) so the freshness filter never interferes unless a test
// stamps a rotation explicitly.
func selectTestLifecycle(t *testing.T, m **MultiTorBackend) []*TorInstance {
	t.Helper()
	addrs := []string{}
	for i := 0; i < 3; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		addrs = append(addrs, ln.Addr().String())
		go func(l net.Listener) {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				go func(cc net.Conn) {
					defer cc.Close()
					buf := make([]byte, 4)
					if _, err := cc.Read(buf); err != nil {
						return
					}
					cc.Write([]byte{0x05, 0x02})
					ahdr := make([]byte, 2)
					if _, err := cc.Read(ahdr); err != nil {
						return
					}
					uname := make([]byte, int(ahdr[1]))
					if _, err := cc.Read(uname); err != nil {
						return
					}
					plen := make([]byte, 1)
					if _, err := cc.Read(plen); err != nil {
						return
					}
					pass := make([]byte, plen[0])
					if _, err := cc.Read(pass); err != nil {
						return
					}
					cc.Write([]byte{0x01, 0x00})
					hdr := make([]byte, 4)
					if _, err := cc.Read(hdr); err != nil {
						return
					}
					var skip int
					switch hdr[3] {
					case 0x01:
						skip = 4 + 2
					case 0x04:
						skip = 16 + 2
					case 0x03:
						l := make([]byte, 1)
						cc.Read(l)
						skip = int(l[0]) + 2
					}
					rest := make([]byte, skip)
					cc.Read(rest)
					cc.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
					time.Sleep(300 * time.Millisecond)
				}(c)
			}
		}(ln)
	}
	lc := NewTorLifecycle(TorLifecycleConfig{
		Binary: "true", DataDir: t.TempDir(),
		BasePort: 0, ControlBase: 0, MaxInstances: 3, Logf: func(string, ...interface{}) {},
	})
	for i, addr := range addrs {
		_, portStr, _ := net.SplitHostPort(addr)
		var port int
		fmt.Sscan(portStr, &port)
		lc.instances = append(lc.instances, &TorInstance{ID: i + 1, SocksPort: port, ControlPort: 0, Cmd: nil, DataDir: "", Ready: true, StartedAt: time.Now()})
	}
	*m = NewMultiTorBackend(lc, 2*time.Second, func(string, ...interface{}) {})
	return lc.instances
}

// sicken marks inst sick: 5 failures + a slow 8s EWMA (respects the live
// minSamples gate, unlike raw low-count injection).
func sicken(inst *TorInstance, p ScoreParams) {
	for i := 0; i < 5; i++ {
		inst.RecordDialOutcome(false, 0, p.Alpha)
	}
	for i := 0; i < 5; i++ {
		inst.RecordDialOutcome(true, 8*time.Second, p.Alpha)
	}
}

func TestSelect_SickInstanceAvoided(t *testing.T) {
	var m *MultiTorBackend
	insts := selectTestLifecycle(t, &m)
	p := DefaultScoreParams()
	m.SetScoreParams(p)
	sicken(insts[0], p)
	// Others stay cold (neutral 1.0); sick inst0 has sr=0.5, lf~=0.2 -> q~=0.1.

	for i := 0; i < 10; i++ {
		conn, err := m.DialContext(context.Background(), "tcp", "example.com:443")
		if err != nil {
			t.Fatalf("dial %d failed: %v", i, err)
		}
		id, _, _, ok := EndpointFromConn(conn)
		conn.Close()
		if !ok {
			t.Fatalf("dial %d: no endpoint claim", i)
		}
		if id == 1 {
			t.Fatalf("dial %d picked sick instance 1 (10 consecutive dials must avoid it)", i)
		}
	}
}

func TestSelect_ColdEqualsLeastInflight(t *testing.T) {
	var m *MultiTorBackend
	insts := selectTestLifecycle(t, &m)
	// Cold + unscored == least-inflight: load inst0, expect inst1 (ID tie-break).
	insts[0].IncInFlight()
	insts[0].IncInFlight()
	if got, _ := m.selectInstance(insts); got.ID != 2 {
		t.Fatalf("unscored pick = %d, want 2 (least-inflight, oldest-ID tie)", got.ID)
	}
	// Enabling scoring with zero samples must pick identically.
	m.SetScoreParams(DefaultScoreParams())
	if got, _ := m.selectInstance(insts); got.ID != 2 {
		t.Fatalf("cold scored pick = %d, want 2 (cold == least-inflight)", got.ID)
	}
}

func TestSelect_FreshnessExclusionAndFallback(t *testing.T) {
	var m *MultiTorBackend
	insts := selectTestLifecycle(t, &m)
	// Only inst3 fresh: inst1+2 rotated 1s ago -> excluded, inst3 serves.
	insts[0].SetLastRotated(time.Now().Add(-time.Second))
	insts[1].SetLastRotated(time.Now().Add(-time.Second))
	if got, _ := m.selectInstance(insts); got.ID != 3 {
		t.Fatalf("fresh-filtered pick = %d, want 3 (only fresh candidate)", got.ID)
	}
	// All rotated within 5s -> fallback serves least-bad (least-inflight).
	insts[2].SetLastRotated(time.Now())
	insts[0].IncInFlight()
	insts[2].IncInFlight()
	if got, _ := m.selectInstance(insts); got.ID != 2 {
		t.Fatalf("all-fresh fallback pick = %d, want 2 (least-inflight)", got.ID)
	}
}

func TestSelect_EmptyReadyFailsClosed(t *testing.T) {
	// No ready instances at all (MaxInstances 0, nothing injected):
	// DialContext must fail closed, never serve.
	lc := NewTorLifecycle(TorLifecycleConfig{
		Binary: "true", DataDir: t.TempDir(),
		BasePort: 0, ControlBase: 0, MaxInstances: 0, Logf: func(string, ...interface{}) {},
	})
	m2 := NewMultiTorBackend(lc, 2*time.Second, func(string, ...interface{}) {})
	if _, err := m2.DialContext(context.Background(), "tcp", "example.com:443"); err == nil {
		t.Fatal("expected fail-closed error with no instances, got nil")
	}
	// Instances exist but none ready: same fail-closed contract.
	var m *MultiTorBackend
	insts := selectTestLifecycle(t, &m)
	for _, inst := range insts {
		inst.SetReady(false)
	}
	if _, err := m.DialContext(context.Background(), "tcp", "example.com:443"); err == nil {
		t.Fatal("expected fail-closed error with no ready instances, got nil")
	}
}

func TestSelect_ConcurrentDialsRace(t *testing.T) {
	var m *MultiTorBackend
	selectTestLifecycle(t, &m)
	m.SetScoreParams(DefaultScoreParams())
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := m.DialContext(context.Background(), "tcp", "example.com:443")
			if err != nil {
				t.Error(err)
				return
			}
			time.Sleep(5 * time.Millisecond)
			conn.Close()
		}()
	}
	wg.Wait()
	// All 32 in-flight wrappers balanced: every instance back to 0.
	for _, inst := range m.lifecycle.GetInstances() {
		if got := inst.InFlight(); got != 0 {
			t.Fatalf("instance %d in-flight = %d after 32 concurrent dials, want 0", inst.ID, got)
		}
	}
}

func TestSelect_KillSwitchDisablesSteering(t *testing.T) {
	var m *MultiTorBackend
	insts := selectTestLifecycle(t, &m)
	p := DefaultScoreParams()
	m.SetScoreParams(p)
	sicken(insts[0], p)
	if !m.ScoredSelection() {
		t.Fatal("ScoredSelection = false after SetScoreParams, want true")
	}
	// Kill-switch: zero ScoreParams disables steering but keeps stats.
	m.SetScoreParams(ScoreParams{})
	if m.ScoredSelection() {
		t.Fatal("ScoredSelection = true after zero ScoreParams, want false")
	}
	if insts[0].DialFailures() == 0 {
		t.Fatal("kill-switch dropped recorded stats; stats must survive disable")
	}
	// Disabled + equal load on sick vs healthy -> least-inflight tie-break
	// by ID no longer avoids the sick instance deterministically; assert the
	// disabled ordering equals pure least-inflight (ID tie-break picks 1).
	if got, _ := m.selectInstance(insts); got.ID != 1 {
		t.Fatalf("disabled pick = %d, want 1 (pure least-inflight ID tie-break)", got.ID)
	}
}
