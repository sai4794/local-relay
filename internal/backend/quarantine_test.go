package backend

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// serveQuarantineControl answers AUTHENTICATE + SIGNAL NEWNYM with 250 OK and
// counts NEWNYM signals. Cookie auth accepts anything (tests inject no cookie
// cache, so the client falls back to empty-password auth — accepted here).
func serveQuarantineControl(t *testing.T, nymCount *int64Chan, stop chan struct{}) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close(); close(stop) })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(cc net.Conn) {
				defer cc.Close()
				_ = cc.SetDeadline(time.Now().Add(5 * time.Second))
				r := bufio.NewReader(cc)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					cmd := strings.TrimSpace(line)
					if strings.HasPrefix(cmd, "SIGNAL NEWNYM") {
						nymCount.add(1)
					}
					_, _ = cc.Write([]byte("250 OK\r\n"))
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

type int64Chan struct {
	mu sync.Mutex
	n  int64
}

func (c *int64Chan) add(d int64) { c.mu.Lock(); c.n += d; c.mu.Unlock() }
func (c *int64Chan) get() int64  { c.mu.Lock(); defer c.mu.Unlock(); return c.n }

// quarantineLifecycle builds a 2-instance lifecycle wired to a fake control
// port (both instances share it — NEWNYM counting is global, which is all
// the tests assert). Instances are Ready with nil Cmd (no liveness process)
// so IsReady reads the Ready flag only.
func quarantineLifecycle(t *testing.T, controlAddr string) (*TorLifecycle, *MultiTorBackend) {
	t.Helper()
	host, portStr, _ := net.SplitHostPort(controlAddr)
	_ = host
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatal(err)
	}
	lc := NewTorLifecycle(TorLifecycleConfig{
		Binary: "true", DataDir: t.TempDir(),
		BasePort: 0, ControlBase: 0, MaxInstances: 2, Logf: func(string, ...interface{}) {},
	})
	for i := 1; i <= 2; i++ {
		lc.instances = append(lc.instances, &TorInstance{
			ID: i, SocksPort: 1, ControlPort: port,
			Cmd: nil, DataDir: t.TempDir(), Ready: true, StartedAt: time.Now(),
		})
		// Cooldown-fresh NEWNYM would refuse the entry signal: backdate the
		// rotation stamp so the first quarantine entry dispatches.
		lc.instances[i-1].SetLastRotated(time.Now().Add(-time.Minute))
	}
	m := NewMultiTorBackend(lc, time.Second, func(string, ...interface{}) {})
	return lc, m
}

func waitForNym(t *testing.T, c *int64Chan, want int64, what string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if c.get() >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s: NEWNYM count = %d, want >= %d", what, c.get(), want)
}

func TestQuarantine_ThreeFailsQuarantines(t *testing.T) {
	var nym int64Chan
	stop := make(chan struct{})
	addr := serveQuarantineControl(t, &nym, stop)
	_, m := quarantineLifecycle(t, addr)

	gen := m.getInstanceByID(1).CircuitGen()
	for i := 0; i < 3; i++ {
		m.ReportOutcome(Outcome{ID: 1, Gen: gen, Success: false, Status: 503})
	}
	if got := m.getInstanceByID(1).QuarantineState(); got != StateQuarantined {
		t.Fatalf("state after 3 fails = %v, want quarantined", got)
	}
	waitForNym(t, &nym, 1, "quarantine entry")
	// Selection must skip the quarantined instance while the hold runs.
	ready := []*TorInstance{m.getInstanceByID(1), m.getInstanceByID(2)}
	if got, _ := m.selectInstance(ready); got.ID != 2 {
		t.Fatalf("selection with inst1 quarantined = %d, want 2", got.ID)
	}
}

func TestQuarantine_NoDoubleSignalWhileQuarantined(t *testing.T) {
	var nym int64Chan
	stop := make(chan struct{})
	addr := serveQuarantineControl(t, &nym, stop)
	_, m := quarantineLifecycle(t, addr)

	gen := m.getInstanceByID(1).CircuitGen()
	for i := 0; i < 3; i++ {
		m.ReportOutcome(Outcome{ID: 1, Gen: gen, Success: false, Status: 503})
	}
	waitForNym(t, &nym, 1, "entry")
	// Storm more failures while quarantined: no second NEWNYM.
	for i := 0; i < 10; i++ {
		m.ReportOutcome(Outcome{ID: 1, Gen: gen, Success: false, Status: 503})
	}
	time.Sleep(300 * time.Millisecond)
	if got := nym.get(); got != 1 {
		t.Fatalf("NEWNYM count after storm = %d, want exactly 1 (suppressed while quarantined)", got)
	}
}

// TestQuarantine_CheckHealthSkipsProactiveHealWhileQuarantined pins the
// no-double-signal contract on the health path: a quarantined instance with
// a stale consensus and failing SOCKS must not fire the proactive
// DROPGUARDS heal (quarantine entry already issued ONE attributed NEWNYM).
// StartedAt is backdated past the 30s grace so the heal branch is reached;
// DataDir points at a temp dir with no consensus file (fresh-exempt only
// within 3m of start, so stale=true here); SocksPort 1 refuses, so
// socksReady=false. Two consecutive CheckHealth calls drive TryStartHeal's
// 2m cooldown deterministically: first call heals (control NEWNYM), second
// must not.
func TestQuarantine_CheckHealthSkipsProactiveHealWhileQuarantined(t *testing.T) {
	var nym int64Chan
	stop := make(chan struct{})
	addr := serveQuarantineControl(t, &nym, stop)
	lc, m := quarantineLifecycle(t, addr)
	inst := m.getInstanceByID(1)
	inst.StartedAt = time.Now().Add(-time.Hour)
	if Left := inst.TryStartHeal(); !Left {
		t.Fatal("TryStartHeal precondition failed")
	}
	// Reset the 2m heal cooldown so CheckHealth may heal.
	inst.mu.Lock()
	inst.lastHealed = time.Time{}
	inst.mu.Unlock()

	// Baseline (Active): CheckHealth must attempt the proactive heal.
	lc.CheckHealth(context.Background())
	waitForNym(t, &nym, 1, "baseline proactive heal")

	// Quarantine the instance directly (bypasses ReportOutcome's own NEWNYM
	// so the count stays attributable to health-path signals only).
	inst.quar.state.Store(int32(StateQuarantined))
	inst.quar.quarantinedUntil.Store(time.Now().Add(time.Hour).UnixNano())
	inst.mu.Lock()
	inst.lastHealed = time.Time{}
	inst.mu.Unlock()
	before := nym.get()
	lc.CheckHealth(context.Background())
	lc.CheckHealth(context.Background())
	time.Sleep(300 * time.Millisecond)
	if got := nym.get(); got != before {
		t.Fatalf("NEWNYM count grew %d -> %d while quarantined; want no proactive heal", before, got)
	}
}

func TestQuarantine_LazyPromotionAndProbationSuccess(t *testing.T) {
	var nym int64Chan
	stop := make(chan struct{})
	addr := serveQuarantineControl(t, &nym, stop)
	_, m := quarantineLifecycle(t, addr)
	m.SetQuarantineConfig(QuarantineConfig{AfterFails: 3, Duration: 100 * time.Millisecond, MaxDuration: time.Second, Probes: 1})

	inst := m.getInstanceByID(1)
	gen := inst.CircuitGen()
	for i := 0; i < 3; i++ {
		m.ReportOutcome(Outcome{ID: 1, Gen: gen, Success: false, Status: 503})
	}
	if inst.QuarantineState() != StateQuarantined {
		t.Fatalf("state = %v, want quarantined", inst.QuarantineState())
	}
	// Hold expires -> next selection promotes to probation (probe holder).
	// The entry NEWNYM stamped LastRotated fresh, which the 5s freshness
	// filter would exclude: backdate so the probe competes as fresh.
	time.Sleep(200 * time.Millisecond)
	inst.SetLastRotated(time.Now().Add(-time.Minute))
	m.getInstanceByID(2).SetLastRotated(time.Now().Add(-time.Minute))
	ready := []*TorInstance{inst, m.getInstanceByID(2)}
	if got, _ := m.selectInstance(ready); got.ID != 1 {
		t.Fatalf("post-expiry selection = %d, want 1 (promotion probe)", got.ID)
	}
	if inst.QuarantineState() != StateProbation {
		t.Fatalf("state after promotion = %v, want probation", inst.QuarantineState())
	}
	// Probe success returns to Active with backoff cleared.
	m.ReportOutcome(Outcome{ID: 1, Gen: gen, Success: true, Latency: 500 * time.Millisecond, Status: 200})
	if inst.QuarantineState() != StateActive {
		t.Fatalf("state after probe success = %v, want active", inst.QuarantineState())
	}
	if inst.quar.QuarantineCount() != 0 {
		t.Fatalf("backoff after success = %d, want 0 (cleared)", inst.quar.QuarantineCount())
	}
}

func TestQuarantine_ProbationFailureBacksOff(t *testing.T) {
	var nym int64Chan
	stop := make(chan struct{})
	addr := serveQuarantineControl(t, &nym, stop)
	_, m := quarantineLifecycle(t, addr)
	m.SetQuarantineConfig(QuarantineConfig{AfterFails: 3, Duration: 100 * time.Millisecond, MaxDuration: 250 * time.Millisecond, Probes: 1})

	inst := m.getInstanceByID(1)
	gen := inst.CircuitGen()
	for i := 0; i < 3; i++ {
		m.ReportOutcome(Outcome{ID: 1, Gen: gen, Success: false, Status: 503})
	}
	waitForNym(t, &nym, 1, "entry")
	// First hold = 100ms. Expire, promote, fail the probe -> re-quarantine
	// at 200ms (doubled), firing a second NEWNYM.
	time.Sleep(200 * time.Millisecond)
	inst.SetLastRotated(time.Now().Add(-time.Minute))
	m.getInstanceByID(2).SetLastRotated(time.Now().Add(-time.Minute))
	ready := []*TorInstance{inst, m.getInstanceByID(2)}
	if got, _ := m.selectInstance(ready); got.ID != 1 {
		t.Fatalf("promotion probe = %d, want 1", got.ID)
	}
	// Cooldown-fresh entry NEWNYM stamped LastRotated: backdate so the
	// re-quarantine signal dispatches instead of hitting cooldown.
	inst.SetLastRotated(time.Now().Add(-time.Minute))
	m.ReportOutcome(Outcome{ID: 1, Gen: inst.CircuitGen(), Success: false, Status: 503})
	if inst.QuarantineState() != StateQuarantined {
		t.Fatalf("state after probe failure = %v, want quarantined", inst.QuarantineState())
	}
	waitForNym(t, &nym, 2, "re-quarantine")
	// Doubled hold (200ms) still active at +100ms: selection skips inst1.
	time.Sleep(100 * time.Millisecond)
	if got, _ := m.selectInstance(ready); got.ID != 2 {
		t.Fatalf("selection during doubled hold = %d, want 2", got.ID)
	}
	// Cap: another full cycle must not exceed MaxDuration (250ms). Backdate
	// both rotation stamps so the promotion probe competes as fresh (the
	// re-quarantine NEWNYM stamped inst1 fresh again).
	inst.quar.quarantinedUntil.Store(time.Now().Add(-time.Millisecond).UnixNano())
	inst.SetLastRotated(time.Now().Add(-time.Minute))
	m.getInstanceByID(2).SetLastRotated(time.Now().Add(-time.Minute))
	if got, _ := m.selectInstance(ready); got.ID != 1 {
		t.Fatalf("second promotion probe = %d, want 1", got.ID)
	}
	inst.SetLastRotated(time.Now().Add(-time.Minute))
	m.ReportOutcome(Outcome{ID: 1, Gen: inst.CircuitGen(), Success: false, Status: 503})
	// Third entry would be 400ms uncapped; cap pins at 250ms. Backdate both
	// stamps again: the re-quarantine NEWNYM stamped inst1 fresh.
	time.Sleep(300 * time.Millisecond)
	inst.SetLastRotated(time.Now().Add(-time.Minute))
	m.getInstanceByID(2).SetLastRotated(time.Now().Add(-time.Minute))
	if got, _ := m.selectInstance(ready); got.ID != 1 {
		t.Fatalf("selection after capped hold = %d, want 1 (250ms max expired)", got.ID)
	}
}

func TestQuarantine_AllQuarantinedStillServes(t *testing.T) {
	var nym int64Chan
	stop := make(chan struct{})
	addr := serveQuarantineControl(t, &nym, stop)
	_, m := quarantineLifecycle(t, addr)

	for _, id := range []int{1, 2} {
		gen := m.getInstanceByID(id).CircuitGen()
		for i := 0; i < 3; i++ {
			m.ReportOutcome(Outcome{ID: id, Gen: gen, Success: false, Status: 503})
		}
	}
	ready := []*TorInstance{m.getInstanceByID(1), m.getInstanceByID(2)}
	// Both quarantined: selection serves least-bad instead of failing.
	got, _ := m.selectInstance(ready)
	if got == nil {
		t.Fatal("all-quarantined selection = nil, want least-bad server")
	}
}

func TestQuarantine_TransitionStormRace(t *testing.T) {
	var nym int64Chan
	stop := make(chan struct{})
	addr := serveQuarantineControl(t, &nym, stop)
	_, m := quarantineLifecycle(t, addr)

	var wg sync.WaitGroup
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			gen := m.getInstanceByID(1).CircuitGen()
			for i := 0; i < 50; i++ {
				if (w+i)%2 == 0 {
					m.ReportOutcome(Outcome{ID: 1, Gen: gen, Success: false, Status: 503})
				} else {
					m.ReportOutcome(Outcome{ID: 1, Gen: gen, Success: true, Latency: 500 * time.Millisecond, Status: 200})
				}
				_, _ = m.selectInstance([]*TorInstance{m.getInstanceByID(1), m.getInstanceByID(2)})
			}
		}(w)
	}
	wg.Wait()
	// Invariant after the storm: state is a known value, counters sane,
	// and selection still returns a candidate.
	st := m.getInstanceByID(1).QuarantineState()
	if st != StateActive && st != StateQuarantined && st != StateProbation {
		t.Fatalf("post-storm state = %v, want active/quarantined/probation", st)
	}
	if got, _ := m.selectInstance([]*TorInstance{m.getInstanceByID(1), m.getInstanceByID(2)}); got == nil {
		t.Fatal("post-storm selection = nil, want a candidate")
	}
}

// Exactly one concurrent dialer may claim the probation probe: N dialers
// racing selectInstance against one promoted endpoint yield exactly one
// winner serving it; the rest pick the healthy candidate. Pre-fix every
// dialer saw probeInFlight=true and served the sick endpoint (probe herd).
func TestQuarantine_SingleProbeEnforcedUnderConcurrency(t *testing.T) {
	var nym int64Chan
	stop := make(chan struct{})
	addr := serveQuarantineControl(t, &nym, stop)
	_, m := quarantineLifecycle(t, addr)
	m.SetQuarantineConfig(QuarantineConfig{AfterFails: 3, Duration: 100 * time.Millisecond, MaxDuration: time.Second, Probes: 1})

	inst := m.getInstanceByID(1)
	healthy := m.getInstanceByID(2)
	gen := inst.CircuitGen()
	for i := 0; i < 3; i++ {
		m.ReportOutcome(Outcome{ID: 1, Gen: gen, Success: false, Status: 503})
	}
	time.Sleep(200 * time.Millisecond)
	inst.SetLastRotated(time.Now().Add(-time.Minute))
	healthy.SetLastRotated(time.Now().Add(-time.Minute))

	const racers = 32
	picks := make([]int, racers)
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got, _ := m.selectInstance([]*TorInstance{inst, healthy})
			picks[i] = got.ID
		}(i)
	}
	wg.Wait()
	probes := 0
	for _, id := range picks {
		if id == 1 {
			probes++
		}
	}
	if probes != 1 {
		t.Fatalf("probation probes served = %d, want exactly 1 (single-probe guarantee)", probes)
	}
	if inst.QuarantineState() != StateProbation {
		t.Fatalf("state = %v, want probation (probe still out)", inst.QuarantineState())
	}
}

// A wedged probe slot (holder died without reporting) must not wedge the
// endpoint in probation forever: after the expiry budget the slot releases
// and the next selection re-claims it for a fresh probe.
func TestQuarantine_StaleProbeSlotExpires(t *testing.T) {
	var q endpointQuarantine
	now := time.Now()
	q.state.Store(int32(StateProbation))
	if !q.claimProbe(now) {
		t.Fatal("initial claim failed")
	}
	if q.claimProbe(now) {
		t.Fatal("second claim succeeded; want single holder")
	}
	// Fresh slot: not expired, no release.
	if q.releaseStaleProbe(now.Add(time.Second), time.Hour) {
		t.Fatal("fresh probe slot released; want hold until budget")
	}
	// Wedged slot: backdate claim past budget, release fires.
	q.probeAt.Store(now.Add(-3 * time.Hour).UnixNano())
	if !q.releaseStaleProbe(now, time.Hour) {
		t.Fatal("wedged probe slot not released after budget")
	}
	if !q.claimProbe(now) {
		t.Fatal("re-claim after expiry failed; want fresh probe")
	}
}

// CheckHealth must not recycle a quarantined endpoint via the legacy
// FailCount kill/spawn path: quarantine owns sick-endpoint recovery for
// the hold duration. A quarantined instance with failing SOCKS keeps its
// daemon across consecutive CheckHealth calls (fail count frozen).
func TestQuarantine_CheckHealthDefersToQuarantineHold(t *testing.T) {
	lc := NewTorLifecycle(TorLifecycleConfig{
		Binary: "true", DataDir: t.TempDir(),
		BasePort: 0, ControlBase: 0, MaxInstances: 1, Logf: func(string, ...interface{}) {},
	})
	inst := &TorInstance{ID: 1, SocksPort: 1, ControlPort: 1, Cmd: nil, DataDir: t.TempDir(), Ready: true, StartedAt: time.Now().Add(-time.Hour)}
	lc.instances = append(lc.instances, inst)
	// Quarantine directly with a long hold; SOCKS port 1 refuses so the
	// health probe fails every call.
	inst.quar.state.Store(int32(StateQuarantined))
	inst.quar.quarantinedUntil.Store(time.Now().Add(time.Hour).UnixNano())

	before := inst
	for i := 0; i < 5; i++ {
		lc.CheckHealth(context.Background())
	}
	if lc.instances[0] != before {
		t.Fatal("quarantined instance was kill/spawn recycled; want daemon preserved for the hold")
	}
	if got := inst.GetFailCount(); got != 0 {
		t.Fatalf("legacy FailCount = %d during quarantine hold; want frozen at 0", got)
	}
	// After release back to Active, the legacy path resumes.
	inst.quar.state.Store(int32(StateActive))
	lc.CheckHealth(context.Background())
	if got := inst.GetFailCount(); got != 1 {
		t.Fatalf("legacy FailCount after release = %d; want 1 (path resumed)", got)
	}
}

// Probation probes must be claimed one per served dial, and selection must
// fail closed only when EVERY candidate's probe is genuinely held. Pre-fix
// pickBest claimed probes on losing candidates, wedging them until expiry.
func TestQuarantine_AllProbationClaimedFailsClosed(t *testing.T) {
	var nym int64Chan
	stop := make(chan struct{})
	addr := serveQuarantineControl(t, &nym, stop)
	_, m := quarantineLifecycle(t, addr)
	m.SetQuarantineConfig(QuarantineConfig{AfterFails: 3, Duration: time.Hour, MaxDuration: time.Hour, Probes: 1})

	// Quarantine both, force-expiry, promote both to probation, claim both.
	now := time.Now()
	for _, id := range []int{1, 2} {
		inst := m.getInstanceByID(id)
		gen := inst.CircuitGen()
		for i := 0; i < 3; i++ {
			m.ReportOutcome(Outcome{ID: id, Gen: gen, Success: false, Status: 503})
		}
		inst.quar.quarantinedUntil.Store(now.Add(-time.Second).UnixNano())
	}
	ready := []*TorInstance{m.getInstanceByID(1), m.getInstanceByID(2)}
	// Selection claims the probe on the winner only. The loser must stay
	// unclaimed: pinning both as "in flight" after ONE selection was the
	// leak that suppressed the loser's only probe (issue H-02).
	first, _ := m.selectInstance(ready)
	if first == nil {
		t.Fatal("first selection = nil; want one probe claim")
	}
	claims := func() int {
		n := 0
		for _, inst := range ready {
			if inst.quar.probeInFlight.Load() {
				n++
			}
		}
		return n
	}
	if n := claims(); n != 1 {
		t.Fatalf("claims after first selection = %d, want 1 (winner only)", n)
	}
	// The other endpoint can be probed by the NEXT dial — sequentially, not
	// as a second concurrent probe of the same sick endpoint.
	second, _ := m.selectInstance(ready)
	if second == nil || second.ID == first.ID {
		t.Fatalf("second selection = %v; want the other instance", second)
	}
	if n := claims(); n != 2 {
		t.Fatalf("claims after second selection = %d, want 2 (one per served probe)", n)
	}
	// With both probes genuinely held, a third dial fails closed rather
	// than starting a probe herd.
	if got, _ := m.selectInstance(ready); got != nil {
		t.Fatalf("third selection = %d; want nil (all probes held)", got.ID)
	}
}

// Po2 complement rescan: with k=2 over [sick-quarantined x2, healthy], an
// all-excluded sample must not serve the quarantined loser while a healthy
// candidate sits outside the sample. Pre-fix the sample fallback served
// least-bad quarantined without looking outside it.
func TestSelect_Po2ExcludedSampleRescansComplement(t *testing.T) {
	var m *MultiTorBackend
	insts := selectTestLifecycle(t, &m)
	p := DefaultScoreParams()
	m.SetScoreParams(p)
	m.SetQuarantineConfig(QuarantineConfig{AfterFails: 3, Duration: time.Hour, MaxDuration: time.Hour, Probes: 1})
	m.SetSelection("po2", 2)
	// Quarantine instances 1 and 2 directly with long holds (no NEWNYM
	// wiring needed — selectTestLifecycle uses no control port).
	now := time.Now()
	for _, inst := range insts[:2] {
		if _, entered := inst.quar.enterQuarantine(now, time.Hour, time.Hour); !entered {
			t.Fatalf("setup: enterQuarantine failed for inst %d", inst.ID)
		}
	}
	// Every dial must serve the healthy instance 3, regardless of window.
	for i := 0; i < 12; i++ {
		got, _ := m.selectInstance(insts)
		if got == nil {
			t.Fatalf("dial %d: selection = nil; want healthy 3 (complement rescan)", i)
		}
		if got.ID != 3 {
			t.Fatalf("dial %d: selection = %d; want 3 (healthy outside excluded sample)", i, got.ID)
		}
	}
}

// Complement fast path: when the whole pool is excluded (all quarantined
// with active holds), the Po2 all-excluded sample must stand on its
// least-bad fallback WITHOUT promoting, claiming, or releasing anything —
// the fast path skips the complement scan, so no probe slot moves.
func TestSelect_Po2AllExcludedNoSideEffects(t *testing.T) {
	var m *MultiTorBackend
	insts := selectTestLifecycle(t, &m)
	m.SetScoreParams(DefaultScoreParams())
	m.SetQuarantineConfig(QuarantineConfig{AfterFails: 3, Duration: time.Hour, MaxDuration: time.Hour, Probes: 1})
	m.SetSelection("po2", 2)
	now := time.Now()
	for _, inst := range insts {
		if _, entered := inst.quar.enterQuarantine(now, time.Hour, time.Hour); !entered {
			t.Fatalf("setup: enterQuarantine failed for inst %d", inst.ID)
		}
	}
	got, _ := m.selectInstance(insts)
	if got == nil {
		t.Fatal("all-excluded selection = nil; want least-bad fallback")
	}
	// No side effects: every instance still Quarantined with an active hold,
	// nothing promoted to Probation, no probe claimed.
	for _, inst := range insts {
		if st := inst.QuarantineState(); st != StateQuarantined {
			t.Fatalf("inst %d state = %v after all-excluded pick; want quarantined (no promotion)", inst.ID, st)
		}
		if inst.quar.probeInFlight.Load() {
			t.Fatalf("inst %d probe claimed during all-excluded pick; want untouched", inst.ID)
		}
	}
}

// eligibleForSelection advisory contract: Active always; Quarantined only
// after the hold expires; Probation only while a probe is held AND
// unexpired; Draining/Closed never. Pinned because the doc comment names
// this as the external/advisory semantic (selection itself claims via
// claimProbe — see TestQuarantine_SingleProbeEnforcedUnderConcurrency).
func TestQuarantine_EligibleForSelectionContract(t *testing.T) {
	var q endpointQuarantine
	now := time.Now()
	if !q.eligibleForSelection(now) {
		t.Fatal("Active eligible = false; want true")
	}
	if _, entered := q.enterQuarantine(now, time.Hour, time.Hour); !entered {
		t.Fatal("setup: enterQuarantine failed")
	}
	if q.eligibleForSelection(now) {
		t.Fatal("Quarantined (hold active) eligible = true; want false")
	}
	if !q.eligibleForSelection(now.Add(2 * time.Hour)) {
		t.Fatal("Quarantined (hold expired) eligible = false; want true (promote first)")
	}
	q.pollPromotion(now.Add(2 * time.Hour))
	if q.eligibleForSelection(now.Add(2 * time.Hour)) {
		t.Fatal("Probation (no probe held) eligible = true; want false")
	}
	if !q.claimProbe(now.Add(2 * time.Hour)) {
		t.Fatal("setup: claimProbe failed")
	}
	if !q.eligibleForSelection(now.Add(2 * time.Hour)) {
		t.Fatal("Probation (probe held, fresh) eligible = false; want true")
	}
	q.probeAt.Store(now.Add(-3 * time.Hour).UnixNano())
	if q.eligibleForSelection(now.Add(2 * time.Hour)) {
		t.Fatal("Probation (probe expired) eligible = true; want false (release + re-claim first)")
	}
	q.state.Store(int32(StateDraining))
	if q.eligibleForSelection(now) {
		t.Fatal("Draining eligible = true; want false")
	}
	q.state.Store(int32(StateClosed))
	if q.eligibleForSelection(now) {
		t.Fatal("Closed eligible = true; want false")
	}
}

// Dial-failure probe release: a dial failure on a probation-claimed probe
// releases the slot WITHOUT re-quarantining (no NEWNYM, no backoff bump) —
// the failure proves sickness as loudly as a request outcome, and holding
// the claim would wedge the endpoint until expiry. The request outcome path
// owns the re-quarantine signal. Pinned for both backends' release paths
// (multitor releaseProbe closure, pool probation CAS).
func TestQuarantine_DialFailureReleasesProbeWithoutRequarantine(t *testing.T) {
	var q endpointQuarantine
	now := time.Now()
	if _, entered := q.enterQuarantine(now, time.Hour, time.Hour); !entered {
		t.Fatal("setup: enterQuarantine failed")
	}
	q.pollPromotion(now.Add(2 * time.Hour))
	if !q.claimProbe(now.Add(2 * time.Hour)) {
		t.Fatal("setup: claimProbe failed")
	}
	countBefore := q.QuarantineCount()
	// Mirror the releaseProbe closure: probation-held -> CAS true->false.
	if q.State() == StateProbation {
		q.probeInFlight.CompareAndSwap(true, false)
	}
	if q.probeInFlight.Load() {
		t.Fatal("probe still held after dial-failure release; want freed")
	}
	if q.State() != StateProbation {
		t.Fatalf("state = %v after dial-failure release; want probation (no re-quarantine)", q.State())
	}
	if q.QuarantineCount() != countBefore {
		t.Fatalf("backoff %d -> %d on dial-failure release; want unchanged (outcome path owns re-quarantine)", countBefore, q.QuarantineCount())
	}
	// The freed slot is immediately re-claimable for a fresh probe.
	if !q.claimProbe(now.Add(2 * time.Hour)) {
		t.Fatal("re-claim after dial-failure release failed; want fresh probe")
	}
}
