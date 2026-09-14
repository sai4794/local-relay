package backend

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/local-relay/proxy/internal/metrics"
	"github.com/local-relay/proxy/internal/transport"
)

// MultiTorBackend manages multiple Tor daemon instances and round-robins
// connections across them. Each instance runs on a separate SOCKS port,
// giving a different outbound IP address.
type MultiTorBackend struct {
	lifecycle   *TorLifecycle
	socksClient *transport.SOCKS5Client
	counter     atomic.Int64
	logf        func(string, ...interface{})
	OnRotate    func() // called after NEWNYM to clear connection pools
	// scoreParams tunes scored selection (score.go). The zero value selects
	// pure least-inflight (today's behavior); SetScoreParams enables
	// quality steering. Stats are still recorded while disabled so
	// enabling later starts from warm data, not cold.
	scoreParams ScoreParams
	scored      atomic.Bool
	// selection names the selection algorithm ("weighted" = full-scan
	// least-effective-load; "po2" = power-of-two-choices sampling).
	// Set via SetSelection; defaults to weighted. Read atomically on the
	// dial path (a string header word — race-free under the race detector).
	selection atomic.Value // string
	// po2Samples is the candidate sample size for po2 selection (2..8).
	po2Samples atomic.Int64
	// quarCfg tunes the quarantine/probation state machine (quarantine.go).
	// Zero value means defaults (see SetQuarantineConfig); quarantine
	// transitions run regardless of scored steering — exclusion is not
	// steering, and the kill-switch (pool.enabled:false) only disables
	// quality ordering, never health exclusion.
	quarCfg QuarantineConfig
	// rotateInflight coalesces concurrent ReportAnomaly rotation triggers
	// onto one in-flight goroutine (pool-path nymInflight equivalent):
	// the winner's rotation covers the losers' 10s window.
	rotateInflight atomic.Bool
	// everServed tracks whether any DialContext has served traffic yet.
	// A cold backend (nothing ever served) has no culprit to attribute a
	// ReportAnomaly(-1) to, so the rotation runs WITHOUT the
	// ResetRequests+OnRotate churn. Set on the first successful serve.
	// hasServedCurrent scopes the flag to the live instance generation:
	// CheckRecycled re-arms it when every instance was replaced, so a
	// recycled-cold stack reads cold again instead of inheriting a stale
	// everServed=true from a dead generation.
	everServed atomic.Bool
}

// SetScoreParams enables scored selection with the given tuning. The zero
// ScoreParams value disables steering (pure least-inflight, today's
// behavior); any non-zero value enables it. Stats record either way.
func (m *MultiTorBackend) SetScoreParams(p ScoreParams) {
	if p == (ScoreParams{}) {
		m.scored.Store(false)
		return
	}
	if p.Alpha <= 0 || p.Alpha > 1 {
		p.Alpha = DefaultScoreParams().Alpha
	}
	if p.LatencyRef <= 0 {
		p.LatencyRef = DefaultScoreParams().LatencyRef
	}
	if p.MinSamples <= 0 {
		p.MinSamples = DefaultScoreParams().MinSamples
	}
	if p.MinQuality <= 0 {
		p.MinQuality = DefaultScoreParams().MinQuality
	}
	m.scoreParams = p
	m.scored.Store(true)
}

// SetQuarantineConfig installs the quarantine/probation tuning. The zero
// value selects DefaultQuarantineConfig; invalid fields fall back to their
// defaults (never zero windows or unbounded backoff).
func (m *MultiTorBackend) SetQuarantineConfig(c QuarantineConfig) {
	d := DefaultQuarantineConfig()
	if c.AfterFails <= 0 {
		c.AfterFails = d.AfterFails
	}
	if c.Duration <= 0 {
		c.Duration = d.Duration
	}
	if c.MaxDuration < c.Duration {
		c.MaxDuration = d.MaxDuration
		if c.MaxDuration < c.Duration {
			c.MaxDuration = c.Duration
		}
	}
	if c.Probes <= 0 {
		c.Probes = d.Probes
	}
	m.quarCfg = c
}

// ScoredSelection reports whether quality steering is enabled.
func (m *MultiTorBackend) ScoredSelection() bool { return m.scored.Load() }

// SetSelection installs the selection algorithm and Po2 sample size.
// selection must be "weighted" (full-scan least-effective-load) or "po2"
// (power-of-two-choices: sample po2Samples candidates, pick the best).
// Unknown names fall back to weighted; po2Samples outside [2,8] falls back
// to 2. Mirrors the pool.selection / pool.po2_samples validation ranges.
func (m *MultiTorBackend) SetSelection(selection string, po2Samples int) {
	if selection != "po2" {
		selection = "weighted"
	}
	if po2Samples < 2 || po2Samples > 8 {
		po2Samples = 2
	}
	m.selection.Store(selection)
	m.po2Samples.Store(int64(po2Samples))
}

// selectionMode returns the live selection algorithm (default weighted when
// never set — atomic.Value zero reads nil).
func (m *MultiTorBackend) selectionMode() string {
	if s, ok := m.selection.Load().(string); ok && s == "po2" {
		return "po2"
	}
	return "weighted"
}

// po2SampleSize returns the live Po2 sample size (default 2 when unset).
func (m *MultiTorBackend) po2SampleSize() int {
	if n := m.po2Samples.Load(); n >= 2 && n <= 8 {
		return int(n)
	}
	return 2
}

// hasServedCurrent reports whether the live instance generation has served.
// everServed latches on the first successful DialContext; CheckRecycled
// (kill/spawn replacement) re-arms it when no live instance carries a
// LastServed stamp, so recycled-cold stacks skip pre-serve NEWNYM dispatch.
func (m *MultiTorBackend) hasServedCurrent() bool {
	if !m.everServed.Load() {
		return false
	}
	m.CheckRecycled()
	return m.everServed.Load()
}

// CheckRecycled re-arms everServed when the live instance generation has
// never served: a kill/spawn (or ShutdownAll/Start) replaces TorInstance
// pointers, and fresh instances start with LastServed==0, so a stale
// everServed=true from a dead generation must not force NEWNYM dispatch
// against a generation with no culprit. When the backend is cold it returns
// true; otherwise it returns false and leaves everServed set. Callers must
// hold no locks; concurrent DialContext serves may set everServed again.
func (m *MultiTorBackend) CheckRecycled() bool {
	if m.lifecycle == nil {
		return false
	}
	for _, cand := range m.lifecycle.GetInstances() {
		if cand.LastServed() > 0 {
			return false
		}
	}
	if m.everServed.CompareAndSwap(true, false) {
		m.logf("multi-tor: instance generation recycled to unserved, re-arming cold-backend gate")
		return true
	}
	return true
}

// NewMultiTorBackend creates a backend that routes through multiple Tor instances.
func NewMultiTorBackend(lifecycle *TorLifecycle, timeout time.Duration, logf func(string, ...interface{})) *MultiTorBackend {
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	if logf == nil {
		logf = func(string, ...interface{}) {}
	}
	return &MultiTorBackend{
		lifecycle:   lifecycle,
		socksClient: transport.NewSOCKS5Client(timeout),
		logf:        logf,
	}
}

// DialContext picks the next Tor instance round-robin and dials through its SOCKS port.
func (m *MultiTorBackend) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	start := time.Now()
	instances := m.lifecycle.GetInstances()
	// Hot-path readiness uses the cached liveness verdict (atomics, no
	// syscalls): the full kill(0)/Wait4 probe runs at most once per
	// instance per liveTTL, plus immediately after any dial failure
	// (MarkLivenessDead below). CheckHealth refreshes in the background.
	ready := make([]*TorInstance, 0)
	for _, inst := range instances {
		if inst.IsReadyLive() {
			ready = append(ready, inst)
		}
	}

	if len(ready) == 0 {
		return nil, fmt.Errorf("no ready Tor instances")
	}

	// In multi-tor mode every request builds a fresh Tor circuit via
	// IsolateSOCKSAuth, so "round-robin" would land a long LLM stream on an
	// instance that might already be serving another one. selectInstance
	// picks the ready instance with the smallest effective load (see
	// score.go); with scoring disabled that reduces exactly to fewest
	// in-flight, tie-broken by oldest rotation so a post-429 instance isn't
	// immediately re-picked. Cooldown-fresh instances (no rotation within
	// 5s) are preferred, falling back to all ready when every instance
	// rotated within 5s. The serving instance, circuit generation, and dial
	// latency ride home on the returned conn (see inFlightConn endpoint
	// fields + EndpointFromConn in outcome.go) so the proxy can attribute
	// success/failure samples per attempt. Scores never fail a dial closed:
	// with no fresh candidate the least-bad ready instance still serves.
	inst, idx := m.selectInstance(ready)

	// IsolateSOCKSAuth: isolation user groups streams to this instance and circuit generation,
	// allowing Tor to reuse warm 3-hop circuits while maintaining instance isolation and
	// ensuring instant circuit refresh when generation increments on rotation.
	isoUser := "relay:" + strconv.Itoa(inst.ID) + ":" + strconv.FormatInt(inst.CircuitGen(), 10)
	socksAddr := "127.0.0.1:" + strconv.Itoa(inst.GetSocksPort())
	conn, err := m.socksClient.Connect(ctx, socksAddr, addr, isoUser)
	// Per-attempt dial failures score err samples on the attempted instance
	// (the outcome path only sees the winner). EWMA untouched — failure
	// latency mixes fast-refused with slow-timeout and would pollute it.
	dialScoreAlpha := m.scoreParams.Alpha
	if !m.scored.Load() {
		dialScoreAlpha = DefaultScoreParams().Alpha
	}
	if err != nil {
		m.logf("multi-tor: dial instance %d failed: %v", inst.ID, err)
		inst.RecordDialOutcome(false, 0, dialScoreAlpha)
		inst.MarkLivenessDead()
		metrics.Default().IncKey(inst.dialErrKey(), 1)
		// Try next instance with its isolation user
		for i := 1; i < len(ready); i++ {
			nextIdx := (idx + i) % len(ready)
			inst = ready[nextIdx]
			socksAddr = "127.0.0.1:" + strconv.Itoa(inst.GetSocksPort())
			isoUser = "relay:" + strconv.Itoa(inst.ID) + ":" + strconv.FormatInt(inst.CircuitGen(), 10)
			conn, err = m.socksClient.Connect(ctx, socksAddr, addr, isoUser)
			if err == nil {
				break
			}
			m.logf("multi-tor: dial instance %d failed: %v", inst.ID, err)
			inst.RecordDialOutcome(false, 0, dialScoreAlpha)
			inst.MarkLivenessDead()
			metrics.Default().IncKey(inst.dialErrKey(), 1)
		}
		if err != nil {
			return nil, fmt.Errorf("all Tor instances failed: %w", err)
		}
	}

	inst.IncRequests()
	metrics.Default().IncKey("lano_requests_total{instance=\""+strconv.Itoa(inst.ID)+"\"}", 1)
	inst.RecordServed()
	m.everServed.Store(true)

	// Score the dial outcome exactly once per request: the request-level
	// outcome path (ReportOutcome, fed by the proxy's claim sink) is the
	// single owner of success/failure samples. Recording here too would
	// double-count every success (dial sample + outcome sample), inflate
	// the success rate, pass the MinSamples gate early, and halve the
	// effective EWMA alpha. Dial latency still rides the claim sink
	// (filled below) so the outcome sample carries the real sample.
	// Dial-failure err samples above stay: the outcome path only sees the
	// winner, so failed attempts would otherwise leave no signal.
	metrics.Default().IncKey(inst.dialOKKey(), 1)

	// Increment in-flight before wrapping so Close always balances it.
	inst.IncInFlight()
	dialLatency := time.Since(start)
	gen := inst.CircuitGen()
	// Attribute this attempt: fill the proxy's claim sink (if it attached
	// one at its pin site) so success/failure samples credit the instance
	// that actually served the dial. The same triple also rides home on the
	// conn for callers that hold the conn but not the ctx (EndpointFromConn).
	fillClaimSink(ctx, "multitor", inst.ID, gen, dialLatency)
	conn = &inFlightConn{Conn: conn, inst: inst, endpointID: inst.ID, endpointGen: gen, dialLatency: dialLatency}

	// Exactly one concurrent dialer wins each rotation window (ClaimRotation
	// is atomic), so threshold crossings never stampede NEWNYM.
	if inst.ClaimRotation(int64(m.lifecycle.rotateAfter)) {
		m.logf("multi-tor: instance %d reached rotation threshold, rotating circuit", inst.ID)
		go func(target *TorInstance) {
			if rotated, err := m.lifecycle.requestNewCircuitResult(target); err != nil {
				m.logf("multi-tor: auto-rotate NEWNYM failed for instance %d: %v", target.ID, err)
			} else if rotated {
				if m.OnRotate != nil {
					m.OnRotate()
				}
			}
		}(inst)
	}

	return conn, nil
}

// inFlightConn decrements the instance's in-flight counter on Close.
// Double-close is safe — the atomic flag guards it.
// Discard marks the tunnel as broken (spent/half-closed) so pooled layers
// below can drop it instead of recycling a dead socket; Close still runs.
type inFlightConn struct {
	net.Conn
	inst     *TorInstance
	released atomic.Bool
	// endpointID/endpointGen/dialLatency carry the scored-selection claim
	// for this dial (outcome.go): ID + circuit generation at serve time and
	// the dial latency sample. Pure attribution metadata — Close/Discard
	// accounting is unchanged.
	endpointID  int
	endpointGen int64
	dialLatency time.Duration
}

// EndpointID returns the serving instance ID carried by this dial.
func (c *inFlightConn) EndpointID() int { return c.endpointID }

// EndpointGen returns the circuit generation at serve time.
func (c *inFlightConn) EndpointGen() int64 { return c.endpointGen }

// DialLatency returns the dial latency sample for this dial.
func (c *inFlightConn) DialLatency() time.Duration { return c.dialLatency }

func (c *inFlightConn) Unwrap() net.Conn {
	return c.Conn
}

// Discard flags the connection as broken and closes it. It unwraps to a
// pooledConnWrap below (pool topology) and forwards the discard so the dead
// tunnel is closed, never re-pooled. In-flight accounting is balanced here,
// exactly as in Close, so a discard never leaks the counter.
func (c *inFlightConn) Discard() error {
	if c.released.CompareAndSwap(false, true) {
		c.inst.DecInFlight()
	}
	if inner, ok := c.Conn.(interface{ Discard() error }); ok {
		return inner.Discard()
	}
	if inner, ok := c.Conn.(interface{ MarkBroken() }); ok {
		inner.MarkBroken()
	}
	return c.Conn.Close()
}

func (c *inFlightConn) Close() error {
	if c.released.CompareAndSwap(false, true) {
		c.inst.DecInFlight()
	}
	return c.Conn.Close()
}

func (c *inFlightConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// selectInstance picks the ready instance with the smallest effective load,
// preferring cooldown-fresh instances (no rotation within 5s) and falling
// back to all ready when every instance rotated within 5s. Single pass, no
// alloc; per-candidate reads are hoisted (one InFlight + one GetLastRotated
// + scoring atomics each) so a burst of dials pays no duplicate scans.
//
// With scoring disabled the quality of every candidate reads 1.0, so the
// ordering reduces exactly to today's least-inflight (tie: oldest rotation,
// then smallest ID — deterministic). Scores never fail closed: the caller
// guarantees len(ready) > 0 and always gets a candidate back.
//
// Quarantine skips plug into the isExcluded hook: candidates the hook
// rejects are skipped unless every candidate is rejected, in which case
// the least-bad one still serves.
//
// Selection algorithm is live-configurable (SetSelection): "weighted" scans
// the full ready set; "po2" samples po2Samples candidates (stride-picked
// from the shared atomic dial counter — no crypto/rand syscall on the hot
// path) and picks the best of the sample. Po2 trades a bounded optimality
// gap for O(1) selection cost at large N; at N=3 both modes agree.
func (m *MultiTorBackend) selectInstance(ready []*TorInstance) (*TorInstance, int) {
	if m.selectionMode() == "po2" {
		return m.selectInstancePo2(ready)
	}
	return m.selectInstanceWeighted(ready, nil)
}

// candidateView is one candidate's hoisted selection inputs, read once per
// dial so a burst of dials pays no duplicate scans or lock acquisitions.
type candidateView struct {
	cand *TorInstance
	idx  int
	load int64
	rot  time.Time
	eff  float64
}

// viewCandidates hoists per-candidate reads (InFlight + GetLastRotated +
// scoring atomics) into a single pass. When sample is non-nil only those
// indexes are viewed (Po2 path); otherwise the full ready set.
func (m *MultiTorBackend) viewCandidates(ready []*TorInstance, p ScoreParams, sample []int) []candidateView {
	n := len(ready)
	if sample != nil {
		n = len(sample)
	}
	views := make([]candidateView, 0, n)
	if sample != nil {
		for _, i := range sample {
			cand := ready[i]
			load := cand.InFlight()
			rot := cand.GetLastRotated()
			q := QualityScore(cand.DialSuccesses(), cand.DialFailures(), int64(cand.DialLatencyEWMA()), p)
			views = append(views, candidateView{cand: cand, idx: i, load: load, rot: rot, eff: EffectiveLoad(load, q, p.MinQuality)})
		}
		return views
	}
	for i, cand := range ready {
		load := cand.InFlight()
		rot := cand.GetLastRotated()
		q := QualityScore(cand.DialSuccesses(), cand.DialFailures(), int64(cand.DialLatencyEWMA()), p)
		views = append(views, candidateView{cand: cand, idx: i, load: load, rot: rot, eff: EffectiveLoad(load, q, p.MinQuality)})
	}
	return views
}

// better reports whether a beats b under the selection ordering: smaller
// effective load wins, tie → smaller load → older rotation → smaller ID.
// Deterministic: identical inputs always agree.
func better(a, b candidateView) bool {
	if a.eff != b.eff {
		return a.eff < b.eff
	}
	if a.load != b.load {
		return a.load < b.load
	}
	if !a.rot.Equal(b.rot) {
		return a.rot.Before(b.rot)
	}
	return a.cand.ID < b.cand.ID
}

// pickBest folds views into best-fresh / best-any / least-bad-excluded
// winners with the freshness preference (fresh = no rotation within 5s).
func (m *MultiTorBackend) pickBest(views []candidateView) (*TorInstance, int) {
	var bestFresh, bestAny, excludedFresh, excludedAny *candidateView
	anyExcludedFresh := false
	for i := range views {
		v := &views[i]
		fresh := time.Since(v.rot) > 5*time.Second
		if m.isExcluded(v.cand) {
			// Track the least-bad excluded candidate per freshness class
			// so an all-quarantined pool still serves instead of failing.
			if fresh && (!anyExcludedFresh || better(*v, *excludedFresh)) {
				cp := *v
				excludedFresh = &cp
				anyExcludedFresh = true
			}
			if excludedAny == nil || better(*v, *excludedAny) {
				cp := *v
				excludedAny = &cp
			}
			continue
		}
		if fresh && (bestFresh == nil || better(*v, *bestFresh)) {
			cp := *v
			bestFresh = &cp
		}
		if bestAny == nil || better(*v, *bestAny) {
			cp := *v
			bestAny = &cp
		}
	}
	if bestFresh != nil {
		return bestFresh.cand, bestFresh.idx
	}
	if bestAny != nil {
		return bestAny.cand, bestAny.idx
	}
	// Every candidate excluded (e.g. all quarantined): serve the least-bad
	// excluded one rather than failing closed. Fresh-excluded wins when it
	// exists to preserve the freshness preference.
	if anyExcludedFresh {
		return excludedFresh.cand, excludedFresh.idx
	}
	return excludedAny.cand, excludedAny.idx
}

// selectInstanceWeighted is the full-scan least-effective-load selection.
func (m *MultiTorBackend) selectInstanceWeighted(ready []*TorInstance, _ []int) (*TorInstance, int) {
	scored := m.scored.Load()
	p := m.scoreParams
	if !scored {
		p = ScoreParams{MinQuality: DefaultScoreParams().MinQuality, MinSamples: 1 << 60}
	}
	return m.pickBest(m.viewCandidates(ready, p, nil))
}

// selectInstancePo2 samples po2Samples candidates by stride from the shared
// atomic dial counter and picks the best of the sample. Stride-picking (not
// rand) keeps the hot path syscall-free and deterministic under test; the
// counter advances on every dial so consecutive dials sample different
// windows. Sampling is over ready indexes, so quarantine exclusion and the
// least-bad fallback still apply within the sample.
func (m *MultiTorBackend) selectInstancePo2(ready []*TorInstance) (*TorInstance, int) {
	scored := m.scored.Load()
	p := m.scoreParams
	if !scored {
		p = ScoreParams{MinQuality: DefaultScoreParams().MinQuality, MinSamples: 1 << 60}
	}
	n := len(ready)
	k := m.po2SampleSize()
	if k > n {
		k = n
	}
	base := int((uint64(m.counter.Add(1)) & 0x7fffffffffffffff) % uint64(n))
	sample := make([]int, 0, k)
	for j := 0; j < k; j++ {
		sample = append(sample, (base+j*(n/k+1))%n)
	}
	return m.pickBest(m.viewCandidates(ready, p, sample))
}

// isExcluded reports whether quarantine currently excludes cand from
// selection. Quarantined endpoints are skipped until their hold expires
// (lazy promotion to probation happens here, on the selection path);
// probation admits ONLY the dialer that CAS-claims the single probe slot
// (claimProbe) — concurrent dials see the claimed slot and pick someone
// else, so a sick endpoint never takes a probe herd. A wedged slot
// (holder died without reporting) is released after its expiry budget so
// the endpoint can be re-probed instead of wedging in probation.
// Draining/closed never serve. Promotion here only moves
// Quarantined->Probation; Probation->Active / Probation->Quarantined
// resolve on the outcome path, where success/failure is known.
func (m *MultiTorBackend) isExcluded(cand *TorInstance) bool {
	now := time.Now()
	switch cand.quar.State() {
	case StateActive:
		return false
	case StateQuarantined:
		if now.UnixNano() < cand.quar.quarantinedUntil.Load() {
			return true
		}
		cand.quar.pollPromotion(now)
		// Fall through: freshly promoted to Probation — claim below.
		if cand.quar.State() != StateProbation {
			return true
		}
		return !cand.quar.claimProbe(now)
	case StateProbation:
		cfg := m.quarConfig()
		if cand.quar.releaseStaleProbe(now, cfg.Duration) {
			return !cand.quar.claimProbe(now)
		}
		return !cand.quar.claimProbe(now)
	default:
		return true
	}
}

// IsHealthy returns true if at least one Tor instance is ready.
func (m *MultiTorBackend) IsHealthy() bool {
	return m.lifecycle.GetReadyCount() > 0
}

// Close marks all instances as not ready.
func (m *MultiTorBackend) Close() error {
	return nil
}

// Status returns multi-tor backend status.
func (m *MultiTorBackend) Status() map[string]interface{} {
	instances := m.lifecycle.GetInstances()
	p := m.scoreParams
	if !m.scored.Load() {
		p = DefaultScoreParams()
	}
	statuses := make([]map[string]interface{}, len(instances))
	for i, inst := range instances {
		exitIP, _ := inst.LastExitIP()
		ok := inst.DialSuccesses()
		fail := inst.DialFailures()
		ewma := inst.DialLatencyEWMA()
		statuses[i] = map[string]interface{}{
			"id":           inst.ID,
			"socks":        inst.GetSocksPort(),
			"ready":        inst.IsReady(),
			"requests":     inst.GetRequests(),
			"in_flight":    inst.InFlight(),
			"exit_ip":      exitIP,
			"dial_ewma_ms": ewma.Milliseconds(),
			"dial_ok":      ok,
			"dial_err":     fail,
			"quality":      QualityScore(ok, fail, int64(ewma), p),
			"state":        inst.QuarantineState().String(),
			"consec_fails": inst.QuarantineConsecFails(),
		}
	}
	top := map[string]interface{}{
		"type":      "multi-tor",
		"instances": statuses,
		"ready":     m.lifecycle.GetReadyCount(),
		"total":     len(instances),
	}
	if m.scored.Load() {
		top["scored_selection"] = true
		top["selection"] = m.selectionMode()
	}
	return top
}

// ReportOutcome records one attributed request outcome: success/failure
// samples feed the scoring stats (failures skip EWMA), and generation-stale
// outcomes (Gen != live CircuitGen) drop — the endpoint rotated since the
// dial, so the sample belongs to a dead circuit, not the live one. Unknown
// IDs drop silently (no panic): pool-slot IDs and recycled instance IDs
// share no namespace with this lookup. Control-port I/O stays fire-and-
// forget exactly like ReportAnomaly; only attribution is new.
func (m *MultiTorBackend) ReportOutcome(o Outcome) {
	if m.lifecycle == nil {
		return
	}
	var target *TorInstance
	for _, cand := range m.lifecycle.GetInstances() {
		if cand.ID == o.ID {
			target = cand
			break
		}
	}
	if target == nil {
		return
	}
	if o.Gen != 0 && o.Gen != target.CircuitGen() {
		return
	}
	p := m.scoreParams
	if !m.scored.Load() {
		p = DefaultScoreParams()
	}
	target.RecordDialOutcome(o.Success, o.Latency, p.Alpha)
	if o.Success {
		target.ResetFailCount()
		m.onEndpointSuccess(target)
		return
	}
	target.IncFailCount()
	m.onEndpointFailure(target, o)
}

// quarConfig returns the live quarantine tuning (defaults when unset).
func (m *MultiTorBackend) quarConfig() QuarantineConfig {
	c := m.quarCfg
	if c.AfterFails <= 0 || c.Duration <= 0 || c.MaxDuration <= 0 || c.Probes <= 0 {
		d := DefaultQuarantineConfig()
		if c.AfterFails <= 0 {
			c.AfterFails = d.AfterFails
		}
		if c.Duration <= 0 {
			c.Duration = d.Duration
		}
		if c.MaxDuration < c.Duration {
			c.MaxDuration = d.MaxDuration
			if c.MaxDuration < c.Duration {
				c.MaxDuration = c.Duration
			}
		}
		if c.Probes <= 0 {
			c.Probes = d.Probes
		}
	}
	return c
}

// onEndpointSuccess resolves the probation probe: the first success returns
// the endpoint to Active (clearing backoff, keeping EWMA to decay). Plain
// Active successes just clear consecutive failures via recordSuccess.
func (m *MultiTorBackend) onEndpointSuccess(target *TorInstance) {
	target.quar.recordSuccess()
}

// onEndpointFailure drives quarantine entry and probation resolution:
//
//   - Probation probe failure: re-quarantine with doubled backoff (the old
//     probe slot clears inside re-enter) and issue ONE attributed NEWNYM.
//   - Active failure: consecutive-fails gate OR success-rate gate
//     (total>=minSamples && sr<0.3) enters quarantine with ONE attributed
//     NEWNYM. While quarantined further failures are suppressed (no
//     double-signal): recordFailure returns false off the Active state.
//
// Entry stamps LastRotated via the NEWNYM path (60s minimum >> 10s cooldown
// and 30s health grace, so no window fights). NEWNYM is fire-and-forget,
// exactly like ReportAnomaly; only attribution (this instance, not a guess)
// is new. Probation successes never signal.
func (m *MultiTorBackend) onEndpointFailure(target *TorInstance, o Outcome) {
	cfg := m.quarConfig()
	now := time.Now()
	if target.quar.State() == StateProbation {
		m.requarantine(target, cfg, now, "probation-probe-failure")
		return
	}
	enter := target.quar.recordFailure(cfg.AfterFails)
	if !enter {
		// Success-rate gate: enough samples and sr<0.3 catches slow-sick
		// endpoints that never trip the consecutive counter (interleaved
		// successes). minSamples comes from the scoring params so both
		// gates agree on what "enough data" means.
		p := m.scoreParams
		if !m.scored.Load() {
			p = DefaultScoreParams()
		}
		ok := target.DialSuccesses()
		fail := target.DialFailures()
		if total := ok + fail; total >= p.MinSamples && total > 0 &&
			float64(ok)/float64(total) < 0.3 {
			enter = target.quar.State() == StateActive
			// recordFailure already bumped consecFail; entering on the rate
			// gate alone must not double-count — it didn't (one Add above).
		}
	}
	if !enter {
		return
	}
	m.enterQuarantine(target, cfg, now, "consec-fails")
}

// enterQuarantine moves Active->Quarantined (winner-only), fires the entry
// metric + ONE attributed NEWNYM, and resets the rotation request counter
// on a won rotation (mirroring ReportAnomaly's won-rotation path).
func (m *MultiTorBackend) enterQuarantine(target *TorInstance, cfg QuarantineConfig, now time.Time, reason string) {
	if _, entered := target.quar.enterQuarantine(now, cfg.Duration, cfg.MaxDuration); !entered {
		return
	}
	m.logf("multi-tor: instance %d quarantined (%s), holding %v", target.ID, reason, cfg.Duration)
	metrics.Default().Inc("lano_quarantine_total", map[string]string{
		"instance": strconv.Itoa(target.ID),
		"reason":   reason,
	})
	go func(t *TorInstance) {
		if rotated, err := m.lifecycle.requestNewCircuitResult(t); err != nil {
			m.logf("multi-tor: quarantine NEWNYM failed for instance %d: %v", t.ID, err)
		} else if rotated {
			t.ResetRequests()
			if m.OnRotate != nil {
				m.OnRotate()
			}
		}
	}(target)
}

// requarantine moves Probation->Quarantined with doubled backoff (the
// backoff exponent survives: recordSuccess only clears on Active return).
// Exactly one NEWNYM fires; the stale probe slot clears on entry.
func (m *MultiTorBackend) requarantine(target *TorInstance, cfg QuarantineConfig, now time.Time, reason string) {
	// Direct CAS Probation->Quarantined: enterQuarantine only fires from
	// Active, and the probe failure must not be lost to a concurrent success
	// that already returned the endpoint to Active (then there is nothing to
	// re-quarantine — the success won the race and cleared backoff).
	if !target.quar.state.CompareAndSwap(int32(StateProbation), int32(StateQuarantined)) {
		return
	}
	target.quar.probeInFlight.Store(false)
	n := target.quar.quarantineCount.Add(1)
	d := cfg.Duration
	for i := int64(1); i < n && d < cfg.MaxDuration; i++ {
		d *= 2
		if d > cfg.MaxDuration || d <= 0 {
			d = cfg.MaxDuration
			break
		}
	}
	target.quar.quarantinedUntil.Store(now.Add(d).UnixNano())
	m.logf("multi-tor: instance %d re-quarantined (%s), holding %v", target.ID, reason, d)
	metrics.Default().Inc("lano_quarantine_total", map[string]string{
		"instance": strconv.Itoa(target.ID),
		"reason":   reason,
	})
	go func(t *TorInstance) {
		if rotated, err := m.lifecycle.requestNewCircuitResult(t); err != nil {
			m.logf("multi-tor: re-quarantine NEWNYM failed for instance %d: %v", t.ID, err)
		} else if rotated {
			t.ResetRequests()
			if m.OnRotate != nil {
				m.OnRotate()
			}
		}
	}(target)
}

// getInstanceByID returns the live instance with the given ID, or nil.
// Outcome-path lookup only; selection uses the ready snapshot.
func (m *MultiTorBackend) getInstanceByID(id int) *TorInstance {
	if m.lifecycle == nil {
		return nil
	}
	for _, cand := range m.lifecycle.GetInstances() {
		if cand.ID == id {
			return cand
		}
	}
	return nil
}

// ReportAnomaly triggers circuit rotation when a 429 or network error occurs on an instance.
// Only rotates the affected instance to prevent churning healthy circuits.
func (m *MultiTorBackend) ReportAnomaly(slotIdx int) {
	instances := m.lifecycle.GetInstances()
	if len(instances) == 0 {
		return
	}

	var target *TorInstance
	if slotIdx >= 0 && slotIdx < len(instances) {
		target = instances[slotIdx]
	} else {
		// If slotIdx is unknown (-1), prefer the most recently served instance
		// among cooldown-ok ones (it most likely served the failed request);
		// fall back to the existing counter logic when none has served yet.
		var best *TorInstance
		var bestServed int64
		for _, cand := range instances {
			served := cand.LastServed()
			if served <= 0 {
				continue
			}
			if time.Since(cand.GetLastRotated()) < 10*time.Second {
				continue
			}
			if best == nil || served > bestServed {
				best = cand
				bestServed = served
			}
		}
		if best != nil {
			target = best
		} else {
			idx := int(m.counter.Add(1)&0x7fffffffffffffff) % len(instances)
			target = instances[idx]
			for i := 0; i < len(instances); i++ {
				cand := instances[(idx+i)%len(instances)]
				if time.Since(cand.GetLastRotated()) >= 10*time.Second {
					target = cand
					break
				}
			}
		}
	}

	m.logf("multi-tor: anomaly reported (slot %d), triggering circuit rotation on instance %d", slotIdx, target.ID)
	// Cold backend (no instance has EVER served in the CURRENT generation):
	// no culprit attribution exists, so skip the NEWNYM dispatch entirely —
	// no evidence, no rotation. Pre-serve anomalies must not churn circuits,
	// reset counters, or fire OnRotate. Once anything has been served,
	// attribution below is unchanged.
	//
	// everServed is consulted only through hasServedCurrent: the flag is
	// latched on first serve and re-armed by CheckRecycled (called on
	// kill/spawn replacement paths) so a full instance recycle back to an
	// unserved generation reads cold again. Without the re-arm, a stale
	// everServed=true from a dead generation would force a dispatch against
	// a fresh generation with no culprit — demonstrated by
	// TestMultiTor_RecycleRearmsColdBackend.
	cold := slotIdx < 0 && !m.hasServedCurrent()
	for _, cand := range instances {
		if cand.LastServed() > 0 {
			cold = false
			break
		}
	}
	if cold {
		m.logf("multi-tor: cold backend (nothing ever served), skipping NEWNYM dispatch for pre-serve anomaly")
		return
	}
	// Coalescing gate: at most one rotation goroutine in flight per backend.
	// Without it every 429/503 in a storm spawns a goroutine that only then
	// loses the 10s cooldown race inside requestNewCircuitResult — spawn
	// churn proportional to failure RPS. The pool path already gates via
	// nymInflight (anomalyNEWNYM); this is the multitor equivalent. Losers
	// skip silently: the winner's rotation covers them (same 10s window).
	if !m.rotateInflight.CompareAndSwap(false, true) {
		return
	}
	// Fire-and-forget: the request path must not block on control-port I/O
	// (TCP connect + AUTH + NEWNYM round-trips). Rotation ordering is still
	// safe — requestNewCircuitResult claims the 10s cooldown atomically, so
	// concurrent triggers collapse onto one NEWNYM and losers get
	// ErrNymCooldown. ResetRequests/OnRotate run only when this trigger
	// actually won the rotation.
	go func(t *TorInstance) {
		defer m.rotateInflight.Store(false)
		if rotated, err := m.lifecycle.requestNewCircuitResult(t); err != nil {
			m.logf("multi-tor: NEWNYM failed for instance %d: %v", t.ID, err)
		} else if rotated {
			m.logf("multi-tor: instance %d circuit rotated", t.ID)
			t.ResetRequests()
			// Clear connection pool so new connections use new circuits
			if m.OnRotate != nil {
				m.OnRotate()
			}
		}
	}(target)
}
