package backend

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/local-relay/proxy/internal/metrics"
	"github.com/local-relay/proxy/internal/transport"
)

// CircuitSlot tracks the health and usage of one Tor circuit path.
type CircuitSlot struct {
	id               int
	healthy          bool
	failCount        int64
	failThreshold    int64
	requestCount     int64
	lastUsed         time.Time
	anomalyCount     int64
	anomalyThreshold int64
	stats            EndpointStats      // lock-free dial latency/quality scoring (score.go); cold-zero is neutral
	quar             endpointQuarantine // lock-free quarantine/probation lifecycle (quarantine.go); zero = Active
	inFlight         atomic.Int64       // checked-out conns via this pool; feeds EffectiveLoad
	mu               sync.RWMutex
}

// CircuitPoolBackend manages multiple concurrent Tor circuits for
// exit-node diversity and rate-limit resilience.
//
// Rotation is driven by TWO mechanisms:
//  1. Rotator (request-count-based, in rotate/rotator.go):
//     Fires ForceRotate() every N requests (config rotation.interval).
//     This provides proactive circuit churn independent of errors.
//  2. Error-driven (in HTTP/SOCKS5 proxy handlers):
//     Fires ForceRotate() on 429/503, timeouts, DNS failures, etc.
//     This provides reactive rotation when circuits are blocked.
//
// Additionally, each slot's maxAge (50 requests) marks it unhealthy
// for round-robin avoidance, but does NOT itself trigger a NEWNYM.
// A new circuit only comes from ForceRotate() or pool exhaustion.
type CircuitPoolBackend struct {
	slots             []*CircuitSlot
	torAddr           string
	controlAddr       string
	controlPass       string
	controlCookiePath string
	timeout           time.Duration
	maxAge            int64
	maxFails          int64
	maxAnomaly        int64
	current           atomic.Int64
	socksClient       *transport.SOCKS5Client
	control           *TorControlClient
	logf              func(format string, args ...interface{})

	// NEWNYM rate limiting with exponential backoff
	lastNymTime time.Time
	nymMu       sync.Mutex
	minNymGap   time.Duration
	nymBackoff  int64 // doubles on each NEWNYM (1, 2, 4, 8, 16); resets on success

	// nymInflight coalesces concurrent NEWNYM triggers: at most one control
	// round-trip is ever in flight, so an anomaly storm (per failure = one
	// goroutine) collapses onto a single signal instead of N goroutines.
	nymInflight atomic.Bool

	// Tor SOCKS5 isolation prefix — each slot gets a unique suffix
	isolationPrefix string

	// scoreParams + quarCfg + selection tune the pool the same way
	// applyPoolTuning tunes multitor (SetScoreParams/SetQuarantineConfig/
	// SetSelection mirrors). Zero values mean defaults; the kill-switch
	// (pool.enabled:false) passes zero ScoreParams = pure least-inflight
	// while stats keep recording.
	scoreParams ScoreParams
	scored      atomic.Bool
	quarCfg     QuarantineConfig
	selection   atomic.Value // string: "weighted" (default) or "po2"
	po2Samples  atomic.Int64

	// Connection pool for SOCKS5 connection reuse
	connPool   []*pooledConn
	connPoolMu sync.Mutex
	maxIdle    int
	idleTTL    time.Duration

	// poolGen is bumped by resetAll/Close. Wrappers created before the bump
	// carry a stale gen and discard (close) instead of re-pooling, so a
	// tunnel checked out before a NEWNYM can never be re-inserted after the
	// rotation evicted the pool.
	poolGen atomic.Int64
}

type PoolConfig struct {
	TorAddress        string
	ControlAddr       string
	ControlPass       string
	ControlCookiePath string
	CircuitCount      int
	MaxCircuitAge     int
	MaxFails          int
	MaxAnomaly        int
	Timeout           time.Duration
	MaxIdle           int
	IdleTTL           time.Duration
	Logf              func(format string, args ...interface{})
}

func NewCircuitPoolBackend(cfg PoolConfig) *CircuitPoolBackend {
	if cfg.CircuitCount < 1 {
		cfg.CircuitCount = 3
	}
	if cfg.MaxCircuitAge < 1 {
		cfg.MaxCircuitAge = 50
	}
	if cfg.MaxFails < 1 {
		cfg.MaxFails = 3
	}
	if cfg.MaxAnomaly < 1 {
		cfg.MaxAnomaly = 2
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.MaxIdle < 1 {
		cfg.MaxIdle = cfg.CircuitCount * 4
	}
	if cfg.IdleTTL == 0 {
		cfg.IdleTTL = 5 * time.Minute
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...interface{}) {}
	}

	p := &CircuitPoolBackend{
		torAddr:           cfg.TorAddress,
		controlAddr:       cfg.ControlAddr,
		controlPass:       cfg.ControlPass,
		controlCookiePath: cfg.ControlCookiePath,
		timeout:           cfg.Timeout,
		maxAge:            int64(cfg.MaxCircuitAge),
		maxFails:          int64(cfg.MaxFails),
		maxAnomaly:        int64(cfg.MaxAnomaly),
		socksClient:       transport.NewSOCKS5Client(cfg.Timeout),
		control: func() *TorControlClient {
			c := NewTorControlClient(cfg.ControlAddr, cfg.ControlPass, cookieFileProvider(cfg.ControlCookiePath))
			c.Logf = cfg.Logf
			return c
		}(),
		logf:            cfg.Logf,
		lastNymTime:     time.Now().Add(-10 * time.Second),
		minNymGap:       10 * time.Second,
		nymBackoff:      1,
		isolationPrefix: "relay-" + strconv.Itoa(cryptoRandInt(99999)),
		maxIdle:         cfg.MaxIdle,
		idleTTL:         cfg.IdleTTL,
		connPool:        make([]*pooledConn, 0, cfg.MaxIdle),
	}

	p.slots = make([]*CircuitSlot, cfg.CircuitCount)
	for i := 0; i < cfg.CircuitCount; i++ {
		p.slots[i] = &CircuitSlot{
			id:               i,
			healthy:          true,
			failThreshold:    p.maxFails,
			anomalyThreshold: p.maxAnomaly,
		}
	}
	// Gen 0 is the exempt "unknown generation" outcome (ReportOutcome and
	// RenewProbe skip the staleness check for Gen 0 so pre-claim callers
	// never false-positive). No live claim may carry it: start at 1 so the
	// gate is airtight from boot — mirroring TorInstance.CircuitGen, which
	// normalizes 0 to 1 at the source.
	p.poolGen.Store(1)

	return p
}

// SetScoreParams enables scored selection with the given tuning. The zero
// ScoreParams value disables steering (pure least-inflight); any non-zero
// value enables it. Stats record either way. Mirrors MultiTorBackend.
func (p *CircuitPoolBackend) SetScoreParams(sp ScoreParams) {
	if sp == (ScoreParams{}) {
		p.scored.Store(false)
		return
	}
	if sp.Alpha <= 0 || sp.Alpha > 1 {
		sp.Alpha = DefaultScoreParams().Alpha
	}
	if sp.LatencyRef <= 0 {
		sp.LatencyRef = DefaultScoreParams().LatencyRef
	}
	if sp.MinSamples <= 0 {
		sp.MinSamples = DefaultScoreParams().MinSamples
	}
	if sp.MinQuality <= 0 {
		sp.MinQuality = DefaultScoreParams().MinQuality
	}
	p.scoreParams = sp
	p.scored.Store(true)
}

// SetQuarantineConfig installs the quarantine/probation tuning. The zero
// value selects DefaultQuarantineConfig. Mirrors MultiTorBackend.
func (p *CircuitPoolBackend) SetQuarantineConfig(c QuarantineConfig) {
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
	p.quarCfg = c
}

// SetSelection installs the selection algorithm and Po2 sample size.
// Mirrors MultiTorBackend.SetSelection.
func (p *CircuitPoolBackend) SetSelection(selection string, po2Samples int) {
	if selection != "po2" {
		selection = "weighted"
	}
	if po2Samples < 2 || po2Samples > 8 {
		po2Samples = 2
	}
	p.selection.Store(selection)
	p.po2Samples.Store(int64(po2Samples))
}

// selectionMode returns the live selection algorithm (default weighted).
func (p *CircuitPoolBackend) selectionMode() string {
	if s, ok := p.selection.Load().(string); ok && s == "po2" {
		return "po2"
	}
	return "weighted"
}

// scoreParamsLive returns the live scoring params (defaults when scoring
// disabled — stats still record with the default alpha).
func (p *CircuitPoolBackend) scoreParamsLive() ScoreParams {
	if !p.scored.Load() {
		return ScoreParams{MinQuality: DefaultScoreParams().MinQuality, MinSamples: 1 << 60, Alpha: DefaultScoreParams().Alpha, LatencyRef: DefaultScoreParams().LatencyRef}
	}
	sp := p.scoreParams
	if sp.Alpha <= 0 || sp.Alpha > 1 {
		sp.Alpha = DefaultScoreParams().Alpha
	}
	return sp
}

// quarConfigLive returns the live quarantine tuning (defaults when unset).
func (p *CircuitPoolBackend) quarConfigLive() QuarantineConfig {
	c := p.quarCfg
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

// DialContext picks the healthiest slot and opens a Tor SOCKS5 connection
// through it with per-slot stream isolation. Reuses pooled connections when
// available to eliminate the per-request SOCKS5 handshake overhead.
// Connections are returned optimistically — dead connections are detected
// by the caller on first write/read and discarded with a single retry.
//
// Selection is scored (mirrors MultiTorBackend.selectInstance): healthy,
// non-quarantined slots compete by least EffectiveLoad (in-flight +1 over
// quality, floored at MinQuality), with an all-excluded least-bad fallback
// (never score-induced fail-closed). The "weighted" mode scans all eligible
// slots (rotated by the dial counter so cold-equal slots spread instead of
// pinning slot 0); "po2" samples po2Samples by stride from the shared dial
// counter. With scoring disabled (pool.enabled:false) quality reads
// cold-neutral and the ordering reduces to least-inflight round-robin.
// Quarantined slots are skipped until their hold expires (lazy promotion
// claims the single probe on selection, like the multitor isExcluded hook).
func (p *CircuitPoolBackend) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	dialStart := time.Now()
	total := len(p.slots)
	if total == 0 {
		return nil, fmt.Errorf("circuit pool is empty")
	}

	sp := p.scoreParamsLive()
	now := time.Now()

	// Eligible slots: healthy AND not quarantine-excluded.
	eligible := make([]slotView, 0, total)
	var excludedBest *slotView
	for idx, slot := range p.slots {
		if !slot.IsHealthy() {
			continue
		}
		switch slot.quar.State() {
		case StateActive:
		case StateQuarantined:
			if now.UnixNano() < slot.quar.quarantinedUntil.Load() {
				load := slot.inFlight.Load()
				eff := EffectiveLoad(load, QualityScore(slot.DialSuccesses(), slot.DialFailures(), int64(slot.DialLatencyEWMA()), sp), sp.MinQuality)
				if excludedBest == nil || eff < excludedBest.eff {
					cp := slotView{slot: slot, idx: idx, eff: eff, load: load}
					excludedBest = &cp
				}
				continue
			}
			slot.quar.pollPromotion(now)
			// Promotion lost the race (a rival promoted first and holds
			// the probe, or stole it between our poll and claim): this is
			// a probation-held probe, NOT least-bad fallback fuel.
			// Recording it into excludedBest would serve a second
			// concurrent probe through the all-excluded fallback (probe
			// herd) — mirroring multitor pickBest, which skips
			// StateProbation for fallback. Skip WITHOUT fallback fuel.
			if slot.quar.State() != StateProbation || !slot.quar.claimProbe(now) {
				if slot.quar.State() == StateQuarantined {
					load := slot.inFlight.Load()
					eff := EffectiveLoad(load, QualityScore(slot.DialSuccesses(), slot.DialFailures(), int64(slot.DialLatencyEWMA()), sp), sp.MinQuality)
					if excludedBest == nil || eff < excludedBest.eff {
						cp := slotView{slot: slot, idx: idx, eff: eff, load: load}
						excludedBest = &cp
					}
				}
				continue
			}
		case StateProbation:
			if slot.quar.releaseStaleProbe(now, p.quarConfigLive().Duration) {
				if !slot.quar.claimProbe(now) {
					continue
				}
			} else if !slot.quar.claimProbe(now) {
				continue
			}
		default:
			continue
		}
		load := slot.inFlight.Load()
		eff := EffectiveLoad(load, QualityScore(slot.DialSuccesses(), slot.DialFailures(), int64(slot.DialLatencyEWMA()), sp), sp.MinQuality)
		eligible = append(eligible, slotView{slot: slot, idx: idx, eff: eff, load: load})
	}
	if len(eligible) == 0 {
		// Every candidate excluded (e.g. all quarantined): serve the
		// least-bad excluded one rather than failing closed — unless
		// nothing is even dialable, in which case fall through to the
		// exhaustion path below.
		if excludedBest != nil {
			eligible = append(eligible, *excludedBest)
		} else {
			p.logf("[pool] all slots exhausted, dispatching async NEWNYM")
			p.asyncNEWNYM()
			return nil, fmt.Errorf("circuit pool exhausted: all slots unhealthy")
		}
	}

	// Order eligible by (eff, load, idx) — deterministic. Weighted rotates
	// the order by the dial counter so cold-equal slots spread instead of
	// pinning slot 0; po2 strides a sample from the counter and orders it.
	order := eligible
	if p.selectionMode() == "po2" {
		k := int(p.po2Samples.Load())
		if k < 2 || k > 8 {
			k = 2
		}
		if k > len(eligible) {
			k = len(eligible)
		}
		base := int((uint64(p.current.Add(1)) & 0x7fffffffffffffff) % uint64(len(eligible)))
		order = make([]slotView, 0, k)
		for j := 0; j < k; j++ {
			order = append(order, eligible[(base+j)%len(eligible)])
		}
	} else {
		p.current.Add(1)
	}
	sortSlotViews(order)
	if p.selectionMode() != "po2" && len(order) > 1 {
		// Spread ONLY across the head tie-run: cold-equal slots rotate
		// instead of pinning slot 0, but a strictly-worse slot is never
		// rotated ahead of the best (parity with multitor weighted, which
		// always serves the best). eff ties share the quality*load verdict;
		// float64 equality here is exact-same-inputs equality (same atomics
		// read once into the views), not measured-quantity fuzz.
		run := 1
		for run < len(order) && order[run].eff == order[0].eff && order[run].load == order[0].load {
			run++
		}
		if run > 1 {
			off := int((uint64(p.current.Load()) & 0x7fffffffffffffff) % uint64(run))
			if off != 0 {
				rot := make([]slotView, 0, len(order))
				rot = append(rot, order[off:run]...)
				rot = append(rot, order[:off]...)
				rot = append(rot, order[run:]...)
				order = rot
			}
		}
	}

	for _, sv := range order {
		idx := sv.idx
		slot := sv.slot

		// Try reusing a pooled connection first (optimistic — no alive check).
		// The entry generation rides out atomically with the conn: a
		// resetAll bump interleaving here cannot tag a pre-rotation tunnel
		// with the new generation (it would re-pool as fresh and defeat
		// rotation isolation).
		if conn, entryGen := p.getConn(idx, addr); conn != nil {
			p.recordDialReuse(slot, idx)
			slot.inFlight.Add(1)
			fillClaimSink(ctx, "pool", idx, entryGen, time.Since(dialStart))
			return &pooledConnWrap{Conn: conn, pool: p, slot: slot, slotIdx: idx, addr: addr, gen: entryGen, endpointID: idx, endpointGen: entryGen, dialLatency: time.Since(dialStart)}, nil
		}

		// No pooled connection — create a new one
		conn, err := p.dialTor(ctx, addr, idx)
		if err != nil {
			slot.RecordFailure()
			slot.RecordDialOutcome(false, 0, sp.Alpha)
			// A dial failure on a probation-claimed probe releases the
			// slot (mirrors the multitor releaseProbe path): the failure
			// proves sickness, and holding the claim would wedge the
			// endpoint until expiry.
			if slot.quar.State() == StateProbation {
				slot.quar.probeInFlight.CompareAndSwap(true, false)
			}
			metrics.Default().IncKey(slot.slotDialErrKey(), 1)
			p.logf("[pool] slot %d dial failed: %v", idx, err)
			continue
		}

		p.recordDialSuccess(slot, idx, time.Since(dialStart))
		slot.inFlight.Add(1)
		gen := p.poolGen.Load()
		fillClaimSink(ctx, "pool", idx, gen, time.Since(dialStart))
		return &pooledConnWrap{Conn: conn, pool: p, slot: slot, slotIdx: idx, addr: addr, gen: gen, endpointID: idx, endpointGen: gen, dialLatency: time.Since(dialStart)}, nil
	}

	// All healthy slots exhausted — dispatch async NEWNYM (non-blocking).
	p.logf("[pool] all slots exhausted, dispatching async NEWNYM")
	p.asyncNEWNYM()

	return nil, fmt.Errorf("circuit pool exhausted: all slots unhealthy")
}

// slotDialOKKey/slotDialErrKey are the pre-baked dial counter keys for one
// pool slot (mirrors TorInstance.dialOKKey/dialErrKey): built once per slot,
// IncKey'd on the hot dial path to skip the per-dial map/escape/sort alloc.
func (s *CircuitSlot) slotDialOKKey() string {
	return "relay_pool_slot_dial_ok_total{slot=\"" + strconv.Itoa(s.id) + "\"}"
}

// slotDialErrKey is the pre-baked failure counter key (see slotDialOKKey).
func (s *CircuitSlot) slotDialErrKey() string {
	return "relay_pool_slot_dial_err_total{slot=\"" + strconv.Itoa(s.id) + "\"}"
}

// slotView is one slot's hoisted selection inputs for pool DialContext.
type slotView struct {
	slot *CircuitSlot
	idx  int
	eff  float64
	load int64
}

// sortSlotViews orders views by (eff, load, idx) — deterministic.
func sortSlotViews(v []slotView) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0; j-- {
			a, b := v[j], v[j-1]
			if a.eff < b.eff || (a.eff == b.eff && (a.load < b.load || (a.load == b.load && a.idx < b.idx))) {
				v[j], v[j-1] = v[j-1], v[j]
			} else {
				break
			}
		}
	}
}

// recordDialReuse records a pooled-conn reuse checkout: request/max-age
// bookkeeping, error-backoff reset, and the ok metric — but NO scoring
// sample. The serving tunnel's dial latency was sampled when the tunnel was
// first established; re-sampling ~0 reuse latency would pin EWMA at 0 and
// disable the latency factor, and the request outcome path (ReportOutcome,
// single owner of success/failure samples — mirroring MultiTorBackend's
// single-owner rule) records the authoritative sample for this request.
// Double-counting (reuse sample + outcome sample) would pass the MinSamples
// gate after ~half the requests and halve the effective EWMA alpha.
func (p *CircuitPoolBackend) recordDialReuse(slot *CircuitSlot, idx int) {
	slot.RecordSuccess()
	metrics.Default().IncKey(slot.slotDialOKKey(), 1)
	p.resetErrorBackoff()
	if slot.ShouldRotate(p.maxAge) {
		slot.SetUnhealthy()
		p.logf("[pool] slot %d reached max age, marking for rotation", idx)
	}
}

// recordDialSuccess records a successful dial for a slot: success counters,
// error-backoff reset, scoring sample (success-only EWMA + ok counter with
// the REAL dial latency — a 0 sample would pin EWMA at 0 and disable the
// latency factor), and max-age rotation marking.
func (p *CircuitPoolBackend) recordDialSuccess(slot *CircuitSlot, idx int, latency time.Duration) {
	slot.RecordSuccess()
	slot.RecordDialOutcome(true, latency, p.scoreParamsLive().Alpha)
	metrics.Default().IncKey(slot.slotDialOKKey(), 1)
	p.resetErrorBackoff()
	if slot.ShouldRotate(p.maxAge) {
		slot.SetUnhealthy()
		p.logf("[pool] slot %d reached max age, marking for rotation", idx)
	}
}

// ReportAnomaly marks a slot as having a rate-limit anomaly.
// Triggers a rate-limited NEWNYM when threshold is exceeded.
// A slotIdx of -1 (or out of range) means "unknown slot": the signal is
// unattributed — dispatch the rate-limited NEWNYM WITHOUT marking any slot
// unhealthy. (A previous version guessed via a lastSlot register; that was
// a global last-writer-wins register, and under concurrency it attributed
// to the most recent dialer instead of the failed request's slot, churning
// an innocent slot while the culprit escaped. Attributed callers must pass
func (p *CircuitPoolBackend) ReportAnomaly(slotIdx int) {
	if slotIdx < 0 || slotIdx >= len(p.slots) {
		p.anomalyNEWNYM(-1)
		return
	}
	slot := p.slots[slotIdx]
	slot.RecordAnomaly()
	if slot.AnomalyCount() >= p.maxAnomaly {
		slot.SetUnhealthy()
		p.logf("[pool] slot %d unhealthy after %d anomalies", slotIdx, slot.AnomalyCount())
		p.anomalyNEWNYM(slotIdx)
	}
}

// RenewProbe heartbeats a live probation probe claim on a pool slot:
// mirrors MultiTorBackend.RenewProbe (gen-gated, unknown IDs drop,
// no-op unless Probation with the slot held).
func (p *CircuitPoolBackend) RenewProbe(id int, gen int64) bool {
	if id < 0 || id >= len(p.slots) {
		return false
	}
	if gen != 0 && gen != p.poolGen.Load() {
		return false
	}
	return p.slots[id].quar.renewProbe(time.Now())
}

// ReportOutcome records one attributed request outcome for a pool slot:
// success/failure samples feed the scoring stats (failures skip EWMA),
// and failures drive the quarantine state machine (consec-fails gate OR
// success-rate gate, single attributed NEWNYM per entry, suppression
// while held, single-probe probation with backoff) — mirroring
// MultiTorBackend.ReportOutcome/onEndpointFailure. Outcome.ID is the slot
// index; Outcome.Gen must match the live poolGen (stale = the slot
// rotated since the dial, sample belongs to a dead circuit). Unknown IDs
// and stale gens drop silently, never panic. Success clears consec fails
// AND backoff via recordSuccess (keeps EWMA to decay).
func (p *CircuitPoolBackend) ReportOutcome(o Outcome) {
	if o.ID < 0 || o.ID >= len(p.slots) {
		return
	}
	if o.Gen != 0 && o.Gen != p.poolGen.Load() {
		return
	}
	slot := p.slots[o.ID]
	sp := p.scoreParamsLive()
	slot.RecordDialOutcome(o.Success, o.Latency, sp.Alpha)
	if o.Success {
		slot.quar.recordSuccess()
		return
	}
	cfg := p.quarConfigLive()
	now := time.Now()
	if slot.quar.State() == StateProbation {
		p.requarantineSlot(slot, o.ID, cfg, now)
		return
	}
	enter := slot.quar.recordFailure(cfg.AfterFails)
	if !enter {
		// Success-rate gate mirrors MultiTorBackend.onEndpointFailure: the
		// threshold comes from DefaultScoreParams when steering is off, so
		// the sr<0.3 entry stays live under the kill-switch (exclusion is
		// not steering). scoreParamsLive would force MinSamples=1<<60 and
		// deaden this gate while multitor kept it — a parity break.
		gate := p.scoreParams
		if !p.scored.Load() {
			gate = DefaultScoreParams()
		}
		ok := slot.DialSuccesses()
		fail := slot.DialFailures()
		if total := ok + fail; total >= gate.MinSamples && total > 0 &&
			float64(ok)/float64(total) < 0.3 {
			enter = slot.quar.State() == StateActive
		}
	}
	if !enter {
		return
	}
	p.enterSlotQuarantine(slot, o.ID, cfg, now)
}

// enterSlotQuarantine moves Active->Quarantined (winner-only), fires the
// entry metric + ONE attributed NEWNYM (coalesced via anomalyNEWNYM, which
// shares the nymInflight gate so entry storms collapse).
func (p *CircuitPoolBackend) enterSlotQuarantine(slot *CircuitSlot, idx int, cfg QuarantineConfig, now time.Time) {
	if _, entered := slot.quar.enterQuarantine(now, cfg.Duration, cfg.MaxDuration); !entered {
		return
	}
	p.logf("[pool] slot %d quarantined, holding %v", idx, cfg.Duration)
	metrics.Default().Inc("lano_quarantine_total", map[string]string{
		"instance": "pool-slot-" + strconv.Itoa(idx),
		"reason":   "consec-fails",
	})
	p.anomalyNEWNYM(idx)
}

// requarantineSlot moves Probation->Quarantined with doubled backoff after
// a failed probe. Mirrors MultiTorBackend.requarantine.
func (p *CircuitPoolBackend) requarantineSlot(slot *CircuitSlot, idx int, cfg QuarantineConfig, now time.Time) {
	if !slot.quar.state.CompareAndSwap(int32(StateProbation), int32(StateQuarantined)) {
		return
	}
	slot.quar.probeInFlight.Store(false)
	n := slot.quar.quarantineCount.Add(1)
	d := cfg.Duration
	for i := int64(1); i < n && d < cfg.MaxDuration; i++ {
		d *= 2
		if d > cfg.MaxDuration || d <= 0 {
			d = cfg.MaxDuration
			break
		}
	}
	slot.quar.quarantinedUntil.Store(now.Add(d).UnixNano())
	p.logf("[pool] slot %d re-quarantined (probation-probe-failure), holding %v", idx, d)
	metrics.Default().Inc("lano_quarantine_total", map[string]string{
		"instance": "pool-slot-" + strconv.Itoa(idx),
		"reason":   "probation-probe-failure",
	})
	p.anomalyNEWNYM(idx)
}

func (p *CircuitPoolBackend) dialTor(ctx context.Context, addr string, slotIdx int) (net.Conn, error) {
	// Per-slot isolation username so Tor's IsolateSOCKSAuth assigns each
	// slot its own circuit to the same destination.
	isoUser := p.isolationPrefix + "-slot" + strconv.Itoa(slotIdx)
	conn, err := p.socksClient.Connect(ctx, p.torAddr, addr, isoUser)
	if err != nil {
		return nil, fmt.Errorf("tor dial via socks5 failed: %w", err)
	}
	return conn, nil
}

// rateLimitedNEWNYM sends SIGNAL NEWNYM to Tor with:
//  1. Exponential backoff: minNymGap × nymBackoff (1×=10s, 16×=160s max)
//     nymBackoff DOUBLES on every NEWNYM (not just error-triggered).
//     It resets to 1 on the next successful DialContext call.
//  2. Cookie auth: reads Tor control auth cookie for AUTHENTICATE.
//  3. Rate limiting: skips if elapsed < effective gap.
//
// On success (rotated=true) → caller should call resetAll().
// A cooldown skip returns (false, ErrNymCooldown) — callers MUST NOT reset.
// A signal failure returns (false, err) — slots NOT reset.
func (p *CircuitPoolBackend) rateLimitedNEWNYM() (rotated bool, err error) {
	if p.controlAddr == "" {
		return false, fmt.Errorf("tor control port not configured")
	}

	p.nymMu.Lock()
	effectiveGap := p.minNymGap * time.Duration(p.nymBackoff)
	elapsed := time.Since(p.lastNymTime)
	if elapsed < effectiveGap {
		p.nymMu.Unlock()
		p.logf("[pool] NEWNYM skipped — last was %.0fs ago (need %.0fs, backoff=%dx)",
			elapsed.Seconds(), effectiveGap.Seconds(), p.nymBackoff)
		return false, ErrNymCooldown
	}
	p.lastNymTime = time.Now()
	// Double the backoff on each NEWNYM (cap at 16x = 160s max gap)
	if p.nymBackoff < 16 {
		p.nymBackoff *= 2
	}
	p.nymMu.Unlock()

	if err := p.control.SignalNEWNYM(false); err != nil {
		// Signal failed: refund the budget so a control-port outage does not
		// wedge the backoff toward 160s and delay recovery after Tor returns.
		p.nymMu.Lock()
		p.lastNymTime = time.Now().Add(-effectiveGap)
		if p.nymBackoff > 1 {
			p.nymBackoff /= 2
		}
		p.nymMu.Unlock()
		return false, err
	}

	p.logf("[pool] Tor NEWNYM completed")
	return true, nil
}

// ErrNymCooldown reports that a NEWNYM was skipped because the last rotation
// is still inside the cooldown window. It is NOT a failure: callers must
// simply leave slot health untouched (no resetAll).
var ErrNymCooldown = fmt.Errorf("NEWNYM skipped: inside cooldown window")

// asyncNEWNYM dispatches a non-blocking NEWNYM to a background goroutine.
// Concurrent triggers coalesce onto one in-flight signal (nymInflight) and
// the rate-limiting/backoff logic inside rateLimitedNEWNYM further bounds
// work to one NEWNYM per minNymGap window.
func (p *CircuitPoolBackend) asyncNEWNYM() {
	if !p.nymInflight.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer p.nymInflight.Store(false)
		if rotated, err := p.rateLimitedNEWNYM(); err != nil {
			p.logf("[pool] async NEWNYM failed: %v", err)
		} else if rotated {
			p.resetAll()
			p.logf("[pool] async NEWNYM succeeded, slots reset")
		}
	}()
}

// anomalyNEWNYM is the ReportAnomaly rotation trigger. It shares the same
// coalescing gate as asyncNEWNYM so failure storms cannot spawn one goroutine
// per failure.
func (p *CircuitPoolBackend) anomalyNEWNYM(slotIdx int) {
	if !p.nymInflight.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer p.nymInflight.Store(false)
		if rotated, err := p.rateLimitedNEWNYM(); err != nil {
			p.logf("[pool] anomaly-triggered NEWNYM failed: %v", err)
		} else if rotated {
			p.resetAll()
			p.logf("[pool] anomaly-triggered NEWNYM succeeded, slots reset")
		}
	}()
}

// resetErrorBackoff resets the exponential backoff to 1x (10s gap).
// Called on every successful Tor dial — backoff only stays elevated
// during sustained error storms.
func (p *CircuitPoolBackend) resetErrorBackoff() {
	p.nymMu.Lock()
	p.nymBackoff = 1
	p.nymMu.Unlock()
}

// BackoffMultiplier returns the current exponential backoff multiplier.
// 1 = normal (10s gap), 16 = max (160s gap).
func (p *CircuitPoolBackend) BackoffMultiplier() int64 {
	p.nymMu.Lock()
	defer p.nymMu.Unlock()
	return p.nymBackoff
}

// resetAll marks all slots healthy and resets their counters.
// Also evicts pooled connections since NEWNYM changes circuits and bumps the
// pool generation so in-flight wrappers checked out before the rotation
// discard on Close instead of re-inserting stale tunnels.
// Does NOT reset nymBackoff — that only resets on successful dial
// via resetErrorBackoff().
func (p *CircuitPoolBackend) resetAll() {
	for _, slot := range p.slots {
		slot.Reset()
	}
	p.evictConns()
	p.poolGen.Add(1)
}

// IsHealthy returns true if at least one slot is healthy.
func (p *CircuitPoolBackend) IsHealthy() bool {
	for _, slot := range p.slots {
		if slot.IsHealthy() {
			return true
		}
	}
	return false
}

// VerifyControl checks control-port authentication without changing state:
// it connects, AUTHENTICATEs, and closes. No SIGNAL is issued. A backend
// with no control address configured reports an error so callers can
// distinguish "nothing to verify" from "auth OK".
func (p *CircuitPoolBackend) VerifyControl() error {
	if p.controlAddr == "" {
		return fmt.Errorf("tor control port not configured")
	}
	return p.control.VerifyAuth()
}

// Close marks all slots unhealthy and evicts pooled connections.
func (p *CircuitPoolBackend) Close() error {
	for _, slot := range p.slots {
		slot.SetUnhealthy()
	}
	p.poolGen.Add(1)
	p.evictConns()
	return nil
}

// ForceRotate sends rate-limited NEWNYM and resets all slots only if
// the NEWNYM was actually issued. A cooldown skip (ErrNymCooldown) or a
// signal failure leaves slots in their current health state — no phantom
// reset.
func (p *CircuitPoolBackend) ForceRotate() error {
	rotated, err := p.rateLimitedNEWNYM()
	if err != nil {
		p.logf("[pool] ForceRotate: NEWNYM failed, slots NOT reset: %v", err)
		return err
	}
	if !rotated {
		return ErrNymCooldown
	}
	p.resetAll()
	return nil
}

// Status returns per-slot metrics for health monitoring.
func (p *CircuitPoolBackend) Status() map[string]interface{} {
	type slotInfo struct {
		Healthy      bool    `json:"healthy"`
		RequestCount int64   `json:"request_count"`
		FailCount    int64   `json:"fail_count"`
		AnomalyCount int64   `json:"anomaly_count"`
		LastUsed     string  `json:"last_used"`
		DialEWMAMs   int64   `json:"dial_ewma_ms"`
		DialOK       int64   `json:"dial_ok"`
		DialErr      int64   `json:"dial_err"`
		Quality      float64 `json:"quality"`
		State        string  `json:"state"`
		ConsecFails  int64   `json:"consec_fails"`
	}

	// Status shows live quality params when steering is on and the true
	// DefaultScoreParams quality when the kill-switch is off — mirroring
	// MultiTorBackend.Status. scoreParamsLive would force MinSamples=1<<60
	// and pin displayed quality at 1.0; operators watching /health must see
	// the same quality the sr gate would compute.
	sp := p.scoreParams
	if !p.scored.Load() {
		sp = DefaultScoreParams()
	}
	slots := make([]slotInfo, len(p.slots))
	healthyCount := 0
	totalReqs := int64(0)

	for i, slot := range p.slots {
		ewma := slot.DialLatencyEWMA()
		ok := slot.DialSuccesses()
		fail := slot.DialFailures()
		state := slot.quar.State().String()
		consec := slot.quar.ConsecFails()
		slot.mu.RLock()
		slots[i] = slotInfo{
			Healthy:      slot.healthy,
			RequestCount: slot.requestCount,
			FailCount:    slot.failCount,
			AnomalyCount: slot.anomalyCount,
			LastUsed:     slot.lastUsed.Format(time.RFC3339),
			DialEWMAMs:   ewma.Milliseconds(),
			DialOK:       ok,
			DialErr:      fail,
			Quality:      QualityScore(ok, fail, int64(ewma), sp),
			State:        state,
			ConsecFails:  consec,
		}
		if slot.healthy {
			healthyCount++
		}
		totalReqs += slot.requestCount
		slot.mu.RUnlock()
	}

	m := map[string]interface{}{
		"type":              "circuit_pool",
		"total_slots":       len(p.slots),
		"healthy_slots":     healthyCount,
		"total_requests":    totalReqs,
		"tor_address":       p.torAddr,
		"slots":             slots,
		"nym_backoff":       p.BackoffMultiplier(),
		"nym_effective_gap": fmt.Sprintf("%.0fs", p.minNymGap.Seconds()*float64(p.BackoffMultiplier())),
	}

	p.nymMu.Lock()
	m["last_newnym_ago"] = time.Since(p.lastNymTime).String()
	m["last_newnym"] = p.lastNymTime.Format(time.RFC3339)
	p.nymMu.Unlock()

	// Selection provenance, mirroring MultiTorBackend.Status: emitted only
	// when steering is on so kill-switch-off Status reads identically
	// stock (no novel keys for scrapers that pin the shape).
	if p.scored.Load() {
		m["scored_selection"] = true
		m["selection"] = p.selectionMode()
	}

	return m
}

// RotateRandomSlot picks a random slot and marks it unhealthy.
// Does NOT call NEWNYM — the caller should call ForceRotate separately.
func (p *CircuitPoolBackend) RotateRandomSlot() {
	total := len(p.slots)
	if total == 0 {
		return
	}
	idx := cryptoRandInt(total)
	p.slots[idx].SetUnhealthy()
	p.logf("[pool] randomly rotated slot %d", idx)
}

// CheckTorReachable probes whether the Tor SOCKS5 endpoint is reachable and
// answers a SOCKS5 no-auth greeting handshake. A bare TCP dial alone would
// succeed against any listener (including a non-Tor process), so the greeting
// write/read distinguishes a live SOCKS5 server. Uses 5s deadlines throughout.
func (p *CircuitPoolBackend) CheckTorReachable() bool {
	addr := p.torAddr
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return false
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return false
	}
	return resp[0] == 0x05 && resp[1] == 0x00
}

// cryptoRandInt returns a uniform random int in [0, max) using crypto/rand.
func cryptoRandInt(max int) int {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0
	}
	return int(n.Int64())
}

// =============================================================================
// CONNECTION POOL — Per-destination tunnel pooling
//
// Tor does NOT support multiple SOCKS5 sessions on the same TCP connection.
// After a SOCKS5 tunnel closes, Tor sends FIN/RST on the socket, making it
// unusable. This was verified with integration tests against real Tor.
//
// Therefore, we pool POST-CONNECT tunnels, keyed by (slotIdx, destAddr).
// Same destination → reuse tunnel (skip TCP + SOCKS5 handshake).
// Different destination → new TCP + SOCKS5 handshake (no reuse possible).
//
// Lifecycle:
//   dialTor() → TCP dial + SOCKS5 handshake + CONNECT → tunnel
//   getConn(slot, addr) → return pooled tunnel for same destination
//   caller Close() → putConn(slot, addr, tunnel) → return to pool
// =============================================================================

type pooledConn struct {
	conn      net.Conn
	key       string // slotIdx+dest — connections are per-destination tunnels
	createdAt time.Time
	// gen is the pool generation at put time. A wrapper checked out after
	// a resetAll bump carries a stale gen and discards (closes) instead of
	// re-pooling; stamping the entry lets getConn hand out conn+gen
	// atomically so DialContext can never tag a pre-rotation tunnel fresh.
	gen int64
}

func poolKey(slotIdx int, addr string) string {
	return string(append([]byte(strconv.Itoa(slotIdx)), ':')) + addr
}

// pooledConnWrap wraps a net.Conn so that Close() returns it to the pool
// instead of closing the underlying socket. This makes the HTTP transport's
// connection lifecycle transparent to the pool.
// gen is the pool generation at checkout time; wrappers that outlive a
// resetAll/Close (a NEWNYM evicted the pool while they were checked out)
// close the socket on Close instead of re-pooling a stale tunnel.
// errored marks a tunnel that the caller observed as broken (spent,
// half-closed, RST) — Discard or a failed write/read prevents it from ever
// re-entering the pool. Close on an errored wrapper closes the socket.
type pooledConnWrap struct {
	net.Conn
	pool     *CircuitPoolBackend
	slot     *CircuitSlot
	slotIdx  int
	addr     string
	gen      int64
	returned atomic.Bool
	errored  atomic.Bool
	// endpointID/endpointGen/dialLatency carry the scored-selection claim
	// for this dial (outcome.go): slot index + pool generation at checkout
	// and the dial latency sample. Pure attribution metadata — Close/
	// Discard pooling semantics are unchanged.
	endpointID  int
	endpointGen int64
	dialLatency time.Duration
}

// EndpointID returns the serving slot index carried by this dial.
func (w *pooledConnWrap) EndpointID() int { return w.endpointID }

// EndpointGen returns the pool generation at checkout time.
func (w *pooledConnWrap) EndpointGen() int64 { return w.endpointGen }

// DialLatency returns the dial latency sample for this dial.
func (w *pooledConnWrap) DialLatency() time.Duration { return w.dialLatency }

func (w *pooledConnWrap) Close() error {
	if w.returned.Swap(true) {
		return nil // already returned
	}
	// Balance the slot.inFlight Add(1) taken at checkout in DialContext.
	// Exactly-once: returned CAS above guarantees one decrement even
	// across Close/Discard double-calls (mirrors inFlightConn).
	if w.slot != nil {
		w.slot.inFlight.Add(-1)
	}
	if w.errored.Load() || w.gen != w.pool.poolGen.Load() {
		return w.Conn.Close()
	}
	w.pool.putConn(w.slotIdx, w.addr, w.Conn)
	return nil
}

// Discard closes the underlying socket and marks the wrapper so a later
// (double) Close never re-pools the spent tunnel. Call this when the caller
// observed a write/read failure, a half-close, or any condition proving the
// tunnel is unusable — it prevents dead tunnels from being handed to the
// next dial.
func (w *pooledConnWrap) Discard() error {
	w.errored.Store(true)
	return w.Close()
}

// Write passes through and latches the errored flag on failure, so a tunnel
// that died mid-request is closed (not re-pooled) when the caller Closes it —
// no call-site change needed: the first failed I/O arms the discard.
func (w *pooledConnWrap) Write(b []byte) (int, error) {
	n, err := w.Conn.Write(b)
	if err != nil {
		w.errored.Store(true)
	}
	return n, err
}

// Read passes through and latches the errored flag on failure (including EOF:
// EOF means the peer closed, so the tunnel is dead for reuse). A clean,
// fully-consumed keep-alive response returns err==nil and stays poolable.
func (w *pooledConnWrap) Read(b []byte) (int, error) {
	n, err := w.Conn.Read(b)
	if err != nil {
		w.errored.Store(true)
	}
	return n, err
}

// MarkBroken is an alias kept for call-site readability where the failure is
// an I/O error rather than an explicit discard decision.
func (w *pooledConnWrap) MarkBroken() { w.errored.Store(true) }

func (w *pooledConnWrap) Unwrap() net.Conn {
	return w.Conn
}

func (w *pooledConnWrap) CloseWrite() error {
	if cw, ok := w.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (p *CircuitPoolBackend) getConn(slotIdx int, addr string) (net.Conn, int64) {
	p.connPoolMu.Lock()

	key := poolKey(slotIdx, addr)
	now := time.Now()

	for i, pc := range p.connPool {
		if pc.key != key {
			continue
		}
		if now.Sub(pc.createdAt) >= p.idleTTL {
			// Lazy TTL reap on the read path: an expired entry is closed
			// inline instead of being handed out. Semantics unchanged —
			// IdleTTL still governs expiry, this just enforces it eagerly.
			conn := pc.conn
			p.connPool[i] = p.connPool[len(p.connPool)-1]
			p.connPool[len(p.connPool)-1] = nil
			p.connPool = p.connPool[:len(p.connPool)-1]
			p.connPoolMu.Unlock()
			conn.Close()
			// Expired entries are rare; re-scan for a fresh match.
			return p.getConn(slotIdx, addr)
		}
		conn := pc.conn
		gen := pc.gen
		p.connPool[i] = p.connPool[len(p.connPool)-1]
		p.connPool[len(p.connPool)-1] = nil
		p.connPool = p.connPool[:len(p.connPool)-1]
		p.connPoolMu.Unlock()
		return conn, gen
	}
	p.connPoolMu.Unlock()
	return nil, 0
}

func (p *CircuitPoolBackend) putConn(slotIdx int, addr string, conn net.Conn) {
	if conn == nil {
		return
	}
	p.connPoolMu.Lock()

	// NOTE: a "liveness" probe read from this conn was tried and reverted.
	// It raced with the SOCKS5 server's own read deadline machinery and
	// dropped the tunnel reliably in pool_test.go. Pooled conns here are
	// POST-CONNECT tunnels (SOCKS5 CONNECT already completed) — if the peer
	// closed cleanly there is nothing readable and the probe misfires. Dead
	// pooled conns are detected by the caller on first write/read and are
	// discarded there (see handleHTTP / handleConnect).

	if len(p.connPool) >= p.maxIdle {
		// Pool full — amortize the stale-connection scan onto the overflow
		// path instead of paying it on every put. evictStaleLocked compacts
		// in place WITHOUT releasing the mutex; closes happen AFTER the
		// lock is released so a wedged peer cannot stall dials holding it.
		stale := p.evictStaleLocked()
		p.connPoolMu.Unlock()
		for _, c := range stale {
			c.Close()
		}
		p.connPoolMu.Lock()
	}

	if len(p.connPool) >= p.maxIdle {
		old := p.connPool[0]
		p.connPool[0] = nil
		p.connPool = p.connPool[1:]
		p.connPoolMu.Unlock()
		old.conn.Close()
		p.connPoolMu.Lock()
	}

	p.connPool = append(p.connPool, &pooledConn{
		conn:      conn,
		key:       poolKey(slotIdx, addr),
		createdAt: time.Now(),
		gen:       p.poolGen.Load(),
	})
	p.connPoolMu.Unlock()
}

// evictStaleLocked compacts idle-expired connections in place and returns
// the expired sockets WITHOUT closing them: the caller must close them after
// releasing connPoolMu so a wedged peer cannot stall dials holding the mutex.
// Callers must hold connPoolMu; the lock is never released inside, so no
// intermediate Unlock/Lock window exists for a concurrent mutator.
func (p *CircuitPoolBackend) evictStaleLocked() []net.Conn {
	now := time.Now()
	var stale []net.Conn
	n := 0
	for _, pc := range p.connPool {
		if now.Sub(pc.createdAt) < p.idleTTL {
			p.connPool[n] = pc
			n++
		} else {
			stale = append(stale, pc.conn)
		}
	}
	for i := n; i < len(p.connPool); i++ {
		p.connPool[i] = nil
	}
	p.connPool = p.connPool[:n]
	return stale
}

func (p *CircuitPoolBackend) evictConns() {
	p.connPoolMu.Lock()
	// Copy-on-evict: hand the evictor its own slice and reset the live pool
	// to a FRESH slice (not p.connPool[:0], which aliases the backing array).
	// The alias let a concurrent putConn append overwrite entries the evictor
	// was about to close — use-after-evict closing a just-pooled tunnel —
	// and fired a -race report (putConn append vs evictConns iteration).
	conns := make([]*pooledConn, len(p.connPool))
	copy(conns, p.connPool)
	for i := range p.connPool {
		p.connPool[i] = nil
	}
	p.connPool = make([]*pooledConn, 0, p.maxIdle)
	p.connPoolMu.Unlock()
	for _, pc := range conns {
		pc.conn.Close()
	}
}

// isConnAlive performs a structural check only — never reads from the socket.
// Returns false for nil connections or those with no local address.
// Dead/broken connections are not detected here; they are caught on first
// write/read by the caller and discarded with a retry.
func isConnAlive(conn net.Conn) bool {
	return conn != nil && conn.LocalAddr() != nil
}

// --- CircuitSlot methods ---

func (s *CircuitSlot) IsHealthy() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.healthy
}

func (s *CircuitSlot) SetUnhealthy() {
	s.mu.Lock()
	s.healthy = false
	s.mu.Unlock()
}

func (s *CircuitSlot) RecordSuccess() {
	s.mu.Lock()
	s.requestCount++
	s.failCount = 0
	s.anomalyCount = 0
	s.lastUsed = time.Now()
	// Do NOT auto-heal healthy flag here. Slots are only restored
	// to healthy via resetAll() (after successful NEWNYM) or Reset().
	// This prevents RecordSuccess from undoing intentional rotation
	// from SetUnhealthy() (e.g. maxAge or RotateRandomSlot).
	s.mu.Unlock()
}

func (s *CircuitSlot) RecordFailure() {
	s.mu.Lock()
	s.failCount++
	if s.failCount >= s.failThreshold {
		s.healthy = false
	}
	s.mu.Unlock()
}

func (s *CircuitSlot) RecordAnomaly() {
	s.mu.Lock()
	s.anomalyCount++
	s.mu.Unlock()
}

func (s *CircuitSlot) AnomalyCount() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.anomalyCount
}

func (s *CircuitSlot) ShouldRotate(maxAge int64) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.requestCount >= maxAge
}

func (s *CircuitSlot) Reset() {
	s.mu.Lock()
	s.healthy = true
	s.failCount = 0
	s.requestCount = 0
	s.anomalyCount = 0
	s.lastUsed = time.Now()
	s.mu.Unlock()
	// NOTE: scoring stats (s.stats) are intentionally NOT cleared here.
	// Rotation is not a cure — a slow exit stays slow after NEWNYM, and
	// clearing EWMA on every resetAll would let a sick slot flap back to
	// neutral every rotation. Only probation success clears (quarantine.go).
}

// --- additive latency/quality scoring (score.go) ---

// RecordDialOutcome logs one dial outcome into the lock-free scoring stats.
// Safe on the hot dial path (atomics only, no slot mutex).
func (s *CircuitSlot) RecordDialOutcome(success bool, latency time.Duration, alpha float64) {
	s.stats.Record(success, latency, alpha)
}

// DialSuccesses returns the scored success count (cold = 0, neutral).
func (s *CircuitSlot) DialSuccesses() int64 { return s.stats.Successes() }

// DialFailures returns the scored failure count.
func (s *CircuitSlot) DialFailures() int64 { return s.stats.Failures() }

// DialLatencyEWMA returns the success-only EWMA dial latency (0 = no samples).
func (s *CircuitSlot) DialLatencyEWMA() time.Duration { return s.stats.LatencyEWMA() }
