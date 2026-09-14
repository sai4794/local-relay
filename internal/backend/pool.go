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
	stats            EndpointStats // lock-free dial latency/quality scoring (score.go); cold-zero is neutral
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
	lastSlot          atomic.Int64

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
	p.lastSlot.Store(-1)

	return p
}

// DialContext picks the healthiest slot and opens a Tor SOCKS5 connection
// through it with per-slot stream isolation. Reuses pooled connections when
// available to eliminate the per-request SOCKS5 handshake overhead.
// Connections are returned optimistically — dead connections are detected
// by the caller on first write/read and discarded with a single retry.
func (p *CircuitPoolBackend) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	dialStart := time.Now()
	total := len(p.slots)
	if total == 0 {
		return nil, fmt.Errorf("circuit pool is empty")
	}

	// Round-robin start with wrap-safe masking: p.current.Add(1) wraps
	// int64 after 2^63 dials (or via test injection), and a negative
	// remainder would index p.slots out of range. The bitmask strips the
	// sign so the sequence stays non-negative across the wrap.
	start := int((uint64(p.current.Add(1)) & 0x7fffffffffffffff) % uint64(total))

	for i := 0; i < total; i++ {
		idx := (start + i) % total
		slot := p.slots[idx]

		if !slot.IsHealthy() {
			continue
		}

		// Try reusing a pooled connection first (optimistic — no alive check).
		// The entry generation rides out atomically with the conn: a
		// resetAll bump interleaving here cannot tag a pre-rotation tunnel
		// with the new generation (it would re-pool as fresh and defeat
		// rotation isolation).
		if conn, entryGen := p.getConn(idx, addr); conn != nil {
			p.lastSlot.Store(int64(idx))
			p.recordDialSuccess(slot, idx)
			fillClaimSink(ctx, "pool", idx, entryGen, time.Since(dialStart))
			return &pooledConnWrap{Conn: conn, pool: p, slotIdx: idx, addr: addr, gen: entryGen, endpointID: idx, endpointGen: entryGen, dialLatency: time.Since(dialStart)}, nil
		}

		// No pooled connection — create a new one
		conn, err := p.dialTor(ctx, addr, idx)
		if err != nil {
			slot.RecordFailure()
			slot.RecordDialOutcome(false, 0, DefaultScoreParams().Alpha)
			metrics.Default().Inc("relay_pool_slot_dial_err_total", map[string]string{"slot": strconv.Itoa(idx)})
			p.logf("[pool] slot %d dial failed: %v", idx, err)
			continue
		}

		p.lastSlot.Store(int64(idx))
		p.recordDialSuccess(slot, idx)
		gen := p.poolGen.Load()
		fillClaimSink(ctx, "pool", idx, gen, time.Since(dialStart))
		return &pooledConnWrap{Conn: conn, pool: p, slotIdx: idx, addr: addr, gen: gen, endpointID: idx, endpointGen: gen, dialLatency: time.Since(dialStart)}, nil
	}

	// All healthy slots exhausted — dispatch async NEWNYM (non-blocking).
	p.logf("[pool] all slots exhausted, dispatching async NEWNYM")
	p.asyncNEWNYM()

	return nil, fmt.Errorf("circuit pool exhausted: all slots unhealthy")
}

// recordDialSuccess records a successful dial for a slot: success counters,
// error-backoff reset, scoring sample (success-only EWMA + ok counter), and
// max-age rotation marking.
func (p *CircuitPoolBackend) recordDialSuccess(slot *CircuitSlot, idx int) {
	slot.RecordSuccess()
	slot.RecordDialOutcome(true, 0, DefaultScoreParams().Alpha)
	metrics.Default().Inc("relay_pool_slot_dial_ok_total", map[string]string{"slot": strconv.Itoa(idx)})
	p.resetErrorBackoff()
	if slot.ShouldRotate(p.maxAge) {
		slot.SetUnhealthy()
		p.logf("[pool] slot %d reached max age, marking for rotation", idx)
	}
}

// ReportAnomaly marks a slot as having a rate-limit anomaly.
// Triggers a rate-limited NEWNYM when threshold is exceeded.
// A slotIdx of -1 (or out of range) means "unknown slot": the most recently
// served slot (tracked via lastSlot) is used when valid. With no serving
// history (cold backend, lastSlot==-1) the rate-limited NEWNYM is still
// dispatched but WITHOUT marking a random slot unhealthy and WITHOUT the
// ResetRequests+OnRotate churn — there is no culprit to attribute yet.
func (p *CircuitPoolBackend) ReportAnomaly(slotIdx int) {
	if slotIdx < 0 || slotIdx >= len(p.slots) {
		if last := int(p.lastSlot.Load()); last >= 0 && last < len(p.slots) {
			slotIdx = last
		} else {
			p.anomalyNEWNYM(-1)
			return
		}
	}
	slot := p.slots[slotIdx]
	slot.RecordAnomaly()
	if slot.AnomalyCount() >= p.maxAnomaly {
		slot.SetUnhealthy()
		p.logf("[pool] slot %d unhealthy after %d anomalies", slotIdx, slot.AnomalyCount())
		p.anomalyNEWNYM(slotIdx)
	}
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

	sp := DefaultScoreParams()
	slots := make([]slotInfo, len(p.slots))
	healthyCount := 0
	totalReqs := int64(0)

	for i, slot := range p.slots {
		ewma := slot.DialLatencyEWMA()
		ok := slot.DialSuccesses()
		fail := slot.DialFailures()
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
			State:        "active",
			ConsecFails:  0,
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
