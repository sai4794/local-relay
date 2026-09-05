package backend

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

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
	dialer            *net.Dialer
	socksClient       *transport.SOCKS5Client
	control           *TorControlClient
	logf              func(format string, args ...interface{})

	// NEWNYM rate limiting with exponential backoff
	lastNymTime time.Time
	nymMu       sync.Mutex
	minNymGap   time.Duration
	nymBackoff  int64 // doubles on each NEWNYM (1, 2, 4, 8, 16); resets on success

	// Tor SOCKS5 isolation prefix — each slot gets a unique suffix
	isolationPrefix string

	// Connection pool for SOCKS5 connection reuse
	connPool   []*pooledConn
	connPoolMu sync.Mutex
	maxIdle    int
	idleTTL    time.Duration
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
		dialer:            &net.Dialer{Timeout: cfg.Timeout},
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
		isolationPrefix: fmt.Sprintf("relay-%d", cryptoRandInt(99999)),
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

	return p
}

// DialContext picks the healthiest slot and opens a Tor SOCKS5 connection
// through it with per-slot stream isolation. Reuses pooled connections when
// available to eliminate the per-request SOCKS5 handshake overhead.
// Connections are returned optimistically — dead connections are detected
// by the caller on first write/read and discarded with a single retry.
func (p *CircuitPoolBackend) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	total := len(p.slots)
	if total == 0 {
		return nil, fmt.Errorf("circuit pool is empty")
	}

	// Try healthy slots round-robin
	start := p.current.Add(1) % int64(total)

	for i := 0; i < total; i++ {
		idx := int((start + int64(i)) % int64(total))
		slot := p.slots[idx]

		if !slot.IsHealthy() {
			continue
		}

		// Try reusing a pooled connection first (optimistic — no alive check)
		if conn := p.getConn(idx, addr); conn != nil {
			slot.RecordSuccess()
			p.resetErrorBackoff()
			if slot.ShouldRotate(p.maxAge) {
				slot.SetUnhealthy()
				p.logf("[pool] slot %d reached max age, marking for rotation", idx)
			}
			return &pooledConnWrap{Conn: conn, pool: p, slotIdx: idx, addr: addr}, nil
		}

		// No pooled connection — create a new one
		conn, err := p.dialTor(ctx, addr, idx)
		if err != nil {
			slot.RecordFailure()
			p.logf("[pool] slot %d dial failed: %v", idx, err)
			continue
		}

		slot.RecordSuccess()
		p.resetErrorBackoff()
		if slot.ShouldRotate(p.maxAge) {
			slot.SetUnhealthy()
			p.logf("[pool] slot %d reached max age, marking for rotation", idx)
		}
		return &pooledConnWrap{Conn: conn, pool: p, slotIdx: idx, addr: addr}, nil
	}

	// All healthy slots exhausted — dispatch async NEWNYM (non-blocking).
	p.logf("[pool] all slots exhausted, dispatching async NEWNYM")
	p.asyncNEWNYM()

	return nil, fmt.Errorf("circuit pool exhausted: all slots unhealthy")
}

// ReportAnomaly marks a slot as having a rate-limit anomaly.
// Triggers a rate-limited NEWNYM when threshold is exceeded.
func (p *CircuitPoolBackend) ReportAnomaly(slotIdx int) {
	if slotIdx < 0 || slotIdx >= len(p.slots) {
		p.RotateRandomSlot()
		go func() {
			if err := p.rateLimitedNEWNYM(); err != nil {
				p.logf("[pool] anomaly-triggered NEWNYM failed: %v", err)
			}
		}()
		return
	}
	slot := p.slots[slotIdx]
	slot.RecordAnomaly()
	if slot.AnomalyCount() >= p.maxAnomaly {
		slot.SetUnhealthy()
		p.logf("[pool] slot %d unhealthy after %d anomalies", slotIdx, slot.AnomalyCount())
		go func() {
			if err := p.rateLimitedNEWNYM(); err != nil {
				p.logf("[pool] anomaly-triggered NEWNYM failed: %v", err)
			}
		}()
	}
}

func (p *CircuitPoolBackend) dialTor(ctx context.Context, addr string, slotIdx int) (net.Conn, error) {
	// Per-slot isolation username so Tor's IsolateSOCKSAuth assigns each
	// slot its own circuit to the same destination.
	isoUser := fmt.Sprintf("%s-slot%d", p.isolationPrefix, slotIdx)
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
// On success → caller should call resetAll(). On failure → slots NOT reset.
func (p *CircuitPoolBackend) rateLimitedNEWNYM() error {
	if p.controlAddr == "" {
		return fmt.Errorf("tor control port not configured")
	}

	p.nymMu.Lock()
	effectiveGap := p.minNymGap * time.Duration(p.nymBackoff)
	elapsed := time.Since(p.lastNymTime)
	if elapsed < effectiveGap {
		p.nymMu.Unlock()
		p.logf("[pool] NEWNYM skipped — last was %.0fs ago (need %.0fs, backoff=%dx)",
			elapsed.Seconds(), effectiveGap.Seconds(), p.nymBackoff)
		return nil
	}
	p.lastNymTime = time.Now()
	// Double the backoff on each NEWNYM (cap at 16x = 160s max gap)
	if p.nymBackoff < 16 {
		p.nymBackoff *= 2
	}
	p.nymMu.Unlock()

	if err := p.control.SignalNEWNYM(false); err != nil {
		return err
	}

	p.logf("[pool] Tor NEWNYM completed")
	return nil
}

// asyncNEWNYM dispatches a non-blocking NEWNYM to a background goroutine.
// The rate-limiting and backoff logic inside rateLimitedNEWNYM prevents
// goroutine explosion — at most one NEWNYM runs per minNymGap window.
func (p *CircuitPoolBackend) asyncNEWNYM() {
	go func() {
		if err := p.rateLimitedNEWNYM(); err != nil {
			p.logf("[pool] async NEWNYM failed: %v", err)
		} else {
			p.resetAll()
			p.logf("[pool] async NEWNYM succeeded, slots reset")
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
// Also evicts pooled connections since NEWNYM changes circuits.
// Does NOT reset nymBackoff — that only resets on successful dial
// via resetErrorBackoff().
func (p *CircuitPoolBackend) resetAll() {
	for _, slot := range p.slots {
		slot.Reset()
	}
	p.evictConns()
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

// Close marks all slots unhealthy and evicts pooled connections.
func (p *CircuitPoolBackend) Close() error {
	for _, slot := range p.slots {
		slot.SetUnhealthy()
	}
	p.evictConns()
	return nil
}

// ForceRotate sends rate-limited NEWNYM and resets all slots only if
// the NEWNYM succeeded. If control port is unreachable, slots stay
// in their current health state — no phantom reset.
func (p *CircuitPoolBackend) ForceRotate() error {
	err := p.rateLimitedNEWNYM()
	if err != nil {
		p.logf("[pool] ForceRotate: NEWNYM failed, slots NOT reset: %v", err)
		return err
	}
	p.resetAll()
	return nil
}

// Status returns per-slot metrics for health monitoring.
func (p *CircuitPoolBackend) Status() map[string]interface{} {
	type slotInfo struct {
		Healthy      bool   `json:"healthy"`
		RequestCount int64  `json:"request_count"`
		FailCount    int64  `json:"fail_count"`
		AnomalyCount int64  `json:"anomaly_count"`
		LastUsed     string `json:"last_used"`
	}

	slots := make([]slotInfo, len(p.slots))
	healthyCount := 0
	totalReqs := int64(0)

	for i, slot := range p.slots {
		slot.mu.RLock()
		slots[i] = slotInfo{
			Healthy:      slot.healthy,
			RequestCount: slot.requestCount,
			FailCount:    slot.failCount,
			AnomalyCount: slot.anomalyCount,
			LastUsed:     slot.lastUsed.Format(time.RFC3339),
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
}

func poolKey(slotIdx int, addr string) string {
	return string(append([]byte(strconv.Itoa(slotIdx)), ':')) + addr
}

// pooledConnWrap wraps a net.Conn so that Close() returns it to the pool
// instead of closing the underlying socket. This makes the HTTP transport's
// connection lifecycle transparent to the pool.
type pooledConnWrap struct {
	net.Conn
	pool     *CircuitPoolBackend
	slotIdx  int
	addr     string
	returned atomic.Bool
}

func (w *pooledConnWrap) Close() error {
	if w.returned.Swap(true) {
		return nil // already returned
	}
	w.pool.putConn(w.slotIdx, w.addr, w.Conn)
	return nil
}

func (w *pooledConnWrap) Unwrap() net.Conn {
	return w.Conn
}

func (w *pooledConnWrap) CloseWrite() error {
	if cw, ok := w.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (p *CircuitPoolBackend) getConn(slotIdx int, addr string) net.Conn {
	p.connPoolMu.Lock()
	defer p.connPoolMu.Unlock()

	key := poolKey(slotIdx, addr)
	now := time.Now()

	for i, pc := range p.connPool {
		if pc.key == key && now.Sub(pc.createdAt) < p.idleTTL {
			conn := pc.conn
			p.connPool[i] = p.connPool[len(p.connPool)-1]
			p.connPool[len(p.connPool)-1] = nil
			p.connPool = p.connPool[:len(p.connPool)-1]
			return conn
		}
	}
	return nil
}

func (p *CircuitPoolBackend) putConn(slotIdx int, addr string, conn net.Conn) {
	if conn == nil {
		return
	}
	p.connPoolMu.Lock()
	defer p.connPoolMu.Unlock()

	p.evictStale()

	// NOTE: a "liveness" probe read from this conn was tried and reverted.
	// It raced with the SOCKS5 server's own read deadline machinery and
	// dropped the tunnel reliably in pool_test.go. Pooled conns here are
	// POST-CONNECT tunnels (SOCKS5 CONNECT already completed) — if the peer
	// closed cleanly there is nothing readable and the probe misfires. Dead
	// pooled conns are detected by the caller on first write/read and are
	// discarded there (see handleHTTP / handleConnect).

	if len(p.connPool) >= p.maxIdle {
		old := p.connPool[0]
		p.connPool[0] = nil
		p.connPool = p.connPool[1:]
		old.conn.Close()
	}

	p.connPool = append(p.connPool, &pooledConn{
		conn:      conn,
		key:       poolKey(slotIdx, addr),
		createdAt: time.Now(),
	})
}

func (p *CircuitPoolBackend) evictStale() {
	now := time.Now()
	n := 0
	for _, pc := range p.connPool {
		if now.Sub(pc.createdAt) < p.idleTTL {
			p.connPool[n] = pc
			n++
		} else {
			pc.conn.Close()
		}
	}
	for i := n; i < len(p.connPool); i++ {
		p.connPool[i] = nil
	}
	p.connPool = p.connPool[:n]
}

func (p *CircuitPoolBackend) evictConns() {
	p.connPoolMu.Lock()
	defer p.connPoolMu.Unlock()
	for _, pc := range p.connPool {
		pc.conn.Close()
	}
	p.connPool = p.connPool[:0]
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
}
