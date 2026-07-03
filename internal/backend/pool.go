package backend

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// CircuitSlot tracks the health and usage of one Tor circuit path.
type CircuitSlot struct {
	id           int
	healthy      bool
	failCount    int64
	failThreshold int64
	requestCount int64
	lastUsed     time.Time
	anomalyCount int64
	anomalyThreshold int64
	mu           sync.RWMutex
}

// CircuitPoolBackend manages multiple concurrent Tor circuits for
// exit-node diversity and rate-limit resilience.
//
// Rotation is driven by TWO mechanisms:
//   1. Rotator (request-count-based, in rotate/rotator.go):
//      Fires ForceRotate() every N requests (config rotation.interval).
//      This provides proactive circuit churn independent of errors.
//   2. Error-driven (in HTTP/SOCKS5 proxy handlers):
//      Fires ForceRotate() on 429/503, timeouts, DNS failures, etc.
//      This provides reactive rotation when circuits are blocked.
//
// Additionally, each slot's maxAge (50 requests) marks it unhealthy
// for round-robin avoidance, but does NOT itself trigger a NEWNYM.
// A new circuit only comes from ForceRotate() or pool exhaustion.
type CircuitPoolBackend struct {
	slots       []*CircuitSlot
	torAddr     string
	controlAddr string
	controlPass string
	timeout     time.Duration
	maxAge      int64
	maxFails    int64
	maxAnomaly  int64
	current     atomic.Int64
	dialer      *net.Dialer
	logf        func(format string, args ...interface{})

	// NEWNYM rate limiting with exponential backoff
	lastNymTime      time.Time
	nymMu            sync.Mutex
	minNymGap        time.Duration
	nymBackoff       int64 // doubles on each NEWNYM (1, 2, 4, 8, 16); resets on success

	// Tor control auth
	controlCookiePath string

	// Tor SOCKS5 isolation prefix — each slot gets a unique suffix
	isolationPrefix string
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
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...interface{}) {}
	}

	p := &CircuitPoolBackend{
		torAddr:         cfg.TorAddress,
		controlAddr:      cfg.ControlAddr,
		controlPass:      cfg.ControlPass,
		controlCookiePath: cfg.ControlCookiePath,
		timeout:         cfg.Timeout,
		maxAge:          int64(cfg.MaxCircuitAge),
		maxFails:        int64(cfg.MaxFails),
		maxAnomaly:      int64(cfg.MaxAnomaly),
		dialer:          &net.Dialer{Timeout: cfg.Timeout},
		logf:            cfg.Logf,
		lastNymTime:     time.Now().Add(-10 * time.Second),
		minNymGap:       10 * time.Second,
		nymBackoff:    1,
		isolationPrefix: fmt.Sprintf("relay-%d", cryptoRandInt(99999)),
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

// DialContext picks the healthiest slot and opens a fresh Tor SOCKS5
// connection through it with per-slot stream isolation. If all slots
// are unhealthy, it tries a NEWNYM with rate limiting.
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
		return conn, nil
	}

	// All healthy slots exhausted — try rate-limited NEWNYM
	p.logf("[pool] all slots exhausted, requesting NEWNYM")
	if err := p.rateLimitedNEWNYM(); err != nil {
		p.logf("[pool] NEWNYM failed: %v", err)
	} else {
		p.resetAll()
	}

	conn, err := p.dialTor(ctx, addr, 0)
	if err != nil {
		return nil, fmt.Errorf("circuit pool exhausted: %w", err)
	}

	p.slots[0].RecordSuccess()
	p.resetErrorBackoff()
	return conn, nil
}

// DialContextWithSlot returns the slot index for anomaly reporting.
func (p *CircuitPoolBackend) DialContextWithSlot(ctx context.Context, network, addr string) (net.Conn, int, error) {
	total := len(p.slots)
	if total == 0 {
		return nil, -1, fmt.Errorf("circuit pool is empty")
	}

	start := p.current.Add(1) % int64(total)

	for i := 0; i < total; i++ {
		idx := int((start + int64(i)) % int64(total))
		slot := p.slots[idx]

		if !slot.IsHealthy() {
			continue
		}

		conn, err := p.dialTor(ctx, addr, idx)
		if err != nil {
			slot.RecordFailure()
			continue
		}

		slot.RecordSuccess()
		p.resetErrorBackoff()
		if slot.ShouldRotate(p.maxAge) {
			slot.SetUnhealthy()
		}
		return conn, idx, nil
	}

	p.logf("[pool] all slots exhausted (with-slot), requesting NEWNYM")
	if err := p.rateLimitedNEWNYM(); err != nil {
		p.logf("[pool] NEWNYM failed: %v", err)
	} else {
		p.resetAll()
	}

	conn, err := p.dialTor(ctx, addr, 0)
	if err != nil {
		return nil, -1, fmt.Errorf("circuit pool exhausted: %w", err)
	}

	p.slots[0].RecordSuccess()
	p.resetErrorBackoff()
	return conn, 0, nil
}

// ReportAnomaly marks a slot as having a rate-limit anomaly.
// Triggers a rate-limited NEWNYM when threshold is exceeded.
func (p *CircuitPoolBackend) ReportAnomaly(slotIdx int) {
	if slotIdx < 0 || slotIdx >= len(p.slots) {
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
	conn, err := p.dialer.DialContext(ctx, "tcp", p.torAddr)
	if err != nil {
		return nil, fmt.Errorf("tor dial failed: %w", err)
	}

	TuneTCP(conn)

	// Use per-slot isolation username so Tor assigns different circuits
	isoUser := fmt.Sprintf("%s-slot%d", p.isolationPrefix, slotIdx)
	if err := p.socks5Handshake(conn, addr, isoUser); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 handshake failed: %w", err)
	}

	return conn, nil
}

// socks5Handshake performs SOCKS5 with optional username-based stream isolation.
// The username is used as the SOCKS5 auth username so Tor's IsolateSOCKSAuth
// assigns different circuits for different usernames to the same destination.
func (p *CircuitPoolBackend) socks5Handshake(conn net.Conn, targetAddr, isoUser string) error {
	// Use username/password auth mode if isolation requested
	var buf [300]byte
	n := 0

	if isoUser != "" {
		// Greeting: SOCKS5, 2 methods (no-auth, username/password)
		buf[n], buf[n+1], buf[n+2], buf[n+3] = 0x05, 0x02, 0x00, 0x02
		n += 4
	} else {
		buf[n], buf[n+1], buf[n+2] = 0x05, 0x01, 0x00
		n += 3
	}

	if _, err := conn.Write(buf[:n]); err != nil {
		return fmt.Errorf("socks5 greeting write: %w", err)
	}

	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return fmt.Errorf("socks5 greeting read: %w", err)
	}

	if resp[0] != 0x05 {
		return fmt.Errorf("socks5 unsupported version: %d", resp[0])
	}

	// Handle username/password auth if server selected it
	if isoUser != "" && resp[1] == 0x02 {
		upBuf := make([]byte, 0, 512)
		upBuf = append(upBuf, 0x01)                                           // version
		upBuf = append(upBuf, byte(len(isoUser)))                             // ulen
		upBuf = append(upBuf, []byte(isoUser)...)                             // uname
		upBuf = append(upBuf, 0x00)                                           // plen (empty password)
		if _, err := conn.Write(upBuf); err != nil {
			return fmt.Errorf("socks5 auth write: %w", err)
		}
		var authResp [2]byte
		if _, err := io.ReadFull(conn, authResp[:]); err != nil {
			return fmt.Errorf("socks5 auth read: %w", err)
		}
		if authResp[1] != 0x00 {
			return fmt.Errorf("socks5 auth rejected: %d", authResp[1])
		}
	} else if resp[1] != 0x00 {
		return fmt.Errorf("socks5 auth method not accepted: %d", resp[1])
	}

	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return fmt.Errorf("socks5 split host port: %w", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("invalid port %q: %w", portStr, err)
	}

	n = 0
	buf[n], buf[n+1], buf[n+2], buf[n+3] = 0x05, 0x01, 0x00, 0x03
	n += 4
	hostLen := len(host)
	if hostLen > 255 {
		return fmt.Errorf("host too long: %d bytes", hostLen)
	}
	buf[n] = byte(hostLen)
	n++
	copy(buf[n:], host)
	n += hostLen
	buf[n], buf[n+1] = byte(port>>8), byte(port&0xff)
	n += 2

	if _, err := conn.Write(buf[:n]); err != nil {
		return fmt.Errorf("socks5 connect write: %w", err)
	}

	var reply [10]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return fmt.Errorf("socks5 connect read: %w", err)
	}

	if reply[1] != 0x00 {
		return fmt.Errorf("socks5 connect failed: code=%d", reply[1])
	}

	return nil
}

// rateLimitedNEWNYM sends SIGNAL NEWNYM to Tor with:
//   1. Exponential backoff: minNymGap × nymBackoff (1×=10s, 16×=160s max)
//      nymBackoff DOUBLES on every NEWNYM (not just error-triggered).
//      It resets to 1 on the next successful DialContext call.
//   2. Cookie auth: reads Tor control auth cookie for AUTHENTICATE.
//   3. Rate limiting: skips if elapsed < effective gap.
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

	conn, err := net.DialTimeout("tcp", p.controlAddr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to control port: %w", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Try cookie auth first, then password, then empty
	authSent := false
	if p.controlCookiePath != "" {
		if cookie, err := os.ReadFile(p.controlCookiePath); err == nil && len(cookie) == 32 {
			hexCookie := hex.EncodeToString(cookie)
			fmt.Fprintf(conn, "AUTHENTICATE %s\r\n", hexCookie)
			authSent = true
		}
	}
	if !authSent && p.controlPass != "" {
		fmt.Fprintf(conn, "AUTHENTICATE \"%s\"\r\n", p.controlPass)
		authSent = true
	}
	if !authSent {
		fmt.Fprintf(conn, "AUTHENTICATE\r\n")
	}

	resp, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("auth failed: %w", err)
	}
	if !strings.HasPrefix(resp, "250") {
		return fmt.Errorf("auth rejected: %s", strings.TrimSpace(resp))
	}

	fmt.Fprintf(conn, "SIGNAL NEWNYM\r\n")
	resp, err = reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("newnym failed: %w", err)
	}
	if !strings.HasPrefix(resp, "250") {
		return fmt.Errorf("newnym rejected: %s", strings.TrimSpace(resp))
	}

	p.logf("[pool] Tor NEWNYM completed")
	return nil
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
// Does NOT reset nymBackoff — that only resets on successful dial
// via resetErrorBackoff().
func (p *CircuitPoolBackend) resetAll() {
	for _, slot := range p.slots {
		slot.Reset()
	}
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

// Close marks all slots unhealthy.
func (p *CircuitPoolBackend) Close() error {
	for _, slot := range p.slots {
		slot.SetUnhealthy()
	}
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
