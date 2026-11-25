package backend

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/local-relay/proxy/internal/transport"
)

type TorBackend struct {
	addr          string
	control       *TorControlClient
	socksClient   *transport.SOCKS5Client
	healthy       bool
	mu            sync.RWMutex
	circuitAge    int
	maxCircuitAge int
	lastRotate    time.Time
	// consecDialFail counts consecutive SOCKS-dial failures for the
	// health gate below; reset on any successful dial or probe.
	consecDialFail int
}

// dialFailThreshold is the consecutive dial failures before single-tor
// marks itself unhealthy. 3 matches the CheckHealth 3-strikes and
// quarantine-entry discipline elsewhere in the backend package.
const dialFailThreshold = 3

type TorConfig struct {
	Address           string
	ControlAddr       string
	ControlPass       string
	ControlCookiePath string
	Timeout           time.Duration
	MaxCircuitAge     int
}

func NewTorBackend(cfg TorConfig) *TorBackend {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.MaxCircuitAge == 0 {
		cfg.MaxCircuitAge = 100
	}
	if cfg.ControlAddr == "" {
		cfg.ControlAddr = "127.0.0.1:9051"
	}

	return &TorBackend{
		addr:          cfg.Address,
		control:       NewTorControlClient(cfg.ControlAddr, cfg.ControlPass, cookieFileProvider(cfg.ControlCookiePath)),
		socksClient:   transport.NewSOCKS5Client(cfg.Timeout),
		healthy:       true,
		maxCircuitAge: cfg.MaxCircuitAge,
	}
}

// VerifyControl checks control-port authentication without changing state:
// it connects, AUTHENTICATEs, and closes. No SIGNAL is issued. A backend
// with no control address configured reports an error so callers can
// distinguish "nothing to verify" from "auth OK".
func (t *TorBackend) VerifyControl() error {
	if t.control == nil || t.control.Addr == "" {
		return ErrControlNotConfigured
	}
	return t.control.VerifyAuth()
}

// cookieFileProvider adapts a static cookie path to the dynamic provider
// signature expected by TorControlClient.
func cookieFileProvider(path string) func() ([]byte, bool) {
	return func() ([]byte, bool) { return readCookieFile(path) }
}

func (t *TorBackend) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := t.socksClient.Connect(ctx, t.addr, addr, "")
	if err != nil {
		// Health gate: a single refused upstream must not fail-close all
		// single-tor traffic — only consecutive dial failures (daemon
		// likely down or wedged) flip healthy=false. An upstream CONNECT
		// rejection and a dead daemon look identical at this layer, so
		// the threshold, not the first error, decides.
		t.mu.Lock()
		t.consecDialFail++
		if t.consecDialFail >= dialFailThreshold {
			t.healthy = false
		}
		t.mu.Unlock()
		return nil, fmt.Errorf("tor dial failed: %w", err)
	}

	t.mu.Lock()
	t.circuitAge++
	t.consecDialFail = 0
	t.healthy = true
	t.mu.Unlock()

	return conn, nil
}

// RequestNewCircuit signals NEWNYM over the control port, replacing the
// current circuit with a fresh one (new exit IP, subject to Tor's guard
// rotation policy). Tor rate-limits NEWNYM natively (~10s), so the same
// 10s cooldown as the anomaly path applies here: without it the
// request-count rotator (every N requests) would issue back-to-back
// signals that Tor rejects or throttles.
func (t *TorBackend) RequestNewCircuit() error {
	t.mu.RLock()
	if time.Since(t.lastRotate) < 10*time.Second {
		t.mu.RUnlock()
		return ErrNymCooldown
	}
	t.mu.RUnlock()
	t.mu.Lock()
	if time.Since(t.lastRotate) < 10*time.Second {
		t.mu.Unlock()
		return ErrNymCooldown
	}
	t.lastRotate = time.Now()
	t.mu.Unlock()

	if err := t.control.SignalNEWNYM(false); err != nil {
		t.mu.Lock()
		if time.Since(t.lastRotate) < 10*time.Second {
			t.lastRotate = time.Time{}
		}
		t.mu.Unlock()
		return err
	}

	t.mu.Lock()
	t.circuitAge = 0
	t.mu.Unlock()

	return nil
}

// ReportAnomaly rotates the single circuit on rate-limit/network signals.
// It mirrors the multi-tor/pool anomaly path so every proxy failure site can
// call router.ReportAnomaly unconditionally: backends that track instances or
// slots rotate the culprit, single-tor rotates its one circuit. A 10s
// cooldown (Tor's native NEWNYM rate limit) collapses anomaly storms into one
// rotation instead of churning on every 429.
//
// The cooldown claim is atomic: the RLock check is only a fast-path filter;
// the claim itself happens under the write lock with a re-check, so N
// concurrent callers collapse onto exactly one NEWNYM instead of each
// passing the stale check and double/triple-issuing the signal.
func (t *TorBackend) ReportAnomaly(_ int) {
	t.mu.RLock()
	if time.Since(t.lastRotate) < 10*time.Second {
		t.mu.RUnlock()
		return
	}
	t.mu.RUnlock()
	t.mu.Lock()
	if time.Since(t.lastRotate) < 10*time.Second {
		t.mu.Unlock()
		return
	}
	t.lastRotate = time.Now()
	t.mu.Unlock()
	if err := t.control.SignalNEWNYM(false); err != nil {
		t.mu.Lock()
		// Refund only if our claim is still the latest: a failure means the
		// SIGNAL never issued, so the timestamp we stamped above is stale and
		// must be cleared — but only when no newer claim superseded us (a
		// since>=10s reading implies a newer claimant owns the window). The
		// 5s control deadline means an uncontended failure returns well inside
		// the 10s window, so the time check alone distinguishes the cases.
		if time.Since(t.lastRotate) < 10*time.Second {
			t.lastRotate = time.Time{}
		}
		t.mu.Unlock()
		return
	}
	t.mu.Lock()
	t.circuitAge = 0
	t.mu.Unlock()
}

func (t *TorBackend) IsHealthy() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.healthy
}

func (t *TorBackend) CheckHealth() bool {
	// SOCKS5 greeting handshake probe (not a bare TCP dial): a bare dial
	// succeeds against any listener on the port, including a non-Tor
	// process or a bootstrapping daemon that cannot yet route circuits.
	if !probeSocks5Greeting(t.addr, 5*time.Second) {
		t.mu.Lock()
		t.healthy = false
		t.mu.Unlock()
		return false
	}

	t.mu.Lock()
	t.healthy = true
	t.mu.Unlock()
	return true
}

// probeSocks5Greeting dials addr and completes a SOCKS5 no-auth greeting
// handshake, returning true only when the peer answers like a SOCKS5 server.
func probeSocks5Greeting(addr string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return false
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return false
	}
	return resp[0] == 0x05 && resp[1] == 0x00
}

func (t *TorBackend) ShouldRotate() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.circuitAge >= t.maxCircuitAge
}

func (t *TorBackend) Close() error {
	t.mu.Lock()
	t.healthy = false
	t.mu.Unlock()
	return nil
}

type DirectBackend struct {
	dialer *net.Dialer
}

func NewDirectBackend(timeout time.Duration) *DirectBackend {
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return &DirectBackend{
		dialer: &net.Dialer{Timeout: timeout},
	}
}

// pinnedDialKey carries one request's proxy-verified bypass resolution:
// normalized-host → the single shared-Lookup IP set the proxy's firewall +
// SSRF verdicts already approved (see WithPinnedDial). A nil slice means the
// host was unresolvable at check time (fail-open, same as today); a nil map
// (or missing entry) means unpinned and dials exactly as before.
type pinnedDialKey struct{}

// WithPinnedDial records the proxy's single shared-Lookup result for host so
// the bypass-direct dial below connects to THOSE addresses instead of
// repeating a Lookup. That closes the check→dial DNS flip window: a name resolving
// public at check time but private at dial time (rebinding, or a stale cache
// entry inside the Resolver TTL) can no longer slip through, because the
// dial never consults fresh DNS. Only the TCP dial uses the verified IP
// literal; TLS SNI/Host still derive from the request URL hostname (Go's
// transport builds them from the URL, not the dialed address), so pinning
// changes the resolution source, never the presented identity. Tor/proxied
// paths never read this key: they hand the hostname to the exit node, which
// resolves independently (no local re-resolution TOCTOU exists there).
func WithPinnedDial(ctx context.Context, host string, ips []net.IP) context.Context {
	// Same canonical form as the security package's normalizeHostKey and the
	// dial-time lookup below so check-time and dial-time entries agree (host
	// here may carry a port or IPv6 brackets). The port is split BEFORE
	// dot-stripping: a "name.:port" input would otherwise keep the dot and
	// miss its pin, falling back to a fresh-DNS legacy dial and reopening
	// the flip window the pin closes.
	hostOnly := host
	if h, _, err := net.SplitHostPort(hostOnly); err == nil {
		hostOnly = h
	}
	key := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSuffix(hostOnly, "]"), "["), "."))
	m, _ := ctx.Value(pinnedDialKey{}).(map[string][]net.IP)
	// Copy-on-write: contexts share the map across retries/attempts of one
	// request, so mutating in place would let a later pin overwrite an
	// earlier one for sibling dials. One entry per request in practice.
	pinned := make(map[string][]net.IP, len(m)+1)
	for k, v := range m {
		pinned[k] = v
	}
	pinned[key] = ips
	return context.WithValue(ctx, pinnedDialKey{}, pinned)
}

// pinnedDialIPs returns the check-time IPs recorded for addr's host ("host"
// or "host:port", same normalization as WithPinnedDial), and whether a pin
// exists. IP-literal hosts need no pin: the dialer connects to them directly
// with no DNS involved, so there is no flip window to close.
func pinnedDialIPs(ctx context.Context, addr string) ([]net.IP, bool) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	// Same canonical form as the security package's normalizeHostKey
	// (lowercase, brackets, one trailing dot) so the dial-time lookup hits
	// the check-time pin entry.
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	if net.ParseIP(host) != nil {
		return nil, false
	}
	m, ok := ctx.Value(pinnedDialKey{}).(map[string][]net.IP)
	if !ok || m == nil {
		return nil, false
	}
	ips, found := m[host]
	if !found {
		return nil, false
	}
	return ips, true
}

func (d *DirectBackend) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	// Pinned path: dial the proxy-verified check-time IPs directly instead
	// of re-resolving. Fail-open-at-check (nil/empty pin) dials unchanged —
	// nothing was verified to pin to — and an all-unreachable pin surfaces
	// the last dial error like a normal multi-address DialContext. Every
	// pinned address is tried in the resolver's order (not just the first),
	// so dual-stack upstreams keep working when only one family is reachable.
	if pinned, ok := pinnedDialIPs(ctx, addr); ok && len(pinned) > 0 {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		var lastErr error
		for _, ip := range pinned {
			literal := net.JoinHostPort(ip.String(), port)
			conn, derr := d.dialer.DialContext(ctx, network, literal)
			if derr == nil {
				TuneTCP(conn)
				return conn, nil
			}
			lastErr = derr
		}
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, fmt.Errorf("pinned dial: no verified addresses for %q", addr)
	}
	conn, err := d.dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	TuneTCP(conn)

	return conn, nil
}

func (d *DirectBackend) IsHealthy() bool {
	return true
}

func (d *DirectBackend) Close() error {
	return nil
}
