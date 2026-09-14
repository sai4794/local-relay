package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/local-relay/proxy/internal/backend"
	"github.com/local-relay/proxy/internal/rotate"
	"github.com/local-relay/proxy/internal/security"
	"github.com/local-relay/proxy/internal/stream"
)

// AuthCheck is a function that checks if a username/password combo is valid.
type AuthCheck func(username, password string) bool

type SOCKS5Proxy struct {
	router    *backend.Router
	firewall  *security.Firewall
	rotator   *rotate.Rotator
	ssrf      *security.SSRFBlocker
	logger    *slog.Logger
	listener  net.Listener
	authCheck AuthCheck
	// listenAddr records the Start address (host:port) so CONNECT targets
	// can be checked for self-dial loops. atomic: written once in
	// Start, read per CONNECT. Mirrors HTTPProxy.listenAddr.
	listenAddr atomic.Value // string
}

func NewSOCKS5Proxy(router *backend.Router, fw *security.Firewall, rotator *rotate.Rotator, logger *slog.Logger, authCheck AuthCheck, ssrf *security.SSRFBlocker, _ int64) *SOCKS5Proxy {
	return &SOCKS5Proxy{
		router:    router,
		firewall:  fw,
		rotator:   rotator,
		ssrf:      ssrf,
		logger:    logger,
		authCheck: authCheck,
	}
}

func (p *SOCKS5Proxy) Start(addr string) error {
	p.listenAddr.Store(addr)
	var err error
	p.listener, err = net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	p.logger.Info("SOCKS5 proxy listening", "addr", addr)

	for {
		conn, err := p.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			p.logger.Error("SOCKS5 accept error", "error", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go p.handleConn(conn)
	}
}

// handshakeTimeout bounds the SOCKS5 greeting/auth/request exchange. Without
// it a client that opens a socket and never speaks pins a goroutine forever
// (slowloris). The deadline is cleared once the tunnel is established.
const handshakeTimeout = 30 * time.Second

// Sentinel errors for malformed SOCKS5 requests. Message text matches the
// previous fmt.Errorf strings so debug logs are unchanged; handleConn uses
// errors.Is to choose the RFC1928 reply code (0x01 general failure, 0x08
// unsupported address type) before closing.
var (
	errSocksBadVersion      = errors.New("invalid version")
	errSocksUnsupportedATYP = errors.New("unsupported address type")
	errSocksEmptyDomain     = errors.New("empty domain")
	errSocksZeroPort        = errors.New("zero port")
)

func (p *SOCKS5Proxy) handleConn(conn net.Conn) {
	defer conn.Close()

	backend.TuneTCP(conn)

	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))

	if err := p.handshake(conn); err != nil {
		p.logger.Debug("SOCKS5 handshake failed", "error", err)
		return
	}

	target, cmd, err := p.readRequest(conn)
	if err != nil {
		// RFC1928 malformed-request replies before close, consistent with the
		// 0x02/0x05/0x07 replies elsewhere: 0x08 for bad ATYP, 0x01 general
		// failure for bad VER / empty domain / port 0 / truncated reads.
		reply := byte(0x01)
		if errors.Is(err, errSocksUnsupportedATYP) {
			reply = 0x08
		}
		p.sendReply(conn, reply, nil)
		p.logger.Debug("SOCKS5 request read failed", "error", err)
		return
	}

	p.recordRotation()

	switch cmd {
	case 0x01: // CONNECT
		p.handleConnect(conn, target)
	case 0x03: // UDP ASSOCIATE
		p.handleUDPAssociate(conn)
	default:
		p.sendReply(conn, 0x07, nil)
	}
}

func (p *SOCKS5Proxy) handshake(conn net.Conn) error {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}

	if buf[0] != 0x05 {
		return fmt.Errorf("unsupported SOCKS version: %d", buf[0])
	}

	nMethods := int(buf[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	// If auth is required, offer both no-auth and user/pass
	if p.authCheck != nil {
		// Check if client supports user/pass auth (0x02)
		for _, m := range methods {
			if m == 0x02 {
				if _, err := conn.Write([]byte{0x05, 0x02}); err != nil {
					return err
				}
				return p.authenticate(conn)
			}
		}
		// Client doesn't support user/pass — reject
		_, err := conn.Write([]byte{0x05, 0xFF})
		return err
	}

	// No auth required
	_, err := conn.Write([]byte{0x05, 0x00})
	return err
}

func (p *SOCKS5Proxy) authenticate(conn net.Conn) error {
	// RFC 1929: version(1) + ulen(1) + uname(ulen) + plen(1) + passwd(plen)
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return err
	}
	if hdr[0] != 0x01 {
		return fmt.Errorf("unsupported auth version: %d", hdr[0])
	}
	ulen := int(hdr[1])
	uname := make([]byte, ulen)
	if _, err := io.ReadFull(conn, uname); err != nil {
		return err
	}
	var plenByte [1]byte
	if _, err := io.ReadFull(conn, plenByte[:]); err != nil {
		return err
	}
	plen := int(plenByte[0])
	passwd := make([]byte, plen)
	if _, err := io.ReadFull(conn, passwd); err != nil {
		return err
	}

	username := string(uname)
	password := string(passwd)

	if p.authCheck != nil && p.authCheck(username, password) {
		_, err := conn.Write([]byte{0x01, 0x00})
		return err
	}
	_, _ = conn.Write([]byte{0x01, 0x01})
	return fmt.Errorf("SOCKS5 auth failed")
}

func (p *SOCKS5Proxy) readRequest(conn net.Conn) (string, byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", 0, err
	}

	if header[0] != 0x05 {
		return "", 0, errSocksBadVersion
	}

	cmd := header[1]

	var target string
	switch header[3] {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", 0, err
		}
		portBytes := make([]byte, 2)
		if _, err := io.ReadFull(conn, portBytes); err != nil {
			return "", 0, err
		}
		port := uint16(portBytes[0])<<8 | uint16(portBytes[1])
		if port == 0 {
			return "", 0, errSocksZeroPort
		}
		target = fmt.Sprintf("%d.%d.%d.%d:%d", addr[0], addr[1], addr[2], addr[3], port)

	case 0x03: // Domain
		domainLen := make([]byte, 1)
		if _, err := io.ReadFull(conn, domainLen); err != nil {
			return "", 0, err
		}
		if domainLen[0] == 0 {
			return "", 0, errSocksEmptyDomain
		}
		domain := make([]byte, domainLen[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", 0, err
		}
		portBytes := make([]byte, 2)
		if _, err := io.ReadFull(conn, portBytes); err != nil {
			return "", 0, err
		}
		port := uint16(portBytes[0])<<8 | uint16(portBytes[1])
		if port == 0 {
			return "", 0, errSocksZeroPort
		}
		target = fmt.Sprintf("%s:%d", string(domain), port)

	case 0x04: // IPv6
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", 0, err
		}
		portBytes := make([]byte, 2)
		if _, err := io.ReadFull(conn, portBytes); err != nil {
			return "", 0, err
		}
		port := uint16(portBytes[0])<<8 | uint16(portBytes[1])
		if port == 0 {
			return "", 0, errSocksZeroPort
		}
		target = fmt.Sprintf("[%s]:%d", net.IP(addr).String(), port)

	default:
		// ATYP value preserved only for the debug log via the wrapped error;
		// errors.Is selects the 0x08 reply. Message text matches the previous
		// string so logs don't change.
		return "", 0, fmt.Errorf("%w: %d", errSocksUnsupportedATYP, header[3])
	}

	return target, cmd, nil
}

func (p *SOCKS5Proxy) handleConnect(conn net.Conn, target string) {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		p.sendReply(conn, 0x01, nil)
		return
	}

	// Self-dial guard (fail-closed): a CONNECT target addressing our own
	// listen socket would re-enter handleConn with the same target forever —
	// one client connection amplifying into an unbounded chain. This runs
	// before the bypass waiver on purpose: loopback self-targets are exactly
	// the ones the waiver would otherwise let through. Reply stays 0x01
	// general failure; no other RFC1928 reply changes.
	if p.isSelfDial(target) {
		p.logger.Warn("blocked SOCKS5 self-dial loop", "target", target)
		p.sendReply(conn, 0x01, nil)
		return
	}

	// Loopback-bypass waiver (mirrors the HTTP forward path): direct
	// localhost/127.0.0.1 requests skip the guards — these
	// operator-configured bypass hosts resolve to loopback, which the
	// blocked ranges would otherwise always trip. The waiver applies only
	// when the target is actually a configured bypass host (consult the
	// shipped Router config instead of hardcoding spellings); with a nil
	// router there is no config to consult, so fall back to the historical
	// localhost/127.0.0.1 spelling check. Non-bypass targets run
	// both guards over one shared Lookup: firewall.AllowIPs performs the
	// single Resolver.Lookup and returns the shared IP slice; SSRF
	// CheckHost re-verdicts over that SAME slice with no second Lookup.
	loopbackSpelling := host == "localhost" || host == "127.0.0.1"
	isBypass := loopbackSpelling && (p.router == nil || p.router.IsBypassHost(host))
	var sharedIPs []net.IP
	if !isBypass {
		var ok bool
		sharedIPs, ok = p.singleLookupVerdict(host)
		if !ok {
			p.logger.Warn("blocked SOCKS5 connection to private/internal IP", "host", host)
			p.sendReply(conn, 0x02, nil)
			return
		}
	}

	// Use request context so client disconnect can cancel the relay
	relayCtx, relayCancel := context.WithCancel(context.Background())
	defer relayCancel()

	// Pin the verified bypass resolution for the direct dial so the
	// check→dial window cannot flip (mirror http.go WithPinnedDial attach,
	// gated on the same routing-verdict gate). No waiver semantics change:
	// non-bypass targets dial exactly as before. The endpoint claim sink
	// rides alongside for per-attempt attribution; legacy ReportAnomaly
	// rotation below is unchanged in this slice.
	var claim backend.EndpointClaim
	relayCtx = backend.WithEndpointClaim(relayCtx, &claim)
	if p.router != nil && p.router.IsBypassHost(host) {
		relayCtx = backend.WithPinnedDial(relayCtx, host, sharedIPs)
	}

	dialCtx, dialCancel := context.WithTimeout(relayCtx, 30*time.Second)
	defer dialCancel()

	destConn, err := p.router.DialContext(dialCtx, "tcp", target)
	if err != nil {
		p.logger.Error("SOCKS5 dial failed", "target", target, "error", err)

		// Attributed failure even with nil rotator (multitor-mode gap:
		// previously SOCKS5 dial failures reported nothing when rotator
		// was nil). Legacy classifier + ForceRotate below unchanged.
		reportOutcome(p.router, &claim, false, 0, 0, 0)
		if p.rotator != nil {
			errStr := err.Error()
			if strings.Contains(errStr, "timeout") ||
				strings.Contains(errStr, "connection refused") ||
				strings.Contains(errStr, "connection reset") ||
				strings.Contains(errStr, "no healthy proxy") {
				p.logger.Warn("SOCKS5 dial failure, triggering rotation", "target", target)
				p.rotator.ForceRotate()
				// Close the SOCKS5 anomaly gap: route dial-failure signals
				// to the backend anomaly path as well (HTTP does this via
				// ReportAnomaly in its retry/rotation paths). The ForceRotate
				// trigger above is unchanged.
				if p.router != nil {
					p.router.ReportAnomaly(-1)
				}
			}
		}
		p.sendReply(conn, 0x05, nil)
		return
	}

	backend.TuneTCP(destConn)

	localAddr := destConn.LocalAddr()
	tcpAddr, ok := localAddr.(*net.TCPAddr)
	if !ok {
		p.sendReply(conn, 0x01, nil)
		destConn.Close()
		p.logger.Error("SOCKS5 local addr is not TCP", "type", fmt.Sprintf("%T", localAddr))
		return
	}
	p.sendReply(conn, 0x00, tcpAddr.IP)

	// Tunnel established — lift the handshake deadline so long-lived
	// streams (LLM completions, downloads) are never truncated.
	_ = conn.SetDeadline(time.Time{})

	p.logger.Info("SOCKS5 CONNECT established", "target", target)

	// NOTE: unlike the HTTP CONNECT path (relayConn, which bounds the tunnel
	// with a 30m context timeout), SOCKS5 tunnels have NO kill timeout here —
	// adding one would change long-lived tunnel behavior. The asymmetry is
	// deliberate; the timer below only observes.
	tunnelStart := time.Now()
	longTunnel := time.AfterFunc(30*time.Minute, func() {
		// Debug only: never closes the tunnel, just records that it is
		// still open past the HTTP parity window.
		p.logger.Debug("SOCKS5 tunnel open past 30m (HTTP parity window)", "target", target, "open_for", time.Since(tunnelStart).String())
	})

	// Use relayCtx so client disconnect cancels the relay
	up, down := stream.Relay(relayCtx, destConn, conn)
	longTunnel.Stop()
	// Parity with HTTP dead-tunnel: zero-byte short tunnel is a failure,
	// anything with bytes (or surviving >= 2s) proves the circuit works.
	if down == 0 && time.Since(tunnelStart) < 2*time.Second {
		reportOutcome(p.router, &claim, false, 0, up, down)
	} else {
		reportOutcome(p.router, &claim, true, 0, up, down)
	}
}

// singleLookupVerdict runs the firewall guard once (the single shared
// Resolver.Lookup) and re-verdicts the SSRF guard over the same IP slice via
// CheckHost — no second Lookup. Nil firewall/SSRF components are open
// (disabled). Returns the shared slice and the combined allow verdict.
func (p *SOCKS5Proxy) singleLookupVerdict(host string) ([]net.IP, bool) {
	var sharedIPs []net.IP
	if p.firewall != nil {
		var ok bool
		sharedIPs, ok = p.firewall.AllowIPs(host)
		if !ok {
			return sharedIPs, false
		}
	}
	if p.ssrf != nil {
		if p.firewall != nil {
			// Re-verdict over the same slice: identical block verdict to a
			// fresh IsBlocked on those IPs, without another Lookup.
			_, blocked := p.ssrf.CheckHost(host, sharedIPs)
			if blocked {
				return sharedIPs, false
			}
			return sharedIPs, true
		}
		if p.ssrf.IsBlocked(host) {
			return nil, false
		}
		return nil, true
	}
	return sharedIPs, true
}

// isSelfDial reports whether target (host:port) addresses this proxy's own
// listen socket. Same semantics as HTTPProxy.isSelfDial: exact
// configured-address match (covers hostnames like "localhost") plus a
// both-sides-loopback match for IP spellings, so a non-loopback hostname
// bound by config can never collide with a loopback target on the same port
// number. "localhost" normalizes to loopback: it has no ParseIP form, so it
// is treated as loopback explicitly on both sides. Unknown listen address
// (never started, e.g. unit-constructed proxies) returns false. Fail-closed:
// a match means handleConnect replies 0x01 and returns without tunneling.
func (p *SOCKS5Proxy) isSelfDial(target string) bool {
	addr, _ := p.listenAddr.Load().(string)
	if addr == "" {
		return false
	}
	tHost, tPort, err := net.SplitHostPort(target)
	if err != nil {
		tHost, tPort = target, ""
	}
	lHost, lPort, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if tPort == "" || tPort != lPort {
		return false
	}
	// Exact configured-address match (covers hostnames like "localhost").
	if strings.EqualFold(tHost, lHost) {
		return true
	}
	// Resolved-loopback match for IP spellings: only block when BOTH sides
	// resolve to loopback. "localhost" has no ParseIP form, so normalize it
	// to loopback explicitly on each side.
	tLoop := strings.EqualFold(strings.TrimSuffix(tHost, "."), "localhost") ||
		net.ParseIP(strings.Trim(tHost, "[]")).IsLoopback()
	lLoop := strings.EqualFold(strings.TrimSuffix(lHost, "."), "localhost") ||
		net.ParseIP(strings.Trim(lHost, "[]")).IsLoopback()
	return tLoop && lLoop
}

func (p *SOCKS5Proxy) handleUDPAssociate(conn net.Conn) {
	p.logger.Debug("UDP ASSOCIATE requested (not supported)")
	p.sendReply(conn, 0x07, nil)
}

func (p *SOCKS5Proxy) sendReply(conn net.Conn, status byte, bindIP net.IP) {
	reply := []byte{0x05, status, 0x00, 0x01}

	if bindIP == nil {
		bindIP = net.IPv4(0, 0, 0, 0)
	}

	if bindIP4 := bindIP.To4(); bindIP4 != nil {
		reply = append(reply, bindIP4...)
	} else {
		reply[3] = 0x04
		reply = append(reply, bindIP.To16()...)
	}

	reply = append(reply, 0x00, 0x00)
	conn.Write(reply)
}

func (p *SOCKS5Proxy) Stop() {
	if p.listener != nil {
		p.listener.Close()
	}
}

func (p *SOCKS5Proxy) recordRotation() {
	if p.rotator != nil && p.rotator.ShouldRotate() {
		p.logger.Info("IP rotation triggered by request count")
	}
}
