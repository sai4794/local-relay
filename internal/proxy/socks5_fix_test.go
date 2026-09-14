package proxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/local-relay/proxy/internal/backend"
	"github.com/local-relay/proxy/internal/rotate"
	"github.com/local-relay/proxy/internal/security"
)

// recordingAnomalyBackend fails every dial with a rotation-triggering error
// and records ReportAnomaly calls. Failing with "connection refused" hits the
// existing ForceRotate substring trigger, so the test asserts both the
// preserved trigger and the new anomaly signal fire.
type recordingAnomalyBackend struct {
	anomalies atomic.Int64
}

func (b *recordingAnomalyBackend) DialContext(_ context.Context, _, _ string) (net.Conn, error) {
	return nil, errors.New("dial tcp: connection refused")
}

func (b *recordingAnomalyBackend) IsHealthy() bool { return true }
func (b *recordingAnomalyBackend) Close() error    { return nil }
func (b *recordingAnomalyBackend) ReportAnomaly(_ int) {
	b.anomalies.Add(1)
}

// A CONNECT to the proxy's own listen address must fail closed with 0x01
// and never tunnel to self. Covers exact-match (127.0.0.1 + same port),
// cross-spelling loopback (localhost target vs 127.0.0.1 listen), and the
// port-mismatch negative (same loopback, different port must pass the guard).
func TestSOCKS5_SelfDialGuard(t *testing.T) {
	newSelfDialProxy := func(t *testing.T) (*SOCKS5Proxy, string) {
		t.Helper()
		router := backend.NewRouter(backend.NewDirectBackend(2 * time.Second))
		// Keep the operator behavior: localhost/127.0.0.1 configured as
		// bypass hosts must NOT bypass the self-dial guard. Without the
		// guard running first, the waiver would let self-targets through.
		router.SetBypassHosts([]string{"localhost", "127.0.0.1"})
		p := testSOCKS5Proxy(t, router)
		addr := startSOCKS5TestProxy(t, p)
		// startSOCKS5TestProxy installs the listener directly (bypassing
		// Start), so record the listen address the way Start would.
		p.listenAddr.Store(addr)
		return p, addr
	}

	socks5Connect := func(t *testing.T, proxyAddr, target string) byte {
		t.Helper()
		c := socks5Dial(t, proxyAddr)
		socks5Greet(t, c)
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		host, port, err := net.SplitHostPort(target)
		if err != nil {
			t.Fatal(err)
		}
		if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
			v4 := ip.To4()
			hi, lo := portToBytes(port)
			req := []byte{0x05, 0x01, 0x00, 0x01, v4[0], v4[1], v4[2], v4[3], hi, lo}
			if _, err := c.Write(req); err != nil {
				t.Fatalf("connect write: %v", err)
			}
		} else {
			req := append([]byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}, host...)
			hi, lo := portToBytes(port)
			req = append(req, hi, lo)
			if _, err := c.Write(req); err != nil {
				t.Fatalf("connect write: %v", err)
			}
		}
		return socks5ReadReply(t, c)
	}

	t.Run("exact-match-self", func(t *testing.T) {
		_, addr := newSelfDialProxy(t)
		if got := socks5Connect(t, addr, addr); got != 0x01 {
			t.Errorf("reply = 0x%02x; want 0x01 (self-dial must fail closed)", got)
		}
	})

	t.Run("cross-spelling-localhost-vs-127", func(t *testing.T) {
		_, addr := newSelfDialProxy(t)
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			t.Fatal(err)
		}
		if got := socks5Connect(t, addr, net.JoinHostPort("localhost", port)); got != 0x01 {
			t.Errorf("reply = 0x%02x; want 0x01 (localhost self-dial must fail closed)", got)
		}
	})

	t.Run("different-port-passes-guard", func(t *testing.T) {
		p, addr := newSelfDialProxy(t)
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			t.Fatal(err)
		}
		// Same loopback, different port: the guard must not fire. Use a
		// closed port so the dial fails downstream with 0x05 — that proves
		// the request passed the self-dial check (0x05 is only reachable
		// past the guard; the guard replies 0x01).
		other := closedLoopbackPort(t)
		if other == port {
			t.Skip("no distinct closed port available")
		}
		target := net.JoinHostPort("127.0.0.1", other)
		if p.isSelfDial(target) {
			t.Fatalf("isSelfDial(%q) = true; want false (port differs)", target)
		}
		if got := socks5Connect(t, addr, target); got != 0x05 {
			t.Errorf("reply = 0x%02x; want 0x05 (must pass guard, fail at dial)", got)
		}
	})

	t.Run("never-started-proxy-allows", func(t *testing.T) {
		p := testSOCKS5Proxy(t, backend.NewRouter(backend.NewDirectBackend(0)))
		if p.isSelfDial("127.0.0.1:1080") {
			t.Error("isSelfDial = true on never-started proxy; want false")
		}
	})
}

// closedLoopbackPort returns a loopback port with nothing listening on it.
func closedLoopbackPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(ln.Addr().String())
	ln.Close()
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// strictLoopbackProxy builds a proxy whose guards actually block loopback
// (default firewall ranges + loopback SSRF ranges), unlike testSOCKS5Proxy
// whose firewall seam allows loopback for upstream tests.
func strictLoopbackProxy(t *testing.T, router *backend.Router) *SOCKS5Proxy {
	t.Helper()
	return &SOCKS5Proxy{
		router:   router,
		firewall: security.NewFirewall(security.FirewallConfig{}),
		ssrf:     security.NewSSRFBlocker([]string{"127.0.0.0/8", "::1/128"}),
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// The loopback waiver must be gated on the router's bypass config: when
// localhost is NOT a configured bypass host, a localhost CONNECT must run the
// guards (loopback blocked by default ranges -> 0x02), not take the waiver.
// When it IS configured (operator behavior), the waiver is preserved (0x00).
func TestSOCKS5_LoopbackWaiverGatedOnBypassConfig(t *testing.T) {
	upstreamAddr, accepted := startLoopbackUpstream(t)
	_, port, err := net.SplitHostPort(upstreamAddr)
	if err != nil {
		t.Fatal(err)
	}

	dialLocalhost := func(t *testing.T, proxyAddr string) byte {
		t.Helper()
		c := socks5Dial(t, proxyAddr)
		socks5Greet(t, c)
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		host := "localhost"
		req := append([]byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}, host...)
		hi, lo := portToBytes(port)
		req = append(req, hi, lo)
		if _, err := c.Write(req); err != nil {
			t.Fatalf("connect write: %v", err)
		}
		return socks5ReadReply(t, c)
	}

	t.Run("localhost-not-configured-stays-blocked", func(t *testing.T) {
		// No bypass hosts configured: localhost resolves to loopback, which
		// the default firewall ranges block -> 0x02. The waiver must not
		// let it through as a direct dial.
		router := backend.NewRouter(backend.NewDirectBackend(2 * time.Second))
		p := strictLoopbackProxy(t, router)
		addr := startSOCKS5TestProxy(t, p)
		if got := dialLocalhost(t, addr); got != 0x02 {
			t.Errorf("reply = 0x%02x; want 0x02 (unconfigured localhost must run guards)", got)
		}
	})

	t.Run("localhost-configured-preserved", func(t *testing.T) {
		router := backend.NewRouter(backend.NewDirectBackend(2 * time.Second))
		router.SetBypassHosts([]string{"localhost", "127.0.0.1"})
		p := strictLoopbackProxy(t, router)
		addr := startSOCKS5TestProxy(t, p)
		if got := dialLocalhost(t, addr); got != 0x00 {
			t.Fatalf("reply = 0x%02x; want 0x00 (configured bypass must establish)", got)
		}
		select {
		case <-accepted:
		case <-time.After(5 * time.Second):
			t.Fatal("upstream never accepted the bypass CONNECT")
		}
	})
}

// A dial failure must both preserve the existing ForceRotate trigger and add
// the ReportAnomaly(-1) signal. Reply code stays 0x05.
func TestSOCKS5_DialFailureReportsAnomaly(t *testing.T) {
	failing := &recordingAnomalyBackend{}
	router := backend.NewRouter(backend.NewDirectBackend(0), failing)
	p := testSOCKS5Proxy(t, router)

	rotated := make(chan struct{}, 1)
	p.rotator = rotate.NewRotator(0, func() {
		select {
		case rotated <- struct{}{}:
		default:
		}
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	addr := startSOCKS5TestProxy(t, p)

	c := socks5Dial(t, addr)
	socks5Greet(t, c)
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	// 8.8.8.8 is a public literal (no DNS needed): it passes both guards and
	// is not a bypass host, so the dial reaches the failing proxied backend.
	if _, err := c.Write([]byte{0x05, 0x01, 0x00, 0x01, 8, 8, 8, 8, 0x00, 0x50}); err != nil {
		t.Fatalf("connect write: %v", err)
	}
	if got := socks5ReadReply(t, c); got != 0x05 {
		t.Fatalf("reply = 0x%02x; want 0x05 (dial failure reply unchanged)", got)
	}
	select {
	case <-rotated:
	case <-time.After(5 * time.Second):
		t.Fatal("ForceRotate trigger lost: rotation callback never fired")
	}
	if n := failing.anomalies.Load(); n != 1 {
		t.Errorf("ReportAnomaly calls = %d; want 1", n)
	}
}

// LOW-7: malformed requests must not count toward rotation. With interval 1,
// every counted request rotates; a run of malformed requests must produce no
// rotations, and the first well-formed CONNECT must produce exactly one.
// (A well-formed request with an unsupported CMD still counts — it passed
// readRequest — so it is asserted in the positive case, not the zero case.)
func TestSOCKS5_RotationCountPurity(t *testing.T) {
	router := backend.NewRouter(backend.NewDirectBackend(2 * time.Second))
	p := testSOCKS5Proxy(t, router)

	var rotations atomic.Int64
	p.rotator = rotate.NewRotator(1, func() {
		rotations.Add(1)
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	addr := startSOCKS5TestProxy(t, p)

	for _, req := range [][]byte{
		{0x04, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0xD2}, // bad VER
		{0x05, 0x01, 0x00, 0x02, 0, 0, 0, 0, 0, 0},         // bad ATYP
		{0x05, 0x01, 0x00, 0x03, 0x00, 0x04, 0xD2},         // empty domain
		{0x05, 0x01, 0x00, 0x01, 10, 0, 0, 1, 0x00, 0x00},  // port zero
	} {
		c := socks5Dial(t, addr)
		socks5Greet(t, c)
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write(req); err != nil {
			t.Fatalf("request write: %v", err)
		}
		socks5ReadReply(t, c)
	}
	// Handshake failure counts as malformed too: greet then close mid-request.
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Write([]byte{0x05, 0x01, 0x00})
	resp := make([]byte, 2)
	_, _ = io.ReadFull(c, resp)
	_, _ = c.Write([]byte{0x05, 0x01})
	_ = c.Close()
	time.Sleep(300 * time.Millisecond)

	if n := rotations.Load(); n != 0 {
		t.Fatalf("rotations after malformed-only traffic = %d; want 0", n)
	}

	// One well-formed CONNECT (blocked 10/8 -> 0x02 reply, but well-formed)
	// must count exactly once.
	c2 := socks5Dial(t, addr)
	socks5Greet(t, c2)
	_ = c2.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c2.Write([]byte{0x05, 0x01, 0x00, 0x01, 10, 0, 0, 1, 0x00, 0x50}); err != nil {
		t.Fatalf("connect write: %v", err)
	}
	if got := socks5ReadReply(t, c2); got != 0x02 {
		t.Fatalf("reply = 0x%02x; want 0x02", got)
	}
	// The rotation callback fires in a goroutine: poll briefly instead of
	// asserting immediately.
	deadline := time.Now().Add(5 * time.Second)
	for rotations.Load() != 1 {
		if time.Now().After(deadline) {
			t.Errorf("rotations after one well-formed request = %d; want 1", rotations.Load())
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// SOCKS5 unspecified-bind parity mirror of
// TestRegression_SelfDialUnspecifiedBind (HTTP): a listener on the
// unspecified address accepts loopback traffic on its port, so loopback and
// unspecified targets on the same port are self-dial and must fail closed
// with 0x01. SOCKS5 targets always carry a port (ATYP framing), so there is
// no implicit-port branch to mirror — unit-level predicate coverage plus
// one live unspecified-listen CONNECT asserting 0x01.
func TestSOCKS5_SelfDialUnspecifiedBind(t *testing.T) {
	router := backend.NewRouter(backend.NewDirectBackend(2 * time.Second))
	router.SetBypassHosts([]string{"localhost", "127.0.0.1"})
	p := testSOCKS5Proxy(t, router)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	for _, listen := range []string{
		net.JoinHostPort("0.0.0.0", port),
		net.JoinHostPort("::", port),
		net.JoinHostPort("127.0.0.1", port),
	} {
		p.listenAddr.Store(listen)
		for _, target := range []string{
			net.JoinHostPort("127.0.0.1", port),
			net.JoinHostPort("localhost", port),
			net.JoinHostPort("0.0.0.0", port),
			"0177.0.0.1:" + port,
			"2130706433:" + port,
			"[::]:" + port,
		} {
			if !p.isSelfDial(target) {
				t.Errorf("SOCKS5 isSelfDial(%q) with listen %q = false; want true", target, listen)
			}
		}
		if external := net.JoinHostPort("93.184.216.34", port); p.isSelfDial(external) {
			t.Errorf("SOCKS5 isSelfDial(%q) with listen %q = true; want false (public never self)", external, listen)
		}
	}
}

// Live end-to-end: proxy listening on 127.0.0.1, CONNECT to the unspecified
// address on the same port must fail closed 0x01 (unspecified target dials
// the local stack).
func TestSOCKS5_SelfDialUnspecifiedLive(t *testing.T) {
	router := backend.NewRouter(backend.NewDirectBackend(2 * time.Second))
	router.SetBypassHosts([]string{"localhost", "127.0.0.1"})
	p := testSOCKS5Proxy(t, router)
	addr := startSOCKS5TestProxy(t, p)
	p.listenAddr.Store(addr)
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	c := socks5Dial(t, addr)
	socks5Greet(t, c)
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	target := net.JoinHostPort("0.0.0.0", port)
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatal(err)
	}
	v4 := net.ParseIP(host).To4()
	hi, lo := portToBytes(portStr)
	req := []byte{0x05, 0x01, 0x00, 0x01, v4[0], v4[1], v4[2], v4[3], hi, lo}
	if _, err := c.Write(req); err != nil {
		t.Fatalf("connect write: %v", err)
	}
	if got := socks5ReadReply(t, c); got != 0x01 {
		t.Errorf("reply = 0x%02x; want 0x01 (unspecified self-dial must fail closed)", got)
	}
}
