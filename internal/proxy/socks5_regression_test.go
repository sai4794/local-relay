package proxy

import (
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/local-relay/proxy/internal/backend"
	"github.com/local-relay/proxy/internal/security"
)

// testSOCKS5Proxy builds a SOCKS5Proxy whose guards allow loopback so real
// loopback TCP upstreams are reachable on test-only ports.
func testSOCKS5Proxy(t *testing.T, router *backend.Router) *SOCKS5Proxy {
	t.Helper()
	fw := security.NewFirewall(security.FirewallConfig{})
	fw.AllowLoopbackForTest()
	return &SOCKS5Proxy{
		router:   router,
		firewall: fw,
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func socks5Dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial socks5 test proxy: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func socks5Greet(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("greet write: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatalf("greet read: %v", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Fatalf("greet resp = %v; want [5 0]", resp)
	}
}

func socks5ReadReply(t *testing.T, c net.Conn) byte {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		t.Fatalf("reply header read: %v", err)
	}
	if hdr[0] != 0x05 {
		t.Fatalf("reply ver = %d; want 5", hdr[0])
	}
	// Consume BND.ADDR+BND.PORT per ATYP so the stream stays framed.
	var rest int
	switch hdr[3] {
	case 0x01:
		rest = 4 + 2
	case 0x04:
		rest = 16 + 2
	case 0x03:
		ln := make([]byte, 1)
		if _, err := io.ReadFull(c, ln); err != nil {
			t.Fatalf("reply domain len read: %v", err)
		}
		rest = int(ln[0]) + 2
	default:
		t.Fatalf("reply atyp = %d", hdr[3])
	}
	if _, err := io.ReadFull(c, make([]byte, rest)); err != nil {
		t.Fatalf("reply body read: %v", err)
	}
	return hdr[1]
}

func startSOCKS5TestProxy(t *testing.T, p *SOCKS5Proxy) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	p.listener = ln
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handleConn(c)
		}
	}()
	return ln.Addr().String()
}

func startLoopbackUpstream(t *testing.T) (string, chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	accepted := make(chan struct{}, 1)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case accepted <- struct{}{}:
			default:
			}
			c.Close()
		}
	}()
	return ln.Addr().String(), accepted
}

// Malformed requests must get RFC1928 replies before close: 0x08 for bad
// ATYP, 0x01 general failure for bad VER / empty domain / port 0.
func TestRegression_SOCKS5MalformedReplies(t *testing.T) {
	router := backend.NewRouter(backend.NewDirectBackend(0))
	p := testSOCKS5Proxy(t, router)
	addr := startSOCKS5TestProxy(t, p)

	cases := []struct {
		name string
		req  []byte
		want byte
	}{
		{"bad-ver", []byte{0x04, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0xD2}, 0x01},
		{"bad-atyp", []byte{0x05, 0x01, 0x00, 0x02, 0, 0, 0, 0, 0, 0}, 0x08},
		{"empty-domain", []byte{0x05, 0x01, 0x00, 0x03, 0x00, 0x04, 0xD2}, 0x01},
		{"port-zero-v4", []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x00}, 0x01},
		{"port-zero-domain", []byte{0x05, 0x01, 0x00, 0x03, 0x03, 'f', 'o', 'o', 0x00, 0x00}, 0x01},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := socks5Dial(t, addr)
			socks5Greet(t, c)
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := c.Write(tc.req); err != nil {
				t.Fatalf("request write: %v", err)
			}
			if got := socks5ReadReply(t, c); got != tc.want {
				t.Errorf("reply = 0x%02x; want 0x%02x", got, tc.want)
			}
		})
	}
}

// Truncated reads (client closes mid-request) must not hang the handler:
// the reply path is skipped for io errors but handleConn must return.
func TestRegression_SOCKS5TruncatedReadCloses(t *testing.T) {
	router := backend.NewRouter(backend.NewDirectBackend(0))
	p := testSOCKS5Proxy(t, router)
	addr := startSOCKS5TestProxy(t, p)

	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		c.Close()
		t.Fatal(err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil {
		c.Close()
		t.Fatal(err)
	}
	// Partial IPv4 request: header + 2 of 4 addr bytes, then close.
	_, _ = c.Write([]byte{0x05, 0x01, 0x00, 0x01, 127, 0})
	_ = c.Close()
	// Give the handler a moment to hit the truncated read and return.
	time.Sleep(200 * time.Millisecond)
}

// A bypass-host CONNECT must reach the loopback upstream through the pinned
// path (firewall loopback allowed for test); non-bypass behavior is unchanged
// (blocked private IP still gets 0x02).
func TestRegression_SOCKS5BypassPinAndBlock(t *testing.T) {
	upstreamAddr, accepted := startLoopbackUpstream(t)
	_, port, err := net.SplitHostPort(upstreamAddr)
	if err != nil {
		t.Fatal(err)
	}

	router := backend.NewRouter(backend.NewDirectBackend(2 * time.Second))
	router.SetBypassHosts([]string{"localhost"})
	p := testSOCKS5Proxy(t, router)
	addr := startSOCKS5TestProxy(t, p)

	t.Run("bypass-connect-established", func(t *testing.T) {
		c := socks5Dial(t, addr)
		socks5Greet(t, c)
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		host := "localhost"
		req := append([]byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}, host...)
		hi, lo := portToBytes(port)
		req = append(req, hi, lo)
		if _, err := c.Write(req); err != nil {
			t.Fatalf("connect write: %v", err)
		}
		if got := socks5ReadReply(t, c); got != 0x00 {
			t.Fatalf("reply = 0x%02x; want 0x00 (bypass CONNECT must establish)", got)
		}
		select {
		case <-accepted:
		case <-time.After(5 * time.Second):
			t.Fatal("upstream never accepted the bypass CONNECT")
		}
	})

	t.Run("private-still-blocked", func(t *testing.T) {
		// 10.0.0.1 stays blocked by the default firewall ranges:
		// AllowLoopbackForTest only removes 127/::1, so 10/8 is unaffected.
		c := socks5Dial(t, addr)
		socks5Greet(t, c)
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write([]byte{0x05, 0x01, 0x00, 0x01, 10, 0, 0, 1, 0x00, 0x50}); err != nil {
			t.Fatalf("connect write: %v", err)
		}
		if got := socks5ReadReply(t, c); got != 0x02 {
			t.Errorf("reply = 0x%02x; want 0x02 (private must stay blocked)", got)
		}
	})
}

func portToBytes(portStr string) (byte, byte) {
	n := 0
	for _, ch := range portStr {
		n = n*10 + int(ch-'0')
	}
	return byte(n >> 8), byte(n & 0xff)
}

// Waiver predicate parity: every router-bypassed host waives on SOCKS5,
// bypass or not, loopback spelling or not. Direct unit check of the gate.
func TestSOCKS5_BypassWaiverPredicate(t *testing.T) {
	router := backend.NewRouter(backend.NewDirectBackend(2 * time.Second))
	router.SetBypassHosts([]string{"internal.example", "localhost"})
	cases := []struct {
		host string
		want bool
	}{
		{"internal.example", true},
		{"sub.internal.example", true},
		{"localhost", true},
		{"127.0.0.1", false}, // not in bypass set -> no waiver
		{"example.com", false},
	}
	for _, tc := range cases {
		got := router.IsBypassHost(tc.host)
		if got != tc.want {
			t.Errorf("IsBypassHost(%q) = %v; want %v", tc.host, got, tc.want)
		}
	}
	// Nil-router fallback keeps historical loopback spellings only.
	var nilRouter *backend.Router
	_ = nilRouter
	for _, h := range []string{"localhost", "127.0.0.1", "::1", "[::1]"} {
		if !isLoopbackSpelling(h) {
			t.Errorf("isLoopbackSpelling(%q) = false; want true", h)
		}
	}
	if isLoopbackSpelling("internal.example") {
		t.Error("isLoopbackSpelling(internal.example) = true; want false")
	}
}
