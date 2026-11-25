package proxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/local-relay/proxy/internal/backend"
)

// F5 / L-16: the proxy-port health alias must reflect router health instead
// of hardcoding 200 ok even when every backend is down.
type unhealthyBackend struct{}

func (unhealthyBackend) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("backend down")
}
func (unhealthyBackend) IsHealthy() bool { return false }
func (unhealthyBackend) Close() error    { return nil }

func TestProxyHealthAliasReflectsRouter(t *testing.T) {
	p := NewHTTPProxy(backend.NewRouter(nil, unhealthyBackend{}), nil, nil, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)), false, nil, 32<<20)
	addr := serveHTTPProxy(t, p)
	status, body := rawProxyRequest(t, addr, "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
	if status != http.StatusServiceUnavailable {
		t.Errorf("degraded /healthz status = %d, want 503", status)
	}
	if !strings.Contains(body, `"status":"degraded"`) {
		t.Errorf("degraded /healthz body = %q, want degraded status", body)
	}
}

func startSOCKS5ForTest(t *testing.T, p *SOCKS5Proxy) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
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

// L-04: RFC1928 requires method 0xFF (no acceptable methods) when the client
// offers an empty method list, rather than silently selecting no-auth.
func TestSOCKS5EmptyMethodListRejected(t *testing.T) {
	p := testSOCKS5Proxy(t, backend.NewRouter(backend.NewDirectBackend(time.Second)))
	c, err := net.DialTimeout("tcp", startSOCKS5ForTest(t, p), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	if reply[0] != 0x05 || reply[1] != 0xFF {
		t.Errorf("method reply = %02x %02x, want 05 ff", reply[0], reply[1])
	}
}

// L-04: RSV must be 0x00 in a SOCKS5 request header.
func TestSOCKS5NonZeroRSVRejected(t *testing.T) {
	p := testSOCKS5Proxy(t, backend.NewRouter(backend.NewDirectBackend(time.Second)))
	c, err := net.DialTimeout("tcp", startSOCKS5ForTest(t, p), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(c, method); err != nil {
		t.Fatal(err)
	}
	// CONNECT, RSV=0x01 (invalid), IPv4 target.
	if _, err := c.Write([]byte{0x05, 0x01, 0x01, 0x01, 127, 0, 0, 1, 0x01, 0xBB}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0x01 {
		t.Errorf("reply code = 0x%02x, want 0x01 (general failure for bad RSV)", reply[1])
	}
}
