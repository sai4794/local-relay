package proxy

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/local-relay/proxy/internal/backend"
	"github.com/local-relay/proxy/internal/security"
)

// testHTTPProxy builds an HTTPProxy with real guard semantics and loopback
// allowed so pinned bypass dials can reach test-only loopback upstreams.
func testHTTPProxy(t *testing.T, router *backend.Router) *HTTPProxy {
	t.Helper()
	fw := security.NewFirewall(security.FirewallConfig{})
	fw.AllowLoopbackForTest()
	return NewHTTPProxy(router, nil, fw, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)), false, nil, 32<<20)
}

// serveHTTPProxy starts p on a loopback test port and returns its address.
func serveHTTPProxy(t *testing.T, p *HTTPProxy) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	p.listenAddr.Store(ln.Addr().String())
	srv := &http.Server{Handler: p}
	t.Cleanup(func() { srv.Close() })
	go srv.Serve(ln)
	return ln.Addr().String()
}

// proxyRequest issues a raw origin-form request through the proxy and returns
// the status line plus body.
func proxyRequest(t *testing.T, proxyAddr, target string, body io.Reader) (int, string) {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	var sb strings.Builder
	fmt.Fprintf(&sb, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", target, hostOf(target))
	if body != nil {
		b, _ := io.ReadAll(body)
		fmt.Fprintf(&sb, "Content-Length: %d\r\n", len(b))
		sb.WriteString("\r\n")
		sb.Write(b)
	} else {
		sb.WriteString("\r\n")
	}
	if _, err := io.WriteString(c, sb.String()); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func hostOf(target string) string {
	if i := strings.Index(target, "://"); i >= 0 {
		target = target[i+3:]
	}
	if i := strings.Index(target, "/"); i >= 0 {
		target = target[:i]
	}
	return target
}

// A bypass-host forward must go through the pinned path: verification is a
// single shared Lookup and the dial reuses those IPs (no re-resolution).
func TestRegression_HTTPBypassPinForward(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "pinned-ok")
	}))
	defer upstream.Close()

	router := backend.NewRouter(backend.NewDirectBackend(2 * time.Second))
	router.SetBypassHosts([]string{"localhost"})
	p := testHTTPProxy(t, router)
	addr := serveHTTPProxy(t, p)

	// "localhost" resolves to loopback here, so rewriting the upstream's
	// 127.0.0.1 address to the bypass name exercises the pin end to end.
	uHost := strings.TrimPrefix(upstream.URL, "http://")
	_, uPort, _ := net.SplitHostPort(uHost)
	target := "http://localhost:" + uPort + "/"
	if code, body := proxyRequest(t, addr, target, nil); code != 200 || body != "pinned-ok" {
		t.Fatalf("bypass forward = %d %q; want 200 %q", code, body, "pinned-ok")
	}
}

// Header-rewritten bypass must consult the router verdict (not the hardcoded
// localhost spelling) and still reach the upstream.
func TestRegression_HTTPHeaderRewriteBypassPin(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "rewrite-ok")
	}))
	defer upstream.Close()

	router := backend.NewRouter(backend.NewDirectBackend(2 * time.Second))
	router.SetBypassHosts([]string{"localhost"})
	p := testHTTPProxy(t, router)
	addr := serveHTTPProxy(t, p)

	uHost := strings.TrimPrefix(upstream.URL, "http://")
	_, uPort, _ := net.SplitHostPort(uHost)

	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Target-Url: http://localhost:%s/\r\nConnection: close\r\n\r\n", uPort)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(b) != "rewrite-ok" {
		t.Fatalf("header-rewrite bypass = %d %q; want 200 %q", resp.StatusCode, b, "rewrite-ok")
	}
}

// A CONNECT to a blocked private IP must stay blocked (0 shared-Lookup
// bypass) — pinning must never open a hole for non-bypass targets.
func TestRegression_HTTPConnectPrivateBlocked(t *testing.T) {
	router := backend.NewRouter(backend.NewDirectBackend(2 * time.Second))
	p := testHTTPProxy(t, router)
	addr := serveHTTPProxy(t, p)

	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(c, "CONNECT 10.0.0.1:80 HTTP/1.1\r\nHost: 10.0.0.1:80\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("CONNECT 10.0.0.1 = %d; want 403", resp.StatusCode)
	}
}

// A body over the configured limit must surface 413 (client error), not a
// 502 from a dead-circuit retry path.
func TestRegression_HTTPBodyOverLimit413(t *testing.T) {
	router := backend.NewRouter(backend.NewDirectBackend(2 * time.Second))
	p := testHTTPProxy(t, router)
	p.bodyLimit = 64 // tiny limit to force the breach deterministically
	addr := serveHTTPProxy(t, p)

	big := strings.Repeat("x", 1<<20+1) // MaxBytesError needs a read past the limit
	code, _ := proxyRequest(t, addr, "http://localhost:9/", strings.NewReader(big))
	if code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-limit body = %d; want 413", code)
	}
}

// A 1MiB+1 body (exactly the replay-boundary probe size) must arrive
// byte-identical through the echo path — the over-cap prefix slice covers
// the full buffered head. The echo server speaks HTTP/1.1 with an explicit
// Content-Length (not HTTP/1.0 close-delimited): with a close-delimited
// response the client cannot distinguish "slow trickle" from "done".
func TestRegression_HTTPBodyBoundaryEcho(t *testing.T) {
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Length", fmt.Sprint(len(b)))
		w.WriteHeader(200)
		w.Write(b)
	}))
	defer echo.Close()

	router := backend.NewRouter(backend.NewDirectBackend(5 * time.Second))
	router.SetBypassHosts([]string{"127.0.0.1"})
	p := testHTTPProxy(t, router)
	addr := serveHTTPProxy(t, p)

	n := maxRetryBodySize + 1
	payload := strings.Repeat("q", n)
	uHost := strings.TrimPrefix(echo.URL, "http://")

	c, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	fmt.Fprintf(c, "POST http://%s/ HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		uHost, uHost, n, payload)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || len(got) != n || string(got) != payload {
		t.Fatalf("boundary echo = %d len=%d; want 200 len=%d byte-identical", resp.StatusCode, len(got), n)
	}
}

// Self-dial (target == own listen socket) must fail closed 508, not recurse.
func TestRegression_HTTPSelfDialLoop(t *testing.T) {
	router := backend.NewRouter(backend.NewDirectBackend(2 * time.Second))
	p := testHTTPProxy(t, router)
	addr := serveHTTPProxy(t, p)

	code, _ := proxyRequest(t, addr, "http://"+addr+"/", nil)
	if code != http.StatusLoopDetected {
		t.Fatalf("self-dial = %d; want 508", code)
	}
}
