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

	"github.com/local-relay/proxy/internal/auth"
	"github.com/local-relay/proxy/internal/backend"
)

// Regression HIGH-1: ?api_key=<proxykey> must authenticate the request but
// must NOT be forwarded upstream. Non-matching api_key values and other
// params must survive.
func TestRegression_QueryApiKeyStripped(t *testing.T) {
	const key = "test-key-0123456789abcdef"
	seenBody := make(chan string, 4)
	seenQuery := make(chan string, 4)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case seenQuery <- r.URL.RawQuery:
		default:
		}
		select {
		case seenBody <- "hit":
		default:
		}
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(func() { up.Close() })

	router := backend.NewRouter(backend.NewDirectBackend(2 * time.Second))
	a := auth.NewAPIKeyAuth(key)
	p := NewHTTPProxy(router, a, nil, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)), false, nil, 32<<20)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	p.listenAddr.Store(ln.Addr().String())
	srv := &http.Server{Handler: p}
	t.Cleanup(func() { srv.Close() })
	go srv.Serve(ln)
	addr := ln.Addr().String()

	upHost := strings.TrimPrefix(up.URL, "http://")

	// Mixed: matching proxy key + unrelated value + another param.
	target := fmt.Sprintf("http://%s/echo?api_key=%s&foo=bar&api_key=upstream-token", upHost, key)
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target, upHost)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("client status=%d; want 200 (query-key auth must pass)", resp.StatusCode)
	}
	var raw string
	select {
	case raw = <-seenQuery:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never hit")
	}
	if strings.Contains(raw, key) {
		t.Errorf("upstream query %q contains proxy key; want stripped", raw)
	}
	if !strings.Contains(raw, "foo=bar") {
		t.Errorf("upstream query %q missing foo=bar; want preserved", raw)
	}
	if !strings.Contains(raw, "api_key=upstream-token") {
		t.Errorf("upstream query %q missing non-matching api_key; want preserved", raw)
	}
}

// Regression HIGH-1 (unit): sole matching api_key param must vanish entirely.
func TestRegression_QueryApiKeySoleValueRemoved(t *testing.T) {
	const key = "test-key-0123456789abcdef"
	seenQuery := make(chan string, 4)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case seenQuery <- r.URL.RawQuery:
		default:
		}
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(func() { up.Close() })

	router := backend.NewRouter(backend.NewDirectBackend(2 * time.Second))
	a := auth.NewAPIKeyAuth(key)
	p := NewHTTPProxy(router, a, nil, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)), false, nil, 32<<20)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	p.listenAddr.Store(ln.Addr().String())
	srv := &http.Server{Handler: p}
	t.Cleanup(func() { srv.Close() })
	go srv.Serve(ln)

	upHost := strings.TrimPrefix(up.URL, "http://")
	target := fmt.Sprintf("http://%s/echo?api_key=%s", upHost, key)
	c, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target, upHost)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("client status=%d; want 200", resp.StatusCode)
	}
	select {
	case raw := <-seenQuery:
		if strings.Contains(raw, "api_key") {
			t.Errorf("upstream query %q still carries api_key; want empty", raw)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never hit")
	}
}

// Regression HIGH-2: CONNECT to the proxy's own listen socket must fail
// closed 508 (mirrors the handleHTTP self-dial guard), before waiver/dial.
func TestRegression_CONNECTSelfDialLoop(t *testing.T) {
	router := backend.NewRouter(backend.NewDirectBackend(2 * time.Second))
	p := testHTTPProxy(t, router)
	addr := serveHTTPProxy(t, p)

	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusLoopDetected {
		t.Fatalf("CONNECT self-dial = %d; want 508", resp.StatusCode)
	}
}

// Regression HIGH-2 alias: listener on 127.0.0.1 vs target "localhost" on the
// same port must be detected as self-dial.
func TestRegression_SelfDialLocalhostAlias(t *testing.T) {
	router := backend.NewRouter(backend.NewDirectBackend(2 * time.Second))
	p := testHTTPProxy(t, router)
	addr := serveHTTPProxy(t, p)
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	alias := net.JoinHostPort("localhost", port)
	if !p.isSelfDial(alias) {
		t.Fatalf("isSelfDial(%q) with listen %q = false; want true", alias, addr)
	}
}

// Regression HIGH-3: the guard waiver must follow router bypass config, not
// spelling. With a router whose bypass set is empty, "localhost" must NOT be
// waived (guards still apply); configured bypass hosts keep working (covered
// by TestRegression_HTTPBypassPinForward).
func TestRegression_WaiverGatedOnRouterVerdict(t *testing.T) {
	router := backend.NewRouter(backend.NewDirectBackend(2 * time.Second))
	// No SetBypassHosts: empty bypass set.
	p := testHTTPProxy(t, router)
	if p.isWaiverHost("localhost") {
		t.Error("isWaiverHost(localhost) with empty bypass set = true; want false (router-gated)")
	}
	if p.isWaiverHost("127.0.0.1") {
		t.Error("isWaiverHost(127.0.0.1) with empty bypass set = true; want false (router-gated)")
	}

	router2 := backend.NewRouter(backend.NewDirectBackend(2 * time.Second))
	router2.SetBypassHosts([]string{"localhost", "127.0.0.1"})
	p2 := testHTTPProxy(t, router2)
	if !p2.isWaiverHost("localhost") || !p2.isWaiverHost("127.0.0.1") {
		t.Error("configured bypass hosts must still be waived; got false")
	}
}

// Regression: a listener on the unspecified address (0.0.0.0 or ::, common
// in containers) accepts loopback traffic on its port, so a loopback target
// on the same port IS the same socket and must trip the self-dial guard.
// Pre-fix isSelfDial required both sides loopback and missed 0.0.0.0.
func TestRegression_SelfDialUnspecifiedBind(t *testing.T) {
	router := backend.NewRouter(backend.NewDirectBackend(2 * time.Second))
	p := testHTTPProxy(t, router)
	_, port, err := net.SplitHostPort(serveHTTPProxy(t, p))
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
			"0177.0.0.1:" + port, // octal loopback
			"2130706433:" + port, // integer loopback
			"127.1:" + port,      // short-form loopback
			"0x7f.0.0.1:" + port, // hex loopback
			"127.0.0.1.:" + port, // trailing-dot loopback
			"[::]:" + port,       // unspecified target dials local stack
		} {
			if !p.isSelfDial(target) {
				t.Errorf("isSelfDial(%q) with listen %q = false; want true", target, listen)
			}
		}
		if other := net.JoinHostPort("127.0.0.1", "1"); p.isSelfDial(other) {
			t.Errorf("isSelfDial(%q) with listen %q = true; want false (different port)", other, listen)
		}
		if external := net.JoinHostPort("93.184.216.34", port); p.isSelfDial(external) {
			t.Errorf("isSelfDial(%q) with listen %q = true; want false (public IP never self)", external, listen)
		}
	}
	// Reverse direction: loopback listener + unspecified target is also self.
	p.listenAddr.Store(net.JoinHostPort("127.0.0.1", port))
	for _, target := range []string{
		net.JoinHostPort("0.0.0.0", port),
		"[::]:" + port,
	} {
		if !p.isSelfDial(target) {
			t.Errorf("isSelfDial(%q) with loopback listen = false; want true (unspecified target dials local)", target)
		}
	}
}
