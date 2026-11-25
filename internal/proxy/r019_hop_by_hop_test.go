package proxy

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/local-relay/proxy/internal/auth"
	"github.com/local-relay/proxy/internal/backend"
)

// startRawTokenUpstream serves a byte-exact HTTP/1.1 response so the upstream
// Connection header is present on the wire. A Go http.Server would normalise
// hop-by-hop headers itself and hide the defect. The optional seen channel
// receives the request headers observed by the raw upstream.
func startRawTokenUpstream(t *testing.T, response string, seen chan http.Header) string {
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
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				if seen != nil {
					h := req.Header.Clone()
					h.Set("Host", req.Host)
					select {
					case seen <- h:
					default:
					}
				}
				_, _ = io.WriteString(c, response)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func rawProxyResponse(t *testing.T, addr, request string) (*http.Response, string) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := io.WriteString(c, request); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(b)
}

func r019Proxy(t *testing.T, bypassHost string, a *auth.APIKeyAuth) string {
	t.Helper()
	router := backend.NewRouter(backend.NewDirectBackend(2 * time.Second))
	router.SetBypassHosts([]string{bypassHost})
	p := NewHTTPProxy(router, a, nil, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)), false, nil, 32<<20)
	return serveHTTPProxy(t, p)
}

// R-019 (RFC 9110 §7.6.1): a header named by the upstream Connection token
// list must not reach the client, even when that Connection header also
// carries "close" (net/http drops it from Response.Header before the proxy
// can read its tokens).
func TestR019UpstreamConnectionTokenHeaderIsStripped(t *testing.T) {
	const response = "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/plain\r\n" +
		"Connection: X-Secret-Hop, close\r\n" +
		"X-Secret-Hop: SHOULD-BE-STRIPPED\r\n" +
		"Content-Length: 5\r\n\r\nhello"
	upAddr := startRawTokenUpstream(t, response, nil)
	addr := r019Proxy(t, "127.0.0.1", nil)

	resp, body := rawProxyResponse(t, addr,
		fmt.Sprintf("GET http://%s/ HTTP/1.1\r\nHost: %s\r\n\r\n", upAddr, upAddr))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Secret-Hop"); got != "" {
		t.Errorf("X-Secret-Hop leaked through proxy = %q, want absent", got)
	}
	if body != "hello" {
		t.Errorf("body = %q, want %q", body, "hello")
	}
}

// The fix must not weaken credential stripping on the request direction.
func TestR019CredentialStrippingWithConnectionTokens(t *testing.T) {
	const response = "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/plain\r\n" +
		"Connection: X-Secret-Hop, close\r\n" +
		"X-Secret-Hop: SHOULD-BE-STRIPPED\r\n" +
		"Content-Length: 2\r\n\r\nok"
	const key = "supersecret"
	seen := make(chan http.Header, 1)
	upAddr := startRawTokenUpstream(t, response, seen)
	addr := r019Proxy(t, "127.0.0.1", auth.NewAPIKeyAuth(key))

	resp, _ := rawProxyResponse(t, addr,
		fmt.Sprintf("GET http://%s/ HTTP/1.1\r\nHost: %s\r\n"+
			"X-Api-Key: supersecret\r\nProxy-Authorization: Basic Zm9vOmJhcg==\r\n\r\n",
			upAddr, upAddr))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Secret-Hop"); got != "" {
		t.Errorf("X-Secret-Hop leaked = %q, want absent", got)
	}
	select {
	case h := <-seen:
		for _, name := range []string{"X-Api-Key", "Proxy-Authorization"} {
			if got := h.Get(name); got != "" {
				t.Errorf("upstream received %s = %q, want absent", name, got)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("raw upstream never observed the request")
	}
}

// The fix must not break SSE streaming: every event still arrives and the
// token-named response header is stripped on the streamed response too.
func TestR019SSEStreamStripsConnectionTokens(t *testing.T) {
	const response = "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/event-stream\r\n" +
		"Connection: X-Secret-Hop, close\r\n" +
		"X-Secret-Hop: SHOULD-BE-STRIPPED\r\n" +
		"\r\ndata: one\r\n\r\ndata: two\r\n\r\n"
	upAddr := startRawTokenUpstream(t, response, nil)
	addr := r019Proxy(t, "127.0.0.1", nil)

	resp, body := rawProxyResponse(t, addr,
		fmt.Sprintf("GET http://%s/ HTTP/1.1\r\nHost: %s\r\n\r\n", upAddr, upAddr))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Secret-Hop"); got != "" {
		t.Errorf("X-Secret-Hop leaked on SSE = %q, want absent", got)
	}
	if !strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Errorf("Content-Type = %q, want text/event-stream", resp.Header.Get("Content-Type"))
	}
	for _, event := range []string{"data: one", "data: two"} {
		if !strings.Contains(body, event) {
			t.Errorf("SSE body %q missing %q", body, event)
		}
	}
}
