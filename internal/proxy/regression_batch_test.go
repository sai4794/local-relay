package proxy

import (
	"bufio"
	"bytes"
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
	"github.com/local-relay/proxy/internal/security"
)

func rawProxyRequest(t *testing.T, addr, request string) (int, string) {
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
	return resp.StatusCode, string(b)
}

// M-04: the proxy-port /healthz alias must be behind the same API-key gate
// as every other proxy request.
func TestProxyHealthAliasRequiresAuth(t *testing.T) {
	const key = "test-key-0123456789abcdef"
	r := backend.NewRouter(backend.NewDirectBackend(2 * time.Second))
	a := auth.NewAPIKeyAuth(key)
	p := NewHTTPProxy(r, a, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), false, nil, 32<<20)
	addr := serveHTTPProxy(t, p)

	status, _ := rawProxyRequest(t, addr, "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
	if status != http.StatusProxyAuthRequired {
		t.Errorf("unauthenticated /healthz status = %d, want 407", status)
	}

	status, body := rawProxyRequest(t, addr,
		"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Api-Key: "+key+"\r\nConnection: close\r\n\r\n")
	if status != http.StatusOK {
		t.Fatalf("authenticated /healthz status = %d, want 200", status)
	}
	if !strings.Contains(body, `"status":"ok"`) {
		t.Errorf("authenticated /healthz body = %q, want local health JSON", body)
	}
}

// M-04: absolute-form requests to a real upstream /healthz must be
// forwarded, not swallowed by the local shortcut.
func TestProxyHealthAliasAbsoluteFormIsForwarded(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "UPSTREAM:%s", r.URL.Path)
	}))
	t.Cleanup(up.Close)
	upHost := strings.TrimPrefix(up.URL, "http://")

	router := backend.NewRouter(backend.NewDirectBackend(2 * time.Second))
	router.SetBypassHosts([]string{"127.0.0.1"})
	p := NewHTTPProxy(router, nil, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), false, nil, 32<<20)
	addr := serveHTTPProxy(t, p)

	req := fmt.Sprintf("GET %s/healthz HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", up.URL, upHost)
	status, body := rawProxyRequest(t, addr, req)
	if status != http.StatusOK {
		t.Fatalf("absolute-form /healthz status = %d, want 200", status)
	}
	if body != "UPSTREAM:/healthz" {
		t.Errorf("absolute-form /healthz body = %q, want forwarded upstream response", body)
	}
}

// M-05: an over-cap body cannot be replayed after the buffered head has been
// consumed. On a 307 the transport must not send the truncated prefix to the
// redirect target.
func TestProxyOverCapBodyRedirectDoesNotReplayTruncatedPrefix(t *testing.T) {
	const payloadSize = (1 << 20) + 8192
	finalLen := make(chan int, 4)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/final", http.StatusTemporaryRedirect)
			return
		}
		b, _ := io.ReadAll(r.Body)
		select {
		case finalLen <- len(b):
		default:
		}
		fmt.Fprintf(w, "final_len=%d", len(b))
	}))
	t.Cleanup(up.Close)
	upHost := strings.TrimPrefix(up.URL, "http://")

	router := backend.NewRouter(backend.NewDirectBackend(5 * time.Second))
	router.SetBypassHosts([]string{"127.0.0.1"})
	p := NewHTTPProxy(router, nil, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), false, nil, 32<<20)
	addr := serveHTTPProxy(t, p)

	payload := bytes.Repeat([]byte("A"), payloadSize)
	var sb strings.Builder
	fmt.Fprintf(&sb, "POST %s/start HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		up.URL, upHost, payloadSize)
	sb.Write(payload)

	status, body := rawProxyRequest(t, addr, sb.String())
	// With no replayable GetBody the transport may return the 307 to the
	// client instead of following it; both outcomes are acceptable as long
	// as the truncated prefix is never replayed to the redirect target.
	if status != http.StatusOK && status != http.StatusTemporaryRedirect {
		t.Fatalf("redirect status = %d, want 200 or 307 (body=%q)", status, body)
	}
	select {
	case n := <-finalLen:
		if n != 0 {
			t.Errorf("redirect target received %d bytes (truncated replay); want 0 for a non-replayable over-cap body", n)
		}
	case <-time.After(300 * time.Millisecond):
		// No replay at all is the expected transport behavior here.
	}
}

// M-08: rate limiting must key on the canonical IP, not the raw spelling,
// or decimal/hex/octal aliases each get a fresh bucket.
func TestFirewallRateLimitCanonicalIPKey(t *testing.T) {
	fw := security.NewFirewall(security.FirewallConfig{RateLimit: 1, RateBurst: 1})
	spellings := []string{"8.8.8.8", "134744072", "0x8.8.8.8", "010.010.010.010"}
	for i, host := range spellings {
		_, ok := fw.AllowIPs(host)
		if i == 0 && !ok {
			t.Fatalf("first request to %s denied, want allowed", host)
		}
		if i > 0 && ok {
			t.Errorf("alias %s got a fresh rate bucket; want denied", host)
		}
	}
}
