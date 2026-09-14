package proxy

import (
	"bufio"
	"encoding/base64"
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

// serveAuthProxy starts an HTTPProxy with API-key auth on a loopback test
// port and returns its address plus a channel capturing upstream headers.
func serveAuthProxy(t *testing.T, key string, seen chan http.Header) (addr, upURL string) {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case seen <- r.Header.Clone():
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
	return ln.Addr().String(), up.URL
}

// rawForward sends a raw absolute-form GET through the proxy and returns the
// headers the upstream observed (failing unless the client got 200).
func rawForward(t *testing.T, addr, upURL string, seen chan http.Header, lines ...string) http.Header {
	t.Helper()
	for len(seen) > 0 {
		<-seen
	}
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	upHost := strings.TrimPrefix(upURL, "http://")
	var sb strings.Builder
	fmt.Fprintf(&sb, "GET %s/ HTTP/1.1\r\nHost: %s\r\n", upURL+"/", upHost)
	for _, l := range lines {
		sb.WriteString(l + "\r\n")
	}
	sb.WriteString("Connection: close\r\n\r\n")
	if _, err := io.WriteString(c, sb.String()); err != nil {
		t.Fatal(err)
	}
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
	case h := <-seen:
		return h
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never hit")
		return nil
	}
}

// Regression: the proxy must consume its own credential after authenticating.
// A proxy key carried in Authorization (bare, Bearer, Basic user:key, or mixed
// with an upstream token) must never reach the upstream byte-identical, while
// unrelated upstream tokens are preserved. X-Api-Key exists solely for proxy
// auth and is always dropped when auth is enabled.
func TestRegression_ProxyCredentialStripped(t *testing.T) {
	const key = "test-key-0123456789abcdef"
	seen := make(chan http.Header, 8)
	addr, upURL := serveAuthProxy(t, key, seen)
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

	t.Run("bearer-proxy-only-stripped", func(t *testing.T) {
		h := rawForward(t, addr, upURL, seen, "Authorization: Bearer "+key)
		if got := h.Values("Authorization"); len(got) != 0 {
			t.Errorf("upstream Authorization=%q; want stripped", got)
		}
	})

	t.Run("bare-proxy-only-stripped", func(t *testing.T) {
		h := rawForward(t, addr, upURL, seen, "Authorization: "+key)
		if got := h.Values("Authorization"); len(got) != 0 {
			t.Errorf("upstream Authorization=%q; want stripped", got)
		}
	})

	t.Run("mixed-proxy-plus-upstream", func(t *testing.T) {
		h := rawForward(t, addr, upURL, seen,
			"Authorization: Bearer "+key,
			"Authorization: Bearer upstream-token-openai")
		if got := h.Values("Authorization"); len(got) != 1 || got[0] != "Bearer upstream-token-openai" {
			t.Errorf("upstream Authorization=%q; want [upstream only]", got)
		}
	})

	t.Run("basic-user-key-stripped", func(t *testing.T) {
		h := rawForward(t, addr, upURL, seen, "Authorization: Basic "+b64("user:"+key))
		if got := h.Values("Authorization"); len(got) != 0 {
			t.Errorf("upstream Authorization=%q; want stripped", got)
		}
	})

	t.Run("basic-mixed-upstream-preserved", func(t *testing.T) {
		h := rawForward(t, addr, upURL, seen,
			"Authorization: Basic "+b64("user:"+key),
			"Authorization: Bearer upstream-token-openai")
		if got := h.Values("Authorization"); len(got) != 1 || got[0] != "Bearer upstream-token-openai" {
			t.Errorf("upstream Authorization=%q; want [upstream only]", got)
		}
	})

	t.Run("x-api-key-proxy-value-stripped", func(t *testing.T) {
		h := rawForward(t, addr, upURL, seen, "X-Api-Key: "+key)
		if got := h.Get("X-Api-Key"); got != "" {
			t.Errorf("upstream X-Api-Key=%q; want stripped", got)
		}
	})

	t.Run("x-api-key-mixed-upstream-preserved", func(t *testing.T) {
		h := rawForward(t, addr, upURL, seen,
			"X-Api-Key: "+key,
			"X-Api-Key: upstream-key")
		if got := h.Values("X-Api-Key"); len(got) != 1 || got[0] != "upstream-key" {
			t.Errorf("upstream X-Api-Key=%q; want [upstream only]", got)
		}
	})

	t.Run("proxy-authorization-dropped", func(t *testing.T) {
		h := rawForward(t, addr, upURL, seen, "Proxy-Authorization: Bearer "+key)
		if got := h.Values("Proxy-Authorization"); len(got) != 0 {
			t.Errorf("upstream Proxy-Authorization=%q; want dropped", got)
		}
	})
}
