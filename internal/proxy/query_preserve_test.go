package proxy

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/local-relay/proxy/internal/auth"
	"github.com/local-relay/proxy/internal/backend"
)

// L-05: re-encoding a query that had nothing stripped changes raw query
// signatures (e.g. %20 becomes + and parameter order is normalized).
func TestProxyQueryRawPreservedWhenNothingStripped(t *testing.T) {
	const key = "test-key-0123456789abcdef"
	const rawQuery = "sig=abc%2Bdef%3D%3D&z=hello%20world"

	seen := make(chan string, 2)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case seen <- r.URL.RawQuery:
		default:
		}
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(up.Close)
	upHost := strings.TrimPrefix(up.URL, "http://")

	router := backend.NewRouter(backend.NewDirectBackend(2 * time.Second))
	router.SetBypassHosts([]string{"127.0.0.1"})
	p := NewHTTPProxy(router, auth.NewAPIKeyAuth(key), nil, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)), false, nil, 32<<20)
	addr := serveHTTPProxy(t, p)

	req := fmt.Sprintf("GET %s/echo?%s HTTP/1.1\r\nHost: %s\r\nX-Api-Key: %s\r\nConnection: close\r\n\r\n",
		up.URL, rawQuery, upHost, key)
	status, _ := rawProxyRequest(t, addr, req)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	select {
	case got := <-seen:
		if got != rawQuery {
			t.Errorf("upstream query = %q, want untouched %q", got, rawQuery)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never saw the request")
	}
}
