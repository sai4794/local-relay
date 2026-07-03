package proxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/local-relay/proxy/internal/auth"
	"github.com/local-relay/proxy/internal/backend"
	"github.com/local-relay/proxy/internal/rotate"
	"github.com/local-relay/proxy/internal/security"
	"github.com/local-relay/proxy/internal/stream"
)

var copyBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 32*1024)
		return &buf
	},
}

type HTTPProxy struct {
	router    *backend.Router
	auth      *auth.APIKeyAuth
	firewall  *security.Firewall
	rotator   *rotate.Rotator
	ssrf      *security.SSRFBlocker
	bodyLimit int64
	logger    *slog.Logger
	transport *http.Transport
	client    *http.Client
	server    *http.Server
}

func NewHTTPProxy(router *backend.Router, authMiddleware *auth.APIKeyAuth, fw *security.Firewall, rotator *rotate.Rotator, logger *slog.Logger, disableKeepAlive bool, ssrf *security.SSRFBlocker, bodyLimit int64) *HTTPProxy {
	// When using multi-tor, force new connections per request so round-robin
	// actually distributes across instances. Without this, the transport's
	// connection pool reuses the same connection, defeating round-robin.
	// Always disable keep-alives for the relay. Each request creates a new
	// connection through DialContext(), ensuring round-robin distributes
	// across Tor instances. Keep-alives would reuse the same connection,
	// defeating IP rotation.
	transport := &http.Transport{
		DialContext:           router.DialContext,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   0,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:  10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     false,
	}

	return &HTTPProxy{
		router:    router,
		auth:      authMiddleware,
		firewall:  fw,
		rotator:   rotator,
		ssrf:      ssrf,
		bodyLimit: bodyLimit,
		logger:    logger,
		transport: transport,
		client: &http.Client{
			Transport: transport,
			Timeout:   60 * time.Second,
		},
	}
}

func (p *HTTPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p.auth != nil && !p.auth.Check(w, r) {
		return
	}

	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

func (p *HTTPProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	p.recordRotation()

	host := r.Host
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	hostOnly, _, err := net.SplitHostPort(host)
	if err != nil {
		http.Error(w, "bad host", http.StatusBadRequest)
		return
	}

	if p.firewall != nil && !p.firewall.AllowHost(hostOnly) {
		p.logger.Warn("blocked connection to private/internal IP", "host", hostOnly)
		http.Error(w, "connection blocked", http.StatusForbidden)
		return
	}

	// SSRF protection for CONNECT
	if p.ssrf != nil && p.ssrf.IsBlocked(host) {
		p.logger.Warn("blocked CONNECT to private/internal IP", "host", host)
		http.Error(w, "connection blocked", http.StatusForbidden)
		return
	}

	start := time.Now()
	destConn, err := p.router.DialContext(r.Context(), "tcp", host)
	if err != nil {
		p.logger.Error("failed to dial upstream", "host", host, "error", err)
		// Fix 4: CONNECT dial failure triggers rotation
		p.triggerRotateOnError("connect-dial-failure", host, err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}

	backend.TuneTCP(destConn)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		destConn.Close()
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		destConn.Close()
		p.logger.Error("hijack failed", "error", err)
		return
	}

	backend.TuneTCP(clientConn)

	p.logger.Info("CONNECT tunnel established",
		"client", clientConn.RemoteAddr(),
		"upstream", host,
	)

	// Track short tunnels as potential errors
	// Add overall timeout to prevent goroutine leak on stalled connections
	relayTimeout := 30 * time.Minute
	relayCtx, relayCancel := context.WithTimeout(r.Context(), relayTimeout)
	defer relayCancel()

	done := make(chan struct{})
	go func() {
		stream.Relay(relayCtx, destConn, clientConn)
		close(done)
	}()

	// If the tunnel closes very quickly (< 2s), it likely means an error response
	// was received inside the tunnel that the client didn't handle.
	timer := time.NewTimer(2 * time.Second)
	select {
	case <-done:
		timer.Stop()
		if time.Since(start) < 2*time.Second {
			p.logger.Warn("short tunnel detected, triggering rotation", "host", host, "duration", time.Since(start))
			if p.rotator != nil {
				p.rotator.ForceRotate()
			}
			p.router.ReportAnomaly(-1)
		}
	case <-timer.C:
		// Tunnel lived long enough — no action needed
	}
}

func (p *HTTPProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	p.recordRotation()

	if r.URL.Host == "" {
		http.Error(w, "missing host", http.StatusBadRequest)
		return
	}

	// SSRF protection — check scheme from raw request URI
	if p.ssrf != nil {
		uri := r.RequestURI
		for _, scheme := range []string{"file://", "gopher://", "javascript:", "data:"} {
			if len(uri) >= len(scheme) && uri[:len(scheme)] == scheme {
				p.logger.Warn("blocked request with disallowed scheme", "scheme", scheme)
				http.Error(w, "scheme not allowed", http.StatusForbidden)
				return
			}
		}
		if p.ssrf.IsBlocked(r.URL.Host) {
			p.logger.Warn("blocked request to private/internal IP", "host", r.URL.Host)
			http.Error(w, "request blocked", http.StatusForbidden)
			return
		}
	}

	// Firewall rate limit (bypass hosts handled by Router)
	if p.firewall != nil && !p.firewall.AllowHost(r.URL.Host) {
		p.logger.Warn("blocked request to private/internal IP", "host", r.URL.Host)
		http.Error(w, "request blocked", http.StatusForbidden)
		return
	}

	req, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	req.Header = r.Header.Clone()
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")
	// Strip client-identifying headers that would leak to upstream
	req.Header.Del("X-Forwarded-For")
	req.Header.Del("X-Real-IP")
	req.Header.Del("Forwarded")
	req.Header.Del("Via")
	req.Header.Del("X-Client-IP")
	req.Header.Del("CF-Connecting-IP")
	req.Header.Del("True-Client-IP")

	resp, err := p.client.Do(req)
	if err != nil {
		p.logger.Error("upstream request failed", "url", sanitizeURL(r.URL), "error", err)
		// Fix 2: Connection-level errors (timeout, DNS, TLS, reset) trigger rotation
		p.triggerRotateOnError("upstream-failure", sanitizeURL(r.URL), err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Rate-limit detection — trigger rotation on 429/503
	// Works independently of request-count rotation
	if resp.StatusCode == http.StatusTooManyRequests ||
		resp.StatusCode == http.StatusServiceUnavailable {
		p.logger.Warn("rate-limit detected, triggering rotation",
			"status", resp.StatusCode,
			"url", sanitizeURL(r.URL),
		)

		// Parse Retry-After header to respect server backoff
		retryAfter := parseRetryAfter(resp)
		if retryAfter > 0 {
			p.logger.Warn("Retry-After header present, delaying rotation",
				"seconds", retryAfter,
			)
			if retryAfter > 30 {
				retryAfter = 30
			}
			select {
			case <-time.After(time.Duration(retryAfter) * time.Second):
			case <-r.Context().Done():
				return
			}
		}

		// Trigger rotation through rotator if available
		if p.rotator != nil {
			p.rotator.ForceRotate()
		}
		// Signal anomaly to the backend pool (works without rotator)
		p.router.ReportAnomaly(-1)
	}

	contentType := resp.Header.Get("Content-Type")
	isSSE := strings.Contains(contentType, "text/event-stream")

	if isSSE {
		stream.CopySSE(w, resp.Body, resp.StatusCode)
	} else {
		for key, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(resp.StatusCode)
		bufPtr, ok := copyBufPool.Get().(*[]byte)
		if !ok {
			buf := make([]byte, 32*1024)
			bufPtr = &buf
		}
		defer copyBufPool.Put(bufPtr)
		io.CopyBuffer(w, resp.Body, *bufPtr)
	}
}

// triggerRotateOnError detects connection-level network errors and triggers
// IP rotation. This covers timeouts, DNS failures, TLS handshake failures,
// and connection resets — failures that happen before an HTTP response is received.
func (p *HTTPProxy) triggerRotateOnError(reason, target string, err error) {
	// Check if it's a network-level error (timeout, DNS, conn refused, reset)
	errStr := err.Error()
	isNetworkErr := strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "no such host") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "TLS handshake") ||
		strings.Contains(errStr, "certificate") ||
		strings.Contains(errStr, "i/o timeout") ||
		strings.Contains(errStr, "deadline exceeded")

	if isNetworkErr {
		p.logger.Warn("connection error detected, triggering rotation",
			"reason", reason,
			"target", target,
			"error_type", fmt.Sprintf("%T", err),
		)
		if p.rotator != nil {
			p.rotator.ForceRotate()
		}
		p.router.ReportAnomaly(-1)
	}
}

// parseRetryAfter extracts the Retry-After value from an HTTP response.
// Returns 0 if the header is missing or unparseable.
func parseRetryAfter(resp *http.Response) int {
	header := resp.Header.Get("Retry-After")
	if header == "" {
		return 0
	}

	// Try seconds format first
	if seconds, err := strconv.Atoi(header); err == nil && seconds > 0 {
		return seconds
	}

	// Try HTTP-date format
	if t, err := http.ParseTime(header); err == nil {
		delay := int(time.Until(t).Seconds())
		if delay > 0 {
			return delay
		}
	}

	return 0
}

func (p *HTTPProxy) Start(addr string) error {
	p.server = &http.Server{
		Addr:              addr,
		Handler:           p,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      0,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	p.logger.Info("HTTP proxy listening", "addr", addr)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	return p.server.Serve(listener)
}

func (p *HTTPProxy) Stop(ctx context.Context) error {
	if p.server != nil {
		return p.server.Shutdown(ctx)
	}
	return nil
}

func (p *HTTPProxy) recordRotation() {
	if p.rotator != nil && p.rotator.ShouldRotate() {
		p.logger.Info("IP rotation triggered by request count")
	}
}

// sanitizeURL strips sensitive query parameters from URLs before logging.
// Case-insensitive matching against a list of sensitive parameter names.
func sanitizeURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	q := u.Query()
	sensitive := []string{"api_key", "apikey", "key", "token", "secret",
		"passwd", "password", "auth", "signature",
		"access_token", "refresh_token", "client_secret",
		"bearer", "jwt", "session", "api-key", "x-api-key",
		"authorization", "private_key", "code", "state"}
	// Build lowercased set for case-insensitive matching
	sensLower := make(map[string]bool, len(sensitive))
	for _, p := range sensitive {
		sensLower[strings.ToLower(p)] = true
	}
	// Iterate over all query keys (preserves original keys)
	for key := range q {
		if sensLower[strings.ToLower(key)] {
			q.Set(key, "***")
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}
