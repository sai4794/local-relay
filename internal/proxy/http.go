package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
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

// Per-model rate limiter for nvidia/moonshotai — 2 req/s (500ms interval)
// to avoid `429 reset after 3m4s`. Kimi removed per user request.
// Each provider has its own independent rate limiter with context awareness,
// so requests to one provider never block requests to other providers.
type hostRateLimiter struct {
	mu   sync.Mutex
	last time.Time
}

var hostLimiters sync.Map // string -> *hostRateLimiter

func getHostLimiter(host string) *hostRateLimiter {
	val, ok := hostLimiters.Load(host)
	if ok {
		return val.(*hostRateLimiter)
	}
	actual, _ := hostLimiters.LoadOrStore(host, &hostRateLimiter{})
	return actual.(*hostRateLimiter)
}

// exactHosts matched at full-name granularity; previous strings.Contains
// matched any host containing the substring (e.g. "notnvidia.example.com").
var rateLimitedHosts = map[string]bool{
	"integrate.api.nvidia.com": true,
	"opencode.ai":              true,
	"api.moonshot.cn":          true,
	"api.moonshot.ai":          true,
}

func enforceModelRateLimit(ctx context.Context, host string) {
	h := strings.ToLower(host)
	// Normalize host key (strip port)
	if strings.Contains(h, ":") {
		if hp, _, err := net.SplitHostPort(h); err == nil {
			h = hp
		}
	}
	// Match exact host or any subdomain of a listed host.
	matchedKey := ""
	for lh := range rateLimitedHosts {
		if h == lh || strings.HasSuffix(h, "."+lh) {
			matchedKey = lh
			break
		}
	}
	if matchedKey == "" {
		return
	}

	hl := getHostLimiter(matchedKey)
	hl.mu.Lock()
	defer hl.mu.Unlock()

	const minInterval = 500 * time.Millisecond // 2 req/s
	now := time.Now()
	if !hl.last.IsZero() && now.Sub(hl.last) < minInterval {
		wait := minInterval - now.Sub(hl.last)
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return
		}
		now = time.Now()
	}
	hl.last = now
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
	usePool   bool
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
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: responseHeaderTimeout,
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
		usePool:   disableKeepAlive,
		client: &http.Client{
			Transport: transport,
			Timeout:   0, // Uncapped: allows long LLM reasoning chains and 100k+ token streams
		},
	}
}

func (p *HTTPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/health" || r.URL.Path == "/healthz" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		mode := "multi_tor"
		if p.usePool {
			mode = "circuit_pool"
		}
		fmt.Fprintf(w, `{"status":"ok","mode":"%s"}`, mode)
		return
	}

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

	// Per-model rate limiter: queue to 2 req/s for nvidia/moonshot to avoid 429 3m4s (kimi removed)
	enforceModelRateLimit(r.Context(), host)

	destConn, err := p.router.DialContext(r.Context(), "tcp", host)
	if err != nil {
		p.logger.Error("failed to dial upstream", "host", host, "error", err)
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

	p.relayConn(host, destConn, clientConn)
}

// relayConn relays bytes between the hijacked client connection and the
// upstream tunnel until the tunnel closes, then cleans up. If the tunnel
// terminates very quickly AND delivered zero bytes back to the client, it
// was almost certainly a dead pooled connection, so we trigger IP rotation:
// the pool/next dial will pick a fresh slot instead of reusing the dead tunnel.
//
// The zero-byte guard matters: fast-but-legitimate tunnels (health probes,
// tiny API calls) also close within the window and previously caused
// needless NEWNYM churn on healthy circuits.
//
// We deliberately relay once via stream.Relay rather than attempting an
// in-band retry. A bidirectional relay necessarily half-closes the client
// socket the instant the dead upstream is detected (sending FIN to the
// client), so the client connection cannot be safely reused for a retry.
func (p *HTTPProxy) relayConn(host string, destConn, clientConn net.Conn) {
	relayCtx, relayCancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer relayCancel()

	start := time.Now()
	clientToUpstream, upstreamToClient := stream.Relay(relayCtx, destConn, clientConn)

	if elapsed := time.Since(start); elapsed < deadTunnelWindow {
		if upstreamToClient == 0 {
			p.logger.Warn("dead tunnel detected (no bytes returned), triggering rotation",
				"host", host, "duration", elapsed, "client_sent", clientToUpstream)
			p.rotateForDeadTunnel()
		} else {
			p.logger.Debug("short tunnel completed with data — no rotation",
				"host", host, "duration", elapsed,
				"upstream_to_client", upstreamToClient, "client_to_upstream", clientToUpstream)
		}
	}
}

const (
	// deadTunnelWindow bounds how long after tunnel start a zero-byte close is
	// still attributed to a dead pooled connection.
	deadTunnelWindow = 2 * time.Second

	// responseHeaderTimeout caps waiting for upstream response headers.
	// It must sit WELL below typical client timeouts (undici ≈250 s) so a
	// stalled circuit surfaces as a retryable error — triggering the
	// fresh-circuit retry — before the caller aborts. Healthy Tor TTFT
	// observed at ≤~30 s; this leaves >4× headroom for slow LLM upstreams.
	responseHeaderTimeout = 120 * time.Second
)

func (p *HTTPProxy) rotateForDeadTunnel() {
	if p.rotator != nil {
		p.rotator.ForceRotate()
	}
	p.router.ReportAnomaly(-1)
}

func (p *HTTPProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	p.recordRotation()

	hasTargetHeader := false
	if r.URL.Host == "" {
		targetHeader := r.Header.Get("x-target-url")
		if targetHeader == "" {
			targetHeader = r.Header.Get("x-relay-target")
		}
		relayPath := r.Header.Get("x-relay-path")
		if targetHeader != "" {
			hasTargetHeader = true
			parsed, err := url.Parse(targetHeader)
			if err != nil {
				http.Error(w, "invalid target URL", http.StatusBadRequest)
				return
			}
			// SSRF validation BEFORE rewrite - block private/internal IPs in target header
			if p.ssrf != nil && p.ssrf.IsBlocked(parsed.Host) {
				p.logger.Warn("blocked x-target-url to private/internal IP", "host", parsed.Host)
				http.Error(w, "request blocked", http.StatusForbidden)
				return
			}
			if relayPath != "" {
				pathParsed, pathErr := url.Parse(relayPath)
				if pathErr == nil {
					parsed.Path = pathParsed.Path
					parsed.RawQuery = pathParsed.RawQuery
				}
				r.URL = parsed
			} else if parsed.Path != "" && parsed.Path != "/" {
				r.URL = parsed
			} else {
				r.URL = parsed.ResolveReference(r.URL)
			}
		} else if r.Host != "" {
			r.URL.Scheme = "http"
			r.URL.Host = r.Host
		}
	}

	r.Header.Del("x-target-url")
	r.Header.Del("x-relay-target")
	r.Header.Del("x-relay-path")

	if r.URL.Host == "" {
		http.Error(w, "missing host", http.StatusBadRequest)
		return
	}

	// Bypass hosts skip SSRF checks ONLY for direct non-header-rewritten loopback requests
	isBypass := false
	if !hasTargetHeader {
		hostOnly := r.URL.Hostname()
		if hostOnly == "localhost" || hostOnly == "127.0.0.1" {
			isBypass = true
		}
	}

	// SSRF protection — check scheme from raw request URI
	if !isBypass && p.ssrf != nil {
		uri := r.RequestURI
		if idx := strings.Index(uri, ":"); idx > 0 {
			if p.ssrf.IsSchemeBlocked(uri[:idx]) {
				p.logger.Warn("blocked request with disallowed scheme", "scheme", uri[:idx])
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
	if !isBypass && p.firewall != nil && !p.firewall.AllowHost(r.URL.Host) {
		p.logger.Warn("blocked request to private/internal IP", "host", r.URL.Host)
		http.Error(w, "request blocked", http.StatusForbidden)
		return
	}

	// Per-model rate limiter: queue to 2 req/s for nvidia/moonshot to avoid 429 3m4s (kimi removed)
	if !isBypass {
		enforceModelRateLimit(r.Context(), r.URL.Host)
	}

	// Enforce the configured request body limit (if set).
	if p.bodyLimit > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, p.bodyLimit)
	}

	// Buffer small bodies so a connect-phase failure (dead circuit, TLS
	// handshake timeout) can be transparently retried on a fresh slot.
	// Oversized bodies stream through single-shot via MultiReader without
	// changing the effective size limit.
	targetURL := r.URL.String()
	headerClone := r.Header.Clone()
	stripForwardHeaders(headerClone)
	var bodyHead []byte // full body when small enough to replay
	bodyOverCap := r.Body != nil
	if r.Body != nil {
		head, err := io.ReadAll(io.LimitReader(r.Body, maxRetryBodySize+1))
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if int64(len(head)) <= maxRetryBodySize {
			bodyHead = head
			bodyOverCap = false
		} else {
			bodyHead = head[:maxRetryBodySize]
		}
	}

	reqBody := func() io.Reader {
		switch {
		case r.Body == nil:
			return nil
		case bodyOverCap: // replay buffered prefix, then live-stream the rest
			return io.MultiReader(bytes.NewReader(bodyHead), r.Body)
		default:
			return bytes.NewReader(bodyHead)
		}
	}

	var resp *http.Response
	var lastErr error
retryLoop:
	for attempt := 1; attempt <= maxUpstreamAttempts; attempt++ {
		req, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, reqBody())
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		req.Header = headerClone

		resp, lastErr = p.client.Do(req)
		if lastErr != nil {
			if !bodyRetryable(bodyOverCap) ||
				attempt == maxUpstreamAttempts || !isRetryableConnectError(lastErr) ||
				r.Context().Err() != nil {
				break
			}
			p.logger.Warn("upstream connect-phase failure, retrying on fresh circuit",
				"url", sanitizeURL(r.URL),
				"attempt", attempt,
				"max_attempts", maxUpstreamAttempts,
				"error", lastErr,
			)
			p.router.ReportAnomaly(-1)
			select {
			case <-time.After(retryDelay(attempt)):
			case <-r.Context().Done():
				break retryLoop
			}
			continue
		}

		// Got response – check for rate-limit that should trigger retry on fresh exit
		contentTypeTmp := resp.Header.Get("Content-Type")
		isSSEtmp := strings.Contains(contentTypeTmp, "text/event-stream")
		if !isSSEtmp && (resp.StatusCode == http.StatusTooManyRequests ||
			resp.StatusCode == http.StatusServiceUnavailable) {
			if attempt < maxUpstreamAttempts && bodyRetryable(bodyOverCap) && r.Context().Err() == nil {
				p.logger.Warn("rate-limit detected, rotating exit and retrying",
					"status", resp.StatusCode,
					"url", sanitizeURL(r.URL),
					"attempt", attempt,
					"max_attempts", maxUpstreamAttempts,
				)
				resp.Body.Close()
				p.router.ReportAnomaly(-1)
				select {
				case <-time.After(retryDelay(attempt)):
				case <-r.Context().Done():
					break retryLoop
				}
				continue
			}
			// Final attempt – still rate-limited, rotate for next request and fall through to forward 429
			p.logger.Warn("rate-limit detected, triggering instant circuit rotation",
				"status", resp.StatusCode,
				"url", sanitizeURL(r.URL),
			)
			p.router.ReportAnomaly(-1)
		}
		break
	}

	if lastErr != nil {
		p.logger.Error("upstream request failed", "url", sanitizeURL(r.URL), "error", lastErr)
		p.triggerRotateOnError("upstream-failure", sanitizeURL(r.URL), lastErr)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")
	isSSE := strings.Contains(contentType, "text/event-stream")

	p.forwardResponse(w, resp, isSSE)
}

// forwardResponse relays an upstream response to the client.
//
//   - Hop-by-hop headers are stripped from the forwarded header block
//     (RFC 9110 §7.6.1) — they describe the upstream hop, not this one.
//   - SSE responses are flushed after every read so LLM token streams
//     reach the client immediately instead of being buffered by net/http.
//   - Everything else is copied through with a pooled buffer.
func (p *HTTPProxy) forwardResponse(w http.ResponseWriter, resp *http.Response, isSSE bool) {
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	stripHopByHopHeaders(w.Header())

	w.WriteHeader(resp.StatusCode)

	bufPtr := copyBufPool.Get().(*[]byte)
	defer copyBufPool.Put(bufPtr)
	buf := *bufPtr

	if !isSSE {
		io.CopyBuffer(w, resp.Body, buf)
		return
	}

	flusher, canFlush := w.(http.Flusher)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, wErr := w.Write(buf[:n]); wErr != nil {
				return
			}
			if canFlush {
				flusher.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}

// hopByHopHeaders must not be forwarded across a single proxy hop.
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func stripHopByHopHeaders(h http.Header) {
	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
}

// stripForwardHeaders removes hop-by-hop headers plus client-identifying
// headers that would leak the caller's identity to the upstream.
func stripForwardHeaders(h http.Header) {
	stripHopByHopHeaders(h)
	for _, name := range []string{
		"Proxy-Connection",
		"Proxy-Authorization",
		"X-Forwarded-For",
		"X-Real-IP",
		"Forwarded",
		"Via",
		"X-Client-IP",
		"CF-Connecting-IP",
		"True-Client-IP",
	} {
		h.Del(name)
	}
}

const (
	// maxUpstreamAttempts bounds transparent retries for connect-phase
	// failures (dead circuit, TLS handshake timeout, reset) and for
	// rate-limit retries (429/503). Each attempt re-dials; ReportAnomaly
	// steers subsequent dials away from the sick one.
	maxUpstreamAttempts = 3

	// maxRetryBodySize caps how much of a request body is buffered for
	// replay across attempts. Larger bodies stream single-shot.
	// 1 MB covers all standard LLM prompts and API JSON payloads without
	// imposing multi-megabyte pre-dial memory buffering overhead.
	maxRetryBodySize = 1 << 20 // 1 MB
)

// retryDelay pauses between upstream attempts with progressive backoff.
// In multi-Tor (3 instances) and circuit pools, alternate healthy circuits/instances
// are already warm and available, making 200ms-400ms fast backoff optimal instead
// of 4-second stalls.
func retryDelay(attempt int) time.Duration {
	d := time.Duration(attempt) * 200 * time.Millisecond
	if d > 1*time.Second {
		d = 1 * time.Second
	}
	return d
}

// bodyRetryable reports whether the buffered body allows another attempt.
func bodyRetryable(streamed bool) bool { return !streamed }

// isRetryableConnectError classifies failures that occurred before any
// response headers arrived — safe to replay the request on a new circuit.
// Client-side cancellations are never retried.
//
// String matching is deliberate here: *url.Error does not satisfy the full
// net.Error interface (no Temporary), so errors.As misses the wrapped
// transport errors ("timeout awaiting response headers", TLS handshake
// timeouts, resets) that are precisely the retryable cases.
func isRetryableConnectError(err error) bool {
	if err == nil {
		return false
	}
	// Only a CANCELED context means the client walked away. DeadlineExceeded
	// must NOT be treated as non-retryable: Go's transport wraps its own
	// dial/TLS/header timeouts in errors whose cause chain includes
	// context.DeadlineExceeded — those are precisely the cases we retry.
	if errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() { // dial/TLS timeouts expose net.Error properly
		return true
	}
	s := err.Error()
	for _, marker := range []string{
		"timeout awaiting response headers",
		"TLS handshake timeout",
		"connection reset",
		"broken pipe",
		"use of closed connection",
		"EOF",
	} {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return false
}

// triggerRotateOnError logs connection-level network errors without destroying Tor circuits.
// Tor's internal circuit manager will automatically rebuild failed circuits in the background.
func (p *HTTPProxy) triggerRotateOnError(reason, target string, err error) {
	p.logger.Debug("upstream connection error observed",
		"reason", reason,
		"target", target,
		"error_type", fmt.Sprintf("%T", err),
	)
}

// sensitiveParams are query parameter names whose values must never appear
// in logs. Matching is case-insensitive.
var sensitiveParams = func() map[string]struct{} {
	names := []string{"api_key", "apikey", "key", "token", "secret",
		"passwd", "password", "auth", "signature",
		"access_token", "refresh_token", "client_secret",
		"bearer", "jwt", "session", "api-key", "x-api-key",
		"authorization", "private_key", "code", "state"}
	m := make(map[string]struct{}, len(names))
	for _, n := range names {
		m[strings.ToLower(n)] = struct{}{}
	}
	return m
}()

// sanitizeURL strips sensitive query parameters from URLs before logging.
func sanitizeURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	clone := *u
	q := clone.Query()
	for key := range q {
		if _, bad := sensitiveParams[strings.ToLower(key)]; bad {
			q.Set(key, "***")
		}
	}
	clone.RawQuery = q.Encode()
	return clone.String()
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
