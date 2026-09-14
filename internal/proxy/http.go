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
	"sync/atomic"
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
	usePool   bool
	// listenAddr records the Start address (host:port) so origin-form
	// requests can be checked for self-dial loops. atomic: written once in
	// Start, read per request.
	listenAddr atomic.Value // string
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

	// Self-dial guard (fail-closed 508, mirrors handleHTTP): a CONNECT target
	// addressing our own listen socket would re-enter ServeHTTP through the
	// dial and recurse. Runs before the waiver/dial on purpose: loopback
	// self-targets are exactly the ones the waiver would otherwise let through.
	if p.isSelfDial(host) {
		p.logger.Warn("blocked self-dial loop", "host", host)
		http.Error(w, "loop detected", http.StatusLoopDetected)
		return
	}

	hostOnly, _, err := net.SplitHostPort(host)
	if err != nil {
		http.Error(w, "bad host", http.StatusBadRequest)
		return
	}

	// Loopback-bypass waiver (mirrors handleHTTP): direct requests to
	// operator-configured bypass hosts skip the guards — bypass entries like
	// localhost/127.0.0.1 resolve to loopback, which the blocked ranges would
	// otherwise always trip. Non-bypass targets run both guards over one
	// shared Lookup: firewall.AllowIPs performs the single Resolver.Lookup;
	// SSRF re-verdicts over that SAME slice via CheckHost with no second Lookup.
	isBypass := p.isWaiverHost(hostOnly)
	var sharedIPs []net.IP
	if !isBypass {
		var ok bool
		sharedIPs, ok = p.singleLookupVerdict(hostOnly)
		if !ok {
			p.logger.Warn("blocked connection to private/internal IP", "host", hostOnly)
			http.Error(w, "connection blocked", http.StatusForbidden)
			return
		}
	}

	// Pin the verified bypass resolution for bypass-routed dials only.
	// The endpoint claim sink rides alongside: DialContext fills it with the
	// serving endpoint + dial latency (see fillClaimSink), so per-attempt
	// outcomes attribute to the instance that served the dial. Legacy
	// ReportAnomaly rotation below is unchanged in this slice.
	var claim backend.EndpointClaim
	dialCtx := backend.WithEndpointClaim(r.Context(), &claim)
	if p.router != nil && p.router.IsBypassHost(hostOnly) {
		dialCtx = backend.WithPinnedDial(dialCtx, hostOnly, sharedIPs)
	}

	destConn, err := p.router.DialContext(dialCtx, "tcp", host)
	if err != nil {
		p.logger.Error("failed to dial upstream", "host", host, "error", err)
		p.triggerRotateOnError("connect-dial-failure", host, err)
		reportOutcome(p.router, &claim, false, 0, 0, 0)
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

	p.relayConn(host, destConn, clientConn, &claim)
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
func (p *HTTPProxy) relayConn(host string, destConn, clientConn net.Conn, claim *backend.EndpointClaim) {
	relayCtx, relayCancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer relayCancel()

	start := time.Now()
	clientToUpstream, upstreamToClient := stream.Relay(relayCtx, destConn, clientConn)

	if elapsed := time.Since(start); elapsed < deadTunnelWindow {
		if upstreamToClient == 0 {
			p.logger.Warn("dead tunnel detected (no bytes returned), triggering rotation",
				"host", host, "duration", elapsed, "client_sent", clientToUpstream)
			p.rotateForDeadTunnel()
			reportOutcome(p.router, claim, false, 0, clientToUpstream, upstreamToClient)
		} else {
			p.logger.Debug("short tunnel completed with data — no rotation",
				"host", host, "duration", elapsed,
				"upstream_to_client", upstreamToClient, "client_to_upstream", clientToUpstream)
			reportOutcome(p.router, claim, true, 0, clientToUpstream, upstreamToClient)
		}
		return
	}
	// Long-lived tunnel (>= 2s): survival proves the circuit works regardless
	// of byte counts (idle LLM streams, quiet keep-alives).
	reportOutcome(p.router, claim, true, 0, clientToUpstream, upstreamToClient)
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

// singleLookupVerdict runs the firewall guard once (the single shared
// Resolver.Lookup) and re-verdicts the SSRF guard over the same IP slice via
// CheckHost — no second Lookup. Nil firewall/SSRF components are open
// (disabled). Returns the shared slice and the combined allow verdict.
// Mirrors SOCKS5Proxy.singleLookupVerdict. The loopback-bypass waiver lives
// in the callers (handleConnect/handleHTTP skip the call for waiver hosts);
// this helper itself always runs both guards.
func (p *HTTPProxy) singleLookupVerdict(host string) ([]net.IP, bool) {
	var sharedIPs []net.IP
	if p.firewall != nil {
		var ok bool
		sharedIPs, ok = p.firewall.AllowIPs(host)
		if !ok {
			return sharedIPs, false
		}
	}
	if p.ssrf != nil {
		if p.firewall != nil {
			// Re-verdict over the same slice: identical block verdict to a
			// fresh IsBlocked on those IPs, without another Lookup.
			_, blocked := p.ssrf.CheckHost(host, sharedIPs)
			if blocked {
				return sharedIPs, false
			}
			return sharedIPs, true
		}
		if p.ssrf.IsBlocked(host) {
			return nil, false
		}
		return nil, true
	}
	return sharedIPs, true
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
			// Scheme gate at header ingest: only http/https targets are
			// relayable; anything else (file:, gopher:, ftp:, ...) is
			// rejected before any DNS or rewrite work.
			if p.ssrf != nil && p.ssrf.IsSchemeBlocked(parsed.Scheme) {
				p.logger.Warn("blocked x-target-url with disallowed scheme", "scheme", parsed.Scheme)
				http.Error(w, "scheme not allowed", http.StatusForbidden)
				return
			}
			// SSRF validation BEFORE rewrite over ONE shared Lookup: the
			// firewall's AllowIPs performs the single Resolver.Lookup and
			// returns the shared IP slice; the SSRF blocker re-verdicts over
			// that SAME slice via CheckHost with no second Lookup (same
			// pattern as singleLookupVerdict below).
			var sharedHeaderIPs []net.IP
			headerAllowed := true
			if p.firewall != nil {
				sharedHeaderIPs, headerAllowed = p.firewall.AllowIPs(parsed.Host)
			}
			if headerAllowed && p.ssrf != nil {
				if p.firewall != nil {
					var blocked bool
					_, blocked = p.ssrf.CheckHost(parsed.Host, sharedHeaderIPs)
					headerAllowed = !blocked
				} else if p.ssrf.IsBlocked(parsed.Host) {
					headerAllowed = false
				}
			}
			if !headerAllowed {
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

	hostOnly := r.URL.Hostname()

	// Bypass hosts skip SSRF/firewall checks ONLY for direct non-header-rewritten loopback requests
	isBypass := !hasTargetHeader && p.isWaiverHost(hostOnly)

	// Self-dial guard (fail-closed 508): a final target addressing our own
	// listen socket would re-enter ServeHTTP with the same target forever —
	// one client connection amplifying into an unbounded chain. This runs
	// before the bypass waiver on purpose: loopback self-targets are exactly
	// the ones the waiver would otherwise let through.
	if p.isSelfDial(r.URL.Host) {
		p.logger.Warn("blocked self-dial loop", "host", r.URL.Host)
		http.Error(w, "loop detected", http.StatusLoopDetected)
		return
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
	}

	// Single shared Lookup across guards (mirrors handleConnect): firewall
	// AllowIPs performs the one Resolver.Lookup (and the single rate-limit
	// charge); SSRF re-verdicts over that SAME slice via CheckHost with no
	// second Lookup. Verdicts are identical to the previous paired
	// IsBlocked+AllowHost checks; the bypass waiver above is unchanged.
	var sharedIPs []net.IP
	if !isBypass {
		var ok bool
		sharedIPs, ok = p.singleLookupVerdict(r.URL.Host)
		if !ok {
			p.logger.Warn("blocked request to private/internal IP", "host", r.URL.Host)
			http.Error(w, "request blocked", http.StatusForbidden)
			return
		}
	}

	// Enforce the configured request body limit (if set).
	if p.bodyLimit > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, p.bodyLimit)
	}

	// Buffer small bodies so a connect-phase failure (dead circuit, TLS
	// handshake timeout) can be transparently retried on a fresh slot.
	// Oversized bodies replay the buffered probe head, then live-stream the
	// rest single-shot, without changing the effective size limit.
	//
	// Consume the proxy's own query credential: authentication already passed
	// above, so a matching api_key value must not be forwarded — the upstream
	// would otherwise receive our API key byte-identical (credential leak).
	// Only matching values are removed (the same MatchesProxyKey predicate
	// authentication uses); non-matching values and other params survive.
	// The strip happens before snapshotting targetURL so the forwarded URL
	// itself is clean.
	if p.auth != nil {
		if q := r.URL.Query(); len(q) > 0 {
			p.auth.StripProxyQueryKey(q)
			r.URL.RawQuery = q.Encode()
		}
	}
	targetURL := r.URL.String()
	headerClone := r.Header.Clone()
	stripForwardHeaders(headerClone)
	// Consume the proxy's own credential: authentication already passed above,
	// so any remaining proxy-key values must not be forwarded — the upstream
	// would otherwise receive our API key byte-identical (credential leak).
	// Only values that carry the proxy key are removed (the same predicate
	// authentication uses); unrelated upstream tokens survive. X-Api-Key is
	// filtered per-value rather than dropped outright because an upstream may
	// use its own X-Api-Key while the client authenticates the proxy via a
	// different header.
	if p.auth != nil {
		p.auth.StripProxyAuthorization(headerClone)
		if vals := headerClone.Values("X-Api-Key"); len(vals) > 0 {
			kept := vals[:0]
			for _, v := range vals {
				if !p.auth.MatchesProxyKey(v) {
					kept = append(kept, v)
				}
			}
			if len(kept) != len(vals) {
				headerClone.Del("X-Api-Key")
				for _, v := range kept {
					headerClone.Add("X-Api-Key", v)
				}
			}
		}
	}
	var bodyHead []byte // full body when small enough to replay
	bodyOverCap := r.Body != nil
	if r.Body != nil {
		head, err := io.ReadAll(io.LimitReader(r.Body, maxRetryBodySize+1))
		if err != nil {
			// Body over the configured limit surfaces here as MaxBytesError:
			// a client error (413), not a dead circuit — no retry, no rotation.
			if isBodyTooLarge(err) {
				p.logger.Warn("request body exceeds limit", "url", sanitizeURL(r.URL))
				http.Error(w, "request entity too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if int64(len(head)) <= maxRetryBodySize {
			bodyHead = head
			bodyOverCap = false
		} else {
			// Keep the WHOLE probe head (maxRetryBodySize+1 bytes): every
			// byte already read must be replayed, or the upstream receives
			// the body one byte short.
			bodyHead = head
		}
	}

	reqBody := func() (io.Reader, func() (io.ReadCloser, error)) {
		switch {
		case r.Body == nil:
			return nil, nil
		case bodyOverCap:
			// Replay buffered prefix, then live-stream the rest. Snapshot the
			// prefix slice per attempt: the transport may retain the reader
			// past the attempt boundary.
			head := append([]byte(nil), bodyHead...)
			return io.MultiReader(bytes.NewReader(head), r.Body),
				func() (io.ReadCloser, error) {
					return io.NopCloser(io.MultiReader(bytes.NewReader(head), r.Body)), nil
				}
		default:
			// Small bodies: a fresh reader per attempt (a consumed reader
			// cannot rewind for retries).
			return bytes.NewReader(bodyHead),
				func() (io.ReadCloser, error) {
					return io.NopCloser(bytes.NewReader(bodyHead)), nil
				}
		}
	}

	var resp *http.Response
	var lastErr error
	// Pin the verified bypass resolution: the transport dials through
	// router.DialContext with the request context, so attaching the pin here
	// makes bypass-routed dials use the check-time IPs instead of fresh DNS.
	// Non-bypass targets carry no pin and dial exactly as before; a nil pin
	// (localhost waiver path, which skips the lookup) also dials unchanged.
	// The endpoint claim sink rides alongside for per-attempt attribution
	// (see the CONNECT path above): reset per attempt so each attempt's
	// dial fills a fresh claim. Legacy ReportAnomaly rotation below is
	// unchanged in this slice.
	var claim backend.EndpointClaim
	baseCtx := r.Context()
	if p.router != nil && p.router.IsBypassHost(r.URL.Hostname()) {
		baseCtx = backend.WithPinnedDial(baseCtx, r.URL.Host, sharedIPs)
	}
retryLoop:
	for attempt := 1; attempt <= maxUpstreamAttempts; attempt++ {
		claim = backend.EndpointClaim{}
		dialCtx := backend.WithEndpointClaim(baseCtx, &claim)
		body, getBody := reqBody()
		req, err := http.NewRequestWithContext(dialCtx, r.Method, targetURL, body)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		// Per-attempt clone: the transport retains the map reference, so
		// sharing one map across attempts would alias them.
		req.Header = headerClone.Clone()
		// Explicit length for MultiReader replay streams: without GetBody /
		// ContentLength the transport sends chunked, and some upstreams
		// (including our echo check) hang up waiting for a framed body.
		if getBody != nil {
			req.GetBody = getBody
			req.ContentLength = r.ContentLength
		} else if bodyOverCap {
			// Over-cap single-shot streams must never carry a GetBody: a
			// half-consumed r.Body cannot be rewound, so a redirect or retry
			// replaying it would corrupt the body. Nil GetBody forces the
			// transport to follow redirects with the documented
			// GetBody-missing behavior instead.
			req.GetBody = nil
		}

		resp, lastErr = p.client.Do(req)
		if lastErr != nil {
			// Body over the configured limit surfaces here as MaxBytesError
			// (buffering only reads the first 1MiB+1): a client error, not a
			// dead circuit — 413 with no retry and no rotation.
			if isBodyTooLarge(lastErr) {
				p.logger.Warn("request body exceeds limit", "url", sanitizeURL(r.URL))
				http.Error(w, "request entity too large", http.StatusRequestEntityTooLarge)
				return
			}
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
			// Rotation-only: the terminal attempt below carries the single
			// attributed sample for this client request (see the final-429
			// branch). Reporting a failure sample per attempt would let one
			// transient blip trip quarantine_after_fails alone.
			p.router.ReportAnomaly(-1)
			select {
			case <-time.After(retryDelay(attempt)):
			case <-r.Context().Done():
				break retryLoop
			}
			continue
		}

		// Got response – check for rate-limit that should trigger retry on fresh exit
		isSSEtmp := stream.HasSSEContentType(resp.Header)
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
				// Rotation-only (see connect-phase branch): the terminal
				// attempt carries the single attributed sample.
				p.router.ReportAnomaly(-1)
				select {
				case <-time.After(retryDelay(attempt)):
				case <-r.Context().Done():
					break retryLoop
				}
				continue
			}
			// Final attempt – still rate-limited, rotate for next request and fall through to forward 429.
			// Terminal outcome (one quarantine sample per CLIENT request,
			// not per attempt): retries above already reported their own
			// attempt samples; a single request must never trip the
			// consecutive-fails gate alone, so intermediate attempts mark
			// rotation only (ReportAnomaly) while the terminal attempt
			// carries the single attributed sample.
			p.logger.Warn("rate-limit detected, triggering instant circuit rotation",
				"status", resp.StatusCode,
				"url", sanitizeURL(r.URL),
			)
			p.router.ReportAnomaly(-1)
			reportOutcome(p.router, &claim, false, resp.StatusCode, 0, 0)
		} else if !isSSEtmp {
			// Non-SSE terminal response: any non-429/503 status proves the
			// circuit works (other 4xx/5xx are upstream verdicts, not dead
			// circuits) — the missing success path. SSE success is recorded
			// after forwardResponse returns (stream completed).
			reportOutcome(p.router, &claim, resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusServiceUnavailable, resp.StatusCode, 0, 0)
		}
		break
	}

	if lastErr != nil {
		p.logger.Error("upstream request failed", "url", sanitizeURL(r.URL), "error", lastErr)
		p.triggerRotateOnError("upstream-failure", sanitizeURL(r.URL), lastErr)
		reportOutcome(p.router, &claim, false, 0, 0, 0)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	isSSE := stream.HasSSEContentType(resp.Header)

	p.forwardResponse(w, resp, isSSE)
	if isSSE {
		// SSE stream completed: survival proves the circuit works. 429/503
		// SSE stays excluded (gated above, same as the retry path).
		if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusServiceUnavailable {
			reportOutcome(p.router, &claim, true, resp.StatusCode, 0, 0)
		}
	}
}

// forwardResponse relays an upstream response to the client.
//
//   - Hop-by-hop headers are stripped from the forwarded header block
//     (RFC 9110 §7.6.1) — they describe the upstream hop, not this one.
//     Headers named by either direction's Connection token list are stripped
//     too: they are hop-scoped by definition, in both directions.
//   - SSE responses are flushed after every read so LLM token streams
//     reach the client immediately instead of being buffered by net/http.
//   - Everything else is copied through with a pooled buffer.
func (p *HTTPProxy) forwardResponse(w http.ResponseWriter, resp *http.Response, isSSE bool) {
	stripConnectionTokens(w.Header(), resp.Header)
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	stripConnectionTokens(w.Header(), resp.Header)
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
// headers that would leak the caller's identity to the upstream. Headers
// named by the client's Connection token list are hop-scoped by definition
// (RFC 9110 §7.6.1) and are stripped in the same pass, so a client cannot
// smuggle a hop header (e.g. "Connection: X-Custom-Hop, Keep-Alive" keeping
// X-Custom-Hop alive upstream).
func stripForwardHeaders(h http.Header) {
	stripConnectionTokens(h)
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

// stripConnectionTokens deletes every header named by the Connection token
// lists found in h itself plus, optionally, extra header blocks (the
// response direction merges the client's pre-existing Connection tokens with
// the upstream's). Token names are trimmed, compared case-insensitively by
// Del, and "Connection" itself is left for stripHopByHopHeaders.
func stripConnectionTokens(h http.Header, extras ...http.Header) {
	seen := map[string]struct{}{}
	collect := func(hd http.Header) {
		for _, v := range hd.Values("Connection") {
			for _, tok := range strings.Split(v, ",") {
				if name := strings.TrimSpace(tok); name != "" {
					if _, ok := seen[strings.ToLower(name)]; !ok {
						seen[strings.ToLower(name)] = struct{}{}
						h.Del(name)
					}
				}
			}
		}
	}
	collect(h)
	for _, e := range extras {
		collect(e)
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

// isBodyTooLarge reports whether err (possibly wrapped by the transport) is
// the configured body-limit breach from http.MaxBytesReader.
func isBodyTooLarge(err error) bool {
	var mbe *http.MaxBytesError
	return errors.As(err, &mbe)
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

// sanitizeURL strips sensitive query parameters and any userinfo credentials
// from URLs before logging. Absolute-form targets can carry user:password,
// which must never reach logs even though it is not a query parameter.
func sanitizeURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	clone := *u
	clone.User = nil
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
	p.listenAddr.Store(addr)
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

// isWaiverHost reports whether the guard-skipping loopback waiver applies to
// host. The waiver is gated on the router's configured bypass verdict
// (IsBypassHost), so operator config — not spelling — decides: localhost,
// 127.0.0.1, [::1]/::1 and any other configured bypass host are unified via
// one verdict. Nil-safe: with no router (unit-constructed proxies) it falls
// back to the legacy localhost/127.0.0.1/::1 spelling check so existing
// tests keep passing.
func (p *HTTPProxy) isWaiverHost(host string) bool {
	if p.router != nil {
		return p.router.IsBypassHost(host)
	}
	h := strings.ToLower(strings.TrimPrefix(strings.TrimSuffix(host, "]"), "["))
	h = strings.TrimSuffix(h, ".")
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

// isSelfDial reports whether target (host or host:port) addresses this
// proxy's own listen socket. Origin-form clients send r.URL.Host == ""; only
// header-rewritten absolute targets reach here with a host, so a match means
// the relay would dial itself and re-enter ServeHTTP with the same target.
// Comparing both the configured host:port string and the resolved loopback
// sockets for the listen port covers "localhost", "127.0.0.1", and "[::1]"
// spellings without depending on resolver aliases. Unknown listen address
// (never started, e.g. unit-constructed proxies) returns false.
func (p *HTTPProxy) isSelfDial(target string) bool {
	addr, _ := p.listenAddr.Load().(string)
	if addr == "" {
		return false
	}
	tHost, tPort, err := net.SplitHostPort(target)
	if err != nil {
		tHost, tPort = target, ""
	}
	lHost, lPort, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if tPort == "" || tPort != lPort {
		return false
	}
	// Exact configured-address match (covers hostnames like "localhost").
	if strings.EqualFold(tHost, lHost) {
		return true
	}
	// Resolved-loopback match: "localhost" is normalized to loopback before
	// comparing, so a listener on 127.0.0.1 and a target of localhost (same
	// port) are detected as the same socket. An unspecified listen host
	// (0.0.0.0 or ::, common in containers) accepts loopback traffic on
	// that port, so it counts as loopback-equivalent on the listen side.
	// Only block when BOTH sides resolve to loopback, so a non-loopback
	// hostname bound by config can never collide with a loopback target on
	// the same port number.
	tLoop := isLoopbackHost(tHost)
	lLoop := isLoopbackHost(lHost) || isUnspecifiedHost(lHost)
	return tLoop && lLoop
}

// isUnspecifiedHost reports whether h is the IPv4 or IPv6 unspecified
// address (0.0.0.0 or ::, bracketed or bare): a listener bound there
// accepts traffic on every local interface, including loopback.
func isUnspecifiedHost(h string) bool {
	ip := net.ParseIP(strings.Trim(h, "[]"))
	return ip != nil && ip.IsUnspecified()
}

// isLoopbackHost reports whether h is a loopback address in any accepted
// spelling: 127.0.0.0/8, ::1 (bracketed or bare), or "localhost"
// (case-insensitive) treated as its conventional loopback alias.
func isLoopbackHost(h string) bool {
	if strings.EqualFold(strings.TrimSuffix(h, "."), "localhost") {
		return true
	}
	if ip := net.ParseIP(strings.Trim(h, "[]")); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
