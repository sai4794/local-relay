# ANALYST_01: Security Analysis — local-relay

**Analyst:** Network Security Engineer (Proxy/Tor/Attack Surface)  
**Date:** 2026-06-24  
**Project:** local-relay — Go HTTP/SOCKS5 relay proxy with Tor integration  
**Scope:** All source files, configs, and build system  

---

## Executive Summary

local-relay is a well-structured Go proxy that routes traffic through Tor for IP rotation. The codebase is minimal (~1400 LOC) with a clean separation of concerns. Overall security posture is **moderate-good (7/10)** for a localhost-only relay tool. Key strengths: constant-time auth comparison, SOCKS5 auth bypass to private IPs, log redaction. Key weaknesses: no auth on SOCKS5, API key in cleartext config, no rate limiting on SOCKS5, Tor control port unauthenticated.

---

## File-by-File Analysis

### 1. cmd/relay/main.go (Score: 7/10)

**Attack Vectors:**
- CLI flags override config — an attacker with shell access can bind to 0.0.0.0 via `--http :8080`
- Tor control address hardcoded to `127.0.0.1:9051` — no auth password passed to TorBackend (ControlPass is empty string)
- Version info exposed at startup (minor)

**Authentication:**
- Auth middleware is optional (`cfg.Auth.Enabled` defaults to false). When disabled, anyone on localhost can use the proxy.
- Auth middleware only applied to HTTP proxy, NOT to SOCKS5 proxy — significant gap.

**Data Exposed:**
- Startup log leaks `backend_addr` (Tor SOCKS address), backend type, listen addresses
- No sensitive data in version output beyond build metadata

**Tor Security:**
- TorBackend created without `ControlPass` — line 77-82 never sets it. This means `AUTHENTICATE ""` is sent to the Tor control port. If Tor is configured with a password, circuit rotation silently fails.
- `MaxCircuitAge: 100` is hardcoded — not configurable via YAML

**Issues:**
- Auth not wired to SOCKS5 proxy (line 130: `NewSOCKS5Proxy` takes no auth parameter)
- Tor control port auth is empty by default

---

### 2. internal/auth/apikey.go (Score: 8/10)

**Attack Vectors:**
- API key accepted via query parameter (`?api_key=...`) — visible in logs, browser history, referrer headers, and HTTP access logs
- Bearer token stripped naively — `strings.TrimPrefix("Bearer ")` doesn't validate format
- No IP-based auth, no TLS client cert auth options

**Authentication:**
- Uses `crypto/subtle.ConstantTimeCompare` — prevents timing attacks. Good.
- Three extraction methods: X-Api-Key header, Proxy-Authorization header (Bearer), query param
- Single API key model — no multi-key support, no key rotation mechanism

**Data Exposed:**
- API key stored in plaintext in config struct and YAML file
- 407 response with `Proxy-Authenticate: Basic realm="proxy"` header is standard but reveals auth is enabled

**Tor Security:** N/A (auth layer, not transport)

**Issues:**
- Query param auth leaks credentials in URLs
- No brute-force protection on auth failures (relies on firewall rate limiter which may not be applied before auth check)

---

### 3. internal/backend/router.go (Score: 8/10)

**Attack Vectors:**
- Bypass hosts check is case-insensitive suffix match — attacker could potentially use DNS rebinding to route traffic directly (bypassing Tor) if they control a domain that matches a bypass entry
- No validation that bypass hosts don't overlap with targets
- Round-robin with atomic counter is non-cryptographic but sufficient for load distribution

**Authentication:** N/A (backend layer)

**Data Exposed:**
- No direct data exposure; clean interface design

**Tor Security:**
- Properly separates Tor backend from direct backend
- Bypass mechanism correctly routes certain hosts directly, bypassing Tor — this is intentional but creates a Tor leak vector for those hosts (e.g., codebuff.com domains go direct, revealing real IP)

**Issues:**
- If direct backend fails, falls through to Tor backend without logging the fallback — could mask routing issues
- `shouldBypass` does suffix match but not exact subdomain match — `.example.com` matches `evil.example.com` which is correct, but also matches `notevil-example.com` which could be surprising

---

### 4. internal/backend/tor.go (Score: 6/10)

**Attack Vectors:**
- **Tor control port has no authentication** — `RequestNewCircuit()` sends `AUTHENTICATE ""` when `controlPass` is empty (line 160-162). Any local process can connect to port 9051 and send SIGNAL NEWNYM, or worse, SIGNAL SHUTDOWN.
- Fixed 300-byte buffer in `socks5Handshake` — safe (max SOCKS5 hostname is 255 bytes), but no bounds check before copy
- No TLS to Tor SOCKS5 port — acceptable for localhost but not for remote Tor
- `CheckHealth()` just does TCP connect — doesn't verify SOCKS5 handshake actually works

**Authentication:**
- SOCKS5 handshake to Tor uses no auth (method 0x00) — correct for default Tor config
- Control port auth is empty string by default — CRITICAL if Tor has HashedControlPassword set

**Data Exposed:**
- Control port connection could leak auth status (250 vs error)
- Error messages from SOCKS5 handshake leak response bytes

**Tor Security:**
- Circuit rotation via NEWNYM is correct approach
- `circuitAge` counter tracks requests, not time — rotation is request-count-based, not time-based (despite the name `MaxCircuitAge`)
- No circuit creation verification — assumes NEWNYM succeeded without checking new circuit works
- Keep-alive on TCP connections is good for Tor stability

**Issues:**
- No control port authentication by default
- Health check is TCP-only, not SOCKS5-level verification
- No proxy authentication to Tor (acceptable but noted)
- Error messages could be more sanitized

---

### 5. internal/config/config.go (Score: 7/10)

**Attack Vectors:**
- API key readable from YAML file on disk — no encryption-at-rest
- Environment variable `PROXY_AUTH_KEY` can enable auth but also exposes key in `/proc/*/environ`
- No config file permission checking — YAML with API key may be world-readable

**Authentication:**
- Auth is disabled by default (`Enabled: false`)
- API key minimum length enforced at 16 chars — good baseline
- No key format validation (no entropy check, no prefix requirements)

**Data Exposed:**
- Config struct contains API key in plaintext
- `applyEnvOverrides` reads multiple env vars — standard practice

**Tor Security:**
- Default backend address `127.0.0.1:9050` is standard Tor
- No Tor-specific config validation (no check for control port, auth password, etc.)

**Issues:**
- No file permission check on config.yaml (should be 0600)
- No config encryption or vault integration
- Validation doesn't check if backend address is reachable

---

### 6. internal/health/health.go (Score: 7/10)

**Attack Vectors:**
- Health endpoint has NO authentication — anyone on localhost can query status
- Exposes backend type, uptime, request count, and health status
- No rate limiting on health endpoint
- `Version: "dev"` hardcoded — doesn't use build-time version

**Authentication:** None on health endpoints.

**Data Exposed:**
- Backend type (tor/socks5/http)
- Uptime duration
- Request count (from rotator)
- Health status (healthy/degraded)

**Tor Security:** N/A (monitoring layer)

**Issues:**
- No auth on /healthz and /readyz
- Information disclosure could help attacker fingerprint the service
- Should bind to loopback only (current implementation binds to configurable address — production uses `127.0.0.1:18888` which is fine)

---

### 7. internal/log/redact.go (Score: 8/10)

**Attack Vectors:**
- Redaction is best-effort — custom headers not in the default list will be logged in plaintext
- `RedactURL` only checks for `token=` and `key=` — misses `secret=`, `password=`, `session=`, etc.
- Body redaction truncates but first 200 bytes are visible (could contain sensitive data in short payloads)

**Authentication:** N/A (logging layer)

**Data Exposed:**
- Properly redacts: Authorization, X-Api-Key, Cookie, Proxy-Authorization, Set-Cookie, Proxy-Authenticate
- Custom `redact_headers` from config are merged — good extensibility
- `RedactValue` shows first 4 chars — could leak useful info for short tokens

**Tor Security:** N/A

**Issues:**
- URL redaction pattern matching is too narrow
- No body content-type-aware redaction
- First 200 bytes of body always logged when body is larger than 200 bytes

---

### 8. internal/proxy/http.go (Score: 7/10)

**Attack Vectors:**
- **CONNECT tunnel is authenticated but request forwarding may leak proxy auth** — line 152 deletes `Proxy-Authorization` header, good
- `WriteTimeout: 0` — no write timeout on HTTP server, potential slowloris/DoS vector
- `MaxHeaderBytes: 1 << 20` (1MB) — large but reasonable
- No request size limit on body — potential memory exhaustion on large POST bodies
- `handleHTTP` passes `r.Body` directly to new request — streaming is efficient but body could be read multiple times by middleware

**Authentication:**
- Auth check happens before CONNECT/HTTP dispatch — correct order
- Auth applies to all HTTP methods including CONNECT

**Data Exposed:**
- Client IP logged on CONNECT tunnel establishment
- Upstream host logged on failed requests
- Full URL logged on upstream request failure (could contain query params with secrets)

**Tor Security:**
- CONNECT tunnel properly routed through router (which selects Tor backend)
- HTTP requests also go through router
- Firewall blocks private IPs before Tor routing — prevents SSRF via proxy

**Issues:**
- No write timeout enables slowloris attacks
- No request body size limit
- Full URL in error logs could leak sensitive query parameters

---

### 9. internal/proxy/socks5.go (Score: 5/10)

**Attack Vectors:**
- **NO AUTHENTICATION on SOCKS5** — anyone who can reach port 11080 can tunnel any TCP traffic
- No connection rate limiting per client on SOCKS5
- `handleUDPAssociate` returns "not supported" but doesn't log client info
- No max connections limit — potential resource exhaustion
- No idle connection timeout on individual SOCKS5 connections

**Authentication:** NONE. This is the most significant security gap.

**Data Exposed:**
- Target host/port logged on successful connections
- Error details logged on failed connections

**Tor Security:**
- CONNECT correctly routed through router to Tor
- Firewall blocks private IPs — good
- No DNS resolution bypass (uses SOCKS5 domain type 0x03, so DNS resolved by Tor — correct)

**Issues:**
- No auth whatsoever on SOCKS5 interface
- No rate limiting on SOCKS5 connections
- No max connection limit
- IPv6 address formatting uses `%x` which produces hex without colons — functional but could be confusing

---

### 10. internal/rotate/rotator.go (Score: 8/10)

**Attack Vectors:**
- Atomic operations prevent race conditions — good
- `onRotate` called in goroutine — if it panics, the rotator continues but rotation fails silently
- Counter is uint64 — overflow not a practical concern

**Authentication:** N/A (rotation logic)

**Data Exposed:**
- Request count exposed via health endpoint
- Rotation trigger logged with request count and interval

**Tor Security:**
- Rotation correctly delegates to `torBackend.RequestNewCircuit()`
- Circuit age tracked per-request (not per-time) — may rotate too frequently or too infrequently depending on traffic pattern

**Issues:**
- No error propagation from `onRotate` callback
- No jitter on rotation interval — predictable rotation timing

---

### 11. internal/security/firewall.go (Score: 8/10)

**Attack Vectors:**
- Rate limiter keyed by `clientIP` — behind Tor, all clients appear as 127.0.0.1 (SOCKS5 proxy connection), so rate limiting is ineffective for Tor-routed traffic
- `allowedDomains` is empty by default, meaning domain bypass is disabled — good default
- No rate limit on domain bypass traffic — bypass hosts are unlimited
- `AddBlockedRange` has no validation that the range doesn't overlap with existing ranges

**Authentication:** N/A (firewall layer)

**Data Exposed:**
- No direct data exposure

**Tor Security:**
- Private IP ranges blocked — prevents SSRF to internal services
- Comprehensive blocklist: RFC1918, loopback, link-local, carrier-grade NAT, benchmarking ranges, IPv6 ULA
- Rate limiter at 50 req/s with burst 100 — reasonable for localhost use

**Issues:**
- Rate limiter keying is ineffective when all traffic comes from localhost
- No per-destination rate limiting
- No geographic or ASN-based blocking options
- Cleanup goroutine is well-implemented with context cancellation

---

### 12. internal/stream/sse.go (Score: 8/10)

**Attack Vectors:**
- `StreamWithBackpressure` has a 5-second timeout per event — if upstream is slow, stream terminates. Could be used as a DoS vector if attacker controls upstream.
- No maximum event size limit in `CopySSE` — `scanner.Buffer` sets 64KB max which is reasonable
- Memory pools (`sync.Pool`) are properly used — no memory leak risk
- No SSE event validation — proxied events pass through unmodified

**Authentication:** N/A (streaming layer)

**Data Exposed:**
- SSE content passed through unmodified — correct behavior for a proxy

**Tor Security:**
- Streaming works through Tor backend correctly
- No timing-based information leakage in streaming

**Issues:**
- No maximum SSE stream duration
- `StreamWithBackpressure` creates per-event copies — could be optimized
- Error handling in scanner loop is minimal

---

## Configuration File Analysis

### config.yaml (Production)
- Auth DISABLED — anyone on localhost can use the proxy
- Bypass hosts include codebuff.com domains — these bypass Tor, leaking real IP
- Rotation interval of 10 requests
- Health on 127.0.0.1:18888 — loopback only, good
- Logging with redaction enabled — good

### config-test.yaml
- Backend type "http" with address "1.1.1.1:53" — DNS port as HTTP backend, unusual but valid for testing
- Auth disabled, rotation disabled
- Good test configuration

---

## Critical Findings Summary

| # | Severity | Finding | File |
|---|----------|---------|------|
| 1 | **HIGH** | SOCKS5 proxy has NO authentication — anyone can tunnel traffic | proxy/socks5.go |
| 2 | **HIGH** | Tor control port has empty auth — no AUTHENTICATE password sent | backend/tor.go |
| 3 | **MEDIUM** | API key in plaintext YAML with no file permission enforcement | config/config.go |
| 4 | **MEDIUM** | No write timeout on HTTP proxy — slowloris DoS possible | proxy/http.go |
| 5 | **MEDIUM** | Rate limiter keyed by localhost IP — ineffective for all proxy traffic | security/firewall.go |
| 6 | **MEDIUM** | API key accepted via URL query parameter — leaks in logs/referers | auth/apikey.go |
| 7 | **LOW** | Health endpoint unauthenticated — information disclosure | health/health.go |
| 8 | **LOW** | Bypass hosts leak real IP for specified domains (intentional but risky) | backend/router.go |
| 9 | **LOW** | No request body size limit on HTTP proxy | proxy/http.go |
| 10 | **LOW** | URL redaction pattern matching too narrow — misses many secret params | log/redact.go |

---

## Recommendations

1. **Add SOCKS5 authentication** — Wire `auth.APIKeyAuth` into `SOCKS5Proxy` (at minimum username/password in SOCKS5 method 0x02)
2. **Set Tor control port password** — Generate `HashedControlPassword` for Tor, pass it via config
3. **Enforce config file permissions** — Check `config.yaml` is mode 0600 on load
4. **Add HTTP write timeout** — Set to 5-10 minutes for streaming, or implement per-handler timeouts
5. **Improve rate limiting** — Key by target domain or use connection-level tracking instead of source IP
6. **Remove query param auth** — Only accept API key via headers
7. **Add auth to health endpoints** — Or verify loopback binding is enforced
8. **Add request body size limits** — Prevent memory exhaustion on large uploads
9. **Expand URL redaction** — Check for `password`, `secret`, `session`, `access_token`, `refresh_token`
10. **Add rotation jitter** — Randomize rotation interval by ±20% to prevent predictable circuit changes

---

## Security Posture Scorecard

| Component | Score | Notes |
|-----------|-------|-------|
| cmd/relay/main.go | 7/10 | Good structure, auth not wired to SOCKS5 |
| internal/auth/apikey.go | 8/10 | Constant-time compare, but query param auth is risky |
| internal/backend/router.go | 8/10 | Clean design, bypass creates intentional Tor leaks |
| internal/backend/tor.go | 6/10 | Control port auth missing, health check too shallow |
| internal/config/config.go | 7/10 | Good validation, no file permission checks |
| internal/health/health.go | 7/10 | Functional but unauthenticated |
| internal/log/redact.go | 8/10 | Good defaults, narrow URL pattern matching |
| internal/proxy/http.go | 7/10 | CONNECT well-handled, missing write timeout and body limits |
| internal/proxy/socks5.go | 5/10 | **No authentication is the critical gap** |
| internal/rotate/rotator.go | 8/10 | Clean atomic design, minor issues |
| internal/security/firewall.go | 8/10 | Good blocklist, rate limiting ineffective for proxy use |
| internal/stream/sse.go | 8/10 | Efficient pools, proper SSE handling |
| config.yaml | 6/10 | Auth disabled by default, bypass hosts leak real IP |
| go.mod | 9/10 | Minimal dependencies (only yaml.v3), reduced attack surface |
| Makefile | 9/10 | Clean build, debug symbols stripped |

**OVERALL SCORE: 7.0 / 10**

The codebase is well-engineered for its scope. The most critical gap is the complete absence of SOCKS5 authentication, which means any process on the host (or network, if bound to non-loopback) can use the proxy as an open relay. The Tor control port authentication issue compounds this — an attacker could stop Tor entirely via the unauthenticated control port. For a localhost-only tool used by a single application (9router), these issues are lower risk, but they violate defense-in-depth principles.
