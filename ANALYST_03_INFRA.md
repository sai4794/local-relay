# ANALYST_03: Infrastructure Architecture Review

**Reviewer:** Infrastructure Architect (HA Proxy Systems)
**Date:** 2026-06-24
**Scope:** /home/stb/local-relay/ — Go proxy relay (HTTP :18080, SOCKS5 :11080, Health :18888)
**Overall Infrastructure Score: 5.8 / 10**

---

## Executive Summary

local-relay is a well-structured single-binary Go proxy relay designed for Tor-based traffic proxying with rate-limit bypass use cases. The codebase demonstrates solid engineering fundamentals — clean separation of concerns, context-aware shutdown, and basic health checking — but exhibits significant gaps in production-readiness: no persistent health state, no metrics/observability, no graceful degradation between backends, no connection pool management, and limited failure recovery. It is suitable for development/personal use but requires substantial hardening for production deployment.

---

## Per-File Analysis

### 1. cmd/relay/main.go

**Purpose:** Application entrypoint; wires all components together, handles signal-based shutdown.

| Dimension | Assessment |
|---|---|
| **Failure Handling** | Config load failure → os.Exit(1). HTTP/SOCKS5 proxy start failures → trigger context cancellation via `stop()`. Tor health check failure → logged as warning but does NOT block startup (graceful degradation: proceeds without Tor). Graceful shutdown with 10s timeout via `context.WithTimeout`. **Weakness:** Health server failure does NOT trigger shutdown — it's fire-and-forget (`go func`). If health server crashes, there's no recovery. |
| **Availability Model** | Single-process, single-instance. No process supervision (no systemd unit, no restart logic). Signal handling (SIGINT/SIGTERM) is correct. The app relies on external process management (systemd, supervisord, or manual) for restart. **No watchdog.** |
| **Scaling** | Single goroutine per proxy server. HTTP proxy uses `http.Server.Serve()` (goroutine-per-connection via Go's net/http). SOCKS5 uses manual goroutine-per-connection. No worker pool limits — unbounded goroutine growth under load. No multi-instance coordination. |
| **Monitoring** | Structured logging via slog (JSON/text). Version/commit/build-time exposed via `-version`. No Prometheus metrics, no pprof, no trace IDs. |
| **Score: 5/10** | Clean wiring, good signal handling, but no process supervision, no metrics, health server failure is silently ignored. |

---

### 2. internal/auth/apikey.go

**Purpose:** API key authentication middleware supporting X-Api-Key header, Proxy-Authorization Bearer, and query param.

| Dimension | Assessment |
|---|---|
| **Failure Handling** | Authentication failure → 407 Proxy Authentication Required with `Proxy-Authenticate` header. Constant-time comparison (`subtle.ConstantTimeCompare`) prevents timing attacks. **No failure logging** — auth failures are silent. No lockout/brute-force protection at this layer (delegated to firewall rate limiter). |
| **Availability Model** | Stateless, in-memory. No external dependencies. Auth is effectively free from an availability standpoint. Single API key only — no key rotation, no key storage backend. |
| **Scaling** | O(n) per-request where n is key extraction attempts (3 paths). Negligible. Stateless design means it scales horizontally trivially. |
| **Monitoring** | None. No counters for auth failures, no audit logging. A misconfigured key gives zero diagnostic signal. |
| **Score: 6/10** | Secure comparison is good. But single-key design, no failure logging, and no multi-key support limit operational utility. |

---

### 3. internal/backend/router.go

**Purpose:** Backend selection with round-robin, health-gating, and bypass-host routing.

| Dimension | Assessment |
|---|---|
| **Failure Handling** | Iterates ALL backends on dial failure — if one fails, tries the next (failover). Bypass hosts attempt direct backend first, fall through to primary if direct fails. Returns "no healthy backends available" if all fail. **Weakness:** No backoff, no circuit breaker, no retry delay. A transient failure immediately marks the backend unhealthy and skips it, but there's no recovery timer — health state depends on the backend's own `IsHealthy()` implementation. |
| **Availability Model** | Active-passive: primary backend (Tor) + direct backend (bypass). Uses atomic counter for round-robin (lock-free). **Not truly HA** — only two backends max, and the "round-robin" is really just failover since TorBackend is always index 0. |
| **Scaling** | Lock-free atomic counter is efficient. `sync.RWMutex` in backends is appropriate. Bypass host lookup is O(n) linear scan — fine for small lists but not optimal. |
| **Monitoring** | None at router level. No dial attempt counters, no latency histograms, no backend-switch events. |
| **Score: 6/10** | Clean failover design, lock-free hot path. But no circuit breaker, no recovery detection, no metrics. The "round-robin" with 1-2 backends is effectively just failover. |

---

### 4. internal/backend/tor.go

**Purpose:** Tor SOCKS5 backend + direct TCP backend with health checking and circuit rotation.

| Dimension | Assessment |
|---|---|
| **Failure Handling** | Dial failure → marks `healthy=false` under mutex. `CheckHealth()` performs a TCP connect probe to Tor's SOCKS port. SOCKS5 handshake errors → connection closed, error returned. Control port circuit rotation has its own error handling (auth failure, NEWNYM rejection). **Weakness:** Once `healthy=false` is set, recovery only happens via explicit `CheckHealth()` call — there's no automatic periodic re-probe. The health server calls `CheckHealth()` which does re-probe, but if the health server is not running, Tor can stay "unhealthy" forever after a single failure. DirectBackend's `IsHealthy()` always returns `true` — it never detects its own failure. |
| **Availability Model** | Single Tor instance. Health is a boolean flag, not a degraded/partial state. Circuit rotation is request-count-based (every N requests), not time-based — a burst of requests can exhaust a circuit quickly. Max circuit age default is 100 requests. |
| **Scaling** | TCP keepalive configured (30s). NoDelay is set. Single dialer per backend instance — no connection pooling at this layer (Go's `net/http.Transport` handles pooling above). The SOCKS5 handshake is synchronous per connection. |
| **Monitoring** | Circuit rotation is logged. Health check failure is logged at startup. No metrics for Tor latency, circuit age, or SOCKS5 handshake success rate. |
| **Score: 5/10** | Functional Tor integration with circuit rotation. But recovery is fragile (depends on external health probing), no connection pooling, no Tor-specific observability. DirectBackend blindly reports healthy. |

---

### 5. internal/config/config.go

**Purpose:** YAML config loading with defaults, environment variable overrides, and validation.

| Dimension | Assessment |
|---|---|
| **Failure Handling** | Three-phase load: defaults → YAML → env overrides → validation. Each phase has clear error messages. Validation catches port conflicts, min key lengths, valid enum values. **Strong design pattern.** Missing: no config reload support (requires restart). |
| **Availability Model** | Static configuration loaded once at startup. No hot-reload, no config watching. Environment variable overrides enable 12-factor deployment. |
| **Scaling** | Not applicable — config is static. |
| **Monitoring** | None — config doesn't expose itself. Logging the loaded config at startup (in main.go) is the only observability. |
| **Score: 8/10** | Excellent config design for the scope. Clean defaults, env overrides, thorough validation, clear error messages. Deducted for no hot-reload. |

---

### 6. internal/health/health.go

**Purpose:** HTTP health check server with `/healthz` and `/readyz` endpoints.

| Dimension | Assessment |
|---|---|
| **Failure Handling** | `/healthz` returns 503 when unhealthy (degraded mode). `/readyz` returns 503 when backend unhealthy. Health server has proper timeouts (Read: 5s, Write: 5s, Idle: 60s). Graceful shutdown via `Shutdown(ctx)` with 5s timeout. **Weakness:** Health check logic delegates entirely to the backend's `IsHealthy()` — there's no independent liveness check (e.g., can the process allocate memory, open files, etc.). Version is hardcoded as `"dev"` — not injected from build vars. |
| **Availability Model** | Liveness + readiness split (Kubernetes-compatible pattern). JSON response format. Uptime tracked from server start. **But:** No authentication on health endpoints — any client can probe. No caching headers. |
| **Scaling** | Lightweight HTTP server. Minimal overhead. Could handle many concurrent health probes. |
| **Monitoring** | Exposes uptime, backend status, request count (via rotator). Warnings array in HealthStatus but never populated. Version string is static "dev". |
| **Score: 6/10** | Good pattern (healthz/readyz), proper timeouts and shutdown. But no independent liveness checks, no auth, no metrics export, version not injected. |

---

### 7. internal/log/redact.go

**Purpose:** Sensitive header/body redaction for logging.

| Dimension | Assessment |
|---|---|
| **Failure Handling** | N/A — pure data transformation. Always succeeds. |
| **Availability Model** | Stateless. No dependencies. |
| **Scaling** | O(n) per header set. Body redaction is O(1). Negligible overhead. Buffer pool not used here (direct slice operations). |
| **Monitoring** | None — redaction itself is not tracked. No counters for how many headers were redacted. |
| **Score: 7/10** | Good security hygiene. Redacts credentials from logs by default. But: `RedactURL` only checks for `token=` and `key=` — misses many sensitive patterns. `RedactValue` is asymmetric (shows first 4 chars). Body redaction loses all data for small bodies — could retain structure. Not actually used anywhere in the proxy code (no `HeaderRedactor` instantiation visible in the proxy handlers). |

**Critical Note:** This file appears UNUSED. No code in `proxy/http.go`, `proxy/socks5.go`, or `main.go` instantiates or calls `HeaderRedactor`. The logging config in `config.go` defines `RedactHeaders` but the proxy code logs headers via slog without redaction. This is a security gap — API keys and auth headers may appear in logs.

---

### 8. internal/proxy/http.go

**Purpose:** HTTP/HTTPS (CONNECT) proxy with auth, firewall, and SSE support.

| Dimension | Assessment |
|---|---|
| **Failure Handling** | Auth failure → 407. Firewall block → 403. Dial failure → 502. Hijack failure → 500 + connection cleanup. HTTP upstream failure → 502. All errors logged. `defer resp.Body.Close()` prevents resource leaks. **Good:** Pool-based buffer (`copyBufPool`) reduces GC pressure. **Weakness:** No request timeout enforcement per-request — relies on transport-level timeouts. CONNECT tunnel has no read/write deadline on the hijacked connection. |
| **Availability Model** | Go's built-in HTTP server (goroutine-per-connection). MaxHeaderBytes limited to 1MB (good for DoS prevention). WriteTimeout is 0 (unlimited) — intentional for long-lived connections/SSE but risky for resource exhaustion. |
| **Scaling** | Transport pool: MaxIdleConns=4, MaxIdleConnsPerHost=2 — very conservative. Good for Tor (limited bandwidth). Idle timeout 90s, TLS handshake timeout 30s, response header timeout 60s, client timeout 300s. SSE detection via Content-Type. ForceAttemptHTTP2=false (correct for proxy use). |
| **Monitoring** | Structured logging of connection establishment, upstream failures, firewall blocks. No request counting, no latency metrics, no active connection gauge. |
| **Score: 6/10** | Solid HTTP proxy implementation. Good error handling, proper connection tuning, SSE support. But: WriteTimeout=0 is risky, no request-level metrics, connection pool settings are hardcoded not configurable. |

---

### 9. internal/proxy/socks5.go

**Purpose:** SOCKS5 proxy with CONNECT and UDP ASSOCIATE (stub) support.

| Dimension | Assessment |
|---|---|
| **Failure Handling** | Handshake failure → close + debug log. Request parse failure → close + debug log. Dial failure → SOCKS5 error reply (0x05 = connection refused). Firewall block → SOCKS5 error reply (0x02 = connection not allowed). **Weakness:** `Start()` returns `nil` on listener accept error (line 43) — silent failure. No graceful drain on stop. |
| **Availability Model** | Raw TCP listener with goroutine-per-connection. No connection limits. No accept backlog tuning. |
| **Scaling** | Unbounded goroutine spawning per accepted connection. 30s timeout on dial only. No per-connection read/write deadlines after SOCKS5 handshake. No connection pool. |
| **Monitoring** | Debug-level logging for handshake failures, info-level for successful connections. No counters. |
| **Score: 5/10** | Functional SOCKS5 with IPv4/IPv6/domain support. But: silent accept failure, no connection limits, no graceful drain, UDP ASSOCIATE is a stub (returns error 0x07). Auth is NOT checked for SOCKS5 (unlike HTTP proxy). |

**Security Note:** SOCKS5 proxy does NOT check API key authentication. The auth middleware is only wired into HTTP proxy. Any client connecting to port 11080 can use the proxy without credentials.

---

### 10. internal/rotate/rotator.go

**Purpose:** Request-count-based circuit rotation trigger.

| Dimension | Assessment |
|---|---|
| **Failure Handling** | No error handling — rotation callback is fire-and-forget via `go r.onRotate()`. Rotation failure is logged by the caller (main.go) but doesn't affect request routing. |
| **Availability Model** | Atomic counter, lock-free. Stateless (except callback). Counter monotonically increases — `Reset()` exists but is never called. |
| **Scaling** | Lock-free atomics. `Add(1)` is atomic and safe for concurrent use. Callback runs in a goroutine — non-blocking to the hot path. |
| **Monitoring** | Logs rotation trigger with count and interval. `GetCount()` exposes total requests. `lastTrade` tracks last rotation time but is never read externally. |
| **Score: 5/10** | Simple and effective for its purpose. But: rotation is request-count only (not time-based), no rotation failure tracking, `lastTrade` is written but never exposed, no rotation latency measurement. |

---

### 11. internal/security/firewall.go

**Purpose:** IP range blocking (RFC1918 etc.) + per-client token bucket rate limiting.

| Dimension | Assessment |
|---|---|
| **Failure Handling** | CIDR parse errors silently skipped (defaults to empty list). Rate limiter cleanup goroutine respects context cancellation. Stop channel for cleanup. **Weakness:** Rate limiter uses a map that grows unbounded between cleanup intervals (5min). Under heavy load from many IPs, this is a memory leak vector. No ceiling on map size. `RateLimiter.Allow()` holds a mutex for the entire check — contention under high concurrency. |
| **Availability Model** | In-memory state. No persistence. Rate limiter state is lost on restart (acceptable for this use case). Cleanup runs every 5 minutes, evicts entries idle for 5 minutes. |
| **Scaling** | Mutex on `RateLimiter.Allow()` is a bottleneck — all rate limit checks serialize on one lock. For high-throughput scenarios, a sharded or per-key lock would be better. Blocked ranges are checked with RLock (good). `AllowHost` does linear scan of all ranges — fine for ~12 CIDRs. |
| **Monitoring** | No metrics for blocked connections, rate-limited requests, or firewall events. |
| **Score: 6/10** | Good default blocked ranges (comprehensive RFC1918 + more). Token bucket is correct. But: no rate limit metrics, unbounded map growth, global mutex on rate limiter, no dynamic rule updates at runtime. |

---

### 12. internal/stream/sse.go

**Purpose:** Server-Sent Events streaming, bidirectional relay, and backpressure-aware streaming.

| Dimension | Assessment |
|---|---|
| **Failure Handling** | `CopySSE` falls back to `CopyRaw` if Flusher not supported. `Relay` cancels context on either direction completion — proper half-close via `CloseWrite()`. `StreamWithBackpressure` has 5s timeout on channel send to prevent goroutine leaks. **Good:** `sync.Pool` for buffer reuse. `Relay` properly closes both connections after `Wait()`. |
| **Availability Model** | Stateless streaming functions. No persistent state. Context cancellation propagates correctly. |
| **Scaling** | Buffer pool (`sync.Pool`) with 32KB buffers reduces allocation. SSE scanner buffer is 64KB max. `StreamWithBackpressure` has channel buffer of 64 events — reasonable. |
| **Monitoring** | None. No byte counters, no SSE event counts, no relay duration tracking. |
| **Score: 7/10** | Well-implemented streaming layer. Proper context handling, buffer pooling, backpressure support. `Relay` correctly handles bidirectional close. But: no metrics, `StreamWithBackpressure` is defined but never called (dead code). |

**Note:** `StreamWithBackpressure` is defined but never used in the codebase. The SSE path in `http.go` uses `CopySSE` instead.

---

### 13. config.yaml

**Purpose:** Runtime configuration for local-relay.

| Dimension | Assessment |
|---|---|
| **Failure Handling** | N/A — static file. |
| **Availability Model** | Binds to loopback (127.0.0.1) on all ports — correct for local use. Tor backend on standard port 9050. Health on 18888. |
| **Scaling** | Rotation interval of 10 requests is aggressive — will trigger NEWNYM frequently. |
| **Monitoring** | Health enabled, JSON logging, info level. Good defaults. |
| **Score: 7/10** | Sensible defaults for the intended use case. Loopback binding is correct. Rotation interval may be too aggressive for production. Auth disabled by default (security concern for non-local use). |

---

### 14. Makefile

**Purpose:** Build system with version injection, cross-compilation, and standard targets.

| Dimension | Assessment |
|---|---|
| **Failure Handling** | `git describe` and `git rev-parse` have fallback defaults. |
| **Availability Model** | N/A — build-time artifact. |
| **Scaling** | Cross-compiles for 5 targets (linux-amd64, linux-arm64, darwin-arm64, darwin-amd64, windows-amd64). |
| **Monitoring** | Version/commit/build-time injected via ldflags — good practice. |
| **Score: 7/10** | Clean build system. Strips debug info (`-s -w`). Missing: no `docker` target, no `rpm`/`deb` packaging, no systemd unit file, no `vet` target. |

---

## Cross-Cutting Infrastructure Concerns

### Failure Recovery Matrix

| Component | Detects Failure | Recovers Autonomously | Exposes Health |
|---|---|---|---|
| Tor backend | Yes (dial fail → unhealthy) | Only via CheckHealth() re-probe | Yes (boolean) |
| Direct backend | No (always reports healthy) | N/A | Misleading |
| HTTP proxy | Yes (server errors) | No (crash → process dies) | No |
| SOCKS5 proxy | Partial (accept error → silent nil) | No | No |
| Health server | Yes (readiness probe) | No | N/A |
| Rate limiter | N/A | Cleanup goroutine | No |
| Auth | N/A | N/A | No |

### Key Infrastructure Gaps

1. **No Metrics/Observability:** No Prometheus endpoint, no request counters, no latency histograms, no connection gauges. Cannot monitor in production without external instrumentation.

2. **No Process Supervision:** No systemd unit, no Docker healthcheck, no restart policy. Relies entirely on external process management.

3. **No Connection Pooling at Proxy Level:** Tor backend creates a new connection per request. The `net/http.Transport` pools idle connections but the pool is small (MaxIdleConns=4).

4. **Security Gap — SOCKS5 Auth Missing:** SOCKS5 proxy does not check API keys. Any client on 127.0.0.1:11080 can proxy without authentication.

5. **Security Gap — Log Redactor Unused:** `HeaderRedactor` is implemented but never instantiated. API keys may appear in structured logs.

6. **No Graceful Drain for SOCKS5:** `Stop()` closes the listener but doesn't wait for in-flight connections to complete. HTTP proxy properly drains via `Shutdown(ctx)`.

7. **Unbounded Goroutine Growth:** Both HTTP and SOCKS5 proxies spawn goroutines per connection with no limits. Under load, memory exhaustion is possible.

8. **No TLS:** All proxy ports are plaintext. For local-only use this is acceptable, but limits deployment options.

9. **DirectBackend Always Healthy:** `DirectBackend.IsHealthy()` always returns `true`. If the direct path is unreachable, connections will fail with dial errors but the router still considers it a viable option.

10. **No Config Hot-Reload:** Configuration changes require a full process restart.

### Deployment Readiness Assessment

| Criterion | Status |
|---|---|
| Single binary | ✅ |
| Cross-platform builds | ✅ (Linux, macOS, Windows) |
| Graceful shutdown | ✅ (HTTP) / ⚠️ (SOCKS5) |
| Health endpoints | ✅ (/healthz, /readyz) |
| Structured logging | ✅ |
| Configuration validation | ✅ |
| Environment variable overrides | ✅ |
| Process supervision | ❌ |
| Systemd unit file | ❌ |
| Docker support | ❌ |
| Prometheus metrics | ❌ |
| TLS termination | ❌ |
| Auth on all endpoints | ❌ (SOCKS5 missing) |
| Log redaction | ⚠️ (implemented but unused) |
| Rate limiting | ✅ |
| Circuit breaker | ❌ |
| Connection limits | ❌ |
| Dynamic reconfiguration | ❌ |

---

## Recommendations (Priority Order)

### P0 — Critical

1. **Wire API key auth into SOCKS5 proxy** — Currently any local client can use the SOCKS5 port without credentials.

2. **Enable log redaction** — Instantiate `HeaderRedactor` in the proxy handlers and redact sensitive headers before logging. API keys in logs are a credential leak.

3. **Fix SOCKS5 silent accept failure** — Line 43 of `socks5.go` returns nil on accept error, masking listener failures.

### P1 — High

4. **Add Prometheus metrics** — Request count, latency, error rate, active connections, backend health gauge, rate limit rejections. This is essential for any operational deployment.

5. **Add connection limits** — Bounded goroutine pool or max-connections config to prevent resource exhaustion.

6. **Add systemd unit file** — For production deployment with auto-restart.

7. **Fix DirectBackend.IsHealthy()** — Should periodically probe or at least not blindly return true.

### P2 — Medium

8. **Add circuit breaker** — Track backend failure rates; after N consecutive failures, stop attempting for a cooldown period.

9. **Add SOCKS5 graceful drain** — Track active connections, wait for them to complete on shutdown.

10. **Add pprof endpoint** — For runtime profiling in development/staging.

11. **Add config hot-reload** — Watch config file for changes, apply without restart.

### P3 — Low

12. **Time-based circuit rotation** — In addition to request-count-based, allow rotation based on elapsed time.

13. **Add Dockerfile** — For containerized deployment.

14. **Sharded rate limiter** — Replace global mutex with sharded map for better concurrent throughput.

15. **Remove dead code** — `StreamWithBackpressure` is unused; either integrate it or remove it.

---

## Final Scores Summary

| File | Score | Rationale |
|---|---|---|
| cmd/relay/main.go | 5/10 | Clean wiring, good signal handling, no process supervision |
| internal/auth/apikey.go | 6/10 | Secure comparison, single-key only, no failure logging |
| internal/backend/router.go | 6/10 | Lock-free failover, no circuit breaker, no metrics |
| internal/backend/tor.go | 5/10 | Functional Tor + rotation, fragile recovery, DirectBackend blind |
| internal/config/config.go | 8/10 | Excellent design, env overrides, validation, no hot-reload |
| internal/health/health.go | 6/10 | Healthz/readyz pattern, no liveness, no auth on endpoints |
| internal/log/redact.go | 7/10 | Good redactor, unused in practice, partial URL redaction |
| internal/proxy/http.go | 6/10 | Solid proxy, SSE support, hardcoded pool settings |
| internal/proxy/socks5.go | 5/10 | Functional SOCKS5, missing auth, silent failure, no drain |
| internal/rotate/rotator.go | 5/10 | Simple counter, no time-based rotation, no failure tracking |
| internal/security/firewall.go | 6/10 | Good defaults, global mutex bottleneck, unbounded map |
| internal/stream/sse.go | 7/10 | Well-implemented streaming, buffer pooling, some dead code |
| config.yaml | 7/10 | Sensible defaults, loopback binding, aggressive rotation |
| Makefile | 7/10 | Clean build system, cross-compilation, no packaging |

**Weighted Average: 5.8 / 10**

---

*Analysis completed. The project demonstrates solid Go engineering fundamentals but requires significant operational hardening for production use: observability, auth completeness, graceful degradation, and process management.*
