# ANALYST_02: Go Code Quality Review — local-relay

**Reviewer:** Go Language Expert (Core Contributor Level)
**Date:** 2026-06-24
**Scope:** All 12 Go source files, ~1875 LOC

---

## Executive Summary

The codebase is well-structured, idiomatic Go with clean package separation.
Most files are solid. A handful of concurrency bugs, a race condition, and a
few resource leaks prevent a higher aggregate score. Overall: **7.2 / 10**.

---

## File-by-File Analysis

### 1. cmd/relay/main.go (215 lines) — Score: 7/10

**Goroutine Safety:**
- Signal context via `signal.NotifyContext` — correct.
- Two goroutines for HTTP and SOCKS5 proxy start, both call `stop()` on failure — correct propagation.
- Health server goroutine does NOT call `stop()` on failure — minor inconsistency.
- `torBackend` and `rotator` captured in closures; both are created before goroutines start, so no race on capture.

**Error Handling:**
- `torBackend.RequestNewCircuit()` error is logged — good.
- `healthSrv.Stop()` called via `defer` inside an `if` block — deferred calls stack on the function's defer list and will run at `main()` exit. This is fine but unusual; most readers expect `defer` to pair with the block scope.

**Resource Leaks:**
- `firewall.StopCleanup()` deferred — correct.
- `healthSrv.Stop()` deferred inside conditional — correct but fragile; if `cfg.Health.Enabled` is false, no health server exists, so no issue.

**Go Idioms:**
- Uses `flag` package correctly. Config override precedence (file → flag → env) is clean.
- `setupLogger` is a clean helper function.

**Issues:**
1. Health server goroutine failure does not trigger graceful shutdown (no `stop()` call).
2. The `defer healthSrv.Stop()` inside the `if` block will only run at program exit — functionally correct but could be clearer.

---

### 2. internal/auth/apikey.go (53 lines) — Score: 8/10

**Goroutine Safety:**
- Immutable struct fields set at construction — inherently safe.

**Error Handling:**
- N/A (no error returns).

**Resource Leaks:**
- N/A.

**Go Idioms:**
- Uses `crypto/subtle.ConstantTimeCompare` — correct for timing-safe comparison.
- `Check` method writes HTTP error response and returns bool — unconventional but functional.
- Missing: no `Basic` auth support (only `Bearer` prefix stripped). If user sends `Authorization: Basic <base64>`, it won't work. Acceptable given the simple API key design.

**Issues:**
1. `extractKey` strips "Bearer " prefix from `X-Api-Key` header unconditionally. A raw API key not prefixed with "Bearer " would work, but so would "Bearer <wrongkey>". The logic is slightly inconsistent: `Proxy-Authorization` only accepts "Bearer", but `X-Api-Key` always strips it.
2. API key passed via URL query parameter (`?api_key=...`) will appear in server logs and referrer headers — security concern (not a code quality issue per se, but worth noting).

---

### 3. internal/backend/router.go (104 lines) — Score: 6/10

**Goroutine Safety — RACE CONDITION:**
- `SetBypassHosts()` writes to `r.bypassHosts` (a slice) without synchronization.
- `shouldBypass()` reads `r.bypassHosts` without synchronization.
- Both are called from different goroutines (main setup vs. request handling).
- **This is a data race.** In practice it's likely safe because `SetBypassHosts` is called once at startup before requests begin, but it's not guaranteed by the Go memory model without a happens-before relationship.

**Error Handling:**
- `Router.Close()` calls `b.Close()` but discards errors — should collect or log them.
- Bypass host dial failure silently falls through to the round-robin loop — acceptable failover behavior.

**Resource Leaks:**
- None. Connections are returned to the caller.

**Go Idioms:**
- Good use of `atomic.Int64` for round-robin index — lock-free and correct.
- `Backend` interface is well-designed with `DialContext`, `IsHealthy`, `Close`.
- `NewRouter(backends ...Backend)` variadic is clean.

**Issues:**
1. **Race condition on `bypassHosts` slice** — needs mutex or must document startup-only mutation.
2. Close errors discarded — could mask real problems during shutdown.
3. The round-robin `Store((idx + 1) % total)` advances the counter even on failed attempts — it skips to the next backend on success but the `cur` variable is stale (read once, then the store is based on loop index). This is actually correct for round-robin but worth noting the pattern.

---

### 4. internal/backend/tor.go (258 lines) — Score: 7/10

**Goroutine Safety:**
- `sync.RWMutex` protects `healthy`, `circuitAge`, `lastCheck` — correct.
- `circuitAge` read in `ShouldRotate()` under RLock, written in `DialContext` under Lock — correct.
- `circuitAge` reset in `RequestNewCircuit()` under Lock — correct.

**Error Handling:**
- `socks5Handshake` errors properly wrapped with `fmt.Errorf("...: %w", err)` — good.
- `RequestNewCircuit()` error from `fmt.Fprintf(conn, ...)` is silently ignored — the write could fail on a closed connection.

**Resource Leaks:**
- `RequestNewCircuit()` properly defers `conn.Close()` — correct.
- `DialContext` closes `conn` on handshake failure — correct.
- `CheckHealth()` closes the probe connection — correct.

**Go Idioms:**
- Good use of `io.ReadFull` for SOCKS5 protocol — correct.
- Buffer reuse in `socks5Handshake` (stack-allocated `[300]byte`) — efficient.

**Issues:**
1. `fmt.Fprintf(conn, ...)` return values ignored in `RequestNewCircuit()` — could silently fail.
2. The `controlPass` is embedded in the AUTHENTICATE command string without escaping. A control password containing `"` or `\` could break the Tor control protocol. Should use proper escaping.
3. `circuitAge` is incremented per `DialContext` call, not per-request. This means circuit age is actually connection count, which is the intended semantic but could confuse readers.

---

### 5. internal/config/config.go (208 lines) — Score: 8/10

**Goroutine Safety:**
- Config is loaded once at startup and never mutated afterward — safe.

**Error Handling:**
- All errors wrapped with `fmt.Errorf("...: %w", err)` — excellent.
- `Validate()` performs thorough checks.

**Resource Leaks:**
- `os.ReadFile` for config file — no leak (file is closed by Go runtime).

**Go Idioms:**
- Clean defaults → file → env override → validate pipeline.
- `loadDefaults` roundtrips through YAML marshal/unmarshal — works but is a code smell. Could use struct copy instead.
- `validateAddress` is a good reusable helper.

**Issues:**
1. `loadDefaults` serializes a struct to YAML and deserializes back — wasteful. A simple struct copy (`*defaultConfig = *cfg`) would suffice.
2. API key minimum length (16 chars) validated but no check for entropy — minor.
3. `ConnectionTimeout()` hardcodes values — could be configurable fields instead.

---

### 6. internal/health/health.go (122 lines) — Score: 7/10

**Goroutine Safety:**
- `HealthServer` fields are set once before `Start()` — safe.
- `SimpleHealthChecker` closure functions are called from HTTP handlers — the closures capture `torBackend` and `rotator` from main, which are created before health server starts — safe in practice.

**Error Handling:**
- `json.NewEncoder(w).Encode(status)` — return value ignored. If encoding fails (unlikely for simple structs), the error is silently swallowed.
- `w.Write(...)` return values ignored in `handleReady` — acceptable for HTTP handlers but technically an unchecked error.
- `hs.server.Shutdown(ctx)` error ignored in `Stop()` — should be logged or returned.

**Resource Leaks:**
- None obvious. Server is properly shut down.

**Go Idioms:**
- Interface `HealthChecker` is clean and minimal.
- Proper use of `context.WithTimeout` for graceful shutdown.

**Issues:**
1. `hs.server.Shutdown(ctx)` error discarded in `Stop()`.
2. `json.Encode` error discarded — unlikely to fail but inconsistent with codebase error handling elsewhere.
3. Health endpoint returns "healthy" when no checker is configured — arguably should return "unknown" or "no-backend".

---

### 7. internal/log/redact.go (80 lines) — Score: 7/10

**Goroutine Safety:**
- `HeaderRedactor` is immutable after construction — safe.

**Error Handling:**
- N/A.

**Resource Leaks:**
- N/A.

**Go Idioms:**
- `headers.Clone()` is correct and prevents mutation of original headers.
- `RedactURL` uses simple substring matching — could miss encoded parameters.

**Issues:**
1. `RedactBody` mutates the input slice via `append(body[:r.maxBodySize], ...)` — if the caller retains a reference to the original slice, data beyond `maxBodySize` is still accessible. Should copy to a new slice first.
2. `RedactValue` shows first 4 chars — this could leak sensitive data (e.g., first 4 chars of a token). A policy decision, but worth noting.
3. `RedactURL` only checks for `token=` and `key=` — misses common patterns like `secret=`, `password=`, `access_token=`.

---

### 8. internal/proxy/http.go (206 lines) — Score: 8/10

**Goroutine Safety:**
- `HTTPProxy` struct fields are set at construction — safe.
- `ServeHTTP` is called by `net/http` server which handles concurrency — the proxy reads `p.router`, `p.auth`, `p.firewall` which are immutable — safe.
- `copyBufPool` is a `sync.Pool` — thread-safe by design.

**Error Handling:**
- Most errors handled with appropriate HTTP error responses.
- `io.CopyBuffer` in `handleHTTP` discards the byte count and error — should be checked (or at minimum the error should be logged for non-EOF cases).

**Resource Leaks:**
- `destConn` properly closed on hijack failure — correct.
- `resp.Body` properly closed via `defer` — correct.
- `clientConn` from hijack is closed by `stream.Relay` — correct.
- `listener` from `net.Listen` is passed to `server.Serve` — server will close it on shutdown.

**Go Idioms:**
- `sync.Pool` for copy buffers — excellent for reducing GC pressure.
- Proper use of `http.Hijacker` for CONNECT tunneling.
- `WriteTimeout: 0` for HTTP proxy — correct (tunnels need no write timeout).
- `DisableKeepAlives: false` and `ForceAttemptHTTP2: false` — sensible for a proxy.

**Issues:**
1. `io.CopyBuffer` error silently dropped in `handleHTTP` (line 176).
2. `handleConnect` does not set TCP keepalive on `clientConn` via `SetKeepAlivePeriod` — keepalive is set but period is not, using system default. Minor.
3. The `handleConnect` function calls `w.WriteHeader(http.StatusOK)` BEFORE `hijacker.Hijack()` — this is technically correct per Go HTTP spec (the 200 response is sent first), but if hijack fails, the response is already committed with no body.

---

### 9. internal/proxy/socks5.go (218 lines) — Score: 7/10

**Goroutine Safety:**
- `SOCKS5Proxy` fields set at construction — safe.
- `p.listener` accessed from `Start()` (main goroutine) and `Stop()` (shutdown goroutine) — **race condition potential** if `Stop()` is called while `Start()` is still running. However, `Stop()` only reads the listener reference which is set before `Start()` enters its accept loop, so this is safe in practice.

**Error Handling:**
- Handshake and request read errors properly handled with debug logging.
- `conn.Write(reply)` in `sendReply` — error discarded. If the write fails, there's nothing useful to do, so this is acceptable.
- `Stream.Relay` errors not checked — but `Relay` doesn't return errors (it closes both connections).

**Resource Leaks:**
- `handleConn` defers `conn.Close()` — correct.
- `handleConnect` closes `destConn` via `stream.Relay` which closes both connections — correct.

**Go Idioms:**
- Clean SOCKS5 protocol implementation.
- `sendReply` handles both IPv4 and IPv6 bind addresses — correct.
- `context.WithTimeout` for dial in `handleConnect` — good.

**Issues:**
1. `handleConnect` creates a context with `context.Background()` instead of deriving from the incoming connection. This means cancellation of the parent (if any) won't propagate. The connection has no parent context, so this is actually correct, but the hardcoded 30s timeout for the dial doesn't account for slow Tor circuits.
2. `sendReply` errors ignored — acceptable for protocol-level writes where there's nothing to do on failure.
3. No authentication in SOCKS5 handshake (always returns "no auth required") — acceptable for a local proxy.

---

### 10. internal/rotate/rotator.go (60 lines) — Score: 8/10

**Goroutine Safety:**
- All fields use `atomic` operations — lock-free and correct.
- `onRotate` callback launched in a goroutine — correct (avoids blocking the caller).
- `onRotate` is a closure capturing `torBackend` — set once at startup, read-only — safe.

**Error Handling:**
- N/A (no error returns).

**Resource Leaks:**
- N/A.

**Go Idioms:**
- Clean use of `sync/atomic` for all mutable state.
- `Reset()` and `SetInterval()` are atomic-safe.
- `GetCount()` is atomic-safe.

**Issues:**
1. `ShouldRotate()` is named like a query but has the side effect of incrementing the counter. This violates the principle of least surprise — a `ShouldX` method shouldn't mutate state. Should be renamed to `CheckAndIncrement()` or the increment should be separate.
2. `lastTrade` (line 14) is written but never read — dead field.
3. The modulo check `count%interval == 0` fires on the first call after reset (count=1 if interval=1) — this is correct but the `counter.Add(1)` happens even when rotation isn't needed, which is fine for atomic performance.

---

### 11. internal/security/firewall.go (202 lines) — Score: 7/10

**Goroutine Safety:**
- `Firewall` uses `sync.RWMutex` for `blockedRanges` and `allowedDomains` — correct.
- `RateLimiter` uses `sync.Mutex` — correct.
- `StartCleanup` goroutine properly uses `select` with context and stop channel — correct.
- `cleanupRateLimiters` acquires rate limiter mutex — correct.

**Error Handling:**
- `AddBlockedRange` returns parse errors — correct.
- `getDefaultBlockedRanges` silently ignores unparseable CIDRs — acceptable (they're hardcoded constants).

**Resource Leaks:**
- `StartCleanup` goroutine exits on context cancellation or stop channel close — correct.
- `RateLimiter.limiters` map grows unboundedly between cleanups — mitigated by cleanup goroutine.

**Go Idioms:**
- `stop chan struct{}` for cancellation — idiomatic.
- Token bucket rate limiter is correct.
- Default blocked ranges cover RFC 1918 and other private ranges comprehensively.

**Issues:**
1. **Rate limiter memory leak potential:** The cleanup interval is 5 minutes, but the cleanup only removes entries older than 5 minutes. If an attacker generates unique IPs faster than cleanup runs, the map could grow. No maximum map size is enforced.
2. `AllowHost` doesn't check rate limiting — `CheckRateLimit` is a separate method that must be called explicitly. This is fine architecturally but means a caller could forget to check rate limits.
3. `cleanupRateLimiters` hardcodes the 5-minute cutoff — should use the configured interval or a separate TTL parameter.

---

### 12. internal/stream/sse.go (149 lines) — Score: 7/10

**Goroutine Safety:**
- `Relay` uses `sync.WaitGroup` + context cancellation — correct bidirectional relay pattern.
- `CloseWrite()` called after copy completes — proper half-close behavior.
- `StreamWithBackpressure` uses goroutines with `select` on context and done channel — correct.
- `CopySSE` runs synchronously in the calling goroutine — correct for HTTP handler context.

**Error Handling:**
- `scanner.Err()` is never checked after `scanner.Scan()` loop completes in both `CopySSE` and `StreamWithBackpressure`. If the scanner encounters an error (e.g., line too long), it's silently ignored.
- `io.CopyBuffer` errors ignored in `CopyRaw`.
- `w.Write` errors ignored in `StreamWithBackpressure`.

**Resource Leaks:**
- `Relay` closes both `dst` and `src` after `wg.Wait()` — correct.
- `StreamWithBackpressure` goroutines exit via context cancellation or channel close — correct.

**Go Idioms:**
- `sync.Pool` for buffer reuse — excellent.
- `interface{ CloseWrite() error }` type assertion — idiomatic for half-close TCP support.
- Context-based cancellation throughout — good.
- `StreamWithBackpressure` channel-based producer/consumer is well-structured.

**Issues:**
1. **`scanner.Err()` never checked** in `CopySSE` and `StreamWithBackpressure` — if a line exceeds the scanner buffer, the error is swallowed.
2. `StreamWithBackpressure` creates a new `[]byte` allocation per event (`make([]byte, len(scanner.Bytes()))`) — defeats the purpose of pooling. Could use the pool.
3. `time.After(5 * time.Second)` in `StreamWithBackpressure` creates a new timer per iteration — minor memory overhead. Could use `time.NewTimer` with reset.
4. `CopySSE` and `StreamWithBackpressure` are near-duplicates — should be unified or `CopySSE` should delegate to `StreamWithBackpressure`.

---

## Summary Table

| File | Score | Race Conditions | Swallowed Errors | Resource Leaks | Idioms |
|------|-------|----------------|-----------------|----------------|--------|
| cmd/relay/main.go | 7/10 | None | Health server failure not propagated | None | Good |
| internal/auth/apikey.go | 8/10 | None (immutable) | None | N/A | Timing-safe compare ✓ |
| internal/backend/router.go | 6/10 | **bypassHosts slice** | Close errors discarded | None | Good interface design |
| internal/backend/tor.go | 7/10 | None (mutex) | Fprintf errors ignored | None | Good protocol impl |
| internal/config/config.go | 8/10 | None (startup-only) | None | None | Clean pipeline |
| internal/health/health.go | 7/10 | None | Shutdown error discarded | None | Good interface |
| internal/log/redact.go | 7/10 | None (immutable) | N/A | N/A | Good clone usage |
| internal/proxy/http.go | 8/10 | None | CopyBuffer error dropped | None | sync.Pool ✓ |
| internal/proxy/socks5.go | 7/10 | Minor (listener) | Write errors ignored | None | Clean protocol |
| internal/rotate/rotator.go | 8/10 | None (atomics) | N/A | N/A | Clean atomics |
| internal/security/firewall.go | 7/10 | None (mutex) | N/A | Rate limiter map unbounded | Idiomatic cleanup |
| internal/stream/sse.go | 7/10 | None | **scanner.Err() never checked** | None | sync.Pool ✓ |

---

## Aggregate Score: 7.2 / 10

---

## Top 5 Critical Issues (Ranked by Severity)

### 1. Data Race on `Router.bypassHosts` (router.go)
**Severity: HIGH** — The `bypassHosts` slice is written by `SetBypassHosts()` and read by `shouldBypass()` without synchronization. Run `go test -race` to confirm. Fix: add a `sync.RWMutex` or use `atomic.Value`.

### 2. `scanner.Err()` Never Checked (sse.go)
**Severity: MEDIUM** — Both `CopySSE` and `StreamWithBackpressure` ignore scanner errors. A line exceeding the buffer limit silently truncates the stream. Fix: add `if err := scanner.Err(); err != nil { log }` after the scan loop.

### 3. Tor Control Password Not Escaped (tor.go)
**Severity: MEDIUM** — `fmt.Fprintf(conn, "AUTHENTICATE \"%s\"\r\n", t.controlPass)` doesn't escape special characters in the password. A password containing `"` breaks the protocol. Fix: use `fmt.Fprintf(conn, "AUTHENTICATE %q\r\n", t.controlPass)` or proper Tor control escaping.

### 4. `RedactBody` Mutates Input Slice (redact.go)
**Severity: LOW-MEDIUM** — `append(body[:r.maxBodySize], ...)` modifies the underlying array if capacity allows, potentially corrupting data held by callers. Fix: `result := make([]byte, 0, r.maxBodySize+20); result = append(result, body[:r.maxBodySize]...); result = append(result, "...[REDACTED]"...)`.

### 5. Rate Limiter Unbounded Map Growth (firewall.go)
**Severity: LOW** — The `limiters` map in `RateLimiter` has no maximum size. Under sustained unique-key load, memory grows without bound until cleanup runs. Fix: add a max-entries check and evict oldest entries when exceeded.

---

## What Worked Well

1. **`sync.Pool` usage** in `http.go` and `sse.go` — excellent for high-throughput proxy workloads.
2. **`Backend` interface** — clean abstraction enabling Tor, direct, and future backends.
3. **Context propagation** — `signal.NotifyContext`, `context.WithTimeout`, `context.WithCancel` used consistently.
4. **Atomic operations** in `rotator.go` and `router.go` — lock-free where possible.
5. **Config pipeline** — defaults → file → env → validate is clean and testable.
6. **TCP tuning** — `SetNoDelay`, `SetKeepAlive`, `SetKeepAlivePeriod` applied consistently.
7. **Graceful shutdown** — `signal.NotifyContext` + `Shutdown(ctx)` pattern used in both proxies.
