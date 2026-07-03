# ANALYST_06 — Performance Engineering Analysis

**Project:** local-relay (Go proxy relay, ~1875 LOC)  
**Date:** 2026-06-24  
**Scope:** Latency hotspots, buffer management efficiency, throughput limits, IP rotation impact, per-file performance design scores.

---

## Executive Summary

The local-relay proxy is well-structured for a low-to-moderate throughput Tor relay. It uses `sync.Pool` for buffer reuse, `atomic` operations for lock-free counters, and a clean bidirectional relay with `CloseWrite()` half-close. However, there are several latency hotspots — most notably the Tor SOCKS5 handshake on every connection (no multiplexing), the `bufio.Scanner` line-by-line SSE parser, and the per-request firewall IP parsing. The connection pool is very small (MaxIdleConns=4), limiting throughput under concurrent load. Overall design is solid for its intended use case but would bottleneck beyond ~100 concurrent connections.

---

## Per-File Analysis

---

### 1. cmd/relay/main.go (215 lines)

**Latency Hotspots:**
- `backend.NewTorBackend()` with hardcoded `MaxCircuitAge: 100` means every 100 requests triggers a `SIGNAL NEWNYM` to Tor control port — this is a blocking TCP connection to the control port, adding ~5-50ms per rotation.
- Health check uses a blocking `net.DialTimeout` with 5s timeout — if Tor is slow to respond, startup blocks.
- Shutdown has a 10s timeout; SOCKS5 proxy uses `listener.Close()` (immediate) while HTTP proxy uses `server.Shutdown()` (graceful). The asymmetry means in-flight SOCKS5 connections are killed abruptly.

**Buffer Management:** N/A (orchestration only).

**Throughput Limits:**
- Two goroutines (HTTP + SOCKS5) accept connections independently — good concurrency model.
- No GOMAXPROCS tuning; defaults to `runtime.NumCPU()` which is fine.
- No connection limits on the listener side; unbounded goroutine-per-connection.

**IP Rotation Impact:**
- Rotation callback fires `torBackend.RequestNewCircuit()` in a goroutine (`go r.onRotate()`) — non-blocking, which is correct.
- `MaxCircuitAge: 100` is hardcoded in main.go rather than configurable — limits flexibility.

**Performance Design Score: 7/10**  
Good startup orchestration, proper signal handling, graceful shutdown. Hardcoded MaxCircuitAge and asymmetric shutdown are minor issues.

---

### 2. internal/auth/apikey.go (53 lines)

**Latency Hotspots:**
- `crypto/subtle.ConstantTimeCompare` is used — correct for timing-safe comparison. The overhead is negligible (~microseconds for typical key lengths).
- `extractKey` performs up to 3 sequential header/query lookups (`Header.Get` × 2 + `URL.Query().Get`). Each `Query().Get` parses the entire query string — O(n) in URL length. For most requests this is <1μs.
- `strings.TrimPrefix` allocates a new string on each call — minor GC pressure under high concurrency.

**Buffer Management:** No buffers involved; pure string operations.

**Throughput Limits:** Negligible. Auth check adds <10μs per request. The `http.Error` call on failure writes a full HTTP response, which is the slowest path but only on auth failure.

**IP Rotation Impact:** None.

**Performance Design Score: 8/10**  
Clean, fast, timing-safe. Minor: could cache the parsed API key as `[]byte` to avoid repeated `[]byte(key)` allocations on every request.

---

### 3. internal/backend/router.go (104 lines)

**Latency Hotspots:**
- `shouldBypass()` does a linear scan of `bypassHosts` with `strings.ToLower` + `strings.HasSuffix` per entry. For N bypass hosts, this is O(N) per connection. With 10+ hosts, this adds measurable overhead.
- `net.SplitHostPort` is called on every connection — allocation of two strings per call.
- Round-robin uses `atomic.Int64` (lock-free) — excellent. But the `Load()` → compute → `Store()` pattern has a subtle race: two goroutines could read the same `cur` value and both try the same backend. This is acceptable for round-robin (no correctness issue, just suboptimal distribution).

**Buffer Management:** No buffers; pure routing logic.

**Throughput Limits:**
- Linear backend failover loop: if all backends are unhealthy, the loop iterates through all of them before returning an error. With few backends (typically 2), this is fine.
- No connection pooling — each `DialContext` creates a new TCP connection. The pool lives in `http.Transport` above, which is appropriate.

**IP Rotation Impact:**
- Router is rotation-agnostic; it routes based on health and bypass rules. Tor circuit rotation happens transparently through the `TorBackend`.

**Performance Design Score: 7/10**  
Lock-free round-robin is well done. Linear bypass host scan could be a map-based lookup for O(1). The atomic race is benign.

---

### 4. internal/backend/tor.go (258 lines)

**Latency Hotspots:**
- **SOCKS5 handshake per connection (`socks5Handshake`)** — This is the single largest latency hotspot in the system. Every TCP connection through Tor requires a full SOCKS5 handshake: 2 round-trips (auth + connect). With Tor relay latency of 50-200ms, this adds 100-400ms per connection. This is fundamental to Tor and unavoidable.
- `net.DialTimeout` for `RequestNewCircuit` uses a 5s timeout for control port — acceptable.
- `CheckHealth()` opens a TCP connection just to verify Tor is reachable, then closes it — adds ~5-50ms at startup.
- `circuitAge` is incremented under `mu.Lock()` (full lock, not RWMutex's RLock) on every `DialContext` — this creates a write lock on every connection. Should use atomic or RWMutex with RLock for reads.

**Buffer Management:**
- `socks5Handshake` uses a stack-allocated `[300]byte` buffer — excellent, zero heap allocation.
- `io.ReadFull` reads directly into stack buffers — efficient.
- `RequestNewCircuit` uses `bufio.NewReader` (heap-allocated) for the control port session — acceptable since circuit rotation is infrequent.

**Throughput Limits:**
- Each connection requires a new SOCKS5 handshake through Tor — no connection multiplexing (Tor doesn't support this natively).
- `SetNoDelay(true)` disables Nagle's algorithm — correct for interactive/proxy traffic, reduces latency at the cost of slightly more packets.
- `KeepAlive` with 30s period is reasonable for detecting dead Tor circuits.

**IP Rotation Impact:**
- `RequestNewCircuit()` connects to Tor control port, authenticates, sends `SIGNAL NEWNYM`, then closes. This takes 50-500ms.
- During rotation, existing connections continue on the old circuit; only new connections get the new exit IP.
- `ShouldRotate()` uses `RLock` — efficient read path.
- `circuitAge` increment uses `Lock()` — this is the hot path. Should use `atomic.Int32.Add(1)` instead.

**Performance Design Score: 6/10**  
Stack-allocated handshake buffers are excellent. But: (1) mutex contention on `circuitAge` in the hot path, (2) no connection pooling within Tor backend, (3) `circuitAge` tracking is per-backend not per-connection, which is architecturally correct but the lock is unnecessarily heavy.

---

### 5. internal/config/config.go (208 lines)

**Latency Hotspots:**
- `loadDefaults` serializes defaults to YAML then deserializes — this is a roundtrip through YAML marshaling just to get defaults. A direct struct copy would be faster, but this runs only once at startup so it's irrelevant.
- `Validate` creates `map[string]bool` on every call for enum checking — trivial overhead at startup.

**Buffer Management:** N/A (startup-only configuration parsing).

**Throughput Limits:** None — config is loaded once and immutable at runtime.

**IP Rotation Impact:**
- `Rotation.Interval` defaults to 1, meaning every single request triggers rotation — this would be catastrophic for performance if `torBackend.ShouldRotate()` also returns true. In practice, the rotator's `ShouldRotate()` fires based on `count % interval == 0`, so with interval=1 it fires every request, but the actual `RequestNewCircuit()` is gated by `TorBackend.ShouldRotate()` (circuitAge >= maxCircuitAge=100). So the double-gating prevents actual rotation every request — but the rotator still logs and fires the goroutine every request, adding overhead.
- `ConnectionTimeout()` returns 30s for Tor, 10s otherwise — hardcoded, not configurable.

**Performance Design Score: 7/10**  
Functional but the YAML roundtrip for defaults is wasteful (irrelevant at startup). The `Interval: 1` default combined with `MaxCircuitAge: 100` creates confusing dual-gating.

---

### 6. internal/health/health.go (122 lines)

**Latency Hotspots:**
- `handleHealth` calls `hs.checker.IsHealthy()` which calls `torBackend.CheckHealth()` — this does a TCP dial to Tor. If Tor is slow, health endpoint responds slowly. This is called on every health check request.
- `json.NewEncoder(w).Encode(status)` creates a JSON encoder per request — minor allocation overhead.
- `handleReady` writes raw bytes — fast.

**Buffer Management:** No pooling; health responses are tiny (<1KB).

**Throughput Limits:**
- Health server has `ReadTimeout: 5s`, `WriteTimeout: 5s`, `IdleTimeout: 60s` — reasonable.
- Single-threaded health checks (no concern since health is low-frequency).

**IP Rotation Impact:** None directly. The health endpoint reports `rotator.GetCount()` for observability.

**Performance Design Score: 7/10**  
Appropriate for its purpose. The `IsHealthy()` call doing a real TCP dial on every health check is heavy — should cache the result with a TTL.

---

### 7. internal/log/redact.go (80 lines)

**Latency Hotspots:**
- `RedactHeaders` clones the entire header map (`headers.Clone()`) — allocates a new map and copies all values. For large headers (cookies, etc.), this is significant.
- `RedactURL` does two `strings.Contains` scans — O(n) in URL length.
- `RedactBody` creates a new byte slice with `append` — allocates.
- `strings.ToLower(key)` in the loop creates a new string per header — GC pressure.

**Buffer Management:**
- No pooling. Every `RedactHeaders` call allocates a new map.
- `RedactBody` allocates via `append`.

**Throughput Limits:**
- Logging redaction runs synchronously on the request path if logging is enabled at debug level. At info/warn/error levels, redacted headers are likely not logged, so the overhead is only incurred when actually writing logs.

**IP Rotation Impact:** None.

**Performance Design Score: 6/10**  
Clone-per-request is wasteful. Could modify headers in-place or use a reusable buffer. At debug log levels, this adds measurable overhead on every logged request. The `defaultRedactHeaders` map is a good pattern.

---

### 8. internal/proxy/http.go (206 lines)

**Latency Hotspots:**
- `http.Transport` configured with `MaxIdleConns: 4`, `MaxIdleConnsPerHost: 2` — extremely conservative. Under 5+ concurrent connections to the same host, connections will be created fresh each time (no pooling), adding TCP + TLS + SOCKS5 handshake latency (100-400ms through Tor).
- `TLSHandshakeTimeout: 30s` — very generous; a stuck TLS handshake ties up a goroutine for 30s.
- `ResponseHeaderTimeout: 60s` — also generous; for Tor with 50-200ms latency this is fine but means slow servers can block connections for up to 60s.
- `handleConnect` does `net.SplitHostPort` + `firewall.AllowHost` (IP parsing) before dialing — adds ~1-10μs.
- `handleHTTP` clones headers (`r.Header.Clone()`) then deletes 2 headers — allocates a new map.
- `client.Do(req)` with `r.Body` as request body — if the body is large, this streams without buffering, which is good.

**Buffer Management:**
- `copyBufPool` (32KB `sync.Pool`) — excellent. Reuses buffers for `io.CopyBuffer` in HTTP responses.
- Pool size of 32KB is a good choice — large enough to minimize syscalls, small enough to not waste memory.
- `defer copyBufPool.Put(bufPtr)` inside the request handler — correctly returns buffer to pool after use.

**Throughput Limits:**
- **MaxIdleConns: 4** is the primary throughput bottleneck. With Tor's latency, connection reuse is critical. With only 4 idle connections, under moderate load (10+ concurrent requests), most connections will be created fresh.
- `ForceAttemptHTTP2: false` — HTTP/2 is disabled, so no multiplexing. This is appropriate for a proxy (HTTP/2 end-to-end would require the proxy to speak HTTP/2).
- No request body size limit — a client could send a multi-GB body, consuming unbounded memory.
- `MaxHeaderBytes: 1 << 20` (1MB) — reasonable.

**IP Rotation Impact:**
- Connection pooling means old Tor circuits may be reused after rotation. The pool's 90s `IdleConnTimeout` means connections live for up to 90s after creation. During rotation, existing pooled connections continue with the old exit IP — this is expected behavior.

**Performance Design Score: 7/10**  
Good use of `sync.Pool` for copy buffers. The connection pool is too small for production use. No request body limits. Good hijack-based tunneling for CONNECT.

---

### 9. internal/proxy/socks5.go (218 lines)

**Latency Hotspots:**
- `handshake()` allocates `make([]byte, 2)` and `make([]byte, nMethods)` per connection — small allocations on every connection.
- `readRequest()` allocates multiple small buffers (`make([]byte, 4)`, `make([]byte, 4)`, `make([]byte, 2)`, etc.) — 5-8 allocations per connection for address parsing.
- `fmt.Sprintf` for IPv4 and IPv6 address formatting — allocates.
- `handleConnect` creates a `context.WithTimeout(Background, 30s)` — good for preventing stuck connections.

**Buffer Management:**
- No pooling for handshake/read buffers. Each connection creates 3-8 small allocations.
- `sendReply` builds reply via `append` on a slice — minor allocation.

**Throughput Limits:**
- Goroutine-per-connection model (go p.handleConn(conn)) — no connection limit. Under extreme load (10K+ connections), this could exhaust memory or hit goroutine limits.
- `stream.Relay` is the main data path — uses `sync.Pool` buffers (32KB), bidirectional with `CloseWrite()` half-close. This is efficient.
- No per-connection timeout for the data relay phase — once connected, connections live indefinitely until the client disconnects.

**IP Rotation Impact:**
- SOCKS5 connections are proxied through the router → Tor backend → SOCKS5 handshake. Each new connection gets the current Tor exit IP. Rotation applies to future connections only.

**Performance Design Score: 6/10**  
Functional but unoptimized. Multiple small allocations per connection could be pooled. No connection limits. No relay-level timeouts.

---

### 10. internal/rotate/rotator.go (60 lines)

**Latency Hotspots:**
- `ShouldRotate()` uses `atomic.Uint64.Add(1)` — lock-free, O(1), <1ns. Excellent.
- The `go r.onRotate()` goroutine launch adds ~1μs overhead (goroutine creation).
- `r.logger.Info(...)` inside `ShouldRotate()` adds logging overhead on every rotation — this runs synchronously before the goroutine launch.

**Buffer Management:** N/A (pure counter logic).

**Throughput Limits:**
- Atomic counter can handle billions of operations/sec — no bottleneck here.
- The `onRotate` callback fires in a goroutine, so it doesn't block the caller. Good.

**IP Rotation Impact:**
- `ShouldRotate()` is called from the hot path (request handling). The atomic add is negligible.
- Rotation frequency is controlled by `interval`. With `interval: 1` (default), rotation fires every request — but the actual circuit change is gated by `TorBackend.ShouldRotate()` (circuitAge >= maxCircuitAge).
- `GetCount()` and `Reset()` use atomic loads/stores — lock-free.

**Performance Design Score: 9/10**  
Clean, lock-free design. The only minor issue is the log statement in the hot path.

---

### 11. internal/security/firewall.go (202 lines)

**Latency Hotspots:**
- **`AllowHost()` calls `net.ParseIP(host)` on every request** — this parses the IP string into a `net.IP` struct. For domain names (the common case), this returns nil and falls through to `allowDomain()`. The `ParseIP` call allocates and does string parsing — ~100ns-1μs per call.
- **`AllowHost()` iterates all `blockedRanges` (11 CIDRs) under RLock** — 11 iterations × `Contains()` check per request. This is ~500ns-1μs but is in the hot path for every connection.
- `allowDomain()` does a map lookup — O(1), fast.
- **RateLimiter uses a `sync.Mutex` (not RWMutex)** — every `Allow()` call takes an exclusive lock. Under high concurrency, this becomes a serialization point. The token bucket algorithm itself is O(1) but the lock contention is O(concurrency).
- `RateLimiter.Allow()` calls `time.Now()` twice — could cache.

**Buffer Management:**
- No buffers. Pure IP/network arithmetic and map lookups.
- `getDefaultBlockedRanges()` parses 11 CIDRs at init — cached in `blockedRanges` slice.

**Throughput Limits:**
- The rate limiter's `sync.Mutex` is the primary throughput bottleneck under high concurrency. Every request serializes on this lock.
- `cleanupRateLimiters()` takes the rate limiter's mutex for the entire cleanup duration (iterating all entries). With many clients, this could cause a multi-millisecond stall.
- No connection limit — only rate limiting.

**IP Rotation Impact:** None.

**Performance Design Score: 6/10**  
The rate limiter mutex contention is a real bottleneck under concurrent load. `net.ParseIP` on every request is wasteful (could cache or use a trie). The 11 CIDR linear scan could be optimized with a radix tree, though 11 is small enough that it's negligible.

---

### 12. internal/stream/sse.go (149 lines)

**Latency Hotspots:**
- **`CopySSE` uses `bufio.Scanner` line-by-line** — this reads one line at a time, creating an event per scan. For SSE, this means one `w.Write()` + one `flusher.Flush()` per event line. The flush is the expensive part — it forces data to the client. For high-frequency SSE (100+ events/sec), this adds per-flush latency.
- `scanner.Buffer(make([]byte, 0, 4096), 64*1024)` allocates a new buffer per `CopySSE` call — not pooled.
- `eventPool.Get()` + `eventPool.Put()` for event assembly — good reuse pattern.

**Buffer Management:**
- `eventPool` (4KB `sync.Pool`) — reused per event. Good.
- `bufPool` (32KB `sync.Pool`) — reused for raw copy. Good.
- `scanner.Buffer` allocates per SSE session — should be pooled.
- `StreamWithBackpressure` creates `make([]byte, len(scanner.Bytes()))` + `copy()` per event — allocates per event, no pooling. This is worse than `CopySSE`.

**Throughput Limits:**
- `CopySSE` flushes after every event — this is correct for SSE (events must be delivered immediately) but limits throughput to network RTT. For local clients, this is fine.
- `StreamWithBackpressure` uses a buffered channel (`eventCh` with cap 64) and a 5s timeout — provides backpressure but the timeout kills the stream if the consumer is slow for 5s. The `make(chan []byte, 64)` means up to 64 events can be buffered.
- `StreamWithBackpressure` allocates `make([]byte, len(scanner.Bytes()))` per event — **no pooling, significant GC pressure** under load.
- `Relay()` function uses `io.CopyBuffer` with 32KB pooled buffers + `CloseWrite()` half-close — this is the most efficient path in the codebase. Bidirectional streaming with proper half-close is textbook optimal.

**IP Rotation Impact:** None.

**Performance Design Score: 7/10**  
`Relay()` is excellent (9/10). `CopySSE` is good (7/10). `StreamWithBackpressure` is poor (5/10) due to per-event allocation and channel overhead. The scanner allocation per session is a minor issue.

---

## Cross-Cutting Performance Analysis

### Connection Lifecycle Latency (Tor path)

| Phase | Latency | Notes |
|-------|---------|-------|
| TCP dial to Tor SOCKS port | 5-50ms | Localhost, variable |
| SOCKS5 auth handshake | 50-200ms | Round-trip through Tor |
| SOCKS5 connect handshake | 50-200ms | Second round-trip through Tor |
| TLS handshake (HTTPS targets) | 100-500ms | Through Tor, depends on target |
| **Total connection setup** | **200-950ms** | **Dominant latency factor** |

This makes connection reuse (keep-alive, pooling) critical. The current pool size of 4 idle connections is insufficient.

### Throughput Bottleneck Ranking

1. **Tor SOCKS5 handshake per connection** (~200-400ms) — fundamental, unavoidable without Tor multiplexing
2. **HTTP Transport pool size (MaxIdleConns=4)** — forces new connections under moderate load
3. **Rate limiter mutex** — serializes all requests under high concurrency
4. **Per-connection allocations in SOCKS5** — 5-8 allocs per connection, no pooling
5. **Firewall IP parsing (net.ParseIP)** — per-request overhead, ~1μs
6. **Header cloning in HTTP proxy** — per-request map allocation

### Buffer Pool Effectiveness

| Pool | Size | Usage | Rating |
|------|------|-------|--------|
| `copyBufPool` (http.go) | 32KB | HTTP response copy | Excellent |
| `bufPool` (sse.go) | 32KB | Raw relay copy | Excellent |
| `eventPool` (sse.go) | 4KB | SSE event assembly | Good |
| SOCKS5 handshake buffers | None | Per-connection alloc | Poor |
| SSE scanner buffers | None | Per-session alloc | Poor |
| StreamWithBackpressure events | None | Per-event alloc | Poor |

### IP Rotation Performance Impact

| Aspect | Impact |
|--------|--------|
| Rotation trigger (atomic counter) | <1ns — negligible |
| Rotation goroutine launch | ~1μs — negligible |
| Tor control port connection | 5-50ms — infrequent (every 100 requests) |
| Circuit age mutex contention | ~100ns per request — minor but unnecessary |
| Post-rotation connection reuse | Existing pooled connections continue on old circuit for up to 90s |
| **Net rotation overhead** | **<0.1% of total request latency** |

IP rotation has negligible performance impact because:
1. The counter is lock-free (atomic)
2. The actual circuit change happens asynchronously in a goroutine
3. Rotation frequency is low (every 100 requests)
4. Only new connections are affected; existing connections are not disrupted

---

## Performance Design Scores Summary

| File | Score | Key Strength | Key Weakness |
|------|-------|-------------|--------------|
| cmd/relay/main.go | 7/10 | Clean orchestration | Hardcoded MaxCircuitAge |
| internal/auth/apikey.go | 8/10 | Timing-safe, fast | Minor alloc per request |
| internal/backend/router.go | 7/10 | Lock-free round-robin | Linear bypass scan |
| internal/backend/tor.go | 6/10 | Stack-allocated handshake | Mutex on hot path (circuitAge) |
| internal/config/config.go | 7/10 | Comprehensive validation | YAML roundtrip for defaults |
| internal/health/health.go | 7/10 | Proper timeouts | TCP dial on every health check |
| internal/log/redact.go | 6/10 | Default redact headers | Clone-per-request |
| internal/proxy/http.go | 7/10 | sync.Pool for copy buffers | Pool too small (4 idle) |
| internal/proxy/socks5.go | 6/10 | Correct protocol impl | 5-8 allocs per connection |
| internal/rotate/rotator.go | 9/10 | Lock-free atomic design | Log in hot path |
| internal/security/firewall.go | 6/10 | Comprehensive CIDR blocking | Mutex contention in rate limiter |
| internal/stream/sse.go | 7/10 | Relay() is textbook optimal | StreamWithBackpressure per-event alloc |

**Overall System Performance Design Score: 6.8/10**

---

## Performance Recommendations (Priority Order)

### Critical
1. **Increase MaxIdleConns to 20-50** and **MaxIdleConnsPerHost to 10** in `http.Transport` — this is the single biggest throughput improvement available.
2. **Replace `sync.Mutex` with `sync.RWMutex` in RateLimiter** — reads (Allow) vastly outnumber writes (cleanup).

### High
3. **Use atomic.Int32 for `circuitAge` in TorBackend** instead of `mu.Lock()` — removes mutex from the hot path.
4. **Pool SOCKS5 handshake buffers** in `socks5.go` — reduce per-connection allocations from 5-8 to 0-1.
5. **Cache `net.ParseIP` results** in firewall or use a pre-compiled CIDR trie for blocked range checks.

### Medium
6. **Pool SSE scanner buffers** in `sse.go` — avoid `make([]byte, 0, 4096)` per session.
7. **Replace `headers.Clone()` in `handleHTTP`** with in-place header modification.
8. **Make `MaxCircuitAge` configurable** in config.yaml.
9. **Cache health check result with TTL** instead of doing TCP dial on every `/healthz` request.

### Low
10. **Add per-connection relay timeout** in SOCKS5 proxy — prevent zombie connections.
11. **Pre-compile API key as `[]byte`** in auth to avoid `[]byte(key)` allocation per request.
12. **Use map for bypass hosts** instead of linear scan in router.

---

*Analysis complete. All 12 source files reviewed. Performance bottlenecks identified and prioritized by impact.*
