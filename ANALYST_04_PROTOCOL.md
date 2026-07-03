# ANALYST_04: Protocol Correctness Analysis

**Analyst:** Protocol Specialist (RFC Expert)  
**Focus:** HTTP CONNECT (RFC 7231/2817), SOCKS5 (RFC 1928), SSE (W3C EventSource Spec)  
**Date:** 2026-06-24

---

## Files Analyzed

| File | Lines | Protocol Role |
|------|-------|---------------|
| internal/proxy/http.go | 206 | HTTP proxy, CONNECT tunnel, plain HTTP forwarding, SSE detection |
| internal/proxy/socks5.go | 218 | SOCKS5 server (RFC 1928) |
| internal/stream/sse.go | 149 | SSE relay, bidirectional TCP relay, backpressure streamer |
| internal/backend/tor.go | 258 | Tor SOCKS5 client (RFC 1928), control protocol (Tor CRLF) |
| internal/backend/router.go | 104 | Backend routing, bypass logic, round-robin failover |
| cmd/relay/main.go | 215 | Protocol initialization, config, lifecycle |

---

## 1. HTTP CONNECT Tunnel (internal/proxy/http.go)

### 1.1 RFC Compliance Check

**RFC 2817 (HTTP CONNECT) + RFC 7231 Section 4.3.6**

| Requirement | Status | Detail |
|-------------|--------|--------|
| Method == CONNECT | ✅ | Line 66: `r.Method == http.MethodConnect` — correct |
| Host header parsing | ⚠️ | Lines 74-83: Adds `:443` default if no port present. Acceptable for proxy use but the RFC says the request-target for CONNECT is `host:port` as-is from the client. If client sends `CONNECT example.com`, adding `:443` is a reasonable default, not a violation. |
| Response code 200 | ✅ | Line 111: `w.WriteHeader(http.StatusOK)` — correct per RFC 2817 |
| Hijack after 200 | ✅ | Lines 104-113: Hijacks after writing 200 OK, then relays bidirectionally — correct tunnel pattern |
| Remove hop-by-hop headers | ✅ | Lines 151-152: Removes `Proxy-Connection` and `Proxy-Authorization` — good practice |

**Issues Found:**

1. **CRITICAL — No 100-continue handling:** RFC 7231 says the server MAY send `100 Continue` before 200. Go's `http.ResponseWriter.WriteHeader(200)` handles this automatically, but if any middleware were to interfere, this could break. Minor concern.

2. **MODERATE — No Proxy-Authenticate on 407:** When auth fails (line 62-64), the `auth.Check()` returns false and the function just returns. The RFC requires a `407 Proxy Authentication Required` response with a `Proxy-Authenticate` header. The current code silently drops the request. This is a real RFC violation for compliant clients.

3. **MODERATE — No Content-Length in error responses:** `http.Error()` sends `text/plain` error bodies. For HTTP/1.1 proxies, this is fine since Go adds Content-Length, but the error body format isn't standardized.

4. **MINOR — Host header without port:** When the client sends `CONNECT example.com HTTP/1.1`, the code adds `:443`. This is common practice but technically the RFC says the target is whatever the client provides. Most real-world clients always include the port.

5. **MINOR — No request body draining:** RFC 7231 says CONNECT requests MUST NOT have a body, but a non-compliant client might send one. The code doesn't drain it, which could cause issues with keep-alive connections (leftover body bytes corrupting the next request).

### 1.2 HTTP Forwarding (handleHTTP)

| Check | Status | Detail |
|-------|--------|--------|
| URL extraction | ✅ | Uses `r.URL.String()` — correct for forward proxy |
| Host header present | ✅ | Line 134: Checks for empty host |
| Header forwarding | ✅ | Clones headers, removes hop-by-hop headers |
| SSE detection | ✅ | Line 163: Checks Content-Type for `text/event-stream` |
| Response body relay | ✅ | Uses pooled 32KB buffer for efficient copying |

**Issues Found:**

1. **MODERATE — All headers forwarded blindly:** Lines 168-172 forward all response headers without filtering hop-by-hop headers (Connection, Transfer-Encoding, TE, Upgrade, etc.). RFC 7230 Section 6.1 says proxies MUST strip hop-by-hop headers. This could cause issues with keep-alive connections or transfer-encoding mismatches.

2. **MINOR — Host header not added:** The outgoing request relies on `r.URL` having the host. For a forward proxy, the request-URI should be absolute-form. Go's `http.NewRequestWithContext` with `r.URL.String()` should produce this correctly, but it depends on how the original request was parsed.

### 1.3 Edge Case Handling

- **Connection failures:** Returns 502 Bad Gateway ✅
- **Hijack failures:** Returns 500, closes destConn ✅  
- **Private IP blocking:** Firewall check before dial ✅
- **Keep-alive:** TCP settings optimized (NoDelay, KeepAlive) ✅
- **SSE responses:** Detected and handled specially ✅

### Score: 7/10

Strong implementation for practical use. Missing proper 407 response on auth failure, no hop-by-hop header stripping on forwarded responses, and no body draining on CONNECT requests are notable gaps.

---

## 2. SOCKS5 Server (internal/proxy/socks5.go)

### 2.1 RFC 1928 Compliance Check

| Requirement | Status | Detail |
|-------------|--------|--------|
| Version check (0x05) | ✅ | Line 85-86: Checks `buf[0] != 0x05` |
| Method negotiation | ⚠️ | Lines 80-96: Reads client's offered methods, always responds `0x05, 0x00` (no auth). RFC 1928 says server MUST select from client's offered methods. If client only offers `0x02` (username/password) but server replies `0x00` (no auth), this is technically a violation. |
| Request version check | ✅ | Line 105: Checks `header[0] != 0x05` |
| Address type 0x01 (IPv4) | ✅ | Lines 113-122: Reads 4 bytes + 2 port bytes |
| Address type 0x03 (Domain) | ✅ | Lines 124-137: Reads 1 length byte + domain + 2 port bytes |
| Address type 0x04 (IPv6) | ✅ | Lines 139-151: Reads 16 bytes + 2 port bytes |
| Reply format | ✅ | Line 197: `0x05, status, 0x00, bindIP, port` — correct |
| CONNECT command (0x01) | ✅ | Line 70: Handled |
| UDP ASSOCIATE (0x03) | ✅ | Lines 191-193: Returns 0x07 (command not supported) — correct rejection |
| BIND command (0x02) | ❌ | Not handled — falls to default case returning 0x07. BIND is rarely used but is part of RFC 1928. |

**Issues Found:**

1. **CRITICAL — IPv6 address formatting bug (lines 148-151):**
   ```go
   target = fmt.Sprintf("[%x:%x:%x:%x:%x:%x:%x:%x]:%d",
       addr[0:2], addr[2:4], ...)
   ```
   The `%x` verb on `[]byte` slices prints each byte as two hex chars. For a 16-byte IPv6 address, this produces e.g. `[fe800000:00000000:00000000:00000000:00000000:00000000:00000000:00000001]:80` which is NOT valid IPv6 bracket notation. Should use `net.IP(addr).String()` for correct formatting like `[fe80::1]:80`.

2. **MODERATE — No SOCKS5 authentication (RFC 1929):** The server always selects method 0x00 (no auth). If a client requires authentication, there's no way to configure it. The SOCKS5 proxy struct has no auth mechanism at all (unlike the HTTP proxy which has API key auth).

3. **MODERATE — Command reply always uses address type 0x01 (IPv4):** Lines 196-208: The bind address in the reply always starts as IPv4 (0x01). When bindIP is nil, it defaults to 0.0.0.0 with type 0x01. When the upstream dial succeeds, `localAddr.IP` is used — if this is an IPv6 address, the type byte is patched to 0x04. This logic is correct but could be cleaner.

4. **MINOR — No BIND command support:** Falls to default (0x07 command not supported). Acceptable for most use cases.

5. **MINOR — No domain name resolution in reply:** The reply uses the local socket address as bind address, which is correct per RFC. But some clients expect the bind address to match the requested address type.

6. **MINOR — No read deadline:** Connections don't have read/write deadlines set. A stalled client could hold a goroutine indefinitely.

### 2.2 Edge Case Handling

- **Connection failures:** Returns 0x05 (connection refused) ✅
- **Firewall blocking:** Returns 0x02 (connection not allowed) ✅
- **Invalid address parsing:** Returns 0x01 (general failure) ✅
- **Unsupported commands:** Returns 0x07 (command not supported) ✅
- **TCP tuning:** NoDelay + KeepAlive configured ✅

### Score: 6/10

Core CONNECT flow works correctly for IPv4 and domain targets. IPv6 address formatting is broken. No method negotiation logic (always picks no-auth). Missing BIND command support. Missing SOCKS5 username/password auth (RFC 1929).

---

## 3. SSE Implementation (internal/stream/sse.go)

### 3.1 W3C EventSource Specification Compliance

| Requirement | Status | Detail |
|-------------|--------|--------|
| Content-Type: text/event-stream | ✅ | Line 34: Set correctly |
| Cache-Control: no-cache | ✅ | Line 35: Set correctly |
| Connection: keep-alive | ✅ | Line 36: Set correctly |
| Flusher support | ✅ | Lines 28-31: Checks for Flusher, falls back to raw copy |
| Line-by-line processing | ✅ | Uses `bufio.Scanner` — correct for SSE's line-oriented format |
| Immediate flush | ✅ | Line 52: `flusher.Flush()` after each event |

**Issues Found:**

1. **CRITICAL — Double-newline event termination is wrong:**
   Lines 47-49:
   ```go
   *bufPtr = append((*bufPtr)[:0], event...)
   *bufPtr = append(*bufPtr, '\n', '\n')
   ```
   SSE events are separated by a blank line (`\n\n`). However, the scanner reads until `\n` and strips the trailing newline. The code then adds `\n\n` back. This means each event ends with `\n\n\n` (the scanner's `\n` was consumed, then two `\n` are appended). Wait — `scanner.Scan()` strips the `\n` delimiter, so the event data doesn't include it. Adding `\n\n` produces correct SSE event boundaries. **This is actually correct** — each event line gets `\n\n` appended, producing the required double-newline separator.

   BUT: SSE events can span multiple lines (with `data:` fields, `event:`, `id:`, `retry:` etc.). The scanner reads line-by-line, so multi-line SSE events are broken up — each line becomes a separate "event" with its own double-newline. A real SSE parser should buffer lines until it hits a blank line (`\n\n`), then dispatch the complete event. The current implementation will break any non-trivial SSE stream.

2. **MODERATE — No multi-line event buffering:** SSE spec says events are delimited by blank lines. A data field can span multiple `data:` lines. The current scanner-based approach sends each line as a separate event, which will corrupt multi-line events by inserting premature blank-line delimiters.

3. **MODERATE — No `retry:` field handling:** The SSE spec defines `retry:` for reconnection intervals. The current implementation passes it through blindly (which is fine for relay), but doesn't validate or parse it.

4. **MINOR — Scanner buffer limits:** Line 41: `scanner.Buffer(make([]byte, 0, 4096), 64*1024)` — max line is 64KB. This is reasonable but could truncate very long SSE data lines.

5. **MINOR — Backpressure timeout in StreamWithBackpressure:** Line 119: `time.After(5 * time.Second)` causes the streamer to give up after 5 seconds of no consumer readiness. This is arbitrary and could cause premature disconnection of slow clients.

### 3.2 Relay Function Analysis

The `Relay()` function (lines 62-94) is a bidirectional TCP relay, not SSE-specific:

| Check | Status | Detail |
|-------|--------|--------|
| Bidirectional copy | ✅ | Two goroutines with io.CopyBuffer |
| Half-close support | ✅ | CloseWrite() called after copy completes |
| Context cancellation | ✅ | Cancel propagated, WaitGroup for completion |
| Connection cleanup | ✅ | Both connections closed after wait |
| Buffer pooling | ✅ | Uses shared pool for allocation efficiency |

This is a well-implemented TCP relay. No RFC issues since it's a raw byte stream.

### 3.3 StreamWithBackpressure

This function (lines 96-138) adds a channel-based buffer between scanner and writer:

| Check | Status | Detail |
|-------|--------|--------|
| Flusher fallback | ✅ | Falls back to CopyRaw if no Flusher |
| Channel buffer | ✅ | 64-event buffer for decoupling |
| Context cancellation | ✅ | Both goroutines respect context |
| Timeout handling | ⚠️ | 5s timeout is arbitrary |
| Memory safety | ⚠️ | Allocates new buffer per event (line 112), no pooling |

### Score: 5/10

The SSE implementation handles the simplest case (single-line events) correctly but fundamentally misunderstands the SSE event model. SSE events can be multi-line with `data:`, `event:`, `id:`, and `retry:` fields. The line-by-line scanner approach breaks these events by inserting premature blank-line separators. For a proxy that relays SSE, this should either pass bytes through transparently (raw copy) or properly buffer complete events before forwarding.

---

## 4. Tor Backend (internal/backend/tor.go)

### 4.1 SOCKS5 Client Compliance (RFC 1928)

| Requirement | Status | Detail |
|-------------|--------|--------|
| Version 0x05 | ✅ | Line 89: `0x05` |
| Method 0x00 (no auth) | ✅ | Line 89: Offers only no-auth |
| Response validation | ✅ | Lines 101-103: Checks version and method |
| CONNECT command (0x01) | ✅ | Line 116 |
| Reserved byte (0x00) | ✅ | Line 116: Third byte is 0x00 |
| Domain address type (0x03) | ✅ | Line 116: Always uses domain type |
| Port encoding (big-endian) | ✅ | Line 126: `port>>8` and `port&0xff` |
| Host length limit (255) | ✅ | Lines 119-121: Checks length |
| Reply validation | ✅ | Lines 138-139: Checks status byte |

**Issues Found:**

1. **MINOR — Always uses domain type (0x03):** Even for IP addresses, it converts them to domain strings (since `net.SplitHostPort` returns a string). This works because Tor resolves domain names internally, but some SOCKS5 servers handle IP types faster than domain type. For Tor this is fine.

2. **MINOR — Fixed 10-byte reply read:** Line 134: `io.ReadFull(conn, reply[:])` reads exactly 10 bytes. For domain-type replies (0x03), the bind address would be at least 5 bytes (1 length + 1 domain + 2 port), but the reply header is already 10 bytes minimum for IPv4. The code reads the full 10 bytes which covers IPv4 bind addresses but ignores longer bind addresses for domain type. For a SOCKS5 *client* talking to Tor, this is fine since we only care about the status byte.

### 4.2 Tor Control Protocol (CRLF commands)

| Check | Status | Detail |
|-------|--------|--------|
| AUTHENTICATE command | ✅ | Lines 158-162: Properly formatted |
| Password quoting | ✅ | Line 159: Password quoted with escaped double quotes |
| SIGNAL NEWNYM | ✅ | Line 172: Correct command for circuit rotation |
| Response parsing | ✅ | Lines 168, 177: Checks for "250" OK response |
| Connection management | ✅ | Dial timeout + deferred close |

**Issues Found:**

1. **MODERATE — Password injection risk:** Line 159:
   ```go
   fmt.Fprintf(conn, "AUTHENTICATE \"%s\"\r\n", t.controlPass)
   ```
   If the password contains a `"` character, it breaks the protocol. The Tor control protocol requires escaping special characters. Should use `fmt.Sprintf("AUTHENTICATE %q\r\n", ...)` or manual escaping.

2. **MINOR — No capability negotiation:** The Tor control protocol spec (control-spec.txt) recommends sending `PROTOCOLINFO` first to discover supported authentication methods. The code jumps straight to `AUTHENTICATE`, which works with password auth but may fail with cookie-based auth.

3. **MINOR — Circuit age tracking is connection-count, not age:** Line 78: `t.circuitAge++` increments per connection, not per unit time. The naming suggests temporal age but it's actually a request counter. The `ShouldRotate()` check (line 214) triggers based on this counter reaching `maxCircuitAge`.

### Score: 7/10

Solid Tor SOCKS5 client implementation. The handshake is RFC-compliant and the Tor control protocol usage is functional. Password injection and missing PROTOCOLINFO negotiation are the main concerns.

---

## 5. Router (internal/backend/router.go)

### 5.1 Protocol-Relevant Analysis

| Check | Status | Detail |
|-------|--------|--------|
| Backend interface | ✅ | Clean DialContext-based abstraction |
| Round-robin | ✅ | Atomic counter for backend selection |
| Health-aware routing | ✅ | Skips unhealthy backends |
| Bypass logic | ✅ | Domain suffix matching for direct connections |
| Failover | ✅ | Tries all backends if first fails |
| Context propagation | ✅ | ctx passed through to backend |

**Issues Found:**

1. **MODERATE — Atomic counter race in round-robin:** Lines 69-84: The `current.Load()` and subsequent `current.Store()` are not atomic together. Two concurrent requests could both read the same index and both try the same backend, then both update to the same next index. This is acceptable for a proxy (the load won't be perfectly balanced but won't break anything).

2. **MINOR — Bypass only uses directBackend:** Line 62: If a bypass host fails on direct connection, it doesn't fall back to the Tor backend. The `conn, err := r.directBackend.DialContext(...)` result is only returned on success, and on failure the code falls through to the regular backend loop. This is actually correct behavior — bypass hosts should go direct, and if direct fails, they should try all backends including Tor. This is good design.

3. **MINOR — No connection count limit:** No maximum concurrent connections per backend.

### Score: 8/10

Clean, well-designed routing layer. The round-robin has minor atomicity issues but they're inconsequential for a proxy use case.

---

## 6. Main Initialization (cmd/relay/main.go)

### 6.1 Protocol Initialization

| Check | Status | Detail |
|-------|--------|--------|
| HTTP proxy init | ✅ | Line 129: Created with router, auth, firewall, logger |
| SOCKS5 proxy init | ✅ | Line 130: Created with router, firewall, logger |
| Tor backend init | ✅ | Lines 76-87: Conditional Tor setup |
| Direct backend init | ✅ | Lines 91-95: Always created as fallback |
| Router assembly | ✅ | Lines 89-96: Correctly handles Tor+Direct or Direct-only |
| Graceful shutdown | ✅ | Lines 176-186: Signal handling + context timeout |
| Health server | ✅ | Lines 146-171: Optional health endpoint |

**Issues Found:**

1. **MINOR — Auth not enabled for SOCKS5:** Line 130: `NewSOCKS5Proxy(router, firewall, logger)` — no auth middleware passed. The SOCKS5 proxy has no authentication support at all, even when `cfg.Auth.Enabled` is true. HTTP proxy gets auth, SOCKS5 does not. This is an asymmetry that could be a security issue.

2. **MINOR — Hardcoded control address:** Line 79: `"127.0.0.1:9051"` hardcoded instead of using `cfg.ControlAddr` or similar config field.

### Score: 8/10

Initialization is clean and well-structured. Minor gaps in SOCKS5 auth parity and hardcoded Tor control address.

---

## Summary Scores

| Component | Protocol | Score | Key Issue |
|-----------|----------|-------|-----------|
| HTTP CONNECT | RFC 2817/7231 | **7/10** | Missing 407 auth response, no hop-by-hop stripping |
| HTTP Forward | HTTP/1.1 | **7/10** | All headers forwarded without filtering |
| SOCKS5 Server | RFC 1928 | **6/10** | IPv6 formatting broken, no auth negotiation |
| SSE Relay | W3C SSE Spec | **5/10** | Multi-line events broken by line-by-line scanner |
| Tor SOCKS5 Client | RFC 1928 | **7/10** | Password injection in control protocol |
| Router | N/A | **8/10** | Minor atomicity issues |
| Main Init | N/A | **8/10** | SOCKS5 has no auth even when configured |

### **Overall Protocol Correctness: 6.9/10**

---

## Priority Fixes

### HIGH PRIORITY
1. **SSE multi-line event buffering** — The scanner-based approach breaks SSE events with multiple data/event/id lines. Either buffer complete events (scan until blank line) or pass through as raw bytes since this is a relay.
2. **IPv6 SOCKS5 address formatting** — Use `net.IP(addr).String()` instead of manual `%x` formatting.
3. **HTTP 407 Proxy Authentication Required** — Return proper 407 with Proxy-Authenticate header when auth fails.

### MEDIUM PRIORITY
4. **Hop-by-hop header stripping** — Remove Connection, Transfer-Encoding, TE, etc. from forwarded HTTP responses.
5. **SOCKS5 authentication support** — Implement RFC 1929 username/password auth method.
6. **Tor control password escaping** — Properly escape special characters in AUTHENTICATE command.
7. **CONNECT body draining** — Drain any unexpected request body before hijacking.

### LOW PRIORITY
8. **SOCKS5 BIND command support** — Rarely used but part of RFC 1928.
9. **Tor PROTOCOLINFO negotiation** — Use capability discovery before AUTHENTICATE.
10. **Connection read/write deadlines** — Add timeouts to SOCKS5 connections to prevent goroutine leaks.
