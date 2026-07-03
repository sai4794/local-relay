# Local Relay Proxy — Engineering Audit Report

**Date:** 2026-07-03
**Codebase:** 19 Go files, ~4,000 lines
**Auditor:** Principal Systems Architect + Security Engineer + SRE

---

## 1. Executive Summary

Local-relay is a Go-based HTTP/SOCKS5 proxy that routes traffic through Tor for IP rotation and rate-limit bypass. The codebase is well-structured with clean package separation and good dependency injection. However, it has **critical security vulnerabilities** (SSRF bypass, no body size enforcement in SOCKS5, TOCTOU in DNS checks), **concurrency bugs** (goroutine leaks, race conditions), and **minimal test coverage** (7 tests total). It is NOT production-ready without fixes.

## 2. Scores

| Category | Score | Rationale |
|----------|-------|-----------|
| Architecture | 7/10 | Clean separation, good DI, but dead code and inconsistencies |
| Security | 3/10 | SSRF bypass via TOCTOU, no body limit in SOCKS5, DNS resolution race |
| Performance | 6/10 | Good buffer pooling, but DNS resolution blocking in firewall |
| Reliability | 5/10 | Goroutine leaks, no panic recovery, bootstrap depends on external host |
| Maintainability | 6/10 | Good naming, but dead code, duplicate code, minimal docs |
| Code Quality | 6/10 | Idiomatic Go mostly, but some inconsistencies |
| Test Quality | 2/10 | 7 tests total, no integration tests, no race tests |
| Production Readiness | 3/10 | Multiple critical issues, no TLS, no access logging |
| Specification Compliance | 60% | Missing: WebSocket, SOCKS5 body limits, time-based rotation |

---

## 3. Issues Found

### P0 — Critical

| # | File | Function | Issue | Impact | Fix |
|---|------|----------|-------|--------|-----|
| 1 | ssrf.go:46 | IsBlocked | DNS resolution TOCTOU — resolves IP at check time, but actual connection may resolve to different IP | SSRF bypass | Resolve IP once at dial time, not check time |
| 2 | socks5.go | handleConnect | No SSRF check for SOCKS5 connections — only checks firewall.AllowHost, not ssrf.IsBlocked | SSRF via SOCKS5 | Add SSRF check to SOCKS5 handleConnect |
| 3 | socks5.go | handleConnect | No body size limit enforcement — bodyLimit field exists but is never used | Memory exhaustion via SOCKS5 | Not applicable for SOCKS5 (no request body) — remove dead field |
| 4 | http.go:188 | handleHTTP | SSRF check uses `r.URL.Host` which can be empty for malformed requests | SSRF bypass | Use r.URL.Hostname() with fallback |
| 5 | firewall.go:57 | AllowHost | DNS resolution on every request is blocking and slow (100ms+ per lookup) | Latency, DNS amplification | Cache DNS results with TTL |

### P1 — High

| # | File | Function | Issue | Impact | Fix |
|---|------|----------|-------|--------|-----|
| 6 | main.go:324 | metrics goroutine | Metrics server goroutine has no panic recovery, no shutdown | Goroutine leak on panic | Add defer recover(), handle shutdown |
| 7 | main.go:314 | health goroutine | Health server goroutine has no panic recovery | Goroutine leak on panic | Add defer recover() |
| 8 | main.go:238 | HTTP proxy goroutine | HTTP proxy goroutine calls stop() on error but doesn't exit | Partial shutdown | Send to error channel, let main handle |
| 9 | pool.go:374-439 | rateLimitedNEWNYM | Reads control_auth_cookie from filesystem on every NEWNYM call — no caching | Performance, race condition | Cache cookie, invalidate on rotation |
| 10 | multitor.go:196 | ReportAnomaly | Goroutine launched per instance without tracking — no WaitGroup | Goroutine leak | Add WaitGroup or limit concurrency |
| 11 | rotator.go:42-46 | ShouldRotate | Goroutine launched without tracking — only ForceRotate has WaitGroup | Inconsistent shutdown | Always use WaitGroup |
| 12 | http.go:202 | handleHTTP | `r.URL.String()` for target includes query params — may double-encode | Malformed upstream URLs | Use r.URL.RequestURI() or rebuild |
| 13 | socks5.go:216 | readRequest | IPv6 address formatting is wrong — uses `%x` instead of proper hex | Broken IPv6 SOCKS5 | Use net.IP.String() |
| 14 | config.go:116 | defaultConfig | API key is hardcoded in source (`***`) — visible in binary | Secret leakage | Remove from defaults, require env/config |
| 15 | torlifecycle.go:290 | CheckHealth | Calls `inst.Cmd.Process.Pid` after Kill() — may be nil | Nil pointer dereference | Check Process != nil before accessing Pid |

### P2 — Medium

| # | File | Function | Issue | Impact | Fix |
|---|------|----------|-------|--------|-----|
| 16 | http.go:262-277 | handleHTTP | Headers copied AFTER status code check — some headers may be missed | Missing response headers | Copy headers before WriteHeader |
| 17 | http.go:275 | handleHTTP | `copyBufPool.Get().(*[]byte)` — type assertion panics if pool returns wrong type | Panic | Use safe type assertion |
| 18 | multitor.go:20 | MultiTorBackend | `current int` field is unused — only `counter atomic.Int64` is used | Dead code | Remove unused field |
| 19 | config.go:69-70 | SecurityConfig | `RequestTimeout` field is defined but never used | Dead config | Remove or wire into relay |
| 20 | config.go:75-76 | LoggingConfig | `RedactHeaders` and `MaxBodyLogSize` defined but never used | Dead config | Remove or wire into logging |
| 21 | health.go:142-191 | handleMetrics | Manual Prometheus formatting instead of using prometheus/client_golang | Fragile, non-standard | Use prometheus library |
| 22 | http.go:83-168 | handleConnect | No timeout on the relay goroutine — hangs forever if one side stalls | Goroutine leak | Add per-connection timeout |
| 23 | pool.go:477-483 | Close | Close() only marks slots unhealthy, doesn't close connections | Resource leak | Close idle connections |
| 24 | torlifecycle.go:314 | killInstance | `os.RemoveAll(inst.DataDir)` deletes data even on failed kill | Data loss | Only delete after confirmed kill |
| 25 | stream/sse.go:39-55 | CopySSE | Scanner doesn't handle binary data well — may split multi-byte UTF-8 | Data corruption | Use io.Copy with flush for SSE |

### P3 — Low

| # | File | Function | Issue | Impact | Fix |
|---|------|----------|-------|--------|-----|
| 26 | main.go:367 | startTime | Package-level var for uptime — minor, but not testable | Minor | Move into HealthServer |
| 27 | config.go:225-226 | validateAddress | No IPv6 validation — only checks format | Minor | Add IPv6 format check |
| 28 | multitor.go:127 | socks5Handshake | `fmt.Sscanf` for port parsing — should use strconv.Atoi | Minor | Use strconv.Atoi |
| 29 | http.go:360-364 | recordRotation | Logs rotation trigger but doesn't actually trigger it | Confusing | Remove or make it trigger |
| 30 | pool.go:500-630 | Status | Large function with deep nesting — hard to read | Readability | Extract helpers |

---

## 4. Specification Compliance

| Requirement | Status | Notes |
|-------------|--------|-------|
| HTTP/1.1 proxy | ✅ Done | Works |
| HTTP/2 | ⚠️ Partial | ForceAttemptHTTP2: false — intentionally disabled |
| HTTP/3 | ❌ Not done | Spec says "not initial version" — acceptable |
| SOCKS5 proxy | ✅ Done | But IPv6 formatting is broken (#13) |
| WebSocket | ❌ Not done | Spec-required, missing |
| SSE streaming | ✅ Done | Works with CopySSE |
| Chunked transfer | ✅ Done | Works via io.CopyBuffer |
| Tor lifecycle | ✅ Done | Spawn, bootstrap, health, restart |
| Circuit rotation | ✅ Done | NEWNYM + pool clear |
| SSRF protection | ⚠️ Partial | TOCTOU bypass (#1), no SOCKS5 check (#2) |
| Authentication | ✅ Done | API key auth with constant-time compare |
| Prometheus metrics | ⚠️ Partial | Manual formatting, not using prometheus lib |
| Health checks | ✅ Done | /healthz, /readyz, /metrics |
| Configuration | ✅ Done | YAML + env overrides + validation |
| Graceful shutdown | ✅ Done | Signal handling + cleanup |
| Body size limits | ⚠️ Partial | HTTP only, not SOCKS5 (#3) |

---

## 5. Top 20 Improvements

1. Fix SSRF TOCTOU — resolve DNS at dial time
2. Add SSRF check to SOCKS5 handler
3. Add panic recovery to all goroutines
4. Fix goroutine leaks (Rotator, MultiTor)
5. Add WebSocket support (spec-required)
6. Cache DNS resolution in firewall
7. Add integration tests
8. Add race detector tests
9. Fix IPv6 SOCKS5 formatting
10. Remove dead code (current field, RequestTimeout, RedactHeaders)
11. Add body size limit to HTTP response
12. Fix metrics to use prometheus library
13. Add access logging
14. Add TLS support for gateway
15. Add request timeout to CONNECT tunnels
16. Fix control_auth_cookie caching
17. Add DNS rebinding protection
18. Add Slowloris protection (already has ReadHeaderTimeout)
19. Add request ID tracking
20. Document architecture in README

---

## 6. Would I Approve This for Production?

**No.** The SSRF bypass (#1, #2) and goroutine leaks (#6, #7, #10) are blocking. The code is well-structured and the Tor integration is solid, but it needs 15-20 hours of fixes before production deployment.

## 7. Would I Approve for Open-Source Release?

**Not yet.** Missing: WebSocket support (spec-required), comprehensive tests, documentation, and the critical security fixes. After the P0/P1 fixes and test coverage, it would be a solid release.
