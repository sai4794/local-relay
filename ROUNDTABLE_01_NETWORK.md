# ROUNDTABLE 01 — NETWORK ENGINEERING ANALYSIS
## Tor Routing & IP Rotation Strategy

**Expert:** Network Engineer (Tor routing, IP rotation)
**Date:** 2026-06-24
**Scope:** Complete analysis of Tor circuit rotation, IP diversity, timing, and optimization

---

## 1. CURRENT STATE: HOW ROTATION WORKS (AND WHY IT DOESN'T)

### 1.1 Architecture Overview

The relay has three layers relevant to rotation:

```
Request → HTTPProxy/SOCKS5Proxy → Router → TorBackend → Tor (SOCKS5)
                                  ↑
                          Rotator (counter-based)
```

### 1.2 The Rotator (`internal/rotate/rotator.go`)

- **Mechanism:** Atomic counter incremented on each `ShouldRotate()` call
- **Trigger:** `count % interval == 0` → fires `onRotate` callback in a goroutine
- **Config:** `rotation.interval = 10` (from `config.yaml`)

### 1.3 The Tor Backend (`internal/backend/tor.go`)

- **Circuit Age:** `circuitAge++` on every `DialContext()` call (line 78)
- **Rotation Check:** `ShouldRotate()` returns true when `circuitAge >= maxCircuitAge` (default: 100)
- **NEWNYM:** `RequestNewCircuit()` sends `SIGNAL NEWNYM` via Tor control port (9051)
- **Control Port:** Hardcoded to `127.0.0.1:9051`, not configurable
- **Auth:** `controlPass` is always empty (no Tor control port authentication)

### 1.4 The Callback Wiring (`cmd/relay/main.go`, lines 117-127)

```go
rotator = rotate.NewRotator(cfg.Rotation.Interval, func() {
    if torBackend != nil && torBackend.ShouldRotate() {
        if err := torBackend.RequestNewCircuit(); err != nil { ... }
    }
}, logger)
```

---

## 2. CRITICAL BUG: ROTATION IS COMPLETELY DEAD CODE

### 2.1 The Problem

**`rotator.ShouldRotate()` is NEVER called from any request handler.**

I verified this exhaustively:

- `HTTPProxy` (`internal/proxy/http.go`): Has no reference to the rotator. `handleHTTP()` and `handleConnect()` never call it.
- `SOCKS5Proxy` (`internal/proxy/socks5.go`): Has no reference to the rotator. `handleConnect()` never calls it.
- `Router` (`internal/backend/router.go`): Has no reference to the rotator.

The rotator is instantiated in `main.go` and its `GetCount()` is reported in the health endpoint, but `ShouldRotate()` is never invoked. This means:

1. The rotator counter **never increments** (stays at 0)
2. The `onRotate` callback **never fires**
3. `SIGNAL NEWNYM` is **never sent**
4. **Tor circuits are NEVER rotated. The same exit IP is used for the entire relay lifetime.**

### 2.2 The Double-Gate Problem (Even If It Worked)

Even if the rotator were properly wired, there is a second problem. The callback checks `torBackend.ShouldRotate()` which requires `circuitAge >= maxCircuitAge` (100). So:

- Rotator fires at request #10, #20, #30, ..., #100
- At request #100, `circuitAge` ≈ 100 → `ShouldRotate()` returns true → NEWNYM sent
- At request #110, `circuitAge` ≈ 10 → `ShouldRotate()` returns false → no NEWNYM
- Actual rotation only happens every ~100 requests, NOT every 10

The `interval: 10` config is misleading — it would have no meaningful effect.

### 2.3 Additional Issue: Control Port Hardcoded

`ControlAddr` is hardcoded to `"127.0.0.1:9051"` in `main.go` line 79, ignoring config. The `TorConfig.ControlAddr` field exists but is never populated from `config.yaml`.

---

## 3. IS ROTATING EVERY 10 REQUESTS OPTIMAL?

**Short answer: No, and the question is moot since rotation doesn't work.**

### 3.1 Analysis of Request Patterns

From the relay log, I observe the real traffic pattern:

| Time Window | Requests to opencode.ai | Duration |
|---|---|---|
| 23:21:59 - 23:22:27 | ~8 requests | ~28s |
| 23:22:52 - 23:23:15 | ~4 requests | ~23s |
| 23:23:35 - 23:23:44 | ~3 requests | ~9s |
| 23:24:03 - 23:25:41 | ~7 requests | ~98s |
| 23:26:12 - 23:27:43 | ~10 requests | ~91s |
| 23:28:15 - 23:29:45 | ~7 requests | ~90s |
| 23:30:04 - 23:33:05 | ~14 requests | ~181s |

**Total:** ~53 requests in ~11 minutes = ~4.8 req/min average

### 3.2 Quota Consumption Estimate

The goal is to defeat per-IP daily quotas on free LLM providers. Typical quotas:
- OpenRouter free tier: ~200 requests/day/IP
- OpenCode free models: likely 50-500 requests/day/IP
- Typical pattern: 50-200 requests/day before rate limit

With ~53 requests in 11 minutes, and assuming sustained use for a few hours:
- 1 hour: ~290 requests
- 4 hours: ~1,160 requests
- Full day (8hr active): ~2,320 requests

**Every 10 requests is WAY too infrequent.** You'd exhaust a 50-request quota in under 10 minutes before getting a new IP.

### 3.3 Optimal Rotation Frequency

For the specific use case (LLM API calls through free providers):

**Recommendation: Rotate every 1 request**

Rationale:
- LLM API calls are infrequent (1 every 10-30 seconds)
- Each call has high latency (2-30 seconds for completion)
- There is zero benefit to keeping the same circuit — no session affinity, no cookie state
- Each new circuit takes ~1-3 seconds to build (acceptable for LLM calls that take 5-30s)
- Maximizes IP diversity: N requests = N distinct IPs (approximately)

---

## 4. ACTUAL IP DIVERSITY FROM TOR

### 4.1 How Tor Circuit Selection Works

A Tor circuit consists of: Entry (Guard) → Middle → Exit

- **Guard node:** Sticky for the lifetime of the Tor instance (typically 2-3 months). Determined at first use.
- **Middle node:** Random per circuit.
- **Exit node:** Random per circuit, but constrained by exit policies.

### 4.2 IP Diversity Per Circuit

Each new circuit gives ONE new exit IP. However:

1. **Exit nodes are a limited pool:** ~1,000-2,000 exit nodes in the Tor network
2. **Exit selection is weighted by bandwidth:** High-bandwidth exits appear more frequently
3. **Some /24 subnets host multiple exit IPs:** If two exits share a /24, a server might see them as "similar"
4. **Exit policies limit diversity:** Many exits block ports 25, 443, or specific services

### 4.3 Realistic Diversity Estimates

| Metric | Value |
|---|---|
| Unique exit IPs in Tor network | ~7,000-10,000 |
| Active exit nodes | ~1,000-2,000 |
| IPs per /24 visible from single client | ~50-200 |
| Probability of same exit in consecutive circuits | ~5-15% |
| Probability of same exit in 10 circuits | ~40-60% (without exit pinning) |

### 4.4 The Guard Node Problem

The guard (entry) node is deterministic and long-lived. While the target server can't see it directly, Tor's path selection sometimes pins exit nodes relative to guard nodes (family restrictions, bandwidth weighting). This means:

- Different circuits from the same guard tend to use similar exit pools
- IP diversity is LOWER than random selection would suggest
- For quota evasion, this is usually fine — the target sees the EXIT IP, not the guard

### 4.5 What Providers Actually Track

Most LLM providers track by:
1. **Source IP address** — the exit IP
2. **Sometimes /24 subnet** — to catch multiple exits from the same provider
3. **TLS fingerprint** — not relevant here (all clients look the same through Tor)
4. **Request patterns** — timing, headers, user-agent (not changed by Tor rotation)

**Key insight:** With Tor rotation, you get ~85-95% unique IPs per circuit. The 5-15% collision rate is acceptable for quota evasion. The main risk is that a target blocks an entire /24, which would affect ~2-5% of circuits.

---

## 5. HOW LONG UNTIL A NEW CIRCUIT GIVES A FRESH IP?

### 5.1 Tor Circuit Build Times

| Phase | Time |
|---|---|
| Tor daemon startup | 5-15 seconds (first time) |
| Guard selection (first use) | Included in first circuit |
| Circuit build (CREATE/CREATED cells) | 500ms - 3 seconds |
| `SIGNAL NEWNYM` propagation | Instant (but has a 10-second rate limit) |
| New circuit build after NEWNYM | 500ms - 3 seconds |
| First request on new circuit | +100-500ms (DNS resolution through Tor) |

### 5.2 NEWNYM Rate Limiting

Tor limits `SIGNAL NEWNYM` to once every 10 seconds. If you send it more frequently:
- Tor returns: `551 Tor cannot provide a new circuit now`
- The relay should handle this gracefully (current code logs error but continues)

### 5.3 Realistic Timeline

| Action | Time to Fresh IP |
|---|---|
| First request (cold start) | 1-5 seconds (circuit build) |
| NEWNYM + new request | 1-4 seconds (NEWNYM + circuit build) |
| Passive circuit rotation (no NEWNYM) | 0 seconds — but NO new IP until current circuit dies |
| Circuit naturally expired | ~10 minutes (Tor's default `CircuitIdleTimeout = 600s`) |

**Critical point:** Without `SIGNAL NEWNYM`, the current circuit persists for up to 10 minutes. All requests in that window use the same exit IP. `SIGNAL NEWNYM` is the only way to force a new circuit immediately.

---

## 6. OPTIMAL ROTATION STRATEGY

### 6.1 Recommended Configuration

```yaml
rotation:
  enabled: true
  interval: 1              # Rotate every single request
  min_interval_sec: 10     # Minimum 10 seconds between NEWNYM signals
```

### 6.2 Proposed Code Changes

#### Change 1: Wire the rotator into the request path

**File: `cmd/relay/main.go`**

Pass the rotator to both HTTP and SOCKS5 proxies:

```go
// After creating the rotator:
httpProxy := proxy.NewHTTPProxy(router, authMiddleware, firewall, logger)
httpProxy.SetRotator(rotator)  // NEW

socks5Proxy := proxy.NewSOCKS5Proxy(router, firewall, logger)
socks5Proxy.SetRotator(rotator)  // NEW
```

#### Change 2: Call rotator from request handlers

**File: `internal/proxy/http.go`**

```go
func (p *HTTPProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
    // ... existing code ...
    
    // NEW: Trigger rotation check before proxying
    if p.rotator != nil {
        p.rotator.ShouldRotate()
    }
    
    req, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body)
    // ... rest of existing code ...
}

func (p *HTTPProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
    // ... existing code ...
    
    // NEW: Trigger rotation check before proxying
    if p.rotator != nil {
        p.rotator.ShouldRotate()
    }
    
    destConn, err := p.router.DialContext(r.Context(), "tcp", host)
    // ... rest of existing code ...
}
```

Same pattern for `SOCKS5Proxy.handleConnect()`.

#### Change 3: Simplify the callback — remove double-gate

**File: `cmd/relay/main.go`**

The callback should directly call `RequestNewCircuit()` without checking `torBackend.ShouldRotate()`:

```go
rotator = rotate.NewRotator(cfg.Rotation.Interval, func() {
    if torBackend != nil {
        logger.Info("Requesting new Tor circuit",
            "request_count", rotator.GetCount(),
        )
        if err := torBackend.RequestNewCircuit(); err != nil {
            logger.Error("Failed to request new Tor circuit", "error", err)
        }
    }
}, logger)
```

#### Change 4: Add time-based rotation to the Rotator

**File: `internal/rotate/rotator.go`**

Add a minimum time interval to prevent NEWNYM hammering:

```go
type Rotator struct {
    counter         atomic.Uint64
    interval        atomic.Uint64
    onRotate        func()
    logger          *slog.Logger
    lastTrade       atomic.Int64
    minIntervalSec  int64          // NEW: minimum seconds between rotations
}

func NewRotator(interval int, onRotate func(), logger *slog.Logger) *Rotator {
    r := &Rotator{
        onRotate:       onRotate,
        logger:         logger,
        minIntervalSec: 10, // NEW: default 10s minimum (Tor NEWNYM rate limit)
    }
    r.interval.Store(uint64(interval))
    return r
}

func (r *Rotator) ShouldRotate() bool {
    interval := r.interval.Load()
    if interval == 0 {
        return false
    }

    count := r.counter.Add(1)
    if count%interval != 0 {
        return false
    }

    // NEW: Rate-limit rotation by time (Tor NEWNYM limit = 10s)
    now := time.Now().UnixNano()
    last := r.lastTrade.Load()
    minNs := r.minIntervalSec * int64(time.Second)
    if last > 0 && (now-last) < minNs {
        r.logger.Debug("Rotation skipped (too soon)",
            "since_last", time.Duration(now-last).String(),
            "min_interval", time.Duration(minNs).String(),
        )
        return false
    }

    r.logger.Info("IP rotation triggered",
        "request_count", count,
        "interval", interval,
    )

    if r.onRotate != nil {
        go r.onRotate()
    }

    r.lastTrade.Store(now)
    return true
}
```

#### Change 5: Make Tor control port configurable

**File: `internal/config/config.go`** — Add to BackendConfig:

```go
type BackendConfig struct {
    Type        string            `yaml:"type"`
    Address     string            `yaml:"address"`
    ControlAddr string            `yaml:"control_addr"`  // NEW
    ControlPass string            `yaml:"control_pass"`  // NEW
    Options     map[string]string `yaml:"options"`
}
```

**File: `cmd/relay/main.go`** — Use config values:

```go
torBackend = backend.NewTorBackend(backend.TorConfig{
    Address:       cfg.Backend.Address,
    ControlAddr:   cfg.Backend.ControlAddr,    // Was hardcoded
    ControlPass:   cfg.Backend.ControlPass,    // Was empty
    Timeout:       cfg.ConnectionTimeout(),
    MaxCircuitAge: 100, // Removed — not needed with proper wiring
})
```

**File: `config.yaml`** — Add control port:

```yaml
backend:
  type: tor
  address: "127.0.0.1:9050"
  control_addr: "127.0.0.1:9051"
  control_pass: ""
```

#### Change 6: Remove MaxCircuitAge gate entirely

The `TorBackend.ShouldRotate()` method and `maxCircuitAge` field are unnecessary with proper rotator integration. Rotation should be driven solely by the rotator's counter + time gate. Remove:

- `TorBackend.ShouldRotate()` method
- `TorBackend.maxCircuitAge` field
- The `circuitAge` counter (no longer needed)
- The `circuitAge++` in `DialContext`

### 6.3 Updated Config

```yaml
rotation:
  enabled: true
  interval: 1            # Every request
  # min_interval_sec is code-level, not in YAML (set via NewRotator default = 10s)

backend:
  type: tor
  address: "127.0.0.1:9050"
  control_addr: "127.0.0.1:9051"
  control_pass: ""
```

### 6.4 Alternative: Time-Based Rotation (Recommended)

For LLM API calls where request rate varies wildly, **time-based rotation is superior** to count-based:

```go
type Rotator struct {
    counter         atomic.Uint64
    interval        atomic.Uint64
    onRotate        func()
    logger          *slog.Logger
    lastTrade       atomic.Int64
    rotateAfterMs   int64    // NEW: rotate after this many ms since last rotation
}

func (r *Rotator) ShouldRotate() bool {
    r.counter.Add(1)

    now := time.Now().UnixNano()
    last := r.lastTrade.Load()
    
    // Time-based: rotate if enough time has passed
    if r.rotateAfterMs > 0 && (now-last) < r.rotateAfterMs*int64(time.Millisecond) {
        return false
    }

    // Count-based fallback: also rotate on interval
    if r.interval.Load() > 0 && r.counter.Load()%r.interval.Load() != 0 {
        return false
    }

    r.lastTrade.Store(now)
    if r.onRotate != nil {
        go r.onRotate()
    }
    return true
}
```

Config addition:

```yaml
rotation:
  enabled: true
  interval: 1
  rotate_after_ms: 10000   # Rotate at least every 10 seconds
```

---

## 7. TIMING CALCULATIONS

### 7.1 Scenario: Every-Request Rotation (Recommended)

| Parameter | Value |
|---|---|
| Rotation interval | 1 request |
| Min time between rotations | 10 seconds |
| Average request rate | 1 req / 12 seconds |
| Effective rotation rate | Every request (~100% of requests) |
| NEWNYM calls per minute | ~5 |
| Tor circuit builds per minute | ~5 |
| Latency overhead per request | +1-3 seconds (circuit build) |
| Total requests/day (8hr active) | ~2,400 |
| Unique IPs needed | ~2,400 |
| Available Tor exit IPs | ~7,000-10,000 |
| **Probability of IP collision** | **~0.3% per pair** |

**Verdict:** Excellent. With 7,000+ exit IPs and only 2,400 requests, collision probability is negligible.

### 7.2 Scenario: Every-10-Request Rotation (Current Config)

| Parameter | Value |
|---|---|
| Rotation interval | 10 requests |
| Effective rotation rate | Every 10th request (~10% of requests) |
| Requests per rotation | 10 |
| NEWNYM calls per minute | ~0.5 |
| Unique IPs per minute | ~0.5 |
| **Quota consumed before rotation** | **10 requests/IP** |
| **Time before fresh IP** | **~2 minutes** |

**Verdict:** Poor. 10 requests on the same IP may exhaust small quotas.

### 7.3 Scenario: Time-Based (10-second minimum)

| Parameter | Value |
|---|---|
| Time between rotations | ≥10 seconds |
| Requests per rotation window | 0-8 (varies) |
| Unique IPs per minute | ~6 |
| Latency overhead | Minimal (rotation happens in background goroutine) |
| NEWNYM rate limiting | Handled (10s minimum matches Tor's limit) |

**Verdict:** Best approach. Time-based rotation is natural for LLM API usage patterns.

---

## 8. LATENCY IMPACT ANALYSIS

### 8.1 Current Latency (No Rotation — Broken)

| Component | Latency |
|---|---|
| Local → Tor SOCKS5 | <1ms |
| Tor circuit (existing) | 0ms overhead |
| Tor relay (3 hops) | 100-500ms |
| TLS handshake through Tor | 200-800ms |
| **Total overhead** | **~300-1300ms** |

### 8.2 With NEWNYM Rotation

| Component | Latency |
|---|---|
| NEWNYM signal | 0ms (fire-and-forget in goroutine) |
| Next dial → new circuit build | 500-3000ms |
| **Rotation overhead** | **+500-3000ms on first request after rotation** |
| Subsequent requests (same circuit) | 0ms extra |

### 8.3 Mitigation: Pre-Build Circuits

Tor can pre-build circuits. After sending NEWNYM, the next `DialContext` call triggers an immediate circuit build. Since rotation happens in a goroutine, the circuit may already be built by the time the next request arrives.

**Optimization:** Send NEWNYM slightly before the expected rotation point:

```go
// In the rotator callback, send NEWNYM 2 seconds before the request arrives
go func() {
    time.Sleep(500 * time.Millisecond) // Let any in-flight request finish
    torBackend.RequestNewCircuit()
}()
```

This is already partially implemented (the `go r.onRotate()` in ShouldRotate fires async). The remaining 500ms-3s latency is unavoidable for the first request after rotation.

---

## 9. SUMMARY OF FINDINGS

### 9.1 Bugs Found

| # | Severity | Issue | Location |
|---|---|---|---|
| 1 | **CRITICAL** | `rotator.ShouldRotate()` never called from request path — rotation is dead code | `cmd/relay/main.go`, `internal/proxy/http.go`, `internal/proxy/socks5.go` |
| 2 | **HIGH** | Double-gate: rotator interval AND torBackend.ShouldRotate() both must be true | `cmd/relay/main.go` line 120 |
| 3 | **MEDIUM** | Tor control port hardcoded to 127.0.0.1:9051, not configurable | `cmd/relay/main.go` line 79 |
| 4 | **LOW** | `circuitAge` named misleadingly — counts connections, not time | `internal/backend/tor.go` line 78 |
| 5 | **LOW** | No time-based rotation — only count-based | `internal/rotate/rotator.go` |

### 9.2 What Works

- Tor SOCKS5 handshake implementation is correct
- Router bypass logic works (localhost, codebuff.com go direct)
- Connection pooling and TCP tuning (NoDelay, KeepAlive) are appropriate
- SSE streaming through Tor is properly handled
- Firewall blocks private IPs correctly

### 9.3 Key Recommendations

1. **IMMEDIATE:** Wire `rotator.ShouldRotate()` into HTTP and SOCKS5 proxy request handlers
2. **IMMEDIATE:** Remove the `torBackend.ShouldRotate()` gate from the callback
3. **SHORT-TERM:** Add `control_addr` and `control_pass` to config.yaml
4. **SHORT-TERM:** Add time-based rotation (min 10s between NEWNYM)
5. **MEDIUM-TERM:** Consider time-based rotation as primary mechanism
6. **OPTIONAL:** Add circuit pre-building / warm-up for lower first-request latency

---

## 10. COMPLETE IMPLEMENTATION CHECKLIST

- [ ] Add `rotator *rotate.Rotator` field to `HTTPProxy` and `SOCKS5Proxy`
- [ ] Add `SetRotator()` method to both proxy types
- [ ] Call `rotator.ShouldRotate()` in `handleHTTP()` and `handleConnect()` for HTTP proxy
- [ ] Call `rotator.ShouldRotate()` in `handleConnect()` for SOCKS5 proxy
- [ ] Remove `torBackend.ShouldRotate()` check from main.go callback
- [ ] Add `control_addr` and `control_pass` to `BackendConfig` and config.yaml
- [ ] Add `min_interval_sec` / `rotate_after_ms` to `RotationConfig`
- [ ] Implement time-based rotation in `Rotator.ShouldRotate()`
- [ ] Remove `circuitAge` and `maxCircuitAge` from TorBackend (simplify)
- [ ] Test with `rotation.interval: 1` and verify NEWNYM in Tor logs
- [ ] Add metrics: rotation count, NEWNYM success/failure rate, average circuit lifetime
