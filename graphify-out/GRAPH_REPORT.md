# Graph Report - local-relay  (2026-08-23)

## Corpus Check
- 60 files · ~69,750 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1029 nodes · 1478 edges · 68 communities (48 shown, 20 thin omitted)
- Extraction: 94% EXTRACTED · 6% INFERRED · 0% AMBIGUOUS · INFERRED: 96 edges (avg confidence: 0.8)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `ce7dd1e5`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- CircuitPoolBackend
- TorBackend
- Config
- HTTPProxy
- SOCKS5Proxy
- TorLifecycle
- main
- Router
- 5. Proposed Architecture: Smart Rotation with Streaming Awareness
- MultiTorBackend
- Rotator
- ROUNDTABLE 02: RATE LIMIT ANALYSIS & BYPASS STRATEGY
- CopySSE
- ANALYST_04: Protocol Correctness Analysis
- 9router Integration for Model Selection
- Local Relay Configuration (config.yaml)
- Exhaustion Alert Script (exhaustion-alert.sh)
- github.com/local-relay/proxy
- ROUNDTABLE 05: Intelligent Model Routing & Quota Optimization
- Per-File Analysis
- ROUNDTABLE 04 — SRE/DevOps: Monitoring, Alerting & Automated Failover
- Per-File Analysis
- File-by-File Analysis
- File-by-File Analysis
- 6.2 Proposed Code Changes
- FILE-BY-FILE ANALYSIS
- 1. `internal/backend/tor.go` — Tor Backend
- 2. `internal/security/firewall.go` — Firewall & Rate Limiter
- 5. `internal/config/config.go` — Configuration
- 6. `cmd/relay/main.go` — Application Entry Point
- 7. `config.yaml` — Configuration File
- 3. `internal/auth/apikey.go` — API Key Authentication
- 4. `internal/log/redact.go` — Header & Body Redaction
- CROSS-CUTTING PRIVACY CONCERNS
- 4. ACTUAL IP DIVERSITY FROM TOR
- 1. CURRENT STATE: HOW ROTATION WORKS (AND WHY IT DOESN'T)
- ROUNDTABLE 01 — NETWORK ENGINEERING ANALYSIS
- 2. CRITICAL BUG: ROTATION IS COMPLETELY DEAD CODE
- 3. IS ROTATING EVERY 10 REQUESTS OPTIMAL?
- 5. HOW LONG UNTIL A NEW CIRCUIT GIVES A FRESH IP?
- 6. OPTIMAL ROTATION STRATEGY
- 7. TIMING CALCULATIONS
- 8. LATENCY IMPACT ANALYSIS
- 9. SUMMARY OF FINDINGS
- HTTPProxy
- Local Relay Auto-Fallback Timer
- Local Relay Health Monitor (local-relay-health.service)
- Systemd Installation Script (install-systemd.sh)
- Passive Exhaustion Detection Algorithm
- Weighted Round-Robin Model Rotation Algorithm
- ModelState Struct for Model Quota Tracking
- ModelQueue Priority Queue Implementation
- QuotaAllocator Struct for Dynamic Model Distribution
- main.go
- Implementation Order
- Rate Limit Benchmark Report
- MultiTorBackend
- Local Relay Proxy — Engineering Audit Report
- Tor Local Relay Proxy
- socks5_multisession_test.go
- graphify.md
- graphify.md
- analyze.sh
- loadtest.sh
- profile.sh
- run_all.sh
- benchmark

## God Nodes (most connected - your core abstractions)
1. `Config` - 33 edges
2. `CircuitPoolBackend` - 30 edges
3. `NewCircuitPoolBackend()` - 28 edges
4. `Finding-by-Finding Verification` - 27 edges
5. `TorLifecycle` - 24 edges
6. `TorInstance` - 23 edges
7. `SOCKS5Proxy` - 22 edges
8. `HTTPProxy` - 21 edges
9. `Rotator` - 20 edges
10. `Router` - 19 edges

## Surprising Connections (you probably didn't know these)
- `buildBackendStack()` --calls--> `NewMultiTorBackend()`  [INFERRED]
  cmd/relay/main.go → internal/backend/multitor.go
- `buildBackendStack()` --calls--> `NewCircuitPoolBackend()`  [INFERRED]
  cmd/relay/main.go → internal/backend/pool.go
- `buildBackendStack()` --calls--> `NewTorBackend()`  [INFERRED]
  cmd/relay/main.go → internal/backend/tor.go
- `buildBackendStack()` --calls--> `NewTorLifecycle()`  [INFERRED]
  cmd/relay/main.go → internal/backend/torlifecycle.go
- `buildRouter()` --calls--> `NewRouter()`  [INFERRED]
  cmd/relay/main.go → internal/backend/router.go

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Local Relay Systemd Service Ecosystem** — roundtable_04_ops_local_relay_systemd_units, roundtable_04_ops_exhaustion_alert_script, roundtable_04_ops_local_relay_health_monitor, roundtable_04_ops_local_relay_fallback_timer, roundtable_04_ops_systemd_install_script [EXTRACTED 0.95]
- **Model Routing Intelligence Components** — roundtable_05_model_routing_model_state, roundtable_05_model_routing_quota_allocator, roundtable_05_model_routing_priority_queue, roundtable_05_model_routing_model_rotation_algorithm, roundtable_05_model_routing_exhaustion_detection [INFERRED 0.85]

## Communities (68 total, 20 thin omitted)

### Community 0 - "CircuitPoolBackend"
Cohesion: 0.10
Nodes (17): CircuitPoolBackend, CircuitSlot, PoolConfig, pooledConn, pooledConnWrap, BenchmarkCryptoRandInt(), cryptoRandInt(), Bool (+9 more)

### Community 1 - "TorBackend"
Cohesion: 0.07
Nodes (32): DirectBackend, TorBackend, TorConfig, TorControlClient, BenchmarkAnomalyReporting(), BenchmarkBackendSelection(), BenchmarkBypassHostCheck(), BenchmarkCircuitSlotOperations() (+24 more)

### Community 2 - "Config"
Cohesion: 0.06
Nodes (48): APIKeyAuth, applyFlagOverrides(), authMiddlewareOrNil(), buildBackendStack(), buildProxies(), buildRotator(), buildRouter(), CancelFunc (+40 more)

### Community 3 - "HTTPProxy"
Cohesion: 0.09
Nodes (28): BenchmarkBufferPool(), BenchmarkConcurrentSOCKS5(), BenchmarkHeaderStripping(), BenchmarkResponseParsing(), BenchmarkSanitizeURL(), BenchmarkSOCKS5HandshakeServer(), BenchmarkTriggerRotateOnError(), B (+20 more)

### Community 4 - "SOCKS5Proxy"
Cohesion: 0.06
Nodes (34): BenchmarkAddBlockedRange(), BenchmarkDNSResolution(), BenchmarkSSRFBlocker(), BenchmarkSSRFBlockerBlocked(), BenchmarkSSRFBlockerConcurrent(), BenchmarkSSRFBlockerDNS(), BenchmarkSSRFBlockerIPv6(), B (+26 more)

### Community 5 - "TorLifecycle"
Cohesion: 0.12
Nodes (9): TorInstance, TorLifecycle, TorLifecycleConfig, Cmd, readCookieFile(), Context, RWMutex, Time (+1 more)

### Community 6 - "main"
Cohesion: 0.19
Nodes (11): HealthChecker, HealthServer, HealthStatus, SimpleHealthChecker, Logger, Request, ResponseWriter, Server (+3 more)

### Community 7 - "Router"
Cohesion: 0.03
Nodes (78): =============================================================================, 1. REQUEST LATENCY, =============================================================================, =============================================================================, 2. THROUGHPUT, =============================================================================, =============================================================================, 3. CONNECTIONS (+70 more)

### Community 8 - "5. Proposed Architecture: Smart Rotation with Streaming Awareness"
Cohesion: 0.05
Nodes (42): 1.1 Request Flow Architecture, 1.2 Connection State Machine, 1.3 Critical Finding: Rotator Is Disconnected From Request Path, 1.4 TorBackend Connection Details, 1. Connection Lifecycle Analysis, 2.1 Current State: No (But Only Because It's Broken), 2.2 If Rotation Were Integrated: The Danger Zones, 2.3 The Real Problem: Circuit Age Is a Lying Metric (+34 more)

### Community 9 - "MultiTorBackend"
Cohesion: 0.05
Nodes (37): #10 — Goroutine leak in ReportAnomaly (multitor.go:196), #11 — Rotator goroutine inconsistency (rotator.go:42-46 vs 71-77), #12 — r.URL.String() double-encoding (http.go:202), #13 — IPv6 SOCKS5 formatting (socks5.go:216-219), #14 — API key hardcoded in source (config.go:116), #15 — nil pointer in CheckHealth (torlifecycle.go:290), #16 — Headers copied after status code (http.go:262-277), #17 — Type assertion panic (http.go:275) (+29 more)

### Community 10 - "Rotator"
Cohesion: 0.14
Nodes (35): Conn, T, tcpPair(), TestDeadConn_DetectedOnWrite(), TestDeadConn_DetectedOnWrite_RST(), TestIsConnAlive_ClosedConn(), TestIsConnAlive_IdleHealthy(), TestIsConnAlive_NilConn() (+27 more)

### Community 11 - "ROUNDTABLE 02: RATE LIMIT ANALYSIS & BYPASS STRATEGY"
Cohesion: 0.05
Nodes (38): 10. LEGAL & ETHICAL CONSIDERATIONS, 1.1 OpenCode Zen Detection Mechanisms, 1.2 Blackbox AI Detection Mechanisms, 1.3 Generic Free LLM Provider Patterns, 1. PROVIDER DETECTION SIGNALS, 2.1 TLS Fingerprinting (JA3/JA4), 2.2 HTTP/2 Fingerprinting, 2.3 Behavior Pattern Analysis (+30 more)

### Community 12 - "CopySSE"
Cohesion: 0.09
Nodes (25): Closer, BenchmarkCopyRaw(), BenchmarkCopySSE(), BenchmarkHasSSEContentType(), BenchmarkRelay(), BenchmarkRelayConcurrent(), BenchmarkRelayThroughNet(), concurrencyName() (+17 more)

### Community 13 - "ANALYST_04: Protocol Correctness Analysis"
Cohesion: 0.06
Nodes (32): 1.1 RFC Compliance Check, 1.2 HTTP Forwarding (handleHTTP), 1.3 Edge Case Handling, 1. HTTP CONNECT Tunnel (internal/proxy/http.go), 2.1 RFC 1928 Compliance Check, 2.2 Edge Case Handling, 2. SOCKS5 Server (internal/proxy/socks5.go), 3.1 W3C EventSource Specification Compliance (+24 more)

### Community 18 - "ROUNDTABLE 05: Intelligent Model Routing & Quota Optimization"
Cohesion: 0.11
Nodes (15): AnomalyReporter, Backend, Router, Bool, Conn, Context, Int64, RWMutex (+7 more)

### Community 19 - "Per-File Analysis"
Cohesion: 0.07
Nodes (27): 10. internal/rotate/rotator.go, 11. internal/security/firewall.go, 12. internal/stream/sse.go, 13. config.yaml, 14. Makefile, 1. cmd/relay/main.go, 2. internal/auth/apikey.go, 3. internal/backend/router.go (+19 more)

### Community 20 - "ROUNDTABLE 04 — SRE/DevOps: Monitoring, Alerting & Automated Failover"
Cohesion: 0.07
Nodes (27): 1. Real-Time 429 Error Detection, 2. IP Rotation Effectiveness Monitoring, 3. Auto-Switch Models When Quota Is Hit, 4. Alert When All Models Are Exhausted, 5. Systemd Service with Auto-Restart, Log Rotation & Health Monitoring, Architecture Summary, Auto-Failover Script, Auto-Fallback Timer (+19 more)

### Community 21 - "Per-File Analysis"
Cohesion: 0.07
Nodes (26): 10. internal/rotate/rotator.go (60 lines), 11. internal/security/firewall.go (202 lines), 12. internal/stream/sse.go (149 lines), 1. cmd/relay/main.go (215 lines), 2. internal/auth/apikey.go (53 lines), 3. internal/backend/router.go (104 lines), 4. internal/backend/tor.go (258 lines), 5. internal/config/config.go (208 lines) (+18 more)

### Community 22 - "File-by-File Analysis"
Cohesion: 0.08
Nodes (24): 10. internal/rotate/rotator.go (60 lines) — Score: 8/10, 11. internal/security/firewall.go (202 lines) — Score: 7/10, 12. internal/stream/sse.go (149 lines) — Score: 7/10, 1. cmd/relay/main.go (215 lines) — Score: 7/10, 1. Data Race on `Router.bypassHosts` (router.go), 2. internal/auth/apikey.go (53 lines) — Score: 8/10, 2. `scanner.Err()` Never Checked (sse.go), 3. internal/backend/router.go (104 lines) — Score: 6/10 (+16 more)

### Community 23 - "File-by-File Analysis"
Cohesion: 0.09
Nodes (21): 10. internal/rotate/rotator.go (Score: 8/10), 11. internal/security/firewall.go (Score: 8/10), 12. internal/stream/sse.go (Score: 8/10), 1. cmd/relay/main.go (Score: 7/10), 2. internal/auth/apikey.go (Score: 8/10), 3. internal/backend/router.go (Score: 8/10), 4. internal/backend/tor.go (Score: 6/10), 5. internal/config/config.go (Score: 7/10) (+13 more)

### Community 24 - "6.2 Proposed Code Changes"
Cohesion: 0.29
Nodes (7): 6.2 Proposed Code Changes, Change 1: Wire the rotator into the request path, Change 2: Call rotator from request handlers, Change 3: Simplify the callback — remove double-gate, Change 4: Add time-based rotation to the Rotator, Change 5: Make Tor control port configurable, Change 6: Remove MaxCircuitAge gate entirely

### Community 25 - "FILE-BY-FILE ANALYSIS"
Cohesion: 0.33
Nodes (5): ANALYST_05 — PRIVACY & ANONYMITY ANALYSIS, EXECUTIVE SUMMARY, FILE-BY-FILE ANALYSIS, PRIVACY SCORE SUMMARY, TOP 10 RECOMMENDATIONS (PRIORITIZED)

### Community 26 - "1. `internal/backend/tor.go` — Tor Backend"
Cohesion: 0.33
Nodes (6): 1. `internal/backend/tor.go` — Tor Backend, (1) Traffic Analysis Resistance: MODERATE, (2) Metadata Leaked, (3) Bypass List Impact, (4) Header Redaction, (5) Privacy Score: **6/10**

### Community 27 - "2. `internal/security/firewall.go` — Firewall & Rate Limiter"
Cohesion: 0.33
Nodes (6): (1) Traffic Analysis Resistance: LOW, 2. `internal/security/firewall.go` — Firewall & Rate Limiter, (2) Metadata Leaked, (3) Bypass List Impact, (4) Header Redaction, (5) Privacy Score: **5/10**

### Community 28 - "5. `internal/config/config.go` — Configuration"
Cohesion: 0.33
Nodes (6): (1) Traffic Analysis Resistance: MODERATE, (2) Metadata Leaked, (3) Bypass List Impact, (4) Header Redaction, 5. `internal/config/config.go` — Configuration, (5) Privacy Score: **6/10**

### Community 29 - "6. `cmd/relay/main.go` — Application Entry Point"
Cohesion: 0.33
Nodes (6): (1) Traffic Analysis Resistance: MODERATE, (2) Metadata Leaked, (3) Bypass List Impact, (4) Header Redaction, (5) Privacy Score: **5/10**, 6. `cmd/relay/main.go` — Application Entry Point

### Community 30 - "7. `config.yaml` — Configuration File"
Cohesion: 0.33
Nodes (6): (1) Traffic Analysis Resistance: MODERATE, (2) Metadata Leaked, (3) Bypass List Impact — CRITICAL, (4) Header Redaction, (5) Privacy Score: **4/10**, 7. `config.yaml` — Configuration File

### Community 31 - "3. `internal/auth/apikey.go` — API Key Authentication"
Cohesion: 0.33
Nodes (6): (1) Traffic Analysis Resistance: N/A, (2) Metadata Leaked — CRITICAL ISSUES, (3) Bypass List Impact, 3. `internal/auth/apikey.go` — API Key Authentication, (4) Header Redaction, (5) Privacy Score: **4/10**

### Community 32 - "4. `internal/log/redact.go` — Header & Body Redaction"
Cohesion: 0.33
Nodes (6): (1) Traffic Analysis Resistance: N/A, (2) Metadata Leaked — SIGNIFICANT GAPS, (3) Bypass List Impact, (4) Header Redaction Completeness: **INCOMPLETE**, 4. `internal/log/redact.go` — Header & Body Redaction, (5) Privacy Score: **4/10**

### Community 33 - "CROSS-CUTTING PRIVACY CONCERNS"
Cohesion: 0.33
Nodes (6): A. The Bypass List Problem, B. API Key in URL, C. Incomplete Header Redaction, CROSS-CUTTING PRIVACY CONCERNS, D. Body Logging, E. No Stream Isolation

### Community 34 - "4. ACTUAL IP DIVERSITY FROM TOR"
Cohesion: 0.33
Nodes (6): 4.1 How Tor Circuit Selection Works, 4.2 IP Diversity Per Circuit, 4.3 Realistic Diversity Estimates, 4.4 The Guard Node Problem, 4.5 What Providers Actually Track, 4. ACTUAL IP DIVERSITY FROM TOR

### Community 35 - "1. CURRENT STATE: HOW ROTATION WORKS (AND WHY IT DOESN'T)"
Cohesion: 0.40
Nodes (5): 1.1 Architecture Overview, 1.2 The Rotator (`internal/rotate/rotator.go`), 1.3 The Tor Backend (`internal/backend/tor.go`), 1.4 The Callback Wiring (`cmd/relay/main.go`, lines 117-127), 1. CURRENT STATE: HOW ROTATION WORKS (AND WHY IT DOESN'T)

### Community 36 - "ROUNDTABLE 01 — NETWORK ENGINEERING ANALYSIS"
Cohesion: 0.50
Nodes (3): 10. COMPLETE IMPLEMENTATION CHECKLIST, ROUNDTABLE 01 — NETWORK ENGINEERING ANALYSIS, Tor Routing & IP Rotation Strategy

### Community 37 - "2. CRITICAL BUG: ROTATION IS COMPLETELY DEAD CODE"
Cohesion: 0.50
Nodes (4): 2.1 The Problem, 2.2 The Double-Gate Problem (Even If It Worked), 2.3 Additional Issue: Control Port Hardcoded, 2. CRITICAL BUG: ROTATION IS COMPLETELY DEAD CODE

### Community 38 - "3. IS ROTATING EVERY 10 REQUESTS OPTIMAL?"
Cohesion: 0.50
Nodes (4): 3.1 Analysis of Request Patterns, 3.2 Quota Consumption Estimate, 3.3 Optimal Rotation Frequency, 3. IS ROTATING EVERY 10 REQUESTS OPTIMAL?

### Community 39 - "5. HOW LONG UNTIL A NEW CIRCUIT GIVES A FRESH IP?"
Cohesion: 0.50
Nodes (4): 5.1 Tor Circuit Build Times, 5.2 NEWNYM Rate Limiting, 5.3 Realistic Timeline, 5. HOW LONG UNTIL A NEW CIRCUIT GIVES A FRESH IP?

### Community 40 - "6. OPTIMAL ROTATION STRATEGY"
Cohesion: 0.50
Nodes (4): 6.1 Recommended Configuration, 6.3 Updated Config, 6.4 Alternative: Time-Based Rotation (Recommended), 6. OPTIMAL ROTATION STRATEGY

### Community 41 - "7. TIMING CALCULATIONS"
Cohesion: 0.50
Nodes (4): 7.1 Scenario: Every-Request Rotation (Recommended), 7.2 Scenario: Every-10-Request Rotation (Current Config), 7.3 Scenario: Time-Based (10-second minimum), 7. TIMING CALCULATIONS

### Community 42 - "8. LATENCY IMPACT ANALYSIS"
Cohesion: 0.50
Nodes (4): 8.1 Current Latency (No Rotation — Broken), 8.2 With NEWNYM Rotation, 8.3 Mitigation: Pre-Build Circuits, 8. LATENCY IMPACT ANALYSIS

### Community 43 - "9. SUMMARY OF FINDINGS"
Cohesion: 0.50
Nodes (4): 9.1 Bugs Found, 9.2 What Works, 9.3 Key Recommendations, 9. SUMMARY OF FINDINGS

### Community 54 - "main.go"
Cohesion: 0.18
Nodes (24): BenchConfig, aggregateByTorCount(), checkIPCorrelation(), findBestConfig(), Client, Duration, Time, main() (+16 more)

### Community 56 - "Implementation Order"
Cohesion: 0.11
Nodes (17): Benchmark & Profiling Implementation Plan, Decision Framework, Expected Hotspots (Hypotheses — To Be Measured), Files to Create, Implementation Order, Phase 1: Setup (30 minutes), Phase 2: CPU Profiling (1 hour), Phase 3: Memory Profiling (1 hour) (+9 more)

### Community 57 - "Rate Limit Benchmark Report"
Cohesion: 0.12
Nodes (16): 3-tor-http-c1 (mode=http_proxy, concurrency=1), Are limits tied to exit IP?, Are limits tied to the API key?, Best Configuration, Bottleneck, Detailed Results, Does increasing Tor instances increase throughput?, Executive Summary (+8 more)

### Community 58 - "MultiTorBackend"
Cohesion: 0.11
Nodes (14): MultiTorBackend, Conn, Context, Dialer, Duration, Int64, RWMutex, NewMultiTorBackend() (+6 more)

### Community 59 - "Local Relay Proxy — Engineering Audit Report"
Cohesion: 0.15
Nodes (12): 1. Executive Summary, 2. Scores, 3. Issues Found, 4. Specification Compliance, 5. Top 20 Improvements, 6. Would I Approve This for Production?, 7. Would I Approve for Open-Source Release?, Local Relay Proxy — Engineering Audit Report (+4 more)

### Community 60 - "Tor Local Relay Proxy"
Cohesion: 0.17
Nodes (11): 1. Build, 2. Run, 3. Test, 🛠️ CLI Flags, Direct Relay Header Mode, 🔌 Integration, ⚡ Key Features, 🚀 Quick Start (+3 more)

### Community 61 - "socks5_multisession_test.go"
Cohesion: 0.48
Nodes (6): Conn, T, socks5Connect(), TestTorSOCKS5_MultiSessionOnSameTCPConnection(), TestTorSOCKS5_MultiSessionThreeRounds(), truncate()

## Knowledge Gaps
- **449 isolated node(s):** `analyze.sh script`, `loadtest.sh script`, `profile.sh script`, `run_all.sh script`, `benchmark` (+444 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **20 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `backendStack` connect `Config` to `CircuitPoolBackend`, `TorBackend`, `SOCKS5Proxy`, `TorLifecycle`, `MultiTorBackend`?**
  _High betweenness centrality (0.056) - this node is a cross-community bridge._
- **Why does `SOCKS5Proxy` connect `ROUNDTABLE 05: Intelligent Model Routing & Quota Optimization` to `Config`, `SOCKS5Proxy`?**
  _High betweenness centrality (0.036) - this node is a cross-community bridge._
- **Why does `NewCircuitPoolBackend()` connect `Rotator` to `CircuitPoolBackend`, `TorBackend`, `Config`, `MultiTorBackend`?**
  _High betweenness centrality (0.034) - this node is a cross-community bridge._
- **Are the 24 inferred relationships involving `NewCircuitPoolBackend()` (e.g. with `buildBackendStack()` and `TestPool_DeadConnDiscarded()`) actually correct?**
  _`NewCircuitPoolBackend()` has 24 INFERRED edges - model-reasoned connections that need verification._
- **What connects `analyze.sh script`, `loadtest.sh script`, `profile.sh script` to the rest of the system?**
  _449 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `CircuitPoolBackend` be split into smaller, more focused modules?**
  _Cohesion score 0.09725158562367865 - nodes in this community are weakly interconnected._
- **Should `TorBackend` be split into smaller, more focused modules?**
  _Cohesion score 0.07493061979648474 - nodes in this community are weakly interconnected._