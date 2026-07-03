# Graph Report - local-relay  (2026-07-03)

## Corpus Check
- 31 files · ~49,402 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 671 nodes · 866 edges · 54 communities (41 shown, 13 thin omitted)
- Extraction: 96% EXTRACTED · 4% INFERRED · 0% AMBIGUOUS · INFERRED: 32 edges (avg confidence: 0.8)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `eab094bd`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- [[_COMMUNITY_CircuitPoolBackend|CircuitPoolBackend]]
- [[_COMMUNITY_TorBackend|TorBackend]]
- [[_COMMUNITY_Config|Config]]
- [[_COMMUNITY_HTTPProxy|HTTPProxy]]
- [[_COMMUNITY_SOCKS5Proxy|SOCKS5Proxy]]
- [[_COMMUNITY_TorLifecycle|TorLifecycle]]
- [[_COMMUNITY_main|main]]
- [[_COMMUNITY_Router|Router]]
- [[_COMMUNITY_5. Proposed Architecture Smart Rotation with Streaming Awareness|5. Proposed Architecture: Smart Rotation with Streaming Awareness]]
- [[_COMMUNITY_MultiTorBackend|MultiTorBackend]]
- [[_COMMUNITY_Rotator|Rotator]]
- [[_COMMUNITY_ROUNDTABLE 02 RATE LIMIT ANALYSIS & BYPASS STRATEGY|ROUNDTABLE 02: RATE LIMIT ANALYSIS & BYPASS STRATEGY]]
- [[_COMMUNITY_CopySSE|CopySSE]]
- [[_COMMUNITY_ANALYST_04 Protocol Correctness Analysis|ANALYST_04: Protocol Correctness Analysis]]
- [[_COMMUNITY_9router Integration for Model Selection|9router Integration for Model Selection]]
- [[_COMMUNITY_Local Relay Configuration (config.yaml)|Local Relay Configuration (config.yaml)]]
- [[_COMMUNITY_Exhaustion Alert Script (exhaustion-alert.sh)|Exhaustion Alert Script (exhaustion-alert.sh)]]
- [[_COMMUNITY_github.comlocal-relayproxy|github.com/local-relay/proxy]]
- [[_COMMUNITY_ROUNDTABLE 05 Intelligent Model Routing & Quota Optimization|ROUNDTABLE 05: Intelligent Model Routing & Quota Optimization]]
- [[_COMMUNITY_Per-File Analysis|Per-File Analysis]]
- [[_COMMUNITY_ROUNDTABLE 04 — SREDevOps Monitoring, Alerting & Automated Failover|ROUNDTABLE 04 — SRE/DevOps: Monitoring, Alerting & Automated Failover]]
- [[_COMMUNITY_Per-File Analysis|Per-File Analysis]]
- [[_COMMUNITY_File-by-File Analysis|File-by-File Analysis]]
- [[_COMMUNITY_File-by-File Analysis|File-by-File Analysis]]
- [[_COMMUNITY_6.2 Proposed Code Changes|6.2 Proposed Code Changes]]
- [[_COMMUNITY_FILE-BY-FILE ANALYSIS|FILE-BY-FILE ANALYSIS]]
- [[_COMMUNITY_1. `internalbackendtor.go` — Tor Backend|1. `internal/backend/tor.go` — Tor Backend]]
- [[_COMMUNITY_2. `internalsecurityfirewall.go` — Firewall & Rate Limiter|2. `internal/security/firewall.go` — Firewall & Rate Limiter]]
- [[_COMMUNITY_5. `internalconfigconfig.go` — Configuration|5. `internal/config/config.go` — Configuration]]
- [[_COMMUNITY_6. `cmdrelaymain.go` — Application Entry Point|6. `cmd/relay/main.go` — Application Entry Point]]
- [[_COMMUNITY_7. `config.yaml` — Configuration File|7. `config.yaml` — Configuration File]]
- [[_COMMUNITY_3. `internalauthapikey.go` — API Key Authentication|3. `internal/auth/apikey.go` — API Key Authentication]]
- [[_COMMUNITY_4. `internallogredact.go` — Header & Body Redaction|4. `internal/log/redact.go` — Header & Body Redaction]]
- [[_COMMUNITY_CROSS-CUTTING PRIVACY CONCERNS|CROSS-CUTTING PRIVACY CONCERNS]]
- [[_COMMUNITY_4. ACTUAL IP DIVERSITY FROM TOR|4. ACTUAL IP DIVERSITY FROM TOR]]
- [[_COMMUNITY_1. CURRENT STATE HOW ROTATION WORKS (AND WHY IT DOESN'T)|1. CURRENT STATE: HOW ROTATION WORKS (AND WHY IT DOESN'T)]]
- [[_COMMUNITY_ROUNDTABLE 01 — NETWORK ENGINEERING ANALYSIS|ROUNDTABLE 01 — NETWORK ENGINEERING ANALYSIS]]
- [[_COMMUNITY_2. CRITICAL BUG ROTATION IS COMPLETELY DEAD CODE|2. CRITICAL BUG: ROTATION IS COMPLETELY DEAD CODE]]
- [[_COMMUNITY_3. IS ROTATING EVERY 10 REQUESTS OPTIMAL|3. IS ROTATING EVERY 10 REQUESTS OPTIMAL?]]
- [[_COMMUNITY_5. HOW LONG UNTIL A NEW CIRCUIT GIVES A FRESH IP|5. HOW LONG UNTIL A NEW CIRCUIT GIVES A FRESH IP?]]
- [[_COMMUNITY_6. OPTIMAL ROTATION STRATEGY|6. OPTIMAL ROTATION STRATEGY]]
- [[_COMMUNITY_7. TIMING CALCULATIONS|7. TIMING CALCULATIONS]]
- [[_COMMUNITY_8. LATENCY IMPACT ANALYSIS|8. LATENCY IMPACT ANALYSIS]]
- [[_COMMUNITY_9. SUMMARY OF FINDINGS|9. SUMMARY OF FINDINGS]]
- [[_COMMUNITY_HTTPProxy|HTTPProxy]]
- [[_COMMUNITY_Local Relay Auto-Fallback Timer|Local Relay Auto-Fallback Timer]]
- [[_COMMUNITY_Local Relay Health Monitor (local-relay-health.service)|Local Relay Health Monitor (local-relay-health.service)]]
- [[_COMMUNITY_Systemd Installation Script (install-systemd.sh)|Systemd Installation Script (install-systemd.sh)]]
- [[_COMMUNITY_Passive Exhaustion Detection Algorithm|Passive Exhaustion Detection Algorithm]]
- [[_COMMUNITY_Weighted Round-Robin Model Rotation Algorithm|Weighted Round-Robin Model Rotation Algorithm]]
- [[_COMMUNITY_ModelState Struct for Model Quota Tracking|ModelState Struct for Model Quota Tracking]]
- [[_COMMUNITY_ModelQueue Priority Queue Implementation|ModelQueue Priority Queue Implementation]]
- [[_COMMUNITY_QuotaAllocator Struct for Dynamic Model Distribution|QuotaAllocator Struct for Dynamic Model Distribution]]

## God Nodes (most connected - your core abstractions)
1. `Config` - 23 edges
2. `CircuitPoolBackend` - 22 edges
3. `SOCKS5Proxy` - 19 edges
4. `HTTPProxy` - 18 edges
5. `main()` - 17 edges
6. `Router` - 16 edges
7. `TorLifecycle` - 16 edges
8. `Rotator` - 16 edges
9. `Per-File Analysis` - 15 edges
10. `TorInstance` - 14 edges

## Surprising Connections (you probably didn't know these)
- `main()` --calls--> `NewAPIKeyAuth()`  [INFERRED]
  cmd/relay/main.go → internal/auth/apikey.go
- `main()` --calls--> `NewMultiTorBackend()`  [INFERRED]
  cmd/relay/main.go → internal/backend/multitor.go
- `main()` --calls--> `NewCircuitPoolBackend()`  [INFERRED]
  cmd/relay/main.go → internal/backend/pool.go
- `main()` --calls--> `NewRouter()`  [INFERRED]
  cmd/relay/main.go → internal/backend/router.go
- `main()` --calls--> `NewDirectBackend()`  [INFERRED]
  cmd/relay/main.go → internal/backend/tor.go

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Local Relay Systemd Service Ecosystem** — roundtable_04_ops_local_relay_systemd_units, roundtable_04_ops_exhaustion_alert_script, roundtable_04_ops_local_relay_health_monitor, roundtable_04_ops_local_relay_fallback_timer, roundtable_04_ops_systemd_install_script [EXTRACTED 0.95]
- **Model Routing Intelligence Components** — roundtable_05_model_routing_model_state, roundtable_05_model_routing_quota_allocator, roundtable_05_model_routing_priority_queue, roundtable_05_model_routing_model_rotation_algorithm, roundtable_05_model_routing_exhaustion_detection [INFERRED 0.85]

## Communities (54 total, 13 thin omitted)

### Community 0 - "CircuitPoolBackend"
Cohesion: 0.10
Nodes (22): CircuitPoolBackend, CircuitSlot, PoolConfig, cryptoRandInt(), Conn, Context, Dialer, Duration (+14 more)

### Community 1 - "TorBackend"
Cohesion: 0.13
Nodes (13): DirectBackend, TorBackend, TorConfig, Conn, TuneTCP(), Conn, Context, Dialer (+5 more)

### Community 2 - "Config"
Cohesion: 0.13
Nodes (18): AuthConfig, BackendConfig, BypassConfig, Config, HealthConfig, LoggingConfig, MetricsConfig, MultiTorConfig (+10 more)

### Community 3 - "HTTPProxy"
Cohesion: 0.07
Nodes (30): APIKeyAuth, Client, Request, ResponseWriter, NewAPIKeyAuth(), Context, Logger, HTTPProxy (+22 more)

### Community 4 - "SOCKS5Proxy"
Cohesion: 0.15
Nodes (11): Conn, IP, Logger, NewSOCKS5Proxy(), IP, IPNet, NewSSRFBlocker(), Listener (+3 more)

### Community 5 - "TorLifecycle"
Cohesion: 0.16
Nodes (8): TorInstance, TorLifecycle, TorLifecycleConfig, Cmd, Context, RWMutex, Time, NewTorLifecycle()

### Community 6 - "main"
Cohesion: 0.15
Nodes (14): Logger, main(), setupLogger(), HealthChecker, HealthServer, HealthStatus, SimpleHealthChecker, Logger (+6 more)

### Community 7 - "Router"
Cohesion: 0.17
Nodes (8): AnomalyReporter, Backend, Router, Conn, Context, Int64, RWMutex, NewRouter()

### Community 8 - "5. Proposed Architecture: Smart Rotation with Streaming Awareness"
Cohesion: 0.05
Nodes (42): 1.1 Request Flow Architecture, 1.2 Connection State Machine, 1.3 Critical Finding: Rotator Is Disconnected From Request Path, 1.4 TorBackend Connection Details, 1. Connection Lifecycle Analysis, 2.1 Current State: No (But Only Because It's Broken), 2.2 If Rotation Were Integrated: The Danger Zones, 2.3 The Real Problem: Circuit Age Is a Lying Metric (+34 more)

### Community 9 - "MultiTorBackend"
Cohesion: 0.17
Nodes (8): MultiTorBackend, Conn, Context, Dialer, Duration, Int64, RWMutex, NewMultiTorBackend()

### Community 10 - "Rotator"
Cohesion: 0.18
Nodes (6): Int64, Logger, NewRotator(), Rotator, Uint64, WaitGroup

### Community 11 - "ROUNDTABLE 02: RATE LIMIT ANALYSIS & BYPASS STRATEGY"
Cohesion: 0.05
Nodes (38): 10. LEGAL & ETHICAL CONSIDERATIONS, 1.1 OpenCode Zen Detection Mechanisms, 1.2 Blackbox AI Detection Mechanisms, 1.3 Generic Free LLM Provider Patterns, 1. PROVIDER DETECTION SIGNALS, 2.1 TLS Fingerprinting (JA3/JA4), 2.2 HTTP/2 Fingerprinting, 2.3 Behavior Pattern Analysis (+30 more)

### Community 12 - "CopySSE"
Cohesion: 0.24
Nodes (10): Header, CopyRaw(), CopySSE(), Context, ResponseWriter, HasSSEContentType(), Relay(), ReadCloser (+2 more)

### Community 13 - "ANALYST_04: Protocol Correctness Analysis"
Cohesion: 0.06
Nodes (32): 1.1 RFC Compliance Check, 1.2 HTTP Forwarding (handleHTTP), 1.3 Edge Case Handling, 1. HTTP CONNECT Tunnel (internal/proxy/http.go), 2.1 RFC 1928 Compliance Check, 2.2 Edge Case Handling, 2. SOCKS5 Server (internal/proxy/socks5.go), 3.1 W3C EventSource Specification Compliance (+24 more)

### Community 18 - "ROUNDTABLE 05: Intelligent Model Routing & Quota Optimization"
Cohesion: 0.06
Nodes (32): 10. Summary, 1.1 Current Provider/Model Inventory (from 9router database), 1.2 Observed Rate Limits (from usage data + error patterns), 1.3 Error Signatures (what 429 looks like per provider), 1. Model Quota Map — Limits, Resets, and Rate Limit Behavior, 2.1 Core Principle: Round-Robin with Weighted Fair Queuing, 2.2 Rotation Strategy: Two-Tier Rotation, 2.3 Implementation: Go struct for model state (+24 more)

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

## Knowledge Gaps
- **312 isolated node(s):** `github.com/local-relay/proxy`, `AnomalyReporter`, `HealthStatus`, `HTTPProxy`, `Executive Summary` (+307 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **13 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `main()` connect `main` to `CircuitPoolBackend`, `TorBackend`, `Config`, `HTTPProxy`, `SOCKS5Proxy`, `TorLifecycle`, `Router`, `MultiTorBackend`, `Rotator`?**
  _High betweenness centrality (0.101) - this node is a cross-community bridge._
- **Why does `NewCircuitPoolBackend()` connect `CircuitPoolBackend` to `main`?**
  _High betweenness centrality (0.036) - this node is a cross-community bridge._
- **Why does `NewHTTPProxy()` connect `HTTPProxy` to `Rotator`, `SOCKS5Proxy`, `main`, `Router`?**
  _High betweenness centrality (0.029) - this node is a cross-community bridge._
- **Are the 15 inferred relationships involving `main()` (e.g. with `NewAPIKeyAuth()` and `NewMultiTorBackend()`) actually correct?**
  _`main()` has 15 INFERRED edges - model-reasoned connections that need verification._
- **What connects `github.com/local-relay/proxy`, `AnomalyReporter`, `HealthStatus` to the rest of the system?**
  _312 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `CircuitPoolBackend` be split into smaller, more focused modules?**
  _Cohesion score 0.09855072463768116 - nodes in this community are weakly interconnected._
- **Should `TorBackend` be split into smaller, more focused modules?**
  _Cohesion score 0.13 - nodes in this community are weakly interconnected._