# Local Relay — Original Requirements → Verification Checklist

**Task:** `t_169f8821` (extract requirements into a verifiable checklist)
**Date:** 2026-11-25
**Scope:** Requirements extraction **only**. No application code was modified. Compliance status is deliberately **NOT ASSESSED** here — that is the job of the implementation/verification workers that consume this checklist.

---

## 0. How to use this document

Each requirement has: a stable **ID**, a **modality** (MUST / SHOULD / MAY / RECOMMENDATION), **acceptance criteria** written as observable checks, **constraints**, one or more **source citations** (`file:line` or `git <sha>`), and **verification hints** (existing tests or commands). A worker verifying compliance must reproduce the acceptance criteria with real commands and record the output — an item is not "verified" because the code appears to contain it.

**Source authority tiers** (used when requirements disagree — see §9 Conflicts):

| Tier | Sources | Use |
|---|---|---|
| **T1 — Contract** | `README.md`, `config.yaml`, service units, `Makefile` | Current documented promise to the operator. Highest authority for runtime defaults and endpoints. |
| **T1 — Original design** | `ROUNDTABLE_0*.md`, `ANALYST_0*.md` (all first committed at `1350b53`, 2026-07-03) | Original specification as recorded in the initial commit. Highest authority for intent and protocol/RFC obligations. |
| **T2 — Verification record** | `ENGINEERING_AUDIT.md`, `AUDIT_VERIFICATION.md`, `bench/metrics_schema.md`, tests, git history | Evidence of what was required/fixed and what is actually emitted. Lower authority than T1 when they conflict. |
| **T3 — Recommendations** | "Recommendations", "Priority Matrix", "Implementation Roadmap" sections, all of `ROUNDTABLE_05_MODEL_ROUTING.md` | **Not obligations.** Only becomes a requirement if adopted in T1 or a later commit. Never convert a T3 "consider/optional" into a MUST. |

**Source inventory (searched, with first-seen commit):**

| Source | Lines | First commit | Role |
|---|---|---|---|
| `README.md` | 163 | `bab7e55` (2026-07-03) | T1 contract: architecture, config reference, CLI, endpoints |
| `config.yaml` | 93 | `1350b53` | T1 effective production configuration |
| `ROUNDTABLE_01_NETWORK.md` | 595 | `1350b53` | T1 rotation strategy, implementation checklist |
| `ROUNDTABLE_02_RATE_LIMIT.md` | 444 | `1350b53` | T1 rate-limit analysis + T3 evasion roadmap |
| `ROUNDTABLE_03_ARCHITECTURE.md` | 1519 | `1350b53` | T1 lifecycle/streaming design, T3 proposed circuit pool |
| `ROUNDTABLE_04_OPS.md` | 978 | `1350b53` | T1 ops deployment + OOS 9router/ops scripts |
| `ROUNDTABLE_05_MODEL_ROUTING.md` | 1164 | `1350b53` | OOS — 9router model routing (see `OOS-001`) |
| `ANALYST_01_SECURITY.md` … `ANALYST_06_PERFORMANCE.md` | 395/383/346/328/363/397 | `1350b53` | T1 protocol/RFC compliance tables + T3 recommendations |
| `ENGINEERING_AUDIT.md` | 137 | `bab7e55` | T2 spec-compliance table, 30 findings |
| `AUDIT_VERIFICATION.md` | 398 | `bab7e55` | T2 finding validation (confirmed / false positive / design choice) |
| `bench/metrics_schema.md` | 79 | `67e1a24` | T2 authoritative metrics schema (implemented vs planned) |
| `local-relay.service`, `tor-local.service` | 20/18 | `67e1a24` / `1350b53` | T1 deployment contract |
| `Makefile` | 35 | `1350b53` | T1 build/test contract |
| 71 `*_test.go` files | 238 tests | throughout history | T2 executable requirements |
| git history | 40+ commits | `1350b53` → `1ec78f4` | requirement evolution |

**No issue files** (`.md` issue templates, `ISSUES*`, etc.) exist in any revision: verified by enumerating all paths ever tracked (`git log --all --name-only`).

---

## 1. Proxy protocols & request handling

### R-001 · HTTP forward/CONNECT listener — MUST
- **Requirement:** Serve an HTTP forward/CONNECT proxy on `server.http`, default `127.0.0.1:18080`.
- **Accept:** `./relay -c config.yaml` starts a listener on `127.0.0.1:18080`; `curl -x http://127.0.0.1:18080 https://api.ipify.org` returns a public IP; `curl -H "x-target-url: http://api.ipify.org/" http://127.0.0.1:18080/` returns a body.
- **Constraints:** Loopback bind by default; non-loopback bind requires `auth.enabled: true` (see `R-047`).
- **Source:** `README.md:13`, `README.md:101`, `README.md:73-76`; `config.yaml:2`; `internal/config/defaults.go:9`.
- **Verify:** `curl` commands above; `internal/proxy/http_test.go`, `internal/proxy/http_pin_test.go`.

### R-002 · SOCKS5 listener — MUST
- **Requirement:** Serve a SOCKS5 (RFC 1928) proxy on `server.socks5`, default `127.0.0.1:11080`.
- **Accept:** `curl --socks5-hostname 127.0.0.1:11080 https://api.ipify.org` returns a public IP.
- **Constraints:** Same bind/auth constraint as R-001. `server.http` and `server.socks5` must not use the same address.
- **Source:** `README.md:14`, `README.md:79`, `README.md:102`; `config.yaml:3`; `internal/config/validate.go:38-40`; `ANALYST_04_PROTOCOL.md:80-93`.
- **Verify:** `internal/proxy/socks5_fix_test.go`, `internal/proxy/socks5_regression_test.go`, `internal/transport/socks5_test.go`.

### R-003 · CONNECT tunnel establishment — MUST
- **Requirement:** On `CONNECT host:port`, reply `200 OK` then hijack the connection and relay bytes bidirectionally (RFC 2817 / RFC 7231 §4.3.6).
- **Accept:** A CONNECT client receives exactly `HTTP/1.1 200 Connection Established` before any tunneled bytes; HTTPS through the proxy succeeds; both directions close cleanly (`CloseWrite` on each half).
- **Constraints:** Hijack failure must return 500 and close the upstream connection; connection failure must return 502.
- **Source:** `ANALYST_04_PROTOCOL.md:26-34`, `ANALYST_04_PROTOCOL.md:66-70`; `README.md:73`; `ENGINEERING_AUDIT.md:87`.
- **Verify:** `internal/stream/stream_test.go` (`TestRelay_Bidirectional`, `TestRelay_ContextCancelUnblocks`), `internal/proxy/http_test.go`.

### R-004 · CONNECT request-target parsing — MUST
- **Requirement:** Accept `CONNECT host:port`; if the client omits the port, default to `:443`.
- **Accept:** `CONNECT example.com` and `CONNECT example.com:443` both establish a tunnel to port 443.
- **Constraints:** Documented as "reasonable default, not an RFC violation" — do not reject portless CONNECT.
- **Source:** `ANALYST_04_PROTOCOL.md:31`, `ANALYST_04_PROTOCOL.md:44`.
- **Verify:** Manual CONNECT with `curl -v -x`.

### R-005 · HTTP forwarding (absolute-form / header mode) — MUST
- **Requirement:** Forward absolute-form HTTP requests, including the `x-target-url` header mode documented in the README.
- **Accept:** `curl -H "x-target-url: http://api.ipify.org/" http://127.0.0.1:18080/` returns the upstream body; empty host is rejected.
- **Constraints:** Clone request headers, remove `Proxy-Connection` / `Proxy-Authorization` before forwarding.
- **Source:** `README.md:75-76`; `ANALYST_04_PROTOCOL.md:48-56`; `ENGINEERING_AUDIT.md:87`.
- **Verify:** `internal/proxy/proxy_high_fixes_test.go`, `internal/proxy/http_pin_test.go`.

### R-006 · Proxy error responses — MUST
- **Requirement:** Return 502 on upstream connect failure, 500 on hijack failure.
- **Accept:** Pointing `backend.address` at a closed port yields 502 for HTTP forward; a forced hijack failure yields 500 and closes the upstream socket.
- **Source:** `ANALYST_04_PROTOCOL.md:66-67`.
- **Verify:** `internal/proxy/http_test.go`.

### R-007 · 407 Proxy Authentication Required — MUST (RFC), GAP
- **Requirement:** When `auth.enabled: true` and credentials are missing/invalid on the HTTP proxy, respond `407` with a `Proxy-Authenticate` header instead of silently dropping the connection.
- **Accept:** `curl -x http://127.0.0.1:18080 ...` without credentials receives `407` and a `Proxy-Authenticate` header; with valid key the request succeeds.
- **Constraints:** Current code silently returns (identified as a real RFC violation).
- **Source:** `ANALYST_04_PROTOCOL.md:40` (MODERATE issue #2), `ANALYST_04_PROTOCOL.md:317` (HIGH PRIORITY #3).
- **Verify:** No known existing test — add/adjust a handler test.

### R-008 · SOCKS5 version & method negotiation — MUST
- **Requirement:** Validate version `0x05`; select an authentication method from the methods the client offers (RFC 1928).
- **Accept:** Greeting with only `0x02` does not receive `0x05,0x00` unless username/password auth is enabled; greeting with unsupported versions is rejected.
- **Constraints:** Always replying `0x00` is flagged as a technical violation when the client did not offer it.
- **Source:** `ANALYST_04_PROTOCOL.md:84-85`, `ANALYST_04_PROTOCOL.md:104`; `ENGINEERING_AUDIT.md:36`; `AUDIT_VERIFICATION.md:30-48` (related SOCKS5 wiring gap).
- **Verify:** `internal/proxy/socks5_regression_test.go`.

### R-009 · SOCKS5 address types — MUST
- **Requirement:** Support IPv4 (`0x01`), domain (`0x03`) and IPv6 (`0x04`) request address types; support CONNECT (`0x01`); reject UDP ASSOCIATE (`0x03`) with `0x07`.
- **Accept:** `curl --socks5-hostname` with an IPv4 literal, a hostname and an IPv6 literal each reach the target; UDP ASSOCIATE returns `0x07`.
- **Constraints:** BIND (`0x02`) is not implemented and returns `0x07` — see `R-011`.
- **Source:** `ANALYST_04_PROTOCOL.md:87-93`, `ANALYST_04_PROTOCOL.md:116-120`; `README.md:79`.
- **Verify:** `internal/proxy/socks5_fix_test.go`, `internal/transport/socks5_test.go`.

### R-010 · SOCKS5 IPv6 address formatting — MUST, GAP
- **Requirement:** Format IPv6 targets as a valid bracketed literal, e.g. `[fe80::1]:80`.
- **Accept:** An IPv6 SOCKS5 CONNECT succeeds; the formatted target is not the `%x`-generated `[fe800000:0000...]`.
- **Constraints:** Must use `net.IP(addr).String()` (or equivalent canonical formatting).
- **Source:** `ANALYST_04_PROTOCOL.md:97-102`, `ANALYST_04_PROTOCOL.md:316`; `ENGINEERING_AUDIT.md:52` (#13); `AUDIT_VERIFICATION.md:172-185` (Confirmed, HIGH).
- **Verify:** No existing IPv6 formatting test — add one.

### R-011 · SOCKS5 BIND command — MAY (explicitly low priority)
- **Requirement:** RFC 1928 BIND is part of the protocol but is **not** required for this relay's documented use cases; current behavior is a correct `0x07` rejection.
- **Accept:** BIND returns `0x07` (command not supported) and does not crash.
- **Source:** `ANALYST_04_PROTOCOL.md:93`, `ANALYST_04_PROTOCOL.md:108`, `ANALYST_04_PROTOCOL.md:326`.
- **Note:** Do NOT treat this as a compliance blocker — it is explicitly LOW PRIORITY.

### R-012 · SOCKS5 reply format — MUST
- **Requirement:** Reply `0x05, status, 0x00, bindIP, port` with correct address-type byte (patch to `0x04` for IPv6 local address).
- **Accept:** Reply bytes parse correctly for IPv4 and IPv6 upstream sockets; failure codes: `0x05` connect refused, `0x02` firewall blocked, `0x01` general failure, `0x07` unsupported.
- **Source:** `ANALYST_04_PROTOCOL.md:90`, `ANALYST_04_PROTOCOL.md:106`, `ANALYST_04_PROTOCOL.md:116-119`.
- **Verify:** `internal/proxy/socks5_fix_test.go`.

### R-013 · SOCKS5 authentication parity — MUST when `auth.enabled: true`, CONFLICTED
- **Requirement:** When API-key auth is enabled, SOCKS5 must also require credentials (README states `api_key` "also enables SOCKS5 user/pass").
- **Accept:** With `auth.enabled: true` and a key configured, an unauthenticated SOCKS5 CONNECT is rejected; `curl --socks5-hostname` with credentials succeeds.
- **Constraints:** Original analysts say no SOCKS5 auth exists at all; README says the feature exists. **See `X-003` — must be resolved by measurement before downstream "fixes".**
- **Source:** `README.md:130`; `ANALYST_01_SECURITY.md:345`, `ANALYST_01_SECURITY.md:360`; `ANALYST_03_INFRA.md:285`; `ANALYST_04_PROTOCOL.md:104`, `ANALYST_04_PROTOCOL.md:286`; `ANALYST_05_PRIVACY.md:357`.
- **Verify:** `internal/proxy/socks5_fix_test.go`, `internal/auth/multivalue_auth_test.go`.

### R-014 · CONNECT request-body draining — SHOULD
- **Requirement:** Drain an unexpected request body on CONNECT before hijacking so keep-alive framing is not corrupted (RFC 7231 CONNECT MUST NOT have a body).
- **Accept:** A CONNECT request carrying a body does not corrupt the next request on the connection.
- **Source:** `ANALYST_04_PROTOCOL.md:46` (MINOR), `ANALYST_04_PROTOCOL.md:323` (MEDIUM PRIORITY #7).

### R-015 · SSE detection — MUST
- **Requirement:** Detect `Content-Type: text/event-stream` on HTTP forward responses and use the SSE copy path.
- **Accept:** A response with that content type is streamed through `CopySSE`; other responses use raw copy; `internal/proxy/classify_test.go` and `TestHasSSEContentType` pass.
- **Source:** `README.md:5`, `README.md:47`; `ANALYST_04_PROTOCOL.md:55`; `ENGINEERING_AUDIT.md:92`.
- **Verify:** `internal/proxy/classify_test.go`, `internal/stream/stream_test.go` (`TestCopySSE`).

### R-016 · SSE response headers & immediate flush — MUST
- **Requirement:** Set `Content-Type: text/event-stream`, `Cache-Control: no-cache`, `Connection: keep-alive`; flush after each event.
- **Accept:** Header trio present on SSE responses; a client observes each event before the stream ends.
- **Source:** `ANALYST_04_PROTOCOL.md:134-139`; `ANALYST_06_PERFORMANCE.md:287` (flush-per-event is correct for SSE).
- **Verify:** `internal/stream/stream_test.go`.

### R-017 · SSE multi-line event integrity — MUST (W3C EventSource), GAP
- **Requirement:** Preserve complete SSE events including multiple `data:` lines, `event:`, `id:`, `retry:` fields and blank-line delimiters; do not emit one "event" per scanned line.
- **Accept:** A stream with `data: line1\ndata: line2\n\n` is relayed as one event with both data lines intact.
- **Constraints:** Current line-by-line `bufio.Scanner` approach is explicitly reported as breaking multi-line events; an alternative acceptable design is transparent raw-byte relay.
- **Source:** `ANALYST_04_PROTOCOL.md:151-155`, `ANALYST_04_PROTOCOL.md:189`, `ANALYST_04_PROTOCOL.md:315`; `ENGINEERING_AUDIT.md:69` (#25 partial), `ANALYST_04_PROTOCOL.md:303` (5/10).
- **Verify:** `internal/stream/stream_test.go` — extend with a multi-line event case.

### R-018 · Raw bidirectional relay — MUST
- **Requirement:** Relay raw bytes in both directions with half-close, context cancellation and cleanup of both connections; use pooled buffers.
- **Accept:** `TestRelay_Bidirectional` and `TestRelay_ContextCancelUnblocks` pass; both connections closed after wait.
- **Source:** `ANALYST_04_PROTOCOL.md:163-173`; `README.md:33`.
- **Verify:** `internal/stream/stream_test.go`.

### R-019 · Hop-by-hop header stripping on forwarded responses — MUST (RFC 7230 §6.1), GAP
- **Requirement:** Strip `Connection`, `Transfer-Encoding`, `TE`, `Upgrade` and other hop-by-hop headers from HTTP responses before writing to the client.
- **Accept:** An upstream response containing `Connection: close` does not leak that header to the client.
- **Source:** `ANALYST_04_PROTOCOL.md:60` (MODERATE), `ANALYST_04_PROTOCOL.md:320` (MEDIUM #4).
- **Verify:** No existing test found — add one.

### R-020 · CONNECT tunnel timeout — SHOULD, GAP
- **Requirement:** Bound the lifetime of a CONNECT relay so a stalled peer cannot hold a goroutine forever (the existing 2 s timer only checks initial tunnel health).
- **Accept:** A tunnel with one side stalled is eventually torn down; shutdown does not hang waiting for it.
- **Source:** `ENGINEERING_AUDIT.md:66` (#22, HIGH), `AUDIT_VERIFICATION.md:259-266` (Confirmed HIGH); `ANALYST_05_PRIVACY.md` (n/a); `ANALYST_06_PERFORMANCE.md:391` (LOW #10).
- **Note:** **Constraint conflict:** a timeout can break legitimate long-lived SSE tunnels — resolution must exempt established SSE streams (see `R-033`).

---

## 2. Tor routing, rotation & exit-IP behavior

### R-021 · Multi-Tor managed instances — MUST (preferred mode)
- **Requirement:** Manage N isolated Tor daemons (`multi_tor.enabled: true`, `max_instances: 3` in production config), each with its own SOCKS and control port.
- **Accept:** Starting the relay spawns 3 Tor processes; ports are `base_port … base_port+N-1` (9150–9152) and `control_base … control_base+N-1` (9160–9162).
- **Constraints:** `multi_tor.binary` must be non-empty, resolvable via `exec.LookPath`, `max_instances >= 1`.
- **Source:** `README.md:16-19`, `README.md:104-111`; `config.yaml:5-14`; `internal/config/validate.go:43-53`; `internal/config/defaults.go:20-28`.
- **Verify:** `internal/backend/tor_health_test.go`, `cmd/relay/lifecycle_test.go`.

### R-022 · Per-instance circuit isolation & round-robin — MUST
- **Requirement:** Rotate across healthy Tor instances in round-robin order; each instance owns an isolated circuit.
- **Accept:** Consecutive dials distribute across healthy instances; an unhealthy instance is skipped; with zero healthy instances the router fails closed.
- **Source:** `README.md:16`, `README.md:23-24`; `ANALYST_04_PROTOCOL.md:250-253`; `internal/backend/multitor.go` (selection).
- **Verify:** `internal/backend/select_test.go`, `internal/backend/multitor_inflight_test.go`, `internal/backend/router_bypass_test.go`.

### R-023 · Fail-closed routing — MUST
- **Requirement:** If no proxy backend is healthy, traffic is blocked — never leaked outside Tor via a direct fallback.
- **Accept:** With all Tor instances marked unhealthy, a proxy request returns an error/degraded response instead of a direct connection.
- **Constraints:** Bypass hosts are an explicit exception (see `R-025`); the precise semantics are ambiguous — see `A-003`.
- **Source:** `README.md:23-24`; `git 078521c` "fail-closed enforcement"; `internal/backend/select.go`/`router.go` (`TestSelect_EmptyReadyFailsClosed`).
- **Verify:** `TestSelect_EmptyReadyFailsClosed`, `TestRouterIsHealthyGatesDegradedReady`.

### R-024 · Bypass hosts go direct — MUST
- **Requirement:** `localhost`, `127.0.0.1`, `codebuff.com`, `www.codebuff.com`, `api.codebuff.com` are routed DIRECT, never through Tor.
- **Accept:** A request to `codebuff.com` uses the direct backend; a request to a non-bypass host uses Tor; suffix matching works at all depths (`x.codebuff.com`).
- **Constraints:** The YAML list **replaces** the defaults (it does not merge) — see `R-042`.
- **Source:** `README.md:21`, `README.md:122`; `config.yaml:40-46`; `ROUNDTABLE_01_NETWORK.md:567`; `ANALYST_04_PROTOCOL.md:252`, `ANALYST_04_PROTOCOL.md:260`.
- **Verify:** `TestIsBypassHost_SuffixAllDepths`, `TestRegression_HTTPBypassPinForward`, `TestRouterIsHealthyGatesDegradedReady`.

### R-025 · Loopback SOCKS waiver gated on bypass config — MUST
- **Requirement:** SOCKS5 connections to loopback targets are only waived through the SSRF/self-dial guard when the host is explicitly in the bypass list.
- **Accept:** Removing a loopback host from `bypass.hosts` causes its SOCKS5 requests to be blocked; adding it back permits them.
- **Source:** `TestSOCKS5_LoopbackWaiverGatedOnBypassConfig`, `TestSOCKS5_BypassWaiverPredicate`, `TestRegression_WaiverGatedOnRouterVerdict`, `TestSOCKS5_SelfDialGuard`.
- **Verify:** Run those four tests.

### R-026 · Exit-IP change triggers — MUST (current documented behavior)
- **Requirement:** In multi-Tor mode an exit IP change occurs on: (1) `rotate_after: 0` → threshold disabled; (2) non-SSE 429/503 response → NEWNYM on the current instance; (3) CONNECT tunnel dying within 2 s → same path; (4) health-probe failures → DROPGUARDS heal, 3 consecutive failures → respawn; (5) Tor `MaxCircuitDirtiness 20` native rebuild.
- **Accept:** Each trigger, exercised independently, produces a NEWNYM or respawn recorded in `lano_rotations_total` / Tor logs; threshold rotation does not fire when `rotate_after: 0`.
- **Source:** `README.md:39-47`; `config.yaml:14`; `ROUNDTABLE_01_NETWORK.md:214-225` (optimal strategy); `ROUNDTABLE_03_ARCHITECTURE.md:1510-1517`.
- **Verify:** `TestRotatorZeroIntervalNeverFires`, `TestRegression_NEWNYMCooldownSentinel`, `TestRegression_PoolColdAnomalyNoPhantomRotation`, `internal/backend/torlifecycle.go`.
- **Note:** Trigger (2) is layer-dependent — see `A-007`.

### R-027 · SSE streams are never rotated mid-flight — MUST
- **Requirement:** SSE streams and established tunnels keep their exit IP until closed; rotation is deferred until idle.
- **Accept:** A long-lived SSE stream through one instance is not re-pinned to another instance; no NEWNYM occurs while the stream is active due to that stream.
- **Source:** `README.md:47`; `ROUNDTABLE_03_ARCHITECTURE.md:297`, `ROUNDTABLE_03_ARCHITECTURE.md:1514-1515` (session pinning, deferred rotation).
- **Verify:** `internal/backend/socks5_multisession_test.go`, `TestTorSOCKS5_MultiSessionOnSameTCPConnection`.

### R-028 · NEWNYM rate-limit / cooldown — MUST
- **Requirement:** Do not issue NEWNYM faster than Tor permits (~1/s); enforce a cooldown and refund claims when no rotation actually occurred.
- **Accept:** Two rapid rotation requests produce at most one NEWNYM within the cooldown; cooldown does not leak claims (`NymRefund` tests).
- **Source:** `ROUNDTABLE_01_NETWORK.md:195-201`; `ROUNDTABLE_03_ARCHITECTURE.md:1502` (risk mitigation); `internal/rotate/rotator_cooldown_test.go`.
- **Verify:** `TestRotatorTriggersAtInterval`, `TestForceRotateCooldown`, `TestRegression_NymRefundZeroClaimNoOp`, `TestRegression_NymRefundKeepsNewerBypassClaim`, `TestShouldRotateUnaffectedByForceCooldown`.

### R-029 · Tor control authentication verified at startup — MUST
- **Requirement:** Verify configured control cookie/password at startup; fail fast on definitive auth rejection, degrade on timeout/unconfigured.
- **Accept:** A bad cookie causes startup failure with a clear message; an unreachable control port degrades without crashing; password containing special characters is escaped.
- **Constraints:** `PROTOCOLINFO` capability negotiation is RECOMMENDED, not required (`ANALYST_04_PROTOCOL.md:233`).
- **Source:** `ANALYST_01_SECURITY.md:346`, `ANALYST_01_SECURITY.md:361`; `ANALYST_04_PROTOCOL.md:227-233`; `cmd/relay/main.go:403-423` (`verifyControlAuthAtStartup`).
- **Verify:** `TestVerifyAuth_BadCookie`, `TestVerifyAuth_CookieOK_NoStateChange`, `TestVerifyAuth_Unreachable`, `TestVerifyAuth_NoControlPort`, `TestVerifyControlAuthDegradesOnTimeoutAndAuthFailed`, `TestPoolVerifyControl_NoControlPort`.

### R-030 · Exit-IP tracking — MUST
- **Requirement:** Track the observed exit IP per Tor instance and expose it as a metric.
- **Accept:** `lano_exit_ip{instance,ip}` reflects the current exit IP and changes after a successful rotation.
- **Source:** `README.md:151` (`lano_up`, `lano_tor_instances`); `bench/metrics_schema.md:36`; `git d65dacd` "exit-IP tracking".
- **Verify:** `TestRefreshExitIP_UsesInstanceCircuitIdentity`, `TestRegression_MetricsExitIPEscaped`.

### R-031 · Global request-count rotation (legacy rotator) — MUST respect disabled state
- **Requirement:** `rotation.enabled` (default `false` in config.yaml) controls the legacy request-count rotator; when disabled it must never fire.
- **Accept:** With `rotation.enabled: false`, `lano_rotation_requests` does not advance from the legacy path; with `true` and `interval: 10`, it advances every 10 requests.
- **Constraints:** **Conflicts with defaults.go** (`Rotation.Enabled: true`, `Interval: 10`) — see `X-001`.
- **Source:** `config.yaml:48-51`; `README.md:124-126`; `internal/config/defaults.go:42-45`; `internal/config/validate.go:101-103`.
- **Verify:** `TestRotatorTriggersAtInterval`, `TestRotatorZeroIntervalNeverFires`, `TestRotatorNegativeIntervalDisabled`, `TestRotator_TriggerStillFires`.

### R-032 · Time-based rotation — RECOMMENDATION (not currently required)
- **Requirement:** Multiple original docs recommend time-based rotation (min 10 s between NEWNYM, or ~30 min interval) in addition to count-based rotation.
- **Accept:** Only if adopted: config keys such as `min_interval_sec` / `rotate_after_ms` exist and rotation occurs on elapsed time.
- **Constraints:** No such keys exist in `config.yaml` or `config.go` today. **Do not treat as a compliance failure without a scope decision** — see `A-002`, `M-007`.
- **Source:** `ROUNDTABLE_01_NETWORK.md:577-578`, `ROUNDTABLE_01_NETWORK.md:591-594`; `ROUNDTABLE_03_ARCHITECTURE.md:1476`; `ANALYST_01_SECURITY.md:369`; `ANALYST_05_PRIVACY.md:355`; `ANALYST_03_INFRA.md:313`.

---

## 3. Security, SSRF & privacy

### R-033 · SSRF blocking on HTTP path — MUST
- **Requirement:** Block requests whose resolved target is in `security.blocked_networks` before dialing, in the HTTP handler and the firewall.
- **Accept:** `curl -H "x-target-url: http://127.0.0.1/" http://127.0.0.1:18080/` is blocked; numeric/hex/URL-encoded loopback lookalikes are blocked.
- **Source:** `README.md:132-136`; `ANALYST_04_PROTOCOL.md:68`; `ENGINEERING_AUDIT.md:35` (#1); `AUDIT_VERIFICATION.md:19-28`.
- **Verify:** `TestSSRFBlocker_IsBlocked`, `TestRegression_HTTPConnectPrivateBlocked`, `TestRegression_NumericIPSSRFBlocked`, `TestRegression_LoopbackCheckRejectsLookalikeHostnames`, `TestRegression_FailClosedDNSBlocksUnresolvable`.

### R-034 · SSRF blocking on SOCKS5 path — MUST, GAP
- **Requirement:** Apply the same `ssrf.IsBlocked(host)` check in SOCKS5 `handleConnect`, not only `firewall.AllowHost`.
- **Accept:** A SOCKS5 CONNECT to a private IP is rejected; `TestRegression_SOCKS5BypassPinAndBlock` passes.
- **Constraints:** Loopback waiver only when host is in bypass config (`R-025`).
- **Source:** `ENGINEERING_AUDIT.md:36` (#2 HIGH), `AUDIT_VERIFICATION.md:30-48` (Confirmed HIGH); `ANALYST_01_SECURITY.md:345`.
- **Verify:** `internal/security/regression_wiring_test.go`, `TestRegression_SOCKS5BypassPinAndBlock`.

### R-035 · Blocked-network list parity — MUST
- **Requirement:** The 18 CIDRs in `config.yaml`, `internal/config/defaults.go` and `internal/security/firewall.go` defaults must match.
- **Accept:** `TestBlockedRanges_MatchConfigDefaults` and `TestBlockedNetworks_DefaultsMatchConfigYAML` pass; the YAML list contains the IPv4 private ranges, IPv6 ULA/link-local/special-use, and multicast ranges.
- **Constraints:** YAML **replaces** defaults; omitted ranges are NOT enforced — config.yaml must enumerate all of them.
- **Source:** `config.yaml:57-81` (explicit comment), `internal/config/defaults.go:51-73`; `internal/config/blocked_networks_sync_test.go`.

### R-036 · Per-destination rate limiting — MUST
- **Requirement:** Limit requests per destination host to `security.rate_limit` req/s with burst `security.rate_burst` (defaults 50/100).
- **Accept:** Exceeding the burst yields a rate-limit denial distinct from an SSRF block; non-IP hosts resolve without blocking the hot path (DNS caching expected).
- **Source:** `README.md:135-136`; `internal/config/defaults.go:75-76`; `internal/config/validate.go:124-128`; `ENGINEERING_AUDIT.md:39` (#5 HIGH); `AUDIT_VERIFICATION.md:74-88`.
- **Verify:** `TestFirewall_RateLimit`, `TestRegression_RateLimitDenialDistinctFromSSRFBlock`, `TestResolver_Lookup`, `TestLivenessCache_HotPath`.

### R-037 · HTTP body size limit — MUST
- **Requirement:** Enforce `security.max_body_size` (32 MB) on HTTP requests; return 413 when exceeded.
- **Accept:** A body larger than the configured limit is rejected with HTTP 413; a body exactly at the boundary is accepted.
- **Source:** `README.md:134`; `config.yaml:81`; `internal/config/defaults.go:74`; `internal/config/validate.go:216-218`; `ENGINEERING_AUDIT.md:102`.
- **Verify:** `TestRegression_HTTPBodyOverLimit413`, `TestRegression_HTTPBodyBoundaryEcho`.

### R-038 · Constant-time API key authentication — MUST
- **Requirement:** Compare API keys in constant time; accept the key via headers; never accept it from a URL query parameter.
- **Accept:** `TestConstantTimeComparePrimitive` passes; a `?api_key=` query parameter is stripped/ignored; multi-value `Authorization` headers are handled.
- **Source:** `README.md:35`, `README.md:128-130`; `ANALYST_01_SECURITY.md:378`; `ANALYST_05_PRIVACY.md:350`; `ANALYST_01_SECURITY.md:350`.
- **Verify:** `internal/auth/apikey_test.go`, `TestRegression_QueryApiKeyStripped`, `TestRegression_MultiValueAuthorization`, `TestRegression_MultiValueProxyKeyHeaders`, `TestRegression_CredentialStripPredicate`.

### R-039 · API key length & non-loopback auth requirement — MUST
- **Requirement:** `auth.api_key` must be ≥16 characters when auth is enabled; any non-loopback `server.http`, `server.socks5`, `health.address` or `metrics.address` bind requires `auth.enabled: true`.
- **Accept:** Config validation rejects a short key and rejects a `0.0.0.0` bind with auth disabled; loopback binds remain valid without auth.
- **Source:** `README.md:130`; `internal/config/validate.go:105-122`; `internal/config/defaults.go:46-49`; `ANALYST_01_SECURITY.md:347`, `ANALYST_01_SECURITY.md:362`.
- **Verify:** `TestRegression_ValidationRules`, `TestFlagOverridesRevalidated`, `TestRegression_NonLoopbackHealthMetricsRequireAuth`, `internal/config/nonloopback_auth_test.go`.

### R-040 · Health/metrics endpoints auth-gated when enabled — MUST
- **Requirement:** When `auth.enabled: true`, the admin health/readyz/metrics endpoints require the key; when disabled and loopback-bound they stay open.
- **Accept:** Unauthenticated `/metrics` returns 401/403 with auth on; all endpoints work without a key when auth off.
- **Source:** `README.md:147-151`; `ANALYST_01_SECURITY.md:351`, `ANALYST_01_SECURITY.md:366`; `internal/health/admin_auth_test.go`.
- **Verify:** `TestHealthServer_AdminAuthGating`, `TestMetricsAuthGate`, `TestHealthServer_NoAuthStaysOpen`, `TestHealthServer_Degraded`.

### R-041 · Sensitive header/URL redaction — MUST (partial gaps flagged)
- **Requirement:** Redact `Authorization`, `X-Api-Key`, `Cookie` and sensitive URL parameters (`token`, `key`) from logs; userinfo must not leak.
- **Accept:** Log lines containing a key do not contain its value; `TestSanitizeURLCaseInsensitive` and `TestRegression_SanitizeURLRedactsUserinfo` pass.
- **Constraints:** ANALYST_05 recommends expanding to `X-Forwarded-For`, `X-Real-IP`, `Forwarded`, `User-Agent`, `Accept-Language`, `Referer`, `Via`, `True-Client-IP`, `password`, `secret`, `session`, `access_token`, `refresh_token` — these are RECOMMENDATIONS, not verified requirements (`X-004`).
- **Source:** `ANALYST_01_SECURITY.md:354`, `ANALYST_01_SECURITY.md:368`; `ANALYST_05_PRIVACY.md:352`, `ANALYST_05_PRIVACY.md:358`; `ANALYST_03_INFRA.md:287`.
- **Verify:** `internal/auth/regression_credential_strip_test.go`, `TestSanitizeURLCaseInsensitive`, `BenchmarkSanitizeURL`.

### R-042 · Self-dial guards — MUST
- **Requirement:** Prevent the relay from dialing itself: canonicalize IPs, reject unspecified binds, handle portless implicit ports, and avoid DNS-flip pinning attacks.
- **Accept:** All `TestRegression_*SelfDial*`, `TestPinnedDial_*` and `TestRegression_HTTPSelfDialLoop` tests pass.
- **Source:** `git da46ac7` "canonical self-dial", `git 4afcb54` "canonical self-dial", `git d511297` "dial-release"; `internal/backend/pinned_dial_test.go`.
- **Verify:** `TestRegression_SelfDialLocalhostAlias`, `TestRegression_SelfDialUnspecifiedBind`, `TestRegression_SelfDialPortlessImplicitPort`, `TestSOCKS5_SelfDialUnspecifiedLive`, `TestPinnedDial_UsesVerifiedIPsDespiteDNSFlip`, `TestPinnedDial_HostnameNeverReachesDialer`.

---

## 4. Configuration & CLI

### R-043 · Config precedence: defaults → YAML → env → CLI flags — MUST
- **Requirement:** Load built-in defaults, then YAML, then env overrides, then CLI flag overrides; re-validate after overrides.
- **Accept:** `PROXY_HTTP` overrides `server.http` from the file; `-http` overrides `PROXY_HTTP`; an invalid value from any layer causes validation failure with exit 1.
- **Constraints:** Precedence is **implemented** but not fully documented — see `A-005`.
- **Source:** `cmd/relay/main.go:55-62` (load → `applyEnvOverrides` inside `config.Load` → `applyFlagOverrides` → `Validate`); `internal/config/env.go:9-89`; `README.md:93-95`; `cmd/relay/main.go:156-182`.
- **Verify:** `TestFlagOverridesRevalidated`, `TestLoad_AcceptsKnownFields`, `TestLoad_RejectsSecondDocument`.

### R-044 · Strict YAML decoding — MUST
- **Requirement:** Reject unknown keys and multiple YAML documents; `config.yaml` must contain only fields defined in the config structs.
- **Accept:** A config with a typo'd key fails to load; a second `---` document fails; `TestStrict_ProductionConfigHasOnlyKnownFields` passes.
- **Source:** `config.yaml:23-26` (explicit comment); `internal/config/strict_test.go`; `internal/config/config.go` (strict decoder).
- **Verify:** `TestLoad_RejectsUnknownFields`, `TestRegression_LoadRejectsSecondDocument`, `TestStrict_ProductionConfigHasOnlyKnownFields`, `TestLoad_RejectsSecondDocument`.

### R-045 · Backend type & address validation — MUST
- **Requirement:** `backend.type` must be `"tor"`; with multi-Tor disabled, `backend.address` must be a valid address distinct from all listeners; `circuit_count >= 1`; `max_circuit_age >= 1`.
- **Accept:** `backend.type: http` is rejected; `backend.address` equal to `server.http` is rejected.
- **Source:** `internal/config/validate.go:10-36`, `internal/config/validate.go:55-61`; `config.yaml:17-21`; `README.md:113-119`.
- **Verify:** `internal/config/validate_test.go`, `TestValidate_RejectsBadMultiTorPorts`, `TestValidate_BackendCollisionCheckedInMultiTorMode`.

### R-046 · Port-collision validation — MUST
- **Requirement:** Reject collisions among `server.http`, `server.socks5`, `health.address`, `metrics.address`, `backend.address`, `backend.control_addr`, and every multi-Tor SOCKS/control port; all ports within 1–65535.
- **Accept:** A config where `health.address` uses the HTTP proxy port fails validation; overlapping multi-Tor instance ranges fail validation.
- **Source:** `internal/config/validate.go:130-210`; `git ad2380c` "port conflict".
- **Verify:** `TestValidate_RejectsPortCollisions`, `TestValidate_RejectsBadMultiTorPorts`.

### R-047 · Pool tuning value ranges — MUST
- **Requirement:** Validate `ewma_alpha (0,1]`, `latency_ref_ms [100,60000]`, `min_samples [1,1000]`, `min_quality (0,1]`, `selection ∈ {weighted, po2}`, `po2_samples [2,8]`, `quarantine_after_fails [1,100]`, `quarantine_secs [5,3600]`, `max_quarantine_secs [quarantine_secs,3600]`, `probation_probes [1,5]`.
- **Accept:** Each out-of-range value produces the specific validation error.
- **Source:** `internal/config/validate.go:63-93`; `config.yaml:27-38`; `git ea32371` "full POOL_* env, schema".
- **Verify:** `internal/config/pool_config_test.go`, `TestPool_RejectsBadValues`, `TestSelect_SetSelectionValidation`.

### R-048 · Logging & security scalar validation — MUST
- **Requirement:** `logging.level ∈ {debug,info,warn,error}`, `logging.format ∈ {json,text}`, all CIDRs parse, `rate_limit`/`rate_burst`/`max_body_size`/`rotate_after` not negative.
- **Accept:** Invalid level, format, CIDR or negative value fails validation.
- **Source:** `internal/config/validate.go:212-235`; `README.md:138`; `config.yaml:83-85`.
- **Note:** README sample says `format: text`, code default is `json` — see `X-005`.
- **Verify:** `internal/config/validate_test.go`, `TestRegression_ValidationRules`.

### R-049 · CLI flags — MUST
- **Requirement:** Support `-c`/`--config` (default `config.yaml`), `-http`, `-socks5`, `-log-level`, `-v` (shortcut for debug, overrides `-log-level`), `-version`.
- **Accept:** `./relay -version` prints build info and exits; `-v` produces debug logs even if `-log-level=error` is also passed; `-http` overrides the file value.
- **Source:** `README.md:82-95`; `cmd/relay/main.go:40-47`, `cmd/relay/main.go:156-182`; `Makefile:5-8`.
- **Verify:** `cmd/relay/main_test.go`, `TestFlagOverridesRevalidated`, `TestHealthServer_VersionWiring`.

### R-050 · Environment overrides — MUST
- **Requirement:** Honor `PROXY_HTTP`, `PROXY_SOCKS5`, `PROXY_BACKEND_ADDR`, `PROXY_AUTH_KEY`, `PROXY_LOG_LEVEL`, `PROXY_HEALTH_ADDR`, `TOR_BINARY`, `TOR_LIBRARY_PATH` and all `POOL_*` variables; `PROXY_AUTH_KEY` also enables auth.
- **Accept:** Each variable changes the corresponding config field; `PROXY_AUTH_KEY` sets `Auth.Enabled = true`; an unparseable `POOL_*` value leaves the file/default value intact (lenient parse).
- **Source:** `README.md:93-95`; `internal/config/env.go:9-89`; `git ea32371` "full POOL_* env"; `internal/config/env.go:35` comment.
- **Verify:** Set each env var and inspect startup behavior; `internal/config/*_test.go`.

### R-051 · `TOR_LIBRARY_PATH` exported to Tor children — MUST
- **Requirement:** Export `TOR_LIBRARY_PATH` as `LD_LIBRARY_PATH` for spawned Tor processes.
- **Accept:** With a Tor binary that needs private libs, child processes start with the correct `LD_LIBRARY_PATH`.
- **Source:** `README.md:95`; `config.yaml:10` (`library_path` comment).
- **Verify:** `cmd/relay/lifecycle_test.go`, `internal/backend/torlifecycle.go`.

---

## 5. Health, metrics & observability

### R-052 · Proxy-port `/health` — MUST
- **Requirement:** `GET :18080/health` returns `200 {"status":"ok","mode":"..."}` when a backend is healthy, otherwise `503 {"status":"degraded","mode":"..."}`; requires the auth key when `auth.enabled: true`.
- **Accept:** Both status codes and JSON shapes observed; auth gate enforced.
- **Source:** `README.md:147`; `README.md:70`.
- **Verify:** `TestHealthServer_Degraded`, `TestHealthServer_AdminAuthGating`.

### R-053 · Admin health endpoints — MUST
- **Requirement:** `GET :18888/health` (alias `/healthz`) returns full status with per-instance/per-slot detail; `GET :18888/readyz` returns `200 {"status":"ready"}` when healthy, else `503 {"status":"not ready"}`.
- **Accept:** All three paths respond; degraded state maps to 503 on both; responses carry a `Content-Type` header.
- **Source:** `README.md:148-149`; `README.md:139`; `internal/health/health.go`.
- **Verify:** `TestHealthServer_Endpoints`, `TestHealthServer_DegradedHasContentType`, `TestHealthServer_ReadyNotReadyHasContentType`, `internal/health/readyz_headers_test.go`.

### R-054 · `/metrics` on admin port — MUST when enabled
- **Requirement:** `GET :18888/metrics` exposes Prometheus gauges only when `metrics.enabled: true` (gated by `SetMetricsEnabled`).
- **Accept:** Disabled → 404/absent; enabled → metric text; labels escaped and numeric TYPE/HELP lines valid.
- **Source:** `README.md:150`; `bench/metrics_schema.md:7-10`; `ENGINEERING_AUDIT.md:98`, `git ea32371`.
- **Verify:** `TestMetricsAuthGate`, `TestRegression_MetricsInstanceNumericTypes`, `TestRegistryIncRender`, `internal/health/regression_metrics_labels_test.go`.

### R-055 · Separate Prometheus listener — MUST when enabled
- **Requirement:** When `metrics.enabled: true`, start a separate listener at `metrics.address` + `metrics.path` (default `127.0.0.1:9090/metrics`) exposing `lano_up` and `lano_tor_instances`.
- **Accept:** `curl 127.0.0.1:9090/metrics` returns `lano_up 1` and `lano_tor_instances <n>`; server shuts down cleanly with timeouts.
- **Source:** `README.md:151`; `bench/metrics_schema.md:42-50`; `internal/config/defaults.go:86-90`; `cmd/relay/main.go:806`.
- **Verify:** `TestMetricsServerTimeoutsAndShutdown`.

### R-056 · Implemented metric series — MUST (schema as documented)
- **Requirement:** Emit the series listed as "Implemented" in `bench/metrics_schema.md` with the documented labels and semantics; do **not** claim the `proxy_*` series under "Planned".
- **Accept:** Counter TYPE/HELP correct (`relay_pool_requests_total` is a counter), `lano_exit_ip` label escaping correct, `lano_endpoint_state` codes 0–4.
- **Source:** `bench/metrics_schema.md:12-50` (implemented), `bench/metrics_schema.md:52-68` (planned — not requirements).
- **Verify:** `TestRegression_MetricsInstanceNumericTypes`, `TestSetGauge`, `TestRegistryIncRender`, `git ea32371` "counter TYPE, HELP/TYPE".

---

## 6. Lifecycle, concurrency & deployment

### R-057 · Graceful shutdown — MUST
- **Requirement:** Handle OS signals with a context timeout; stop health, metrics, proxies and Tor daemons; wait for in-flight work.
- **Accept:** `SIGTERM` exits within the configured timeout with no leaked child processes; run twice to check the double-start bind race (logged PID disambiguates).
- **Source:** `ANALYST_04_PROTOCOL.md:281`; `ENGINEERING_AUDIT.md:101`; `cmd/relay/main.go:395` (pre-bind), `git 1ec78f4` "Log PID on startup".
- **Verify:** `cmd/relay/lifecycle_test.go`, `cmd/relay/recovery_test.go`, `internal/rotate/rotator_shutdown_test.go`.

### R-058 · Goroutine tracking & panic recovery — MUST (audit remediation)
- **Requirement:** Track goroutines spawned for NEWNYM/health/rotator work (WaitGroup or bounded concurrency) and recover panics in long-lived server goroutines.
- **Accept:** Shutdown with in-flight rotation does not leak goroutines; a panic in a health/metrics handler does not kill the process.
- **Source:** `ENGINEERING_AUDIT.md:45-50` (#6,#7,#10,#11); `AUDIT_VERIFICATION.md:90-121`; `git bab7e55` "Audit fixes Phase 1-6".
- **Verify:** `TestRotator_WaitGuardsLateAdd`, `TestPool_RenewProbeGenGate`, `internal/backend/multitor.go` (`ReportAnomaly`).

### R-059 · Pre-bind listeners at startup — MUST
- **Requirement:** Bind all configured listener ports before spawning Tor daemons so port conflicts fail fast.
- **Accept:** With a port already taken, startup exits with a clear error before any Tor process is spawned.
- **Source:** `cmd/relay/main.go:395`, `cmd/relay/main.go:530` (`preBindProxies`); `git ad2380c` "port conflict".

### R-060 · Build/test/lint/cross-compile targets — MUST
- **Requirement:** `make build`, `make test`, `make lint`, `make cross-compile` work; build binary is `./relay` with version/commit/build-time ldflags and stripped symbols.
- **Accept:** All four targets exit 0; `./relay -version` shows the injected metadata; cross-compile produces the 6 listed platform binaries.
- **Source:** `Makefile:1-32`; `README.md:51-54`, `README.md:155-160`; `ANALYST_01_SECURITY.md:391` (stripped symbols).
- **Verify:** Run each make target.

### R-061 · systemd deployment — MUST
- **Requirement:** `local-relay.service` runs as `stb:stb` from `/home/stb/local-relay`, starts `./relay -c config.yaml`, `Restart=always`, `RestartSec=3`, `LimitNOFILE=65536`, `NoNewPrivileges=true`; `tor-local.service` runs Tor with `Restart=always`, `RestartSec=5`, `LimitNOFILE=65536`, `ExecReload` HUP.
- **Accept:** `systemctl status local-relay` shows active; killing the process causes restart; journal receives stdout/stderr.
- **Source:** `local-relay.service:1-20`; `tor-local.service:1-18`; `README.md:56-60`; `ROUNDTABLE_04_OPS.md:677-737`.
- **Note:** `local-relay.service` is absent from the initial commit (added `67e1a24`) — a requirement introduced after the original design docs.

### R-062 · Race-free tests — MUST
- **Requirement:** `go test -race ./...` passes; the project was explicitly hardened for races (bypassHosts slice, atomic counters, quarantine transitions).
- **Accept:** Command exits 0 with no race reports.
- **Source:** `README.md:157`; `ANALYST_02_GO_QUALITY.md:358` (data race finding); `git 078521c` "100% test coverage" claim — see `A-009`.
- **Verify:** `go test -race ./...`.

### R-063 · Performance characteristics — SHOULD (measurement-based, no hard SLO documented)
- **Requirement:** The original design targets low-latency proxying with pooled buffers, cached DNS, cached health results, pre-baked metric keys, and bounded connection pools.
- **Accept:** Benchmarks (`go test -bench . ./...`) run; any claimed improvement meets the documented decision framework in `bench/IMPLEMENTATION_PLAN.md:178` — see `M-004`.
- **Source:** `ANALYST_06_PERFORMANCE.md:375-393`; `bench/IMPLEMENTATION_PLAN.md:123-194`; `README.md:162-163`; `git 85f6b58`, `git 1dc7735`.

---

## 7. Scored pool / outcome feedback (post-audit requirements)

### R-064 · Pool kill switch — MUST
- **Requirement:** `pool.enabled: false` restores pure least-inflight selection while statistics keep recording; `true` enables scored selection.
- **Accept:** With `POOL_ENABLED=false` (or YAML) the least-inflight path is used and stats still update; `TestSelect_KillSwitchDisablesSteering` and `TestPool_KillSwitchKeepsSrGate` pass.
- **Source:** `config.yaml:23-28`; `internal/config/env.go:35-40`; `internal/backend/select_test.go`.

### R-065 · EWMA scored selection & Po2 — MUST when `pool.selection` set
- **Requirement:** `weighted` selection uses success-only EWMA latency and endpoint quality; `po2` picks the better of two distinct samples; cold instances are neutral and excluded only with fallback.
- **Accept:** `TestScore_*`, `TestSelect_Po2*`, `TestSelect_ColdEqualsLeastInflight`, `TestSelect_FreshnessExclusionAndFallback` pass; deterministic tie-breaking.
- **Source:** `config.yaml:27-34`; `git 10d4d4e` "pool scored selection"; `internal/backend/score.go`, `internal/backend/select.go`.

### R-066 · Quarantine & probation — MUST
- **Requirement:** After `quarantine_after_fails` failures, quarantine for `quarantine_secs` (max `max_quarantine_secs`); promote via `probation_probes` successful probes; no double NEWNYM while quarantined; cooldown on failed probe; all-quarantined still serves.
- **Accept:** The 15 `quarantine_test.go` cases and `pool_quarantine_test.go` cases pass; metrics `lano_quarantine_total` labels are `consec-fails` / `probation-probe-failure`.
- **Source:** `config.yaml:35-38`; `bench/metrics_schema.md:22`; `git 10d4d4e`, `git d511297`.
- **Verify:** `internal/backend/quarantine_test.go`, `internal/backend/pool_quarantine_test.go`.

### R-067 · Outcome attribution & single-owner semantics — MUST
- **Requirement:** Each request outcome is attributed to exactly one serving instance/slot; a stale generation is discarded; reports outside the claim window are dropped; pool-slot anomalies use `pool-slot-N` labels.
- **Accept:** `TestReportOutcome_AttributesToServingInstance`, `TestReportOutcome_SingleSamplePerRequest`, `TestPool_GenZeroOutcomeDrops`, `TestPool_StaleGenDiscardsOnClose`, `TestRegression_PoolWarmAnomalyKeepsAttribution` pass.
- **Source:** `git da46ac7` "single-owner outcomes", `git d511297` "pool gen fencing", `git c335903`; `internal/backend/outcome.go`, `internal/backend/pool.go`.

### R-068 · Connection pool recycling & liveness — MUST
- **Requirement:** Pool connections keyed per destination; evict stale/dead connections (including RST and half-closed); bounded overflow; liveness cached with TTL; in-flight count decremented on close.
- **Accept:** `internal/backend/pool_test.go`, `pool_recycle_test.go`, `liveness_cache_test.go`, `isconnalive_test.go` pass.
- **Source:** `git da46ac7` "cookie eviction", `git d86e1b2` "cached liveness", `git 4afcb54` "probe heartbeat"; `README.md:31`.
- **Verify:** `TestConnPool*`, `TestIsConnAlive_*`, `TestLivenessCache_*`, `TestInFlightConn_CloseDecrements`.

### R-069 · Control-cookie handling — MUST
- **Requirement:** Read the control auth cookie correctly; evict/re-read it when auth is rejected; do not cache a stale cookie across rotation failures.
- **Accept:** `TestCookieEvict_OnAuthRejected`, `TestCookieEvict_CheckHealthReverifiesAndReReadies`, `TestCookieEvict_TransportFailureKeepsCache` pass.
- **Source:** `git da46ac7` "cookie eviction"; `ENGINEERING_AUDIT.md:48` (#9), `AUDIT_VERIFICATION.md:123-134` (caching recommended, optional).
- **Verify:** `internal/backend/cookie_evict_test.go`.

### R-070 · Probe heartbeat / claim extension — MUST
- **Requirement:** Renew-probe heartbeats extend a slot's claim; fail-closed when all probation slots are claimed; stale probe slots expire without double-signalling.
- **Accept:** `TestRenewProbe_HeartbeatExtendsClaim`, `TestRenewProbe_RouterFanout`, `TestQuarantine_AllProbationClaimedFailsClosed`, `TestQuarantine_StaleProbeSlotExpires` pass.
- **Source:** `git 30c9790` "probe heartbeat", `git d511297` "pool RenewProbe/Status/sr-gate".
- **Verify:** `internal/backend/quarantine_test.go`.

---

## 8. Executable requirements encoded in tests

These are requirements that exist **only** as test assertions (no prose spec). They are binding for regression purposes: a change that breaks them is a compliance failure.

### R-071 · Test suite completeness — MUST
- **Requirement:** All 238 tests across 71 `*_test.go` files pass (`go test ./...`).
- **Accept:** `go test ./...` exits 0 and reports 238 passing tests in 71 test files; no skipped/failed packages.
- **Source:** Test inventory generated from `grep '^func Test'` across the repo on 2026-11-25.
- **Verify:** `go test ./...` (record count: 238).

### R-072 · Config regression invariants — MUST
- **Requirement:** Multi-document YAML rejected; unknown fields rejected; production config has only known fields; validation rules hold after flag overrides; blocked-network lists stay in sync; non-loopback binds require auth.
- **Accept:** Every named config regression test passes and each malformed config variant is rejected with a non-zero exit.
- **Source:** `internal/config/regression_multidoc_test.go`, `strict_test.go`, `validate_test.go`, `blocked_networks_sync_test.go`, `nonloopback_auth_test.go`.
- **Verify:** `go test ./internal/config/...`.

### R-073 · Security regression invariants — MUST
- **Requirement:** SSRF blocks numeric IPs strictly, unresolvable hosts fail closed, "looks numeric" hostnames fall through correctly, no-lookup verdicts match lookup verdicts, wiring tests confirm SSRF+firewall parity.
- **Accept:** Every named security regression test passes; blocked and allowed cases match the documented blocked-network list.
- **Source:** `internal/security/regression_nolookup_parity_test.go`, `internal/security/regression_ssrf_test.go`, `internal/security/regression_strict_numeric_test.go`, `internal/security/regression_wiring_test.go`, `internal/security/blocked_ranges_sync_test.go`, `internal/security/security_test.go`.
- **Verify:** `go test ./internal/security/...`.

### R-074 · Routing/pool regression invariants — MUST
- **Requirement:** Self-dial guards, bypass pinning, cold-anomaly attribution, pool generation fencing, kill-switch behavior, Po2 coverage, cooldown semantics.
- **Accept:** Every named backend regression test passes; no self-dial or generation-fencing case regresses.
- **Source:** `internal/backend/regression_claim_rotation_test.go`, `internal/backend/regression_cooldown_test.go`, `internal/backend/select_test.go`, `internal/backend/quarantine_test.go`.
- **Verify:** `go test ./internal/backend/...`.

### R-075 · Proxy/stream regression invariants — MUST
- **Requirement:** HTTP body limit boundary, header rewrite bypass pin, credential stripping, SOCKS5 truncated reads, SSE copy, multi-session SOCKS5 on one TCP connection.
- **Accept:** Every named proxy/stream test passes; boundary and truncation cases behave as asserted.
- **Source:** `internal/proxy/*_test.go`, `internal/stream/stream_test.go`, `internal/backend/socks5_multisession_test.go`.
- **Verify:** `go test ./internal/proxy/... ./internal/stream/...`.

---

## 9. Ambiguities — flag, do not guess

| ID | Ambiguity | Why it matters | Source |
|---|---|---|---|
| **A-001** | The "original specification" is **not a single document**. `ENGINEERING_AUDIT.md` says "Spec-required" for WebSocket (`:91`, `:112`, `:137`) and quotes "Spec says 'not initial version'" for HTTP/3 (`:89`), but no spec file exists in the working tree or in **any** git revision (verified by enumerating all tracked paths). | WebSocket and HTTP/3 cannot be verified as obligations. Do not mark them non-compliant on the strength of the audit alone. | `ENGINEERING_AUDIT.md:89-91`, `git log --all --name-only` |
| **A-002** | Rotation semantics differ across eras: original docs assume count-based rotation every 10 requests is active and must be wired in; current README/config disable it in favor of feedback (429/dead-tunnel) rotation; code *defaults* still enable count-based rotation. | Determines whether `R-031` is a defect or a deliberate supersession. Needs a scope decision before any fix. | `README.md:39-47`, `README.md:124-126`; `config.yaml:14`, `config.yaml:48-51`; `internal/config/defaults.go:42-45`; `ROUNDTABLE_01_NETWORK.md:558-579` |
| **A-003** | "Fail-closed" is used for two different behaviors: (a) block traffic when no backend is healthy, and (b) bypass hosts "routed DIRECT, fail-closed". The code routes bypass hosts direct and falls back to Tor when the direct dial fails. | A verifier cannot decide the expected behavior for a bypass host when Tor is down without a ruling. | `README.md:21-24`; `ANALYST_04_PROTOCOL.md:260`; `git 078521c` |
| **A-004** | Severity/modality is inconsistent across documents: e.g. SOCKS5 body limit is P0 CRITICAL in `ENGINEERING_AUDIT.md:37` but "Design Choice — not a bug" in `AUDIT_VERIFICATION.md:50-57`; SSRF TOCTOU is CRITICAL→LOW/Partially Correct. | Downstream fix tasks need to know which assessment binds. Rule: preserve modality, prefer the verification record (T2) for *whether* to fix. | `ENGINEERING_AUDIT.md:35-37`; `AUDIT_VERIFICATION.md:19-57`, `AUDIT_VERIFICATION.md:304-331` |
| **A-005** | Config precedence (defaults → YAML → env → CLI) is implemented but **never stated** in README. | A worker cannot tell whether `PROXY_HTTP` should beat `-http` without reading code. | `cmd/relay/main.go:55-62`; `README.md:93-95` |
| **A-006** | Where 429 detection belongs. README assigns it to local-relay (non-SSE 429 response → NEWNYM); ROUNDTABLE_04 says local-relay is a Layer-4 TCP proxy that "cannot see HTTP response status codes" for CONNECT tunnels, so 429 detection must happen in 9router. | Both can be true (HTTP forward vs CONNECT), but no doc states the layer split. Affects `R-026` trigger 2 verification method. | `README.md:42`; `ROUNDTABLE_04_OPS.md:26`, `ROUNDTABLE_04_OPS.md:968` |
| **A-007** | SOCKS5 user/password auth: README says `api_key` "also enables SOCKS5 user/pass"; six analyst sections say no SOCKS5 auth exists and none can be configured. | Must be resolved by running the proxy with auth enabled before treating either state as the requirement. See `X-003`. | `README.md:130`; `ANALYST_01_SECURITY.md:345`; `ANALYST_04_PROTOCOL.md:104,286` |
| **A-008** | `max_body_size` applicability: enforced for HTTP, and the audit's spec table marks "Body size limits" as Partial, but the verification report calls SOCKS5 body limits a design choice (SOCKS5 has no request body). | Whether SOCKS5 needs a body limit is undecidable from the docs; do not add one on assumption. | `ENGINEERING_AUDIT.md:37,102`; `AUDIT_VERIFICATION.md:50-57`; `config.yaml:81` |
| **A-009** | `git 078521c` claims "100% test coverage", but no coverage gate/threshold exists in Makefile or CI config. | Cannot verify "100% coverage" as a requirement; treat as a historical claim, not an acceptance criterion. | `git 078521c`; `Makefile:18-19` |
| **A-010** | WebSocket support is called "spec-required" but there is no spec, no implementation, no test, and no README mention. | Same as A-001, called out separately because it is the one most likely to be "fixed" speculatively. | `ENGINEERING_AUDIT.md:91,112,137` |

## 10. Conflicts — source A vs source B

| ID | Conflict | Sources | Resolution guidance |
|---|---|---|---|
| **X-001** | Rotation enabled state: `config.yaml` sets `rotation.enabled: false` and `multi_tor.rotate_after: 0`; `internal/config/defaults.go:42-45` sets `Rotation.Enabled: true, Interval: 10` and `RotateAfter: 50`. | `config.yaml:14,49-51`; `internal/config/defaults.go:27,42-45`; `README.md:41,125` | T1 config file wins for the production configuration; the default only applies when config omits these keys. Flag as a **documentation/defaults divergence** to fix, not as a runtime defect. |
| **X-002** | "WebSocket is spec-required" vs no spec artifact anywhere in git history. | `ENGINEERING_AUDIT.md:91` vs `git log --all --name-only` | Treat as unresolved (`A-001`), not as a mandatory feature. |
| **X-003** | SOCKS5 auth exists (`README.md:130`) vs "no SOCKS5 authentication at all" (analyst docs). | `README.md:130` vs `ANALYST_01_SECURITY.md:345`, `ANALYST_03_INFRA.md:285`, `ANALYST_04_PROTOCOL.md:104,286`, `ANALYST_05_PRIVACY.md:357` | Verify empirically with `auth.enabled: true`; update the checklist item after measurement. |
| **X-004** | Header/URL redaction scope: analysts call current coverage "narrow/incomplete" and list 14 more headers/params; no T1 document requires them. | `ANALYST_01_SECURITY.md:354,368`; `ANALYST_05_PRIVACY.md:352,358` vs `README.md` (silent) | Keep `R-041` at the documented minimum; extras are RECOMMENDATIONS. |
| **X-005** | Logging format default: README sample `format: text`; code default `format: json`; `config.yaml` says `text`. | `README.md:138`; `internal/config/defaults.go:80`; `config.yaml:85` | Effective production value is `text` (config file wins). Fix the code default or the doc — a doc/default divergence, not a runtime bug. |
| **X-006** | Tor control address configurability: original docs call it "hardcoded to 127.0.0.1:9051, not configurable"; current defaults and config structs expose `backend.control_addr` / `control_cookie_path`. | `ROUNDTABLE_01_NETWORK.md:560`, `ROUNDTABLE_01_NETWORK.md:590`, `ANALYST_04_PROTOCOL.md:288` vs `internal/config/defaults.go:15-16`, `README.md:118-119` | Requirement was implemented after the original analysis; `R-029` reflects the current state. |
| **X-007** | Ops docs say rotation happens "every 10 requests"; current config disables count-based rotation entirely. | `ROUNDTABLE_04_OPS.md:970`, `ROUNDTABLE_05_MODEL_ROUTING.md:1133` vs `config.yaml:14,50` | Same as X-001 — historical documentation drift. |

## 11. Missing requirements — cannot be verified from available sources

| ID | Missing | Source that implies it | Consequence |
|---|---|---|---|
| **M-001** | No versioned specification document with acceptance criteria (the audit repeatedly cites an unnamed "spec"). | `ENGINEERING_AUDIT.md:89,91,112,137` | Highest-priority gap: request the spec before certifying full compliance. |
| **M-002** | WebSocket framing/subprotocol/ping-pong requirements. | `ENGINEERING_AUDIT.md:91` | Cannot design a conformance test. |
| **M-003** | HTTP/3 requirements. | `ENGINEERING_AUDIT.md:89` | Explicitly "not initial version" — no action needed once the spec is located. |
| **M-004** | Hard performance SLOs (latency, throughput, requests/day) — analysis gives recommendations and a "15% improvement" decision framework but no acceptance thresholds. | `ANALYST_06_PERFORMANCE.md`; `bench/IMPLEMENTATION_PLAN.md:178-194`; `ROUNDTABLE_02_RATE_LIMIT.md:413-417` ("500+ requests/day") | `R-063` is SHOULD, not MUST. |
| **M-005** | Time-based rotation config keys and thresholds (`min_interval_sec`, `rotate_after_ms`) never landed in config. | `ROUNDTABLE_01_NETWORK.md:591`; `config.yaml` (absent) | See `A-002`; do not invent keys. |
| **M-006** | No API, database or UI requirements exist for this project. The root audit task mentions them generically. | `t_9e3c23a3` body vs repo file inventory | **Not applicable** — record as N/A, not as a compliance failure. |
| **M-007** | No explicit requirement for `metrics.address` in `config.yaml`, though README documents it and code defaults it. | `README.md:140,151`; `internal/config/defaults.go:89`; `config.yaml:91-93` | Minor documentation gap only. |

## 12. Explicitly out of scope — do not "fix" these in local-relay

| ID | Item | Why out of scope | Source |
|---|---|---|---|
| **OOS-001** | 9router model routing, quota budgeting, model priority/fallback, OpenRouter quota polling (all of `ROUNDTABLE_05_MODEL_ROUTING.md`, `ROUNDTABLE_04_OPS.md` §3–4) | "local-relay has no concept of 'models' — it just proxies TCP connections. Model switching logic belongs in 9router." | `ROUNDTABLE_04_OPS.md:972`; `ROUNDTABLE_05_MODEL_ROUTING.md:1148-1164` |
| **OOS-002** | Shell scripts for 429 detection, rotation monitoring, systemd units under `/home/stb/local-relay/scripts/` | Deployment/observability aids for the operator, not relay code requirements. Some are explicitly "no code changes". | `ROUNDTABLE_04_OPS.md:45-50`, `ROUNDTABLE_04_OPS.md:828-860` |
| **OOS-003** | TLS termination, access logging, HTTP/3, WebSocket, TLS-fingerprint (JA3/uTLS) evasion | Raised as audit gaps or T3 roadmap items only; no T1 requirement and no spec artifact. | `ENGINEERING_AUDIT.md:89,91,121,137`; `ROUNDTABLE_02_RATE_LIMIT.md:372` (P2) |

---

## 13. Verification workflow for downstream workers

1. **Resolve first:** `A-001`/`M-001` (locate the spec), `X-001`/`A-002` (rotation semantics), `X-003`/`A-007` (SOCKS5 auth). Do not implement fixes for these until decided.
2. **Baseline:** run `go test ./...`, `go test -race ./...`, `make build`, `make lint`; record exact output. Compare to `R-071` (238 tests / 71 test files).
3. **Per-item evidence:** for each `R-xxx`, execute the acceptance criteria and record command + observed output + file/line reference. Mark C / PC / NC (compliant / partially compliant / non-compliant).
4. **Regression:** after any fix, rerun the full suite and the item's verification hint; confirm no previously passing test fails.
5. **Report:** final compliance report must cite `R-xxx` IDs and include the ambiguity/conflict/missing tables from §9–§11 verbatim so nothing is silently dropped.

**Checklist statistics:** 75 requirement items (`R-001`–`R-075`), 10 ambiguities, 7 conflicts, 7 missing requirements, 3 out-of-scope groups. Every item cites at least one source location.
