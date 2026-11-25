# Final Requirements Compliance Report — local-relay

| Field | Value |
|---|---|
| Task | `t_2fe406d9` (second end-to-end audit after fixes); follow-up fix `t_fecba6aa` (R-019) |
| Workspace | `/home/strong/local-relay` |
| Commit under test | `1ec78f492b03ef1d2f913806eea59b101ec137d3` (working tree contains the 26 fixes from `t_c7e616a6`; this verification task changed no application code) |
| Verification date | 2026-11-25 (UTC/IST) |
| Checklist | `REQUIREMENTS_CHECKLIST.md` — 75 items R-001…R-075 |
| Toolchains | Go 1.25.0 (`/home/strong/.hermes/cache/scratch/go-toolchain/go/bin/go`), golangci-lint 2.15.0 |
| Verdict | **58 compliant · 16 partially compliant · 0 non-compliant · 1 not applicable** (R-019 upgraded PC→C by follow-up `t_fecba6aa`; original audit verdict 57/17/0/1) |
| Raw evidence | `/home/strong/local-relay/final-evidence/` (original 14 command logs + 2 evidence maps, plus `r019-fix-*` follow-up logs) |

## 1. Executive summary

The application builds and runs. Full tests, race detector, vet, gofmt, build and all five cross-compile targets pass; live HTTP proxy, SOCKS5, health, readyz, metrics, auth gates, SSRF/fail-closed routing, CONNECT tunnelling, config strictness and graceful shutdown were exercised against the freshly built binary. No previously passing test regressed: PASS count rose from 305 (baseline) to 341 with the same 0 FAIL and the same 2 Tor-only skips.

Not everything is compliant. `make lint` still fails with the same 56 findings as baseline; the benchmark suite still hangs in `BenchmarkTuneTCP`; real Tor-backed rotation/exit-IP workflows cannot be exercised on this host; and the proxy-port health `mode` field still reports `multi_tor` in degraded single-Tor mode. A live probe during this audit did find a response header named in the upstream `Connection` token list being forwarded (R-019); follow-up task `t_fecba6aa` fixed the root cause and re-probed it compliant with fresh evidence, so R-019 is now C. Remaining issues are documented with evidence below rather than claimed as working.

## 2. Method and evidence rules

- Every "PASS"/"observed" claim below comes from a command run in this task; raw output is in `final-evidence/*.log` and exit codes in `final-evidence/exit-codes.log`.
- Test-backed items were mapped mechanically from the checklist's named tests and referenced `*_test.go` files to `--- PASS:` lines in `final-evidence/make-test.log` (`final-evidence/requirement-evidence-map.json`).
- Live probes ran against isolated scratch configs with loopback listeners and a local Python upstream; all spawned listeners were closed afterwards.
- No screenshots: the repository has no UI layer (fresh search for `html/template`, `http.FileServer`, embedded JS/CSS returned no matches). No database exists either (no `database/sql`, sqlite, bbolt, Redis or Mongo usage), so database and UI interactions are **N/A** per checklist M-006, not compliance failures.
- Tor daemon, systemd/root operations and external public-IP endpoints were out of reach; those limits are stated per item.

## 3. Command results and baseline comparison

| Command | Baseline (`BASELINE_REPORT.md`) | This run | Verdict |
|---|---|---|---|
| `make test` | exit 0, 305 PASS / 0 FAIL / 2 SKIP | exit 0, **341 PASS / 0 FAIL / 2 SKIP** (`make-test.log`) | No regression; +36 assertions from fixes |
| `go test -count=1 ./...` | exit 0, 11/11 ok | exit 0, 11/11 ok (`go-test.log`) | No regression |
| `go test -race -count=1 ./...` | exit 0, 11/11 ok | exit 0, 11/11 ok (`go-test-race.log`) | No regression |
| `go vet ./...` | exit 0 | exit 0, no output (`go-vet.log`) | No regression |
| `gofmt -l cmd internal` | not recorded | exit 0, 0 files (`gofmt.log`) | Clean |
| `make build` | exit 0 | exit 0, stripped ELF, version stamped (`make-build.log`, `binaries.log`) | No regression |
| `./relay -version` | exit 0, go1.25.0 | exit 0, `local-relay 1ec78f4-dirty (commit=1ec78f4, built=…, go=go1.25.0)` (`version.log`) | No regression |
| `make cross-compile` | **exit 2**, windows/amd64 `Wait4`/`WNOHANG` | **exit 0**, all 5 targets incl. PE32+ Windows binary (`make-cross-compile.log`, `binaries.log`) | **F1 fixed** |
| `make lint` | exit 2, 56 findings (50 errcheck/4 staticcheck/2 unused) | exit 2, **56 findings, same split** (`make-lint.log`) | Unchanged defect F2 |
| `go test -bench .` smoke | exit 124, hang at `BenchmarkTuneTCP` | exit 124 after 8 benchmarks, same hang (`bench-smoke.log`) | Unchanged defect F3 |
| `./relay -c config.yaml` | exit 1, Tor binary missing | exit 1, same missing `/home/stb/tor/tor/tor` (`startup-production.log`) | Unchanged environment limit F4 |
| Malformed config probes | unknown key / multi-doc rejected | exit 1 for unknown key, multi-doc and missing file (`config-errors.log`) | No regression |

## 4. Live workflow evidence (fresh binary)

From `final-evidence/workflows.log`, `targeted-probes.log`, `raw-probes.log`:

| Probe | Result | Baseline comparison |
|---|---|---|
| Admin `/health`, `/healthz`, `/readyz` (degraded) | 503 / 503 / 503 with JSON | same |
| Proxy-port `/health` (no auth, degraded) | **503 degraded** | was **200 hardcoded** → F5 status fixed; `mode` still `multi_tor` |
| Proxy-port `/health` (auth on, no key) | **407** + `Proxy-Authenticate` | was served before auth → M-04 fixed |
| Admin `/metrics`, standalone `/metrics` | 200 with key; 407 without | same gating |
| HTTP bypass forward / SOCKS5 bypass forward | 200 / 200 | same |
| SSRF HTTP 10.0.0.1 / SOCKS5 10.0.0.1 | 403 / curl 97 rejected | same |
| Non-bypass HTTP / CONNECT | 502 fail-closed / curl 502 | same |
| Raw CONNECT tunnel to local target | 200, bytes relayed both ways | same |
| SOCKS5 auth parity | no creds curl 97, creds 200 | baseline also had auth; X-003 resolved: README correct |
| CLI/env precedence | flag 28081 > env 28082 > file 28080 | newly measured |
| Pre-bind conflict | exit 1, clear error, no ready log | newly measured |
| SIGTERM (both instances) | exit 0 within 15 s | same; F6 spurious ERROR lines persist |

## 5. Per-requirement compliance (R-001 … R-075)

Legend: **C** compliant · **PC** partially compliant · **NC** non-compliant · **N/A** not an obligation. Test counts refer to named/referenced tests confirmed PASS in `final-evidence/make-test.log`.

### 1. Proxy protocols & request handling

| ID | Status | Evidence and limitations |
|---|---|---|
| R-001 | **PC** | Live `workflows.log`: proxy listeners HTTP 28080 / SOCKS5 21080 bound, absolute-form bypass forward HTTP 200, local CONNECT tunnel 200; 9 referenced tests PASS (`make-test.log`). Public-IP egress via api.ipify.org untestable (no Tor daemon). |
| R-002 | **PC** | Live `workflows.log`: SOCKS5 listener 21080 bypass forward HTTP 200, private target rejected; 11 referenced tests PASS. Tor-backed public-IP SOCKS5 request not exercised. |
| R-003 | **C** | Live raw CONNECT to 127.0.0.1:19997 returned `HTTP/1.1 200 OK` and relayed post-handshake bytes (`raw-probes.log`); 8 referenced tests PASS including `TestRelay_Bidirectional`. |
| R-004 | **PC** | Source `internal/proxy/http.go:119-122` appends `:443` when CONNECT authority has no port; no live portless CONNECT test (no local TLS service on 443). |
| R-005 | **C** | Live absolute-form forward HTTP 200 (`workflows.log`); 13 referenced tests PASS. Header-mode to loopback returns 403 by documented design (F7) — noted, not a forwarding-path failure. |
| R-006 | **C** | Live non-bypass and CONNECT failures returned 502 `bad gateway` / curl 502 (`workflows.log`); 3 referenced tests PASS including hijack-error cases. |
| R-007 | **C** | Live `407 Proxy Authentication Required` with `Proxy-Authenticate: Basic realm="proxy"` on proxy /health and forward with no key (`targeted-probes.log`, `workflows.log`). |
| R-008 | **C** | 4 referenced tests PASS; live auth-enabled SOCKS5 negotiation: no creds → curl 97 "No authentication method was acceptable", creds → 200. |
| R-009 | **C** | 7 referenced tests PASS including `TestOutboundSOCKS5_IPv6LiteralUsesATYP4`; live IPv4/hostname CONNECT 200, UDP/private rejected. |
| R-010 | **C** | `internal/proxy/socks5.go:276` uses `fmt.Sprintf("[%s]:%d", net.IP(addr).String(), port)`; `TestOutboundSOCKS5_IPv6LiteralUsesATYP4` PASS. |
| R-011 | **C** | MAY item: `internal/proxy/socks5.go:124,514` replies 0x07 for unsupported command; no crash observed. |
| R-012 | **C** | 6 referenced tests PASS including malformed-reply and address-type reply cases. |
| R-013 | **C** | X-003 resolved empirically: auth-enabled instance logged "SOCKS5 authentication enabled"; unauthenticated SOCKS5 CONNECT rejected (curl 97), `--proxy-user key:key` returned 200 (`workflows.log`). README claim confirmed. |
| R-014 | **PC** | SHOULD item; no automated test found. Raw CONNECT-with-body probe returned 200 but the follow-on request was not observed echoed (`raw-probes.log`), so body-drain behavior is unverified. |
| R-015 | **C** | 6 referenced tests PASS (`TestHasSSEContentType`, classify/stream tests). |
| R-016 | **C** | 5 referenced tests PASS for header trio and per-event flush. |
| R-017 | **C** | 5 referenced tests PASS including multi-line event integrity cases. |
| R-018 | **C** | 5 referenced tests PASS (`TestRelay_Bidirectional`, `TestRelay_ContextCancelUnblocks`); live bidirectional tunnel verified. |
| R-019 | **C** | Root cause: Go's `shouldClose` (`transfer.go:502,748-763`) deletes the response `Connection` header when it carries `close`, erasing the token list before `forwardResponse` ran. Fixed by capturing the raw response head on the dialed connection and restoring the exact wire `Connection` values into `resp.Header` before the existing stripper runs (`http.go:59,635-646,772,838-964`). Three raw-upstream regressions pass (`r019_hop_by_hop_test.go`) and the fresh live probe no longer shows `X-Secret-Hop` (`r019-fix-raw-probe.log`); credential stripping and SSE streaming re-verified. Updated by follow-up task `t_fecba6aa` — see `FIXES_APPLIED.md`. |
| R-020 | **PC** | SHOULD item. `http.go:229` bounds HTTP CONNECT relay at 30 min; `socks5.go:391-398` explicitly has no SOCKS5 kill timeout (deferred M-10). No stalled-peer teardown test. |

### 2. Tor routing, rotation & exit-IP behavior

| ID | Status | Evidence and limitations |
|---|---|---|
| R-021 | **PC** | 8 referenced tests PASS (config/lifecycle); no Tor daemon, so spawning 3 instances on 9150-9152/9160-9162 not exercised. |
| R-022 | **C** | 13 referenced tests PASS for round-robin/health-aware selection; real multi-instance live routing unavailable (no Tor). |
| R-023 | **C** | Live fail-closed: non-bypass HTTP 502 and CONNECT 502 with log "no healthy proxy backends — connection blocked (fail-closed)"; 2 named tests PASS. |
| R-024 | **C** | Live bypass forward 200 to 127.0.0.1 target; 3 named tests PASS incl. suffix matching. |
| R-025 | **C** | 4 named tests PASS (loopback waiver gating). |
| R-026 | **PC** | 3 named rotation-trigger tests PASS (zero-interval, cooldown sentinel, cold-anomaly); real NEWNYM/exit-IP/429/dead-tunnel triggers need Tor (deferred L-07). |
| R-027 | **PC** | `TestTorSOCKS5_MultiSessionOnSameTCPConnection` and `TestTorSOCKS5_MultiSessionThreeRounds` are SKIPPED (Tor not on 127.0.0.1:9150); no live SSE mid-flight test. |
| R-028 | **C** | 6 named tests PASS (interval, force-cooldown, NymRefund cases). |
| R-029 | **C** | 6 named tests PASS; live startup with unreachable control port logged degrade/fail-closed and continued serving. |
| R-030 | **PC** | 2 named tests PASS; standalone /metrics live returns `lano_up 1`, but `lano_exit_ip` change after rotation not observable without Tor. |
| R-031 | **C** | 4 named tests PASS; production config disables legacy rotation, X-001 documentation/default divergence recorded. |
| R-032 | **N/A** | RECOMMENDATION only (checklist A-002/M-007); no config keys exist and no scope decision adopted. Not a compliance failure. |

### 3. Security, SSRF & privacy

| ID | Status | Evidence and limitations |
|---|---|---|
| R-033 | **C** | Live SSRF block HTTP 403 for `10.0.0.1` and loopback header-mode; 5 named tests PASS. |
| R-034 | **C** | Live SOCKS5 CONNECT to 10.0.0.1 rejected (curl 97) with log "blocked SOCKS5 connection to private/internal IP"; 6 referenced tests PASS. |
| R-035 | **C** | 2 named tests PASS; startup log reports `blocked_networks=18`. |
| R-036 | **C** | 4 named tests PASS incl. canonical IP bucket key fix (M-08). |
| R-037 | **C** | 2 named tests PASS (413 over-limit and boundary echo). |
| R-038 | **C** | 6 named tests PASS; live `?api_key=` accepted for auth and stripped before forwarding (query-preserve tests PASS). |
| R-039 | **C** | 3 named tests PASS; strict config probe rejected unknown key and non-loopback bind rules covered by tests. |
| R-040 | **PC** | Auth gate enforced live for admin health/readyz/metrics and proxy (407 + challenge header) with/without correct key; checklist acceptance names 401/403, observed 407 — auth requirement met, status-code expectation divergent. |
| R-041 | **C** | 3 named tests PASS for URL/userinfo redaction and header stripping. |
| R-042 | **C** | 53 referenced tests PASS incl. all named self-dial/pinned-dial cases. |

### 4. Configuration & CLI

| ID | Status | Evidence and limitations |
|---|---|---|
| R-043 | **C** | Live precedence measured: `-http 28081` + `PROXY_HTTP=28082` bound 28081; `PROXY_HTTP` alone bound 28082; file 28080 unused (`targeted-probes.log`); 3 tests PASS. |
| R-044 | **C** | Live strict-decode probe: unknown key and multi-doc rejected, exit 1 (`config-errors.log`); 6 referenced tests PASS. |
| R-045 | **C** | 4 referenced tests PASS for type/address validation. |
| R-046 | **C** | 2 named tests PASS; live port-conflict probe exited 1 with "HTTP proxy bind failed" before ready (`targeted-probes.log`). |
| R-047 | **C** | 5 referenced tests PASS incl. unparseable POOL_* fail-fast (M-12). |
| R-048 | **C** | 4 referenced tests PASS for scalar/CIDR validation. |
| R-049 | **C** | `./relay -version` exit 0 with injected metadata (`version.log`); live flag-over-env verified; `TestFlagOverridesRevalidated` PASS; `main.go:182-183` makes `-v` override log level (no debug-level line emitted on the probed startup path). |
| R-050 | **C** | 22 referenced tests PASS; live `PROXY_HTTP` override measured; unparseable POOL_* fail-fast test PASS. |
| R-051 | **C** | 6 referenced tests PASS for LD_LIBRARY_PATH propagation to Tor children. |

### 5. Health, metrics & observability

| ID | Status | Evidence and limitations |
|---|---|---|
| R-052 | **PC** | F5 status fixed: proxy /health returned 503 `{"status":"degraded","mode":"multi_tor"}` in single-tor degraded mode (was hardcoded 200). Residual: `mode` still reports `multi_tor` because it is derived from the pool flag, not topology (`http.go:99-103`). |
| R-053 | **C** | Live admin /health and /healthz returned 503 degraded JSON, /readyz 503 `{"status":"not ready"}`; 3 tests PASS incl. Content-Type. |
| R-054 | **C** | Live admin /metrics 200 with auth key, 407 without; 5 referenced tests PASS. |
| R-055 | **C** | Live standalone 127.0.0.1:29090/metrics returned `lano_up 1`; shutdown test PASS. |
| R-056 | **C** | 3 named tests PASS; live metrics exposition shows HELP/TYPE and numeric gauges. |

### 6. Lifecycle, concurrency & deployment

| ID | Status | Evidence and limitations |
|---|---|---|
| R-057 | **C** | Both live instances exited 0 on SIGTERM within 15 s; 12 referenced tests PASS. Residual F6 spurious ERROR lines on normal close documented. |
| R-058 | **C** | 2 named tests PASS; H-01 panic containment and generation-gated cleanup implemented and verified by fix task, suite green. |
| R-059 | **C** | Live pre-bind conflict probe: port 28080 occupied → exit 1, "HTTP proxy bind failed", no ready log (`targeted-probes.log`); `main.go:127,569`. |
| R-060 | **PC** | `make build`, `make test`, `make cross-compile` exit 0 and `./relay -version` stamped; all 5 targets incl. Windows built. `make lint` still exits 2 with 56 findings (same as baseline). |
| R-061 | **PC** | Unit files statically match requested directives (User/Group stb, WorkingDirectory, ExecStart, Restart=always/RestartSec, LimitNOFILE=65536, NoNewPrivileges, ExecReload HUP); runtime `systemctl status`/kill-restart not possible on this host. |
| R-062 | **C** | `go test -race -count=1 ./...` exit 0, 11/11 packages ok (`go-test-race.log`). |
| R-063 | **PC** | SHOULD item with no hard SLO. Benchmark smoke exited 124 (outer timeout) after 8 benchmarks, stalled in `BenchmarkTuneTCP` (F3, unchanged from baseline). |

### 7. Scored pool / outcome feedback

| ID | Status | Evidence and limitations |
|---|---|---|
| R-064 | **C** | 11 referenced tests PASS incl. kill-switch and SR-gate cases. |
| R-065 | **C** | 16 referenced tests PASS for EWMA/Po2/cold/freshness behavior. |
| R-066 | **C** | 23 referenced tests PASS incl. 15 quarantine cases and metrics labels. |
| R-067 | **C** | 5 named tests PASS for single-owner attribution and generation fencing. |
| R-068 | **C** | 23 referenced tests PASS for pool recycling/liveness/in-flight counters. |
| R-069 | **C** | 3 named tests PASS for cookie eviction/re-read. |
| R-070 | **C** | 17 referenced tests PASS for heartbeat/claim/stale-slot behavior. |

### 8. Executable requirements encoded in tests

| ID | Status | Evidence and limitations |
|---|---|---|
| R-071 | **PC** | Fresh inventory: 82 test files, 265 top-level tests, 33 benchmarks; `make test` 341 PASS / 0 FAIL / 2 SKIP, 11/11 packages ok. Checklist baseline figure (238 tests / 71 files) is stale after 26 fixes added tests; both skips are Tor integration tests. |
| R-072 | **C** | Config package tests PASS; live malformed-config probes exit 1; `blocked_networks=18` logged. |
| R-073 | **C** | 14 referenced tests PASS incl. numeric/strict-nolookup/wiring parity. |
| R-074 | **C** | 30 referenced tests PASS for self-dial, bypass pin, generation fencing, kill switch, Po2, cooldown. |
| R-075 | **PC** | 46 referenced tests PASS; 2 SOCKS5 multi-session integration tests SKIPPED (no Tor daemon) — see R-027. |

## 6. Baseline findings: then vs now

| Finding | Baseline | Current | Evidence |
|---|---|---|---|
| F1 Windows cross-compile | broken | **fixed** | `make-cross-compile.log` exit 0, PE32+ binary in `binaries.log` |
| F2 lint 56 findings | open | **open, unchanged** | `make-lint.log` |
| F3 benchmark hang | open | **open, unchanged** | `bench-smoke.log` exit 124 |
| F4 production config Tor paths | open | **open (environment)** | `startup-production.log` exit 1 |
| F5 proxy /health hardcoded 200 | open | **partially fixed**: status now 503; `mode` still misleading | `workflows.log`, `http.go:99-103` |
| F6 shutdown ERROR log noise | open | **open** | `workflows.log` log tails |
| F7 header-mode loopback 403 by design | open | **unchanged by design** | `workflows.log` 403 |
| NEW R-019 token-named header leak | not previously probed | **fixed and re-probed compliant** (follow-up `t_fecba6aa`) | `r019-fix-raw-probe.log`, `r019-fix-validation.log` |

## 7. Remaining issues and limitations (honest)

1. **`make lint` fails** with 56 default-ruleset findings (50 errcheck, 4 staticcheck, 2 unused). No repository linter config exists, so the intended ruleset is undefined; this is a policy decision, not a quick fix. R-060 is therefore partially compliant.

2. **Benchmark suite hangs** at `BenchmarkTuneTCP` (`internal/backend/bench_test.go`, accept with no dialer). Benchmark-only; production tests unaffected. R-063 partially compliant.

3. **No Tor daemon on this host** (`127.0.0.1:9150` refused; `/home/stb/tor/tor/tor` and `/home/stb/tor/data_multi` absent). Real egress, exit-IP rotation, 429/dead-tunnel NEWNYM, quarantine recovery, multi-instance lifecycle and two SOCKS5 multi-session integration tests are therefore skipped or untested. This affects R-001/002/021/026/027/030 and R-075; it is an environment limitation, not evidence of a defect.

4. **Proxy-port health `mode` is still derived from the pool flag** (`internal/proxy/http.go:99-103`), so a degraded single-Tor instance reports `mode:"multi_tor"`. Status code/shape are correct.

5. **Response hop-by-hop stripping was incomplete** for headers named by the upstream `Connection` token list (R-019): the original probe forwarded `X-Secret-Hop` (`raw-probes.log`). Fixed in follow-up `t_fecba6aa` by restoring Go's erased `Connection` values from the raw response head before stripping; three raw-upstream regressions and a fresh live probe now pass (`r019-fix-validation.log`, `r019-fix-raw-probe.log`). No longer an open defect. Scope note: capture is on the plaintext upstream hop; HTTPS upstreams remain TLS-wrapped above this connection, so token recovery does not apply there.

6. **CONNECT request-body draining unverified** (R-014, SHOULD): no automated test; raw probe inconclusive.

7. **Admin auth returns 407**, not the 401/403 stated in the checklist acceptance text (`targeted-probes.log`). The key is enforced and a valid challenge header is sent; this is a checklist/status-code divergence.

8. **Shutdown logs spurious ERROR lines** for normal `Server closed` / closed-listener errors; both instances still exit 0 (F6).

9. **No systemd activation check**: `systemctl status`, kill-and-restart and journal assertions require root/system state; unit files were verified statically only (R-061).

10. **No database or UI exists**: database operations and UI interactions are N/A (fresh source search found none), so no evidence can be produced for them and none is claimed.

11. **No versioned original spec** exists in the tree or any git revision, so WebSocket/HTTP-3 obligations (A-001/A-010) cannot be certified either way. Full compliance cannot be certified until that document is supplied.

12. **Checklist R-071 count is stale** (238 tests / 71 files). Fresh inventory is 82 files / 265 top-level tests / 33 benchmarks; all tests pass, 2 Tor-only skips.


## 8. Ambiguities, conflicts, missing requirements and out-of-scope items (verbatim from checklist §9–§12)

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

### Empirical resolution note

- **X-003 / A-007 (SOCKS5 auth): RESOLVED by measurement.** With `auth.enabled: true` an unauthenticated SOCKS5 CONNECT was rejected (`curl: (97) No authentication method was acceptable`) and `--proxy-user <key>:<key>` returned HTTP 200. The README claim is correct; the analyst claims of "no SOCKS5 auth" are not. R-013 is marked compliant on this evidence.

- **X-001 / A-002 (rotation state)** remains a documentation/defaults divergence: production `config.yaml` disables legacy rotation while `defaults.go` enables it. The effective config was used for grading R-031; no speculative change was made.


## 13. Evidence index

| File | Contents |
|---|---|
| `final-evidence/00-environment.log` | timestamp, Go/lint tool versions, commit |

| `final-evidence/exit-codes.log` | exit status of every command in §3 and the probe scripts |

| `final-evidence/make-test.log`, `go-test.log`, `go-test-race.log`, `go-vet.log`, `gofmt.log` | full suite, race, vet, format |

| `final-evidence/make-build.log`, `make-cross-compile.log`, `binaries.log`, `version.log` | build and five target binaries |

| `final-evidence/make-lint.log`, `bench-smoke.log`, `startup-production.log`, `config-errors.log` | known failures and config rejection probes |

| `final-evidence/workflows.log` | no-auth and auth live workflow probes + shutdown logs |

| `final-evidence/targeted-probes.log` | CLI/env precedence, 407 headers, pre-bind conflict |

| `final-evidence/raw-probes.log` | hop-by-hop stripping and CONNECT body probes |

| `final-evidence/requirement-evidence-map.json` | R-ID → named tests, referenced files, PASS/SKIP classification |

| `final-evidence/requirement-test-map.json` | first-pass direct test-name mapping (raw) |

| Scratch: `/home/strong/.hermes/cache/scratch/final-verify/` | scratch configs, probe scripts, raw relay/target logs |


## 14. Sign-off

Acceptance criteria assessed: the application **builds and runs** (build/cross-compile/live probes), **critical functionality is verified** (proxy, SOCKS5, auth, SSRF, health, metrics, shutdown), **regressions are ruled out or documented** (305→341 PASS, 0 FAIL, F1 fixed; F2/F3/F4/F6/F7 unchanged; R-019 fixed and re-probed in follow-up `t_fecba6aa`), and this report **states compliance per requirement with supporting evidence**. Full compliance is **not** certified: partially compliant items and the missing original specification remain, as detailed above. No success claim in this report rests on an unexecuted command or a sibling task's summary alone.

