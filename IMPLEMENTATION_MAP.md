# Local Relay — Implementation Map & Prioritized Issue Inventory

Task: `t_2c158115` (read-only mapping). Repo: `/home/strong/local-relay`, git HEAD `1ec78f4`, clean tracked tree at audit start.
Companion artifact: `REQUIREMENTS_CHECKLIST.md` (R-001…R-075, produced by sibling task `t_169f8821`). Requirement IDs below refer to that file.

**No application code was modified by this task.** The only new file is this report. `git status` at audit start already showed untracked `REQUIREMENTS_CHECKLIST.md` and four `relay-*` cross-compile binaries from a concurrent sibling worker; those are not from this task.

---

## 0. Method and verification evidence

Approach: five parallel, scope-limited static investigations (entrypoint/config/deploy; auth/security; request handling; backend/Tor/pool; historical-audit reconciliation + test inventory), followed by **independent re-verification of every reported high/medium claim by reading the cited lines directly**. Claims in the repository's markdown audit docs were treated as untrusted leads, never as evidence.

Verification actually executed (Go binary found in module cache, not on `PATH`):

```
GOROOT=/home/strong/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.11.linux-amd64
PATH=$GOROOT/bin:$PATH

go version                 -> go version go1.26.11 linux/amd64
go test -count=1 ./...     -> ok, 11/11 packages, exit 0
go test -race -count=1 ./... -> ok, 11/11 packages, exit 0
```

Per-package `ok`: `cmd/relay`, `internal/auth`, `internal/backend`, `internal/config`, `internal/health`, `internal/metrics`, `internal/proxy`, `internal/rotate`, `internal/security`, `internal/stream`, `internal/transport`.

Test inventory (measured, not inferred): **71 `*_test.go`, 238 `func Test…`, 33 `func Benchmark…`**.

Tooling caveat discovered and neutralized: the Hermes output layer rewrites some `=` characters to `***` in displayed text (e.g. `apiKey :*** cfg.Auth.APIKey`). Raw bytes at `cmd/relay/main.go:604` are `3a 3d` (`:=`). **No issue in this report is based on that display artifact.**

### Scope note: frontend / database / migrations / background jobs

There is no frontend, database, migration system, or external job queue in this repository. Measured: 154 files total, 102 `.go`, 20 `.md`, 13 `.json`, 4 `.sh`, 2 `.service`, 1 `.yaml`; no SQL, no JS/TS, no ORM/driver in `go.mod` (only standard library, `gopkg.in/yaml.v3`, `golang.org/x/net`, `golang.org/x/sync`). The requirements checklist likewise contains no frontend/DB/migration items. "Background work" is in-process only: the 30 s monitor loop (`cmd/relay/main.go:638-683`), 5 min cache eviction (`main.go:35-37`), and rotator goroutine. Absence of frontend/DB is therefore **not** recorded as a defect; asserting one would be an unverified claim.

---

## 1. Architecture map

### 1.1 Package responsibilities (requirement IDs from REQUIREMENTS_CHECKLIST.md)

| Component | Files | Responsibility | Requirements handled |
|---|---|---|---|
| Composition root | `cmd/relay/main.go` (938 lines) | flags → config → backend stack → router → security → proxies → health/metrics → serve → shutdown | R-021, R-026, R-029, R-031, R-040, R-043, R-049–R-051, R-057–R-061 |
| Configuration | `internal/config/{config,defaults,env,validate,validate_address}.go` | defaults → strict YAML (`KnownFields(true)`, single doc) → env → `Validate`; topology predicates; port-collision map | R-043–R-048, R-050, R-051 |
| HTTP proxy | `internal/proxy/http.go` (~1040 lines), `clear.go`, `outcome.go` | forward/CONNECT, header-mode target (`x-target-url`/`x-relay-target`/`x-relay-path`), shared DNS verdict, body buffering/retry, 429/503 feedback, SSE flush, hop-by-hop stripping | R-001, R-003–R-007, R-014–R-019, R-026, R-027, R-033, R-036, R-037, R-041 |
| SOCKS5 proxy | `internal/proxy/socks5.go` | RFC1928 greeting, RFC1929 user/pass, IPv4/domain/IPv6 request parsing, guards, tunnel relay | R-002, R-008–R-013, R-025, R-034, R-038, R-042 |
| Outbound transport | `internal/transport/socks5.go` | SOCKS5 client used to reach Tor; per-circuit isolation user | R-021, R-022 |
| Stream | `internal/stream/sse.go` | SSE detection/copy and bidirectional `Relay` with `CloseWrite` half-close | R-015–R-018, R-027 |
| Backend routing | `internal/backend/router.go` | direct backend + proxied backends; bypass map (exact + dot-suffix); fail-closed when no backend healthy | R-023–R-025 |
| Tor lifecycle | `internal/backend/torlifecycle.go` | spawn N daemons, SOCKS/control ports, bootstrap probes, health/respawn, NEWNYM/DROPGUARDS, exit-IP cache | R-021, R-026, R-028–R-030, R-069 |
| Backends | `internal/backend/{multitor,pool,tor,tcp,control}.go` | round-robin multi-Tor, circuit-pool slots, single Tor, control protocol | R-021–R-023, R-026, R-028–R-030, R-064, R-068, R-069 |
| Scoring/quarantine/outcomes | `internal/backend/{score,quarantine,outcome}.go` | EWMA latency, success-rate quality, effective load, Po2/weighted selection, Active→Quarantined→Probation state machine, attributed 429/503/dead-tunnel feedback | R-064–R-067, R-070 |
| Security | `internal/security/{ssrf,firewall,resolver,canonical_ip}.go` | blocked CIDR verdicts, per-host token bucket, shared TTL/singleflight DNS cache, numeric-IP canonicalization, `.onion` exemption | R-033–R-036, R-041, R-042 |
| Auth | `internal/auth/apikey.go` | constant-time key compare across `Proxy-Authorization`, `X-Api-Key`, `?api_key=***`, `Authorization`; credential stripping | R-007, R-013, R-038–R-041 |
| Health/metrics | `internal/health/health.go`, `internal/metrics/metrics.go` | `/health`, `/healthz`, `/readyz`, `/metrics`, separate Prometheus listener, gauge registry | R-052–R-056 |
| Rotate | `internal/rotate/rotator.go` | request-count trigger, cooldown on `ForceRotate`, `Wait`/shutdown guard | R-031, R-032, R-057 |
| Build/deploy | `Makefile`, `local-relay.service`, `tor-local.service`, `config.yaml` | ldflags version stamping, cross-compile, systemd units, shipped config | R-059–R-061 |

### 1.2 Startup / control flow

```
main()  [main.go:39]
  flags (c/config/version/v/http/socks5/log-level)      :40-47
  config.Load: defaults -> YAML(KnownFields, 1 doc) -> env -> Validate :55 (config.go:120-162)
  applyFlagOverrides -> Validate again                   :60-64
  setupLogger -> signal.NotifyContext                    :66-77
  buildBackendStack: multi_tor > pool > single-tor > (unreachable) direct :79,186-265
  buildRouter(direct + chosen proxy backend; bypass hosts)               :80,331-353
  setupSecurity(shared Resolver -> SSRFBlocker? + Firewall)              :81,362-389
  buildRotator (disabled in multi-tor; config disables it)               :82,554-585
  verifyControlAuthAtStartup (failExit on definitive rejection)          :84-87,414-457
  buildProxies(HTTP + SOCKS5, auth middleware, firewall, rotator, SSRF)  :89-90,589-615
  health Bind + probe-bind HTTP/SOCKS5/metrics -> failExit on failure    :99-139,509-540
  startServers / health listener / metrics / 30s monitor                 :142-144
  "Local relay is ready" -> <-ctx.Done() -> shutdown                     :146-153,890-911
```

### 1.3 Request flow (HTTP)

```
ServeHTTP (http.go:86)
  |- path /health|/healthz -> local JSON 200, BEFORE auth           :87-96  [issue M-04]
  |- auth.Check (407 on failure)                                    :98-100
  |- CONNECT -> handleConnect :109 ; else handleHTTP :371
handleHTTP:
  recordRotation() (before any validation)                          :372    [issue L-03]
  header-mode target rewrite; skip guards for bypass hosts          :374-475
  singleLookupVerdict -> firewall.AllowIPs + ssrf.CheckHost over ONE lookup :488-513
  pin verified IPs via WithPinnedDial ONLY for bypass hosts          :158-160 / :630-632
  client.Do with retry on 429/503/dead tunnel; body <=1 MiB replayable;
  GetBody set for ALL bodies incl. over-cap                          :569-659 [issue M-05]
  forwardResponse: strip hop-by-hop, per-read Flush for SSE          :781+
  outcome feedback -> quarantine/NEWNYM via attributed claim        (outcome.go)
```

### 1.4 Request flow (SOCKS5) and backend selection

```
Serve loop (socks5.go:58) -> greeting/method(s) -> RFC1929 auth -> request :
  recordRotation() :114 -> loopback/bypass waiver :305 -> singleLookupVerdict :307-315
  -> WithPinnedDial for bypass only :329-330 -> router.DialContext :333
Router.DialContext (router.go:100+):
  bypass host -> direct backend, no Tor fallback, no range re-check  :117-126
  otherwise -> healthy proxy backend(s), fail-closed when none      :128+
MultiTorBackend.DialContext:
  ready = instances filtered by IsReadyLive ONLY                    :213-218
  selectInstance -> pickBestEx -> isExcluded (CLAIMS PROBE)          :505-562,678-701
  dial via SOCKS5 isolation user; on failure retry RAW ready slice   :279-303 [issues H-02,H-04]
CircuitPoolBackend: slots + pooled post-CONNECT tunnels, gen-stamped on NEWNYM
  resetAll: evictConns() then poolGen.Add(1)                         :795-801
  conn wrapper checks gen, then putConn re-loads poolGen under lock  :1056-1059,1181-1187 [issue H-03]
```

### 1.5 Configuration actually shipped (`config.yaml`)

multi_tor enabled (3 instances, ports 9150/9160, `rotate_after: 0`); circuit pool enabled with weighted/Po2 tuning and quarantine; bypass hosts `localhost`, `127.0.0.1`, `codebuff.com`, `www.codebuff.com`, `api.codebuff.com`; global count rotation **disabled**; `auth.enabled: false`; 17 blocked CIDRs; 32 MiB body cap; health on `127.0.0.1:18888`; metrics **disabled**. README's configuration reference omits the `[pool]` section and the `TOR_LIBRARY_PATH` behavior is documented in prose only.

---

## 2. Prioritized issue inventory

Severity rubric: **High** = service-availability, isolation, or circuit-integrity failure reachable in the shipped topology; **Medium** = security/ correctness/operational defect with a concrete trigger; **Low** = protocol strictness, documentation, code quality, or defense-in-depth gap. Every entry below was re-read directly in current HEAD. "Static" = code-trace verified; the race detector passed but does not cover the described interleavings (no targeted test exists).

### 2.1 High

| ID | Issue | Evidence (file:line) | Reproduction / trigger | Safe fix |
|---|---|---|---|---|
| **H-01** | Panic in any serving goroutine is logged but never stops the process. `recover` calls only `logger.Error`; `stop()` is only reached on the `serve()` error path. Health/metrics goroutines have the same shape. A dead listener can coexist with a live PID and the "ready" log, so `Restart=always` never fires. (R-058) | `cmd/relay/main.go:619-631` (`startServerGoroutine`), `:878-887` (`runComponent`), `:843-854` (metrics), ready log `:146` | Force a panic in an HTTP/SOCKS5 handler or health handler → goroutine exits, process survives, port no longer served. | Call `stop()` (and `failExit` before ready) inside `recover`; add a regression test that injects a panic into a served handler and asserts process-context cancellation. |
| **H-02** | Quarantine probe slots are claimed by `isExcluded()` during candidate *evaluation*, not when dialing. `pickBestEx` evaluates every candidate and serves one; losers keep `probeInFlight=true` until 60 s+ stale expiry. With two probation candidates one served dial leaves the other falsely "probe in flight", suppressing its only probe and potentially failing closed. (R-066, R-070) | `internal/backend/multitor.go:505-562`, `:678-701`; `internal/backend/quarantine.go:182-191`; pool analogue `internal/backend/pool.go:320-369` | Two instances in Probation with expired holds; one `selectInstance` call; both `probeInFlight` become true, only one is dialed (test at `quarantine_test.go:465-474` pins both claimed). | Split verdict from claim: make exclusion read-only, call `claimProbe` only on the winner immediately before dial; release on dial failure. Add a test asserting losers retain `probeInFlight=false`. |
| **H-03** | Circuit-pool NEWNYM isolation TOCTOU: `resetAll` evicts **before** bumping `poolGen`; a connection wrapper checks its generation outside `connPoolMu` and `putConn` later stamps a **fresh** generation under the lock. A pre-rotation tunnel can be re-pooled with the new generation and reused after NEWNYM. (R-026, R-027, R-068) | `internal/backend/pool.go:795-801`, `:1056-1059`, `:1145-1187` (stamp at `:1185`); `pool_gen_test.go:43-56` covers only put-then-bump | Interleave: wrapper reads `w.gen == poolGen == 1`; `resetAll` evicts and bumps to 2; wrapper's `putConn` appends the old socket stamped gen=2; next dial reuses a burned circuit. | Bump generation and evict atomically under `connPoolMu`; pass checkout gen into `putConn` and verify under that same lock, closing mismatches. Add a deterministic interleaving test. |
| **H-04** | MultiTor dial-failure retry iterates the raw `ready` snapshot (filtered only by `IsReadyLive`) with **no** `isExcluded`/`claimProbe` check, so retries can use quarantined instances, issue a second concurrent probe against a probation slot, or reset counts via a success that never passed a probe. (R-066, R-067, R-070) | `internal/backend/multitor.go:213-218`, `:279-303`; quarantine entry only inside selection at `:678-701` | Instance 1 fails SOCKS handshake while instance 2 is quarantined/held → retry at `:286-300` dials instance 2 anyway. | Carry per-candidate verdicts from selection into retry; skip excluded candidates; if a probation candidate must be retried, claim explicitly and release on failure. |

### 2.2 Medium

| ID | Issue | Evidence | Reproduction / trigger | Safe fix |
|---|---|---|---|---|
| **M-01** | `Load()` validates *before* CLI overrides; a high-precedence flag cannot repair an invalid lower-precedence value, contradicting documented precedence. (R-043, R-049) | `internal/config/config.go:158-162`; `cmd/relay/main.go:55-64` | `logging.level: bogus` in YAML + `-log-level debug` → `Load` fails before flags apply. | Make `Load` parse-only (or add skip-validation), apply CLI overrides, validate once in `main`. |
| **M-02** | `PROXY_AUTH_KEY` unconditionally sets `Auth.Enabled=true`; no env/CLI switch can turn it off, overriding `auth.enabled: false` silently. (R-038–R-040, R-050) | `internal/config/env.go:19-22`; no auth flag `main.go:40-47` | `export PROXY_AUTH_KEY=…` with `auth.enabled: false` → auth on, and no flag to disable. | Add explicit `PROXY_AUTH_ENABLED`/`-auth` toggle or make the env var key-only; document precedence. |
| **M-03** | Empty `blocked_networks` skips `SSRFBlocker` construction entirely; both scheme checks are gated on `p.ssrf != nil`, so defense-in-depth disappears. Firewall defaults still block private ranges, so this is weakening rather than full SSRF removal. (R-033, R-035, R-048) | `cmd/relay/main.go:366-370`; `internal/proxy/http.go:393`, `:475-478`; validation does not require non-empty (`internal/config/validate.go:230-235`) | `security.blocked_networks: []` → no blocker; `x-target-url: gopher://…` skips the scheme gate. | Always construct the blocker (empty CIDR list allowed) or extract stateless scheme validation. |
| **M-04** | Proxy-port `/health` and `/healthz` return 200 JSON **before** API-key auth, and absolute-form requests (`GET http://upstream/health`) are intercepted instead of forwarded. Contradicts README:147 and `health.go`'s own comment. (R-007, R-040, R-052) | `internal/proxy/http.go:86-100`; `internal/health/health.go:34-39`; `README.md:147` | `curl -x http://127.0.0.1:18080 http://any/healthz` → `{"status":"ok",...}` without a key; a real upstream `/health` becomes unreachable through the proxy. | Restrict the shortcut to origin-form (`r.URL.Host == "" && r.URL.Scheme == ""`) and place it after auth; align comment and README. |
| **M-05** | Over-cap request bodies get a non-nil `GetBody` that replays the 1 MiB prefix plus an already-consumed `r.Body`; the intended `GetBody=nil` branch is unreachable. On 307/308 redirects or retries the upstream receives a truncated/corrupt body. (data correctness) | `internal/proxy/http.go:569`, `:583-606`, `:649-659` (else-if dead) | Body >1 MiB + upstream 307/308 → Go transport calls `GetBody`, redirect target gets prefix+EOF. | Return nil `GetBody` in the over-cap case; set `ContentLength=-1` for the single-shot reader; add a large-body redirect test. |
| **M-06** | Tor control auth-failure strike counter is cleared on *every* non-"auth rejected" error (timeouts/refusals), defeating "3 consecutive rejections" recycle. (R-029, R-069) | `internal/backend/torlifecycle.go:772-796` (`noteAuthResult`), recycle gate `:916-922`; `cookie_evict_test.go:180-186` only tests clean rejections | reject, reject, timeout, reject → count returns to 0; instance never recycled. | Reset only on `err == nil`; leave count untouched on other errors. |
| **M-07** | `TorLifecycle.Start` cleans up spawned daemons on spawn errors but not on `ctx.Done`, zero-ready deadline, or superseded-generation returns; daemons stay alive and can make a later `Start` mark new instances ready via old listeners. (R-057, R-021) | `internal/backend/torlifecycle.go:616-620` vs `:636-638`, `:643-648`, `:652-658`, `:678-693`; error only logged at `main.go:209-211` | Start with a Tor binary that never bootstraps and cancel ctx → orphan children + port collision on restart. | Call `shutdownAllLocked` on every failure return of `Start` under the same lock. |
| **M-08** | Per-host rate-limit key is the raw hostname spelling taken **before** numeric canonicalization, so decimal/hex/octal/short IPv4 spellings each get a fresh bucket. (R-036) | `internal/security/firewall.go:186-195`; `internal/security/ssrf.go:213-282` accepts alternate spellings; `regression_ssrf_test.go:31-36` codifies allowing them | With limit 1/burst 1: `8.8.8.8` then `134744072`, `0x8.8.8.8`, `08.08.08.08` all allowed. | Key the limiter on canonical IP (`parseNumericIP(...).String()`) and reuse that canonicalization for cache/verdict. |
| **M-09** | No connection limit or bounded goroutine pool anywhere in `cmd/` or `internal/`; only a per-host token bucket and SOCKS5 handshake timeout. Slowloris-style resource exhaustion is bounded only by `ReadHeaderTimeout`. (R-063, performance/DoS) | `internal/proxy/http.go:1011-1019`; `internal/security/firewall.go:93-133`; `internal/proxy/socks5.go:75`; grep for maxconn/semaphore returns nothing | Open many connections to distinct hosts / incomplete SOCKS handshakes → unbounded goroutines and sockets. | Add a global semaphore with a configured cap and per-connection deadlines; expose a metric for rejected connections. |
| **M-10** | `WriteTimeout: 0` on the HTTP proxy and an unbounded `context.WithCancel` SOCKS5 relay (HTTP relay has a 30 min timeout) → stuck peers can hold goroutines indefinitely. (R-020, R-063) | `internal/proxy/http.go:1016`, HTTP relay timeout `:218`; `internal/proxy/socks5.go:318-319` | Establish a tunnel and stop reading without closing → no deadline evicts it on SOCKS5 path. | Apply a configurable idle/write deadline to both relay paths (preserve the documented long SSE exemption explicitly). |
| **M-11** | API key is still accepted via `?api_key=`; stripping before forwarding mitigates but does not remove URL/referrer/log leakage risk. (R-041) | `internal/auth/apikey.go:147-151`; partial strip `internal/proxy/http.go:526-534`, `:551-565` | Send `GET http://target/?api_key=<key>` with no header → authenticated; key transits client/proxy logs. | Deprecate/remove query-parameter auth; if retained, add a warning metric and require an explicit opt-in. |
| **M-12** | `POOL_*` env overrides silently swallow parse failures (`if err == nil { assign }`, no else), unlike strict YAML decoding; a typo keeps defaults with no warning. (R-047, R-050) | `internal/config/env.go:35-88`; `internal/config/pool_config_test.go:98-161` codifies lenient behavior | `POOL_EWMA_ALPHA=0.5abc POOL_QUARANTINE_SECS=xyz` → defaults used, no error. | Fail fast on parse errors (or emit a warning), and update the test that pins leniency. |
| **M-13** | `shutdown()` waits on `rotator.Wait()` with no timeout before any proxy/metrics/Tor cleanup; a stuck rotation callback blocks SIGTERM until SIGKILL, skipping Tor shutdown. (R-057) | `cmd/relay/main.go:890-908` (`Wait()` at `:893`, timeout context only created at `:896`) | Block a `ForceRotate` callback → SIGTERM never completes. | Run `Wait()` under a bounded `select` using the 10 s shutdown context. |
| **M-14** | Startup fail-fast classifies backend errors by `strings.Contains` on message text; reworded or untyped errors flip "degrade fail-closed" into process exit (or vice versa). (R-029, R-057) | `cmd/relay/main.go:414-464` (`:421-442` substring switch, `isTimeoutErr` `:461-464`), failExit `:84-87` | Return an error not containing the four exact substrings and not implementing `net.Error` → `failExit`. | Export typed/sentinel errors from backend packages; use `errors.Is`/`errors.As`. |
| **M-15** | README systemd instructions cannot work as written (unit in repo root is not discovered by name), and both units lack restart limits/hardening; `tor-local.service` may run a second Tor stack alongside managed multi-tor. (R-061) | `README.md:56-60`; `local-relay.service:1-20` (`Restart=always`, only `NoNewPrivileges`); `tor-local.service:1-18`; `config.yaml:6-13` | `sudo systemctl enable --now local-relay.service` from repo root → unit not found; repeated bind failures restart Tor every 3 s forever. | Document `install -m 644 … /etc/systemd/system/` + `daemon-reload`; add `StartLimitIntervalSec/Burst` and hardening; clarify/order the two Tor units. |

### 2.3 Low

| ID | Issue | Evidence | Suggested fix |
|---|---|---|---|
| L-01 | Bypass canonicalization strips IPv6 brackets in `isBypassHost`/dial but not in `SetBypassHosts`; configuring `[::1]` never matches. (R-024) | `internal/backend/router.go:46-51` vs `:64-66`, `:104-108` | One shared normalizer on both paths. |
| L-02 | Outbound SOCKS5 client always emits ATYP `0x03` (domain), so IPv6-literal targets are sent as a "hostname" and fail. (R-009, R-010) | `internal/transport/socks5.go:84-100` (`:97`) | Emit `0x04`+16 bytes for `net.ParseIP` non-IPv4, `0x01`+4 for IPv4. |
| L-03 | Rotation counter increments before SSRF/firewall/body validation; rejected requests still churn circuits. (R-031) | `internal/proxy/http.go:372`; `internal/proxy/socks5.go:114`; `internal/rotate/rotator.go:38-57` | Count only requests that pass guards, immediately before dial. |
| L-04 | SOCKS5 strictness: method `0x00` selected when the client offers zero methods (RFC wants `0xFF`); RSV byte not validated. (R-008, R-012) | `internal/proxy/socks5.go:126-160`, `:198-206` | Reply `0xFF` for empty method list; reject `RSV != 0`. |
| L-05 | Any query string is re-encoded with `url.Values.Encode()` even when nothing was stripped, breaking signature-over-raw-query upstreams. **SUSPECTED** (depends on upstream signing). | `internal/proxy/http.go:534-539` | Re-encode only when a key was actually removed. |
| L-06 | Prometheus exposition is hand-rolled (`fmt.Fprintf` HELP/TYPE) instead of `prometheus/client_golang`; no library dependency. (R-054–R-056) | `internal/health/health.go:251-252`, `:372`, `:390-391`; `internal/metrics/metrics.go`; `go.mod` | Adopt the official client library or generate from a metric registry. |
| L-07 | No time-based rotation, jitter, TLS-fingerprint or header randomization; rotation is fixed-count only (and disabled in shipped config). Recommendation-level, not a MUST. (R-031, R-032) | `internal/rotate/rotator.go:12`, `:38-57`; `config.yaml:49-51`; no uTLS/header-randomization symbols | Add optional time-based trigger + jitter behind config if required by policy. |
| L-08 | No WebSocket upgrade path; `ServeHTTP` dispatches only CONNECT vs HTTP. "Missing spec item" is **unverifiable** — sibling task found the cited original spec absent from tree and history. | `internal/proxy/http.go:97-105`; sibling handoff A-001/M-001 | Do not "fix" until the requirement is sourced. |
| L-09 | Default `multi_tor.data_dir` is a predictable `/tmp/local-relay-tor`; no path validation. (R-021, R-048) | `internal/config/defaults.go:23`; `internal/config/validate.go:43-53` | Default to a 0700 user-owned state dir; validate absolute/non-empty. |
| L-10 | Port-collision validation keys on port number only, rejecting legitimate same-port/different-interface binds. (R-046) | `internal/config/validate.go:134-209` (`map[int]string`) | Key on normalized host+port. |
| L-11 | Two separate `auth.APIKeyAuth` instances are built (proxy and admin/metrics), so any future stateful auth would diverge. (R-038) | `cmd/relay/main.go:89-90` vs `:103`, used at `:779`, `:818` | Compute `authMw` once and reuse. |
| L-12 | `probeBind` has an acknowledged TOCTOU: another process can take the port between probe and `Start`, which then only logs the failure after the "ready" log. (R-059) | `cmd/relay/main.go:509-540` (comment `:514-518`), `:626-628`, ready at `:146` | Pre-bind real listeners (as health already does via `Bind`/`StartListener`) and pass them to `Serve`. |
| L-13 | Build not reproducible (`--dirty` + wall-clock BuildTime, no `-trimpath`/`CGO_ENABLED=0`); `.PHONY` omits `install` and `run`. (R-060) | `Makefile:2-13`, `:25-35` | Use commit time / `SOURCE_DATE_EPOCH`, add `-trimpath`, fix `.PHONY`. |
| L-14 | Backend control settings not validated (format of `control_addr`, existence of cookie file); shipped config omits both so hardcoded `/home/stb/...` default applies. (R-045, R-069) | `internal/config/validate.go:180-186`; `internal/config/defaults.go:15-16`; `config.yaml:17-21` | Validate host:port; require cookie or password auth when applicable; portable default. |
| L-15 | Dial-time probation probe failures release the claim with no backoff; a dead endpoint is re-probed at full request rate (tests mark this intentional). (R-070) | `internal/backend/multitor.go:274-283`; `internal/backend/pool.go:449-455`; `quarantine_test.go:584-614` | Synthesize a failure outcome and route through requarantine, or document the rate as accepted. |
| L-16 | Reported health/readiness (`IsReady`/kill probe) can disagree with dial eligibility (`IsReadyLive` cached dead verdict), so `/health` can advertise an instance the router will fail to dial. (R-052, R-053) | `internal/backend/multitor.go:704-707`, `:730` vs `:215`; `internal/backend/torlifecycle.go:159-162`, `:832-840` | Base health on the same verdict the dial path uses, or expose both. |
| L-17 | Code-quality nits: redundant `stripConnectionTokens(w.Header(), …)` on an empty header map; missing `Backend`-level doc for kill-switch reset semantics. | `internal/proxy/http.go:782` vs `:788`; `cmd/relay/main.go:299-309` | Remove the no-op call; keep comments tied to tests. |

---

## 3. Reconciliation with the repository's historical audit docs

Of 25 distinct material claims extracted from `ENGINEERING_AUDIT.md`, `AUDIT_VERIFICATION.md`, `ANALYST_0*.md`, and `ROUNDTABLE_0*.md` and checked against HEAD: **17 are already fixed**, **7 remain open**, **1 unverifiable**, **1 partially fixed**. Do not re-file the fixed items; current-code evidence follows in the companion data (abridged list):

| Historical claim | Status at HEAD | Current-code evidence |
|---|---|---|
| SSRF check→dial TOCTOU on bypass/direct dials; SOCKS5 no SSRF; per-request DNS | Fixed (partial — see caveat below) | one shared lookup `http.go:488-513`, `socks5.go:302-312`; pinned dials `http.go:158-160`, `:630-632`, `socks5.go:329-330`, `tor.go:333-352`; resolver `resolver.go:60-140` |
| SOCKS5 no auth; Tor control empty auth; IPv6 SOCKS encoding; data-race on bypassHosts; Scanner errors; unescaped control password; cookie re-read per NEWNYM; idle conn leak; `os.RemoveAll` on failed kill; rotator dead code; 429 handling; panic leaks; health unauthenticated | Fixed | `main.go:600-609`; `control.go:104-120`, `:116`; `socks5.go:262`; `router.go:25-27`; `sse.go:15-48`; `torlifecycle.go:459-460`, `:803-817`, `:1122-1158`; `pool.go:823-831`; `http.go:697-728`, `:1039`; `socks5.go:528`; `health.go:113-124` |
| Query-param API key | Still open | `apikey.go:147-151` → issue M-11 |
| Manual Prometheus text formatting | Still open | `health.go:251-252`, `:372` → L-06 |
| Time-based rotation / jitter / TLS fingerprint / header randomization | Still open | `rotator.go:38-57` → L-07 |
| No connection limits | Still open | no semaphore symbol → M-09 |
| HTTP `WriteTimeout:0` / unbounded SOCKS5 relay | Still open | `http.go:1016`, `socks5.go:318-319` → M-10 |
| WebSocket support | Still open but unverifiable requirement | `http.go:97-105` → L-08 |
| Rate-limiter map unbounded | Partially fixed | 10 min idle eviction `firewall.go:310-334`, no hard cap |
| `RedactBody` mutates input | Unverifiable | no `RedactBody`/`internal/log` in tree |

**Important caveat on the "SSRF TOCTOU fixed" historical claim:** two investigations disagreed. Re-verification shows `WithPinnedDial` is attached **only when `router.IsBypassHost(host)`** (`http.go:158-160`, `:630-632`; `socks5.go:329-330`), and `DirectBackend.DialContext` re-resolves when no pin is present (`tor.go:333-353`). A theoretical non-bypass DNS flip on a *direct-only* router is **not reachable through validated config**: `Validate` requires `backend.type == "tor"` (`validate.go:14-16`) and `IsTor()` then always constructs a Tor/pool/multi-tor backend (`config.go:167-177`, `main.go:189-262`). The remaining, non-fixable-by-pinning property is that Tor resolves hostnames at the exit node, so check-time DNS is best-effort for proxied traffic. This is why no High finding was filed for DNS rebinding.

### Documentation contradictions (verified)

- `README.md:147` and `internal/health/health.go:34-39` say proxy-port `/health(z)` is authenticated; `internal/proxy/http.go:86-100` serves it before auth → M-04.
- `README.md:105-119` documents `backend.control_addr`/`control_cookie_path` in `config.yaml`; shipped `config.yaml:17-21` sets neither → L-14.
- `ROUNDTABLE_04_OPS.md` claims the relay "cannot see HTTP response codes"; `internal/proxy/http.go:697-728` parses 429/503 (true only for opaque CONNECT tunnels).
- `ROUNDTABLE_01_NETWORK.md` "rotation is dead code" is stale: `ShouldRotate` is called (`http.go:1039`, `socks5.go:528`) but disabled by shipped config (a documented design conflict, not a code bug).
- `AUDIT_VERIFICATION.md` cites a literal `***` API key and `internal/log/redact.go`; current defaults use `""` (`defaults.go:44-46`) and the file does not exist.

---

## 4. Test inventory and coverage gaps

Measured: 71 test files / 238 test functions / 33 benchmarks; all ten production packages have tests (`cmd/relay` 3 files/11 tests; `internal/backend` 30/131; `internal/proxy` 9/33; `internal/config` 7/17; `internal/security` 7/14; `internal/health` 5/10; `internal/rotate` 3/7; `internal/auth` 3/5; `internal/stream` 2/5; `internal/metrics` 1/4; `internal/transport` 1/1). `go test ./...` and `go test -race ./...` both pass.

Gaps correlated with the issues above:

- No deterministic concurrency test for the pool generation interleaving (H-03) or quarantine-loser claim (H-02); `pool_gen_test.go:43-56` only covers put-then-bump; `quarantine_test.go:465-474` pins the losing-claim behavior as expected.
- No test asserting proxy-port `/healthz` auth behavior (M-04), large-body 307/308 replay (M-05), or alternate-IP-spelling rate limiting (M-08).
- No end-to-end test that an HTTP 429 triggers retry + rotation (only status-classifier unit tests).
- No tests for unimplemented features (time-based rotation, connection limits, WebSocket, jitter/TLS fingerprint) — do not add tests that assert absent behavior.
- No test for control `AUTHENTICATE` escaping or SOCKS5 BIND; no CONNECT relay-timeout test.

---

## 5. Verification limitations / honesty notes

- All concurrency findings are static code traces. The race detector passing does **not** disprove H-02/H-03/H-04 because no test exercises those interleavings.
- Runtime behavior against a real Tor daemon was not exercised; no Tor binary/config path in this environment is assumed functional. Reproduction steps involving Tor are code-level descriptions.
- Severity of L-05 is explicitly SUSPECTED (upstream-dependent); L-08's requirement cannot be confirmed because the cited original spec is absent.
- Historical audit-doc claims were used only as pointers; every issue above has a current-code citation.
- No claim in this report asserts that untested behavior is correct; the only correctness evidence offered is the actual `go test` / `go test -race` output quoted in §0.
