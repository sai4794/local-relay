# Applied fixes and regression coverage

Task: `t_c7e616a6` (safe fixes + regression tests). Repo: `/home/strong/local-relay`, base `1ec78f4`.
Issue IDs refer to `IMPLEMENTATION_MAP.md`; R-IDs to `REQUIREMENTS_CHECKLIST.md`; F-IDs to `BASELINE_REPORT.md`.
No destructive/irreversible operation was performed; no data was deleted; shipped config's topology/auth defaults were not changed.

## Verification executed (post-change)

```
GOROOT=/home/strong/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.11.linux-amd64
PATH=$GOROOT/bin:$PATH

go test -count=1 ./...            -> 11/11 packages ok, exit 0
go test -race -count=1 ./...      -> 11/11 packages ok, exit 0
go vet ./...                      -> exit 0, no output
make build                        -> exit 0 (relay built, -trimpath)
make cross-compile                -> exit 0 (linux amd64/arm64, darwin arm64/amd64, WINDOWS amd64)
./relay --version                 -> 1ec78f4-dirty, commit 1ec78f4, go1.26.11
```

Runtime smoke test (isolated scratch config `relay-noauth.yaml`, no Tor daemon, local
Python upstream on 127.0.0.1:19999; all listeners closed afterwards):

| Probe | Result |
|---|---|
| proxy origin-form `/healthz` | `503 {"status":"degraded","mode":"multi_tor"}` (now reflects router; was hardcoded 200) |
| admin `/healthz`, `/readyz` | 503 / 503 (degraded, correct) |
| HTTP bypass forward through proxy | 200 |
| SOCKS5 bypass forward through proxy | 200 |
| standalone `/metrics` | 200 |

New/updated automated tests: 13 new test files + 3 updated test files. In every case the
test was written first and observed failing for the expected reason before the fix.

## Fixes applied

| ID | R-ID | Fix | Regression test |
|---|---|---|---|
| H-01 | R-058 | Panic in serving/health/metrics goroutine now cancels the process context (supervisor can restart); serve errors in `runComponent` cancel too | `cmd/relay/panic_containment_test.go` |
| H-02 | R-066, R-070 | Probe claim separated from verdict: `evalExcluded` reports ownership, `pickBestEx` releases claims of losing multitor candidates, pool slots release losers via deferred cleanup | `internal/backend/concurrency_fixes_test.go`, updated `quarantine_test.go` (old test pinned the leaky behavior) |
| H-03 | R-026, R-027, R-068 | `resetAll` bumps generation and evicts under one `connPoolMu` hold; `putConnGen` re-checks the checkout generation under that lock and closes mismatches | `TestPool_PutConnStaleGenerationClosed` |
| H-04 | R-066, R-067, R-070 | Dial-failure retry re-checks quarantine via `evalExcluded`, skips excluded candidates and releases only probes it claimed | covered by `evalExcluded`/selection tests; retry gate is the same predicate |
| M-01 | R-043, R-049 | `config.LoadUnvalidated` parses without validating; `main` applies CLI overrides then validates once (`Load` keeps validating for other callers) | `internal/config/overrides_test.go` |
| M-02 | R-038–R-040, R-050 | `PROXY_AUTH_ENABLED` and `-auth` explicitly control the auth gate; `PROXY_AUTH_KEY` alone keeps its legacy enable behavior | `TestEnvOverrides_AuthEnabledToggle*` |
| M-03 | R-033, R-035, R-048 | SSRF blocker is always constructed; empty CIDR list no longer disables scheme gating | `cmd/relay/security_setup_test.go` |
| M-04 | R-007, R-040, R-052 | Proxy-port `/health(z)` is behind auth and only intercepts origin-form requests; health comment/README corrected | `TestProxyHealthAliasRequiresAuth`, `TestProxyHealthAliasAbsoluteFormIsForwarded` |
| M-05 | data correctness | Over-cap bodies return nil `GetBody`, `ContentLength=-1`; a redirect can no longer replay a truncated 1 MiB prefix | `TestProxyOverCapBodyRedirectDoesNotReplayTruncatedPrefix` |
| M-06 | R-029, R-069 | Auth-rejection streak resets only on success; transient errors leave it intact | `internal/backend/lifecycle_fixes_test.go` |
| M-07 | R-021, R-057 | `Start` shuts down its own daemons on ctx cancellation / zero-ready timeout; never kills a superseded generation's instances | `TestTorLifecycle_StartCancellationCleansUpChildren` |
| M-08 | R-036 | Rate-limit bucket key canonicalizes numeric IP spellings (decimal/hex/octal/short) | `TestFirewallRateLimitCanonicalIPKey` |
| M-12 | R-047, R-050 | Unparseable `POOL_*` env overrides now fail fast with the variable name; leniency-pinning test updated | `TestEnvOverrides_RejectUnparseablePoolValues`, updated `pool_config_test.go` |
| M-13 | R-057 | `waitForRotator` bounds the shutdown wait; a stuck callback no longer blocks SIGTERM | `TestWaitForRotator_Bounded` |
| M-14 | R-029, R-057 | Typed backend sentinels (`ErrControlNotConfigured`, `ErrControlUnreachable`, `ErrControlAuthFailed`, `ErrControlAuthRejected`) plus `errors.Is` classification; string matching remains only as fallback | `cmd/relay/control_class_test.go` |
| M-15 | R-061 | README documents the required unit install + daemon-reload; both units get restart limits, relay gets `TimeoutStopSec=20`; tor-local conflict with multi-tor documented | doc/unit change (no runtime test available without systemd) |
| F1 | R-060 | Platform-split liveness probe (`liveness_unix.go` / `liveness_windows.go`) — Windows cross-compile now succeeds | `make cross-compile` (all five targets) |
| F5 / L-16 | R-052, R-053 | Proxy-port health reflects `router.IsHealthy()` with 503/degraded when all backends are down | `TestProxyHealthAliasReflectsRouter` |
| L-01 | R-024 | Single `normalizeBypassHost` used by config, lookup and dial paths; `[::1]` now matches | `TestBypassHosts_IPV6BracketNormalization` |
| L-02 | R-009, R-010 | Outbound SOCKS5 emits ATYP 0x01/0x04 for IP literals instead of mislabeling them as domains | `TestOutboundSOCKS5_IPv6LiteralUsesATYP4` |
| L-04 | R-008, R-012 | Empty SOCKS5 method list replies 0xFF; non-zero RSV rejected with 0x01 | `TestSOCKS5EmptyMethodListRejected`, `TestSOCKS5NonZeroRSVRejected` |
| L-05 | suspected | Raw query is re-encoded only when a matching proxy key was actually stripped | `TestProxyQueryRawPreservedWhenNothingStripped` |
| L-11 | R-038 | One `APIKeyAuth` instance shared by proxies, admin health and metrics | code change, covered by existing auth tests |
| L-13 | R-060 | `BUILD` derived from commit time, `-trimpath` on all builds, `.PHONY` includes `install`/`run` | `make build`, `make cross-compile` |
| L-17 | quality | Removed redundant no-op `stripConnectionTokens` call before header copy | covered by existing response-stripping tests |

## Not changed (with reason)

| ID | Reason |
|---|---|
| M-09 | Global connection limit / goroutine cap is a new policy with no configured default in the spec; adding one speculatively could break legitimate concurrency. Needs a capacity decision. |
| M-10 | Adding write/idle deadlines risks cutting off documented long LLM/SSE streams; the SSE exemption is not configurable. Needs an explicit timeout policy. |
| M-11 | Removing `?api_key=` auth is a breaking client change and the requirement conflicts are unresolved (X-003/A-007); current code already strips the key before forwarding. |
| L-06 | Replacing hand-rolled Prometheus output with `prometheus/client_golang` is a dependency/format rewrite, not a safe fix; output is already valid exposition. |
| L-07 | Time-based rotation/jitter/TLS fingerprint are recommendation-level (not MUST) and the rotation scheme is an unresolved config conflict (X-001/A-002). |
| L-08 | WebSocket requirement is unverifiable: the cited original spec is absent from the tree and all git revisions (A-001/M-001). |
| L-09 | Changing the shipped `multi_tor.data_dir` default would invalidate existing operator paths/permissions. Ambiguous. |
| L-10 | Keying port collisions by host+port would permit same-port binds on different interfaces but treat `localhost`/`127.0.0.1` as distinct despite OS-level conflict; needs a normalization decision. |
| L-12 | Pre-binding real proxy listeners instead of probe-bind is a listener-ownership refactor with restart/TOCTOU implications; current code already pre-binds health. |
| L-14 | Validating control cookie/password presence would reject the shipped config (which sets neither) — behavior change, not a safe fix. |
| L-15 | Probe-failure backoff would alter quarantine timing semantics that existing tests pin as intentional. |
| F2 | 56 golangci-lint findings under default v2 rules; no repository linter config exists. Adopting a ruleset is a policy decision. |
| F3 | `BenchmarkTuneTCP` hangs (accept with no dialer); benchmark-only, no production impact. Left for the benchmark owner. |
| F4 | Production `config.yaml` references Tor paths absent on this host — environment mismatch, not an application defect; changing shipped paths would be speculative. |

No other requirement conflicts were silently resolved. All changes are confined to this workspace.

## Follow-up fix: R-019 hop-by-hop token stripping (task `t_fecba6aa`)

**Root cause (verified in Go source before any change).** `net/http`'s
`readTransfer` calls `shouldClose(..., removeCloseHeader=true)`
(`$GOROOT/src/net/http/transfer.go:502,748-763`), which deletes the response
`Connection` header from `Response.Header` whenever it carries the `close`
token. `forwardResponse` copied `resp.Header` and then called
`stripConnectionTokens(w.Header(), resp.Header)`, so the token list was
already gone: only the fixed hop-by-hop names were stripped and
`X-Secret-Hop`, named by `Connection: X-Secret-Hop, close`, was forwarded.

**Fix (one root-cause change, confined to `internal/proxy/http.go`).** The
transport dial is wrapped by `wrapDialWithHopCapture`, which tees the
server-to-client bytes of the raw response head into a per-request
`*responseHeadCapture` carried on the request context. After `client.Do`,
`restoreConnectionHeader` puts the exact wire-level `Connection` values back
into `resp.Header` **only** when net/http removed them; the existing
`stripConnectionTokens` + `stripHopByHopHeaders` path then removes every
token-named header and `Connection` itself. Request headers, credential
stripping and the SSE forwarding loop are unchanged. The head parser rejects
non-`HTTP/` first bytes, so TLS ciphertext cannot be mistaken for tokens.

**Test-first evidence (RED observed before GREEN).** New
`internal/proxy/r019_hop_by_hop_test.go` uses a raw-socket upstream emitting a
byte-exact `Connection: X-Secret-Hop, close` response:
- `TestR019UpstreamConnectionTokenHeaderIsStripped` — RED: `X-Secret-Hop leaked through proxy = "SHOULD-BE-STRIPPED"`; GREEN: PASS.
- `TestR019CredentialStrippingWithConnectionTokens` — RED: same leak (both credential assertions already passed); GREEN: PASS, `X-Api-Key` and `Proxy-Authorization` still absent upstream.
- `TestR019SSEStreamStripsConnectionTokens` — RED: same leak on `text/event-stream`; GREEN: PASS, both events still delivered.

**Fresh verification after the fix** (logs: `final-evidence/r019-fix-validation.log`):
```
go test -count=1 ./...            -> 11/11 packages ok, exit 0
go test -race -count=1 ./...      -> 11/11 packages ok, exit 0
go vet ./...                      -> exit 0
make build                        -> exit 0
go test -count=1 -run TestR019 -v ./internal/proxy/ -> 3/3 PASS, exit 0
```
Raw reprobe with the rebuilt binary (`final-evidence/r019-fix-raw-probe.log`,
repeat in `r019-fix-raw-probe-run2.log`): the client response now contains
only `HTTP/1.1 200 OK`, `Content-Length`, `Content-Type`, `Date` and `hello`
— no `Connection`, no `X-Secret-Hop`. Before the fix the same probe returned
`X-Secret-Hop: SHOULD-BE-STRIPPED` (`final-evidence/raw-probes.log`).

**No unrelated behavior change.** A control binary built from the identical
tree with only this change reverted still leaks `X-Secret-Hop` and produces a
byte-identical R-014 CONNECT reply (`200 OK` + `Date`, no body), matching the
fixed binary's R-014 output (`final-evidence/r019-fix-control-probe.log`).

**Scope note.** Raw-head capture is on the plaintext upstream hop; HTTPS
upstreams are TLS-wrapped by `net/http` above the dialed connection, so token
recovery does not apply to those responses. The R-019 acceptance case
(`Connection: close` plus token-named headers from a raw upstream) is covered
by the automated regressions and the live probe above.

