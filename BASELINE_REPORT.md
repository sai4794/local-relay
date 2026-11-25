# Baseline Build, Test & Workflow Evidence — local-relay

- Task: `t_8d334f6f` (baseline evidence only; **no issues fixed**)
- Workspace: `/home/strong/local-relay`
- Commit under test: `1ec78f4` (branch `pool-foundation`); build stamp `2026-11-25T10:48:18Z`
- Go toolchain used: `go1.25.0 linux/amd64` (locally installed in scratch — see Environment)
- Date: 2026-11-25 (IST)

---

## 1. Available commands discovered

| Source | Command | Purpose |
|---|---|---|
| `Makefile` | `make build` | `go build -ldflags … -o relay ./cmd/relay` |
| `Makefile` | `make clean` | remove `relay` and `relay-*` binaries |
| `Makefile` | `make test` | `go test -v ./...` |
| `Makefile` | `make lint` | `golangci-lint run ./...` |
| `Makefile` | `make cross-compile` | 5 targets: linux amd64/arm64, darwin arm64/amd64, windows amd64 |
| `Makefile` | `make install` | build + install to `/usr/local/bin` (not run — system change) |
| `Makefile` | `make run` | build + `./relay --config config.yaml` (not run — production config invalid here) |
| `README.md` | `go test -race ./...`, `go test -bench . ./...` | race detector, benchmarks |
| `cmd/relay/main.go` | `-c` / `-config`, `-http`, `-socks5`, `-log-level`, `-v`, `-version` | CLI flags |
| `README.md` | `PROXY_HTTP`, `PROXY_SOCKS5`, `PROXY_BACKEND_ADDR`, `PROXY_AUTH_KEY`, `PROXY_LOG_LEVEL`, `PROXY_HEALTH_ADDR`, `TOR_BINARY`, `TOR_LIBRARY_PATH` | env overrides |
| `bench/` | `run_all.sh`, `loadtest.sh`, `analyze.sh`, `profile.sh` | load-test tooling (not run; needs external load generator) |

**CI configuration: none found** (no `.github/workflows`, `.gitlab-ci.yml`, `Jenkinsfile`, or similar in the repo).

---

## 2. Environment limitations

1. **Go toolchain absent on host** (`go: command not found`; no `golangci-lint` either). To avoid system changes, Go 1.25.0 and golangci-lint v2.15.0 were downloaded and extracted into `/home/strong/.hermes/cache/scratch/go-toolchain/`. All results below use those binaries. `gcc` is present (`/usr/bin/gcc`), so `-race` works. `make` 4.4.1 present.
2. **Tor unavailable**: `config.yaml` sets `multi_tor.enabled: true` with `binary: /home/stb/tor/tor/tor` and `data_dir: /home/stb/tor/data_multi`; neither exists on this host. Real Tor routing, exit-IP rotation, NEWNYM/429/503 feedback, circuit-pool and multi-instance health could not be exercised.
3. **No database**: repo-wide search of `*.go` found no `sqlite`, `bbolt`, `sql.Open`, Postgres/MySQL/Redis usage. Database operations are **N/A**.
4. **No UI**: no `html/template`, `http.FileServer`, or frontend assets serving an application UI (only JSON health/metrics endpoints). UI interaction testing is **N/A**.
5. No app proxy env vars were set (`env | grep -i proxy` → none), so curl probes were not redirected by a system proxy.

---

## 3. Command results (exact commands)

| # | Command (as run) | Exit | Result / evidence |
|---|---|---|---|
| 1 | `make test` | **0** | **PASS.** 305 `--- PASS:`, 0 `--- FAIL:`, 11/11 packages `ok`. Log: `baseline-evidence/make-test.log` |
| 2 | `go test ./...` | **0** | **PASS.** 11/11 packages `ok` (cmd/relay, auth, backend, config, health, metrics, proxy, rotate, security, stream, transport). `baseline-evidence/test.log` |
| 3 | `go test -race ./...` | **0** | **PASS.** 11/11 packages `ok` under race detector. `baseline-evidence/go-test-race.log` |
| 4 | `go vet ./...` | **0** | **PASS.** No output. `baseline-evidence/go-vet.log` |
| 5 | `make build` | **0** | **PASS.** Produced `relay` (7.5 MB) with `Version=1ec78f4 Commit=1ec78f4 BuildTime=2026-11-25T10:48:18Z`. `baseline-evidence/make-build.log` |
| 6 | `make lint` | **2** | **FAIL.** 56 findings: 50 `errcheck`, 4 `staticcheck`, 2 `unused`; no `.golangci*` config in repo so v2 defaults applied. `baseline-evidence/make-lint.log` |
| 7 | `make cross-compile` | **2** | **FAIL.** linux amd64/arm64 and darwin arm64/amd64 built; **windows/amd64 failed**: `internal/backend/torlifecycle.go:99,183: undefined: syscall.Wait4 / syscall.WNOHANG`. `baseline-evidence/make-cross-compile.log` |
| 8 | `go test -run '^$' -bench . -benchtime=1x ./...` | **124 (timeout)** | **HANG.** Reached 8 benchmarks then stalled. `baseline-evidence/bench-smoke.log` |
| 9 | `go test ./internal/backend -run '^$' -bench '^BenchmarkTuneTCP$' -benchtime=1x -timeout 12s` | **124 (timeout)** | **HANG confirmed** even with 12 s Go timeout / 35 s outer cap. `baseline-evidence/bench-tuneTCP.log` |
| 10 | `./relay -version` | **0** | `local-relay 1ec78f4 (commit=1ec78f4, built=…, go=go1.25.0)` |
| 11 | `./relay -c config.yaml` | **1** | Config rejected: `multi_tor.binary not found in PATH: exec: "/home/stb/tor/tor/tor": stat …: no such file or directory`. `baseline-evidence/startup-production.log` |
| 12 | `./relay -c /nonexistent.yaml` | **1** | `reading config file: open /nonexistent.yaml: no such file or directory` (expected) |
| 13 | `./relay -c bad-unknown-key.yaml` | **1** | Strict decode works: `field not_a_real_key not found in type config.Config` |
| 14 | `./relay -c bad-multidoc.yaml` | **1** | `multiple YAML documents are not allowed` |
| 15 | Cleanup: `make clean` | **0** | Removed `relay` and all cross-compiled binaries; `git diff --stat` empty (no source modified) |

Generated build artifacts were removed after testing. Two unrelated untracked files (`IMPLEMENTATION_MAP.md`, `REQUIREMENTS_CHECKLIST.md`) appeared in the shared workspace during this run, written by sibling tasks; this task did not touch them.

---

## 4. Manual workflow evidence

Two isolated relay instances were launched from scratch configs (`relay-noauth.yaml`, `relay-auth.yaml`) with `multi_tor.enabled: false`, single-tor backend at an unused port, loopback listeners, `bypass.hosts: [localhost, 127.0.0.1]`, metrics enabled, and a local Python HTTP server at `127.0.0.1:19999` as the upstream. All processes were terminated after each run; no ports remain listening.

### 4.1 No-auth instance (`relay-noauth.yaml`)

| Probe | HTTP | Observed |
|---|---|---|
| `GET 127.0.0.1:28888/health` | 503 | `{"status":"degraded",…,"healthy":false,…}` |
| `GET 127.0.0.1:28888/healthz` | 503 | same degraded JSON |
| `GET 127.0.0.1:28888/readyz` | 503 | `{"status":"not ready"}` |
| `GET 127.0.0.1:28888/metrics` | 200 | `relay_healthy 0` |
| `GET 127.0.0.1:29090/metrics` (standalone) | 200 | `lano_up 1` |
| `GET 127.0.0.1:28080/health` (proxy port) | 200 | `{"status":"ok","mode":"multi_tor"}` — see Finding F5 |
| `curl -x …28080 http://127.0.0.1:19999/` | **200** | bypass HTTP forward returned test page |
| `curl --socks5-hostname …21080 http://127.0.0.1:19999/` | **200** | bypass SOCKS5 returned test page |
| `curl -H 'x-target-url: http://127.0.0.1:19999/' …28080/` | 403 | `request blocked` — by design, see Finding F7 |
| `curl -x …28080 http://10.0.0.1/` | 403 | `request blocked`; log: `blocked request to private/internal IP` |
| `curl -x …28080 http://example.com/` | 502 | `bad gateway`; log: `no healthy proxy backends — connection blocked (fail-closed)` |
| `curl -x …28080 https://example.com/` (CONNECT) | 502 | `CONNECT tunnel failed, response 502` (fail-closed) |
| SIGTERM shutdown | exit 0 | graceful; two spurious ERROR log lines — Finding F6 |

Log: `baseline-evidence/relay-noauth.log`. Startup correctly logged `Tor is not running`, `degraded: no healthy proxied backend — traffic fails closed until Tor recovers`, and bound all three listeners. A first run without `bypass.hosts` (defaults contain no bypass entries) correctly returned 403 for all loopback targets; preserved as `relay-noauth-nobypass.log`.

### 4.2 Auth-enabled instance (`relay-auth.yaml`, key `X-Api-Key`)

| Probe | HTTP | Observed |
|---|---|---|
| admin `/health`, `/readyz`, `/metrics` with **no** key | 407 | `Proxy Authentication Required` |
| admin `/health` with wrong key | 407 | `Proxy Authentication Required` |
| admin `/health` with correct key | 503 | degraded JSON (correct status under valid auth) |
| admin `/readyz` with correct key | 503 | `{"status":"not ready"}` |
| admin `/metrics` / standalone `/metrics` with correct key | 200 | metrics bodies |
| proxy forward with no key | 407 | `Proxy Authentication Required` |
| proxy forward with `X-Api-Key` | 200 | test page |
| proxy forward with `?api_key=<key>` | 200 | test page |
| SOCKS5 with no credentials | fail | `curl (97) No authentication method was acceptable` |
| SOCKS5 with credentials | 200 | test page |

Log: `baseline-evidence/relay-auth.log`. Shutdown exit 0.

---

## 5. Findings (documented, **not fixed**)

| ID | Severity | Finding |
|---|---|---|
| F1 | High | `make cross-compile` is broken for `windows/amd64`: `syscall.Wait4`/`WNOHANG` are Unix-only, used at `internal/backend/torlifecycle.go:99` and `:183`. |
| F2 | Medium | `make lint` fails with 56 issues (50 errcheck, 4 staticcheck, 2 unused) under golangci-lint v2.15.0 defaults; repo has no linter config, so the expected baseline is undefined. |
| F3 | Medium | `go test -bench . ./...` hangs indefinitely in `BenchmarkTuneTCP` (`internal/backend/bench_test.go:179-189`): `ln.Accept()` is called with no client dialing. Reproduces even with `-benchtime=1x` and `-timeout 12s`. |
| F4 | Medium | Production `config.yaml` cannot start on this host because the configured Tor binary/data dir do not exist. This is an environment mismatch, not necessarily a code defect, but it blocks the documented `make run` / systemd workflow. |
| F5 | Medium | Proxy-port `/health` (`internal/proxy/http.go:87-95`) always returns 200 `{"status":"ok",…}` and derives `mode` only from the `usePool` flag; in the tested single-tor degraded instance it reported `mode:"multi_tor"` while the admin `/health` correctly returned 503 degraded. Misleading monitoring signal. |
| F6 | Low | Normal SIGTERM shutdown logs `level=ERROR msg="HTTP proxy failed" error="http: Server closed"` and `level=ERROR msg="health server failed" error="accept … use of closed network connection"`. Process still exits 0; log noise only. |
| F7 | Low / by design | `x-target-url` header-mode forwarding intentionally does not receive the loopback/bypass waiver (`internal/proxy/http.go:456`), so a header pointing at a bypass host is blocked 403. `config.yaml` `security.blocked_networks` replaces (not merges with) defaults and includes `127.0.0.0/8`, so omitting `bypass.hosts` also blocks all loopback forwarding. Config trap / workflow limitation. |

---

## 6. Not verifiable in this environment

- Real Tor-backed egress, exit-IP retrieval (`api.ipify.org` examples in README), 429/503-triggered NEWNYM rotation, dead-tunnel rotation, quarantine/probation recovery, multi-instance health and full-stack restart — all require Tor daemons that are absent.
- `make install`, systemd unit activation (`local-relay.service`, `tor-local.service`) — require root/system state changes, explicitly out of scope for a non-destructive baseline.
- Database operations and UI interactions — no such components exist in the codebase.
- `bench/` load-test scripts — need external load-generation tooling; not run.

---

## 7. Evidence files

Raw logs saved at `/home/strong/local-relay/baseline-evidence/` (14 `.log` files; gitignored via `*.log`): `test.log`, `make-test.log`, `go-vet.log`, `make-build.log`, `go-test-race.log`, `make-lint.log`, `make-cross-compile.log`, `bench-smoke.log`, `bench-tuneTCP.log`, `startup-production.log`, `relay-noauth.log`, `relay-noauth-nobypass.log`, `relay-auth.log`, `target-server.log`. Scratch probe configs/scripts remain under `/home/strong/.hermes/cache/scratch/baseline-logs/`.

All pass/fail statements above are backed by the recorded exit codes and logs from this run; no success claim is based on inference.
