# Tor Local Relay Proxy

A lightweight, high-performance Go HTTP + SOCKS5 relay proxy that routes local
traffic through multiple managed Tor daemons with automatic exit-IP rotation on
rate limits (429/503), per-instance circuit isolation, and unbuffered SSE
streaming.

---

## Architecture

```
CLIENT ─┬─ HTTP :18080 ──► auth → SSRF/firewall → Router ─┐
        ├─ SOCKS5 :11080 ────────────────────────────────┤
        │                                                ▼
        │                                    MultiTorBackend (round-robin)
        │                                    ├─ tor instance 1 (:9150)
        │                                    ├─ tor instance 2 (:9151)
        │                                    └─ tor instance 3 (:9152)
        │
        └─ bypass hosts (localhost, 127.0.0.1, codebuff.com, www.codebuff.com, api.codebuff.com) → direct, never through Tor

Router is FAIL-CLOSED: if no proxy backend is healthy, traffic is blocked,
never leaked outside Tor.
```

| Package | Responsibility |
|---|---|
| `cmd/relay` | composition root: config → backends → proxies → lifecycle |
| `internal/proxy` | HTTP forward/CONNECT server, SOCKS5 RFC-1928 server |
| `internal/backend` | backend selection (`Backend`, `Router`), multi-Tor lifecycle, circuit pool, Tor control client |
| `internal/security` | SSRF blocker, per-host firewall/rate limiter, shared DNS cache |
| `internal/stream` | bidirectional relay, SSE copy |
| `internal/rotate` | request-count rotation trigger |
| `internal/auth` | constant-time API-key auth |
| `internal/config` | YAML+env+defaults loading and validation |
| `internal/health` | admin endpoints `/health`, `/readyz`, `/metrics` |

## Exit-IP change conditions (multi-tor mode)

1. `multi_tor.rotate_after` is **0 (disabled)** — threshold rotation is off; instances only rotate on the feedback paths below.
2. A non-SSE **429/503** response → NEWNYM on the current round-robin instance.
3. A CONNECT tunnel dying within 2 s (dead pooled conn heuristic) → same path as 2.
4. Health monitor probe failures → DROPGUARDS auto-heal; 3 consecutive failures → instance respawned fresh.
5. Tor's own `MaxCircuitDirtiness 20` rebuilds circuits natively (code: `internal/backend/torlifecycle.go`).

SSE streams are never rotated mid-flight. Established tunnels keep their IP until closed.

## Quick start

### Build
```bash
make build          # produces ./relay (the binary systemd runs)
```

### Run (production)
```bash
sudo systemctl enable --now local-relay.service   # unit file in repo root
journalctl -u local-relay -f
```

### Run (manual)
```bash
./relay -c config.yaml
```

### Test
```bash
# health
curl http://127.0.0.1:18888/health

# outgoing IP via CONNECT
curl -x http://127.0.0.1:18080 https://api.ipify.org

# plain HTTP forward / header mode
curl -H "x-target-url: http://api.ipify.org/" http://127.0.0.1:18080/

# SOCKS5
curl --socks5-hostname 127.0.0.1:11080 https://api.ipify.org
```

## CLI flags

| Flag | Default | Description |
|---|---|---|
| `-c` | `config.yaml` | Path to config file |
| `-http` | — | Override HTTP proxy listen address |
| `-socks5` | — | Override SOCKS5 listen address |
| `-log-level` | — | `debug`, `info`, `warn`, `error` |
| `-v` | — | Shortcut for `-log-level debug` (overrides `--log-level`) |
| `-version` | — | Print build info |

Env overrides: `PROXY_HTTP`, `PROXY_SOCKS5`, `PROXY_BACKEND_ADDR`,
`PROXY_AUTH_KEY`, `PROXY_LOG_LEVEL`, `PROXY_HEALTH_ADDR`, `TOR_BINARY`,
`TOR_LIBRARY_PATH` (exported as `LD_LIBRARY_PATH` for spawned Tor children; see `multi_tor.library_path` in `config.yaml`).

## Configuration reference (config.yaml)

```yaml
server:
  http: "127.0.0.1:18080"      # HTTP/CONNECT proxy
  socks5: "127.0.0.1:11080"    # SOCKS5 proxy

multi_tor:                      # preferred mode: N managed tor daemons
  enabled: true
  binary: "/path/to/tor"
  data_dir: "/path/to/data_multi"
  base_port: 9150               # SOCKS ports: base_port .. base_port+N-1
  control_base: 9160            # control ports likewise
  max_instances: 3
  rotate_after: 0               # 0 disables threshold rotation (rotate on 429/feedback only)

backend:                        # fallback single-tor mode
  type: "tor"
  address: "127.0.0.1:9050"
  circuit_count: 3              # >1 ⇒ circuit-pool mode
  max_circuit_age: 50
  control_addr: "127.0.0.1:9051"
  control_cookie_path: "/home/stb/tor/data/control_auth_cookie"

bypass:
  hosts: ["localhost", "127.0.0.1", "codebuff.com", "www.codebuff.com", "api.codebuff.com"]   # routed DIRECT, fail-closed

rotation:
  enabled: false                # global request-count rotation (Rotator)
  interval: 50

auth:
  enabled: false
  api_key: ""                   # ≥16 chars; also enables SOCKS5 user/pass

security:
  blocked_networks: [ ...CIDRs... ]
  max_body_size: 33554432       # 32 MB
  rate_limit: 50                # req/s per destination host
  rate_burst: 100

logging:   { level: info, format: text }     # text | json
health:    { enabled: true, address: "127.0.0.1:18888" }
metrics:   { enabled: false, address: "127.0.0.1:9090", path: "/metrics" }
```

## Endpoints

| URL | Purpose |
|---|---|
| `GET :18080/health` | proxy health reflecting router state: 200 `{"status":"ok","mode":"..."}` when a backend is healthy, else 503 `{"status":"degraded","mode":"..."}` (requires auth key when `auth.enabled: true`) |
| `GET :18888/health` (alias `/healthz`) | full status incl. per-instance/per-slot detail; 503 `{"status":"degraded",...}` when unhealthy |
| `GET :18888/readyz` | readiness gate: 200 `{"status":"ready"}` when healthy, else 503 `{"status":"not ready"}` |
| `GET :18888/metrics` | Prometheus gauges (only when `metrics.enabled: true`; gated by `SetMetricsEnabled`) |
| `GET <metrics.address><metrics.path>` | separate Prometheus listener (`/metrics` on `127.0.0.1:9090` when `metrics.enabled: true`): `lano_up`, `lano_tor_instances` |

## Development

```bash
make test            # unit tests
go test -race ./...
make lint            # golangci-lint
make cross-compile   # release binaries
```

Benchmarks exist for pool, router, stream, proxy and security packages
(`go test -bench . ./...`). Load-testing tooling lives in `bench/`.
