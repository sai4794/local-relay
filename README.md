# Local Relay Proxy

A production-grade Go HTTP/SOCKS5 proxy that routes traffic through multiple Tor instances for IP rotation, rate-limit bypass, and privacy.

## Features

- **Multi-Tor**: 3 Tor instances with round-robin IP rotation
- **SSRF Protection**: Blocks private/loopback/link-local CIDRs (HTTP + SOCKS5)
- **429 Rotation**: Auto-rotates on rate limit errors with instant IP change
- **Health Checks**: /healthz, /readyz, /metrics endpoints
- **Prometheus Metrics**: Request counts, Tor instances, uptime
- **Forward Proxy**: Standard HTTP proxy protocol (9router compatible)
- **WebSocket**: CONNECT tunnel support
- **SSE Streaming**: Flush-per-line for event streams
- **Bypass Hosts**: Direct connection for specified hosts
- **API Key Auth**: Optional authentication via header/query/proxy-header
- **Panic Recovery**: All goroutines protected against panics
- **Connection Timeout**: 30-minute max per CONNECT tunnel

## Quick Start

```bash
# Build
cd /home/stb/local-relay
go build -o relay ./cmd/relay/

# Run
./relay -c config.yaml

# Test
curl -x http://127.0.0.1:18080 http://api.ipify.org
```

## Configuration

See `config.yaml` for all options. Key settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `multi_tor.enabled` | `true` | Enable multi-Tor mode |
| `multi_tor.max_instances` | `3` | Number of Tor daemons |
| `multi_tor.base_port` | `9150` | Starting SOCKS port |
| `multi_tor.rotate_after` | `50` | Circuit rotation threshold |
| `rotation.enabled` | `false` | Request-count rotation (disabled) |
| `security.blocked_networks` | Private CIDRs | SSRF protection |
| `security.max_body_size` | `32MB` | Max request body |
| `auth.enabled` | `false` | API key authentication |
| `health.enabled` | `true` | Health endpoint |
| `metrics.enabled` | `true` | Prometheus metrics |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `PROXY_HTTP` | Override HTTP proxy address |
| `PROXY_SOCKS5` | Override SOCKS5 proxy address |
| `PROXY_AUTH_KEY` | Set API key (enables auth) |
| `PROXY_LOG_LEVEL` | Override log level |
| `TOR_BINARY` | Override Tor binary path |

## Ports

| Port | Purpose |
|------|---------|
| 18080 | HTTP proxy |
| 11080 | SOCKS5 proxy |
| 18888 | Health endpoint |
| 9090 | Prometheus metrics |
| 9150-9152 | Tor instances |

## Architecture

```
Client → HTTP/SOCKS5 → Auth → SSRF → Firewall → Router → Tor SOCKS5 → Internet
                                                         ↑
                                                  Multi-Tor
                                                  (N instances, round-robin)

Rotation: 429/503/network errors → NEWNYM + ClearIdleConns
```

## Security

- SSRF protection blocks private/loopback/link-local CIDRs
- Scheme blocking (file://, gopher://, javascript:, data:)
- API key auth with constant-time comparison
- DNS caching with 5-minute TTL
- Panic recovery on all goroutines
- Connection timeout (30 min max)
- Rate limiting (configurable)

## Testing

```bash
go test ./...                    # Run all tests
go test -race ./...              # Race detector
go test -v ./internal/backend/   # Verbose
```

## Project Structure

```
local-relay/
├── cmd/relay/main.go           # Entry point
├── internal/
│   ├── auth/apikey.go          # API key authentication
│   ├── backend/
│   │   ├── multitor.go         # Multi-Tor backend
│   │   ├── pool.go             # Circuit pool (single Tor)
│   │   ├── router.go           # Request routing
│   │   ├── tcp.go              # TCP tuning
│   │   ├── tor.go              # Single Tor backend
│   │   └── torlifecycle.go     # Tor process management
│   ├── config/config.go        # Configuration
│   ├── health/health.go        # Health endpoints
│   ├── proxy/
│   │   ├── clear.go            # Connection pool clearing
│   │   ├── http.go             # HTTP proxy
│   │   └── socks5.go           # SOCKS5 proxy
│   ├── rotate/rotator.go       # Request-count rotation
│   ├── security/
│   │   ├── firewall.go         # IP blocking + DNS cache
│   │   └── ssrf.go             # SSRF protection
│   └── stream/sse.go           # SSE streaming + relay
├── config.yaml                 # Configuration
├── ENGINEERING_AUDIT.md        # Audit report
├── AUDIT_VERIFICATION.md       # Audit verification
└── README.md                   # This file
```

## License

MIT
