# Prometheus Metrics for local-relay

This file reconciles the metrics schema against what the code actually emits.
Series listed under "Implemented" are emitted today; series under "Planned"
do not exist in code and are aspirational.

Sources: `internal/metrics.Registry` (counters/gauges rendered by
`internal/health.handleMetrics`), `internal/health.handleMetrics` direct
`Fprintf` series, `cmd/relay.startMetricsServer` (separate Prometheus
listener on `metrics.address` + `metrics.path`, default `/metrics`).

## Implemented series (real code)

### Counters (`internal/metrics` registry)

| Series | Labels | Written at |
|---|---|---|
| `lano_requests_total` | `instance` | `internal/backend/multitor.go` (`IncKey`, per dial) |
| `lano_rotations_total` | `instance`, `trigger` (`anomaly`, `health`) | `internal/backend/torlifecycle.go` (after NEWNYM) |

### Gauges (`internal/health.handleMetrics` + registry `Set`)

| Series | Labels | Source |
|---|---|---|
| `relay_healthy` | none | `handleMetrics`: 1 = healthy, 0 = degraded |
| `lano_in_flight` | `instance` | per-instance in-flight count from multi-tor `Status()` |
| `lano_exit_ip` | `instance`, `ip` | info-style gauge (`1`), observed exit IP per instance |
| `relay_pool_slots_total` | none | circuit-pool `Status().total_slots` |
| `relay_pool_slots_healthy` | none | circuit-pool `Status().healthy_slots` |
| `relay_pool_requests_total` | none | circuit-pool `Status().total_requests` |
| `relay_pool_nym_backoff` | none | circuit-pool `Status().nym_backoff` |
| `relay_rotation_requests` | none | rotation request count (counter semantics) |

### Separate Prometheus listener (`cmd/relay.startMetricsServer`)

Served only when `metrics.enabled: true` at `metrics.address` +
`metrics.path` (default `/metrics`):

| Series | Labels | Source |
|---|---|---|
| `lano_up` | none | constant `1` |
| `lano_tor_instances` | none | `TorLifecycle.GetReadyCount()` |

## Planned series (NOT implemented — do not query)

The following `proxy_*` names appear in old drafts/dashboards but have no
emitter in code. They are retained here as a build list, not a schema:

- `proxy_request_duration_seconds` (histogram) + `_bucket/_sum/_count`
- `proxy_requests_total`, `proxy_bytes_sent_total`, `proxy_bytes_received_total`
- `proxy_active_connections`, `proxy_idle_connections`,
  `proxy_connections_created_total`, `proxy_connections_reused_total`
- `proxy_backend_healthy`, `proxy_backend_latency_seconds`,
  `proxy_backend_failures_total`
- `proxy_newnym_duration_seconds` (histogram), `proxy_newnym_total`,
  `proxy_circuit_age`, `proxy_circuit_healthy`
- `proxy_goroutines`, `proxy_memory_alloc_bytes`, `proxy_memory_sys_bytes`,
  `proxy_gc_cycles_total`, `proxy_open_fds`
- `proxy_errors_total`, `proxy_retries_total`
- `proxy_rate_limit_hits_total`, `proxy_throttle_tokens`

Example real exposition (labels vary):

```
relay_healthy 1
lano_in_flight{instance="1"} 3
lano_exit_ip{instance="1",ip="185.220.100.1"} 1
lano_requests_total{instance="1"} 42
lano_rotations_total{instance="1",trigger="anomaly"} 2
relay_pool_slots_total 3
```
