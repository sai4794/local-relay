# =============================================================================
# Prometheus Metrics for local-relay
#
# Add these metrics to cmd/relay/main.go or create a new metrics package.
# This file defines the metrics schema — implementation is separate.
# =============================================================================

# =============================================================================
# 1. REQUEST LATENCY
# =============================================================================
# Histogram: proxy_request_duration_seconds
# Labels: backend_type, target_host, method, status_code
# Buckets: 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10
#
# Usage:
#   proxy_request_duration_seconds_bucket{backend_type="tor",target_host="api.openai.com",method="POST",status_code="200",le="0.5"} 1234
#   proxy_request_duration_seconds_sum{backend_type="tor",target_host="api.openai.com",method="POST",status_code="200"} 617.0
#   proxy_request_duration_seconds_count{backend_type="tor",target_host="api.openai.com",method="POST",status_code="200"} 2468

# =============================================================================
# 2. THROUGHPUT
# =============================================================================
# Counter: proxy_requests_total
# Labels: backend_type, target_host, method, status_code
#
# Counter: proxy_bytes_sent_total
# Labels: backend_type, target_host
#
# Counter: proxy_bytes_received_total
# Labels: backend_type, target_host

# =============================================================================
# 3. CONNECTIONS
# =============================================================================
# Gauge: proxy_active_connections
# Labels: backend_type
#
# Gauge: proxy_idle_connections
# Labels: backend_type
#
# Counter: proxy_connections_created_total
# Labels: backend_type
#
# Counter: proxy_connections_reused_total
# Labels: backend_type

# =============================================================================
# 4. BACKEND HEALTH
# =============================================================================
# Gauge: proxy_backend_healthy
# Labels: backend_id, backend_type
# Values: 1 (healthy), 0 (unhealthy)
#
# Gauge: proxy_backend_latency_seconds
# Labels: backend_id, backend_type
#
# Counter: proxy_backend_failures_total
# Labels: backend_id, backend_type, error_type

# =============================================================================
# 5. ROTATION
# =============================================================================
# Histogram: proxy_newnym_duration_seconds
# Buckets: 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5
#
# Counter: proxy_newnym_total
# Labels: success (true/false)
#
# Gauge: proxy_circuit_age
# Labels: slot_id
#
# Gauge: proxy_circuit_healthy
# Labels: slot_id

# =============================================================================
# 6. RESOURCE USAGE
# =============================================================================
# Gauge: proxy_goroutines
#
# Gauge: proxy_memory_alloc_bytes
#
# Gauge: proxy_memory_sys_bytes
#
# Counter: proxy_gc_cycles_total
#
# Gauge: proxy_open_fds

# =============================================================================
# 7. ERRORS
# =============================================================================
# Counter: proxy_errors_total
# Labels: error_type (timeout, dns, tls, connection_refused, connection_reset, 429, 503)
#
# Counter: proxy_retries_total
# Labels: backend_type

# =============================================================================
# 8. RATE LIMITING
# =============================================================================
# Counter: proxy_rate_limit_hits_total
# Labels: status_code (429, 503)
#
# Gauge: proxy_throttle_tokens
# Labels: backend_id
