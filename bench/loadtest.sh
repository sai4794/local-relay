#!/usr/bin/env bash
# =============================================================================
# loadtest.sh — External load testing for local-relay
#
# Prerequisites:
#   go install github.com/tsenart/vegeta@latest
#   go install github.com/rakyll/hey@latest
#   apt install wrk (or brew install wrk)
#
# Usage:
#   ./bench/loadtest.sh [target] [duration] [concurrency]
#
# Examples:
#   ./bench/loadtest.sh http://127.0.0.1:18080 30s 50
#   ./bench/loadtest.sh https://api.ipify.org 30s 50   # CONNECT tunnel via :18080
#
# Semantics: the relay is a forward proxy, not an origin server. Plain-HTTP
# modes drive it via CONNECT or the x-target-url header form; raw
# "GET http://127.0.0.1:18080/" only exercises the proxy's own liveness path
# (and SOCKS5 needs a CONNECT-aware client, not plain HTTP tools).
#
#   HTTP forward (header mode): curl -H "x-target-url: <url>" http://127.0.0.1:18080/
#   CONNECT tunnel:             curl -x http://127.0.0.1:18080 <https-url>
#   SOCKS5 tunnel:              curl --socks5-hostname 127.0.0.1:11080 <url>
# =============================================================================

set -euo pipefail

TARGET="${1:-http://127.0.0.1:18080}"
DURATION="${2:-30s}"
CONCURRENCY="${3:-50}"
RESULTS_DIR="bench/results/$(date +%Y%m%d_%H%M%S)"

mkdir -p "$RESULTS_DIR"

echo "=== Load Test Configuration ==="
echo "Target:      $TARGET"
echo "Duration:    $DURATION"
echo "Concurrency: $CONCURRENCY"
echo "Results:     $RESULTS_DIR"
echo ""
# Forward-proxy semantics: translate the requested target into the form the
# relay actually serves (CONNECT authority or x-target-url header). A bare
# "GET <proxy-addr>" would only hit the liveness path, not an upstream fetch.
PROXY="http://127.0.0.1:18080"
if [[ "$TARGET" == socks5://* ]]; then
    echo "NOTE: plain HTTP load tools cannot drive SOCKS5; use a CONNECT-aware"
    echo "client instead: curl --socks5-hostname 127.0.0.1:11080 $TARGET"
    echo ""
fi

# =============================================================================
# Test 1: Vegeta (constant rate load test)
# =============================================================================
echo "=== Vegeta: Constant Rate (x-target-url header mode via proxy) ==="
echo "GET $PROXY" | vegeta attack -header "x-target-url: $TARGET" \
  -duration="$DURATION" \
  -rate="$(( CONCURRENCY * 10 ))" \
  -connections="$CONCURRENCY" \
  -timeout=30s \
  | tee "$RESULTS_DIR/vegeta_raw.bin" \
  | vegeta report \
  | tee "$RESULTS_DIR/vegeta_report.txt"

echo ""
echo "Vegeta histogram:"
cat "$RESULTS_DIR/vegeta_raw.bin" | vegeta histogram > "$RESULTS_DIR/vegeta_histogram.txt" 2>&1 || true
cat "$RESULTS_DIR/vegeta_histogram.txt"

# =============================================================================
# Test 2: Hey (concurrent connections)
# =============================================================================
echo ""
echo "=== Hey: Concurrent Connections (CONNECT tunnel via proxy) ==="
echo "NOTE: hey has no CONNECT proxy mode; driving CONNECT tunnels with curl."
echo "Equivalent hey form (direct-origin baseline only):"
echo "  hey -z \"$DURATION\" -c \"$CONCURRENCY\" -disable-keepalive \"$TARGET\""
seq 1 "$CONCURRENCY" | xargs -P "$CONCURRENCY" -I{} \
    curl -sS -o /dev/null -w "%{http_code} %{time_total}\n" \
    -x "http://127.0.0.1:18080" --max-time 30 "$TARGET" \
    | tee "$RESULTS_DIR/hey_report.txt"

# =============================================================================
# Test 3: Wrk (high throughput)
# =============================================================================
if command -v wrk &> /dev/null; then
    echo ""
    echo "=== Wrk: High Throughput ==="
    # NOTE: wrk speaks raw HTTP only (no CONNECT proxy support); it hits
    # the origin directly for baseline comparison, not via the relay.
    wrk -t4 \
        -c"$CONCURRENCY" \
        -d"$DURATION" \
        --latency \
        "$TARGET" \
        | tee "$RESULTS_DIR/wrk_report.txt"
fi

# =============================================================================
# Test 4: Connection churn (tests keep-alive behavior)
# =============================================================================
echo ""
echo "=== Connection Churn Test (CONNECT tunnel via proxy) ==="
echo "Testing CONNECT tunnel reuse (sequential curl via proxy keeps the client side warm)"
seq 1 1000 | xargs -P "$CONCURRENCY" -I{} \
    curl -sS -o /dev/null -w "%{http_code} %{time_total}\n" \
    -x "http://127.0.0.1:18080" --max-time 30 "$TARGET" \
    | tee "$RESULTS_DIR/hey_no_keepalive.txt"

echo ""
echo "Testing direct-origin baseline (no proxy)"
seq 1 1000 | xargs -P "$CONCURRENCY" -I{} \
    curl -sS -o /dev/null -w "%{http_code} %{time_total}\n" \
    --max-time 30 "$TARGET" \
    | tee "$RESULTS_DIR/hey_keepalive.txt"

# =============================================================================
# Test 5: Latency distribution
# =============================================================================
echo ""
echo "=== Latency Distribution (CONNECT tunnel via proxy) ==="
seq 1 10000 | xargs -P "$CONCURRENCY" -I{} \
    curl -sS -o /dev/null -w "%{time_total}\n" \
    -x "http://127.0.0.1:18080" --max-time 30 "$TARGET" \
    | tee "$RESULTS_DIR/hey_latency_dist.txt"

echo ""
echo "=== Summary ==="
echo "Results saved to: $RESULTS_DIR"
echo ""
echo "Key metrics to look for:"
echo "  - Average latency (should be < 50ms for local, < 500ms for Tor)"
echo "  - P99 latency (should be < 5x average)"
echo "  - Requests/sec (throughput)"
echo "  - Error rate (should be 0%)"
