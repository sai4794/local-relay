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
#   ./bench/loadtest.sh socks5://127.0.0.1:11080 60s 100
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

# =============================================================================
# Test 1: Vegeta (constant rate load test)
# =============================================================================
echo "=== Vegeta: Constant Rate ==="
echo "GET $TARGET" | vegeta attack \
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
echo "=== Hey: Concurrent Connections ==="
hey -z "$DURATION" \
    -c "$CONCURRENCY" \
    -disable-keepalive \
    "$TARGET" \
    | tee "$RESULTS_DIR/hey_report.txt"

# =============================================================================
# Test 3: Wrk (high throughput)
# =============================================================================
if command -v wrk &> /dev/null; then
    echo ""
    echo "=== Wrk: High Throughput ==="
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
echo "=== Connection Churn Test ==="
echo "Testing with DisableKeepAlives=true (current behavior)"
hey -n 1000 \
    -c "$CONCURRENCY" \
    -disable-keepalive \
    "$TARGET" \
    | tee "$RESULTS_DIR/hey_no_keepalive.txt"

echo ""
echo "Testing with keep-alive enabled"
hey -n 1000 \
    -c "$CONCURRENCY" \
    "$TARGET" \
    | tee "$RESULTS_DIR/hey_keepalive.txt"

# =============================================================================
# Test 5: Latency distribution
# =============================================================================
echo ""
echo "=== Latency Distribution ==="
hey -n 10000 \
    -c "$CONCURRENCY" \
    -disable-keepalive \
    "$TARGET" \
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
