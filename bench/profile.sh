#!/usr/bin/env bash
# =============================================================================
# profile.sh — CPU, memory, and goroutine profiling for local-relay
#
# Prerequisites:
#   go install github.com/google/pprof@latest
#   go install golang.org/x/tools/cmd/pprof@latest
#
# Usage:
#   ./bench/profile.sh [binary_path] [duration_seconds] [--pprof[=port]]
#
# Examples:
#   ./bench/profile.sh ./relay 30
#   ./bench/profile.sh ./relay 60 --pprof
#   ./bench/profile.sh ./relay 60 --pprof=6060
#
# This script:
#   1. Starts the relay
#   2. Runs a load test against it
#   3. Collects Go benchmark CPU/memory profiles locally
#   4. Optionally collects live pprof profiles (--pprof only)
#   5. Generates flamegraphs
#   6. Opens the pprof web UI
#
# Profiling note: the relay exposes NO pprof endpoint, so live-profile
# collection is OFF by default. Pass --pprof to start a local
# net/http/pprof listener and exercise the collection plumbing against it
# (intended for pprof-enabled relay builds listening on that port).
# =============================================================================

set -euo pipefail

BINARY="${1:-./relay}"
DURATION="${2:-30}"
PPROF=0
PPROF_PORT=6060
for arg in "$@"; do
    case "$arg" in
        --pprof) PPROF=1 ;;
        --pprof=*) PPROF=1; PPROF_PORT="${arg#--pprof=}" ;;
    esac
done
# Shift off binary/duration positionals when present so extra flags parse.
if [[ "${1:-}" == --pprof* ]]; then BINARY="./relay"; fi
if [[ "${2:-}" == --pprof* ]]; then DURATION="30"; fi
RESULTS_DIR="bench/profiles/$(date +%Y%m%d_%H%M%S)"

mkdir -p "$RESULTS_DIR"

echo "=== Profiling Configuration ==="
echo "Binary:   $BINARY"
echo "Duration: ${DURATION}s"
echo "Pprof:    $([ "$PPROF" -eq 1 ] && echo ":$PPROF_PORT" || echo "disabled (pass --pprof to collect)")"
echo "Results:  $RESULTS_DIR"
echo ""

# =============================================================================
# Step 1: Start the relay
# =============================================================================
echo "=== Starting relay ==="
"$BINARY" \
    -c config.yaml \
    -v \
    &> "$RESULTS_DIR/relay.log" &
RELAY_PID=$!

# Wait for relay to start
sleep 2

# Check if relay is running
if ! kill -0 $RELAY_PID 2>/dev/null; then
    echo "ERROR: Relay failed to start. Check $RESULTS_DIR/relay.log"
    cat "$RESULTS_DIR/relay.log"
    exit 1
fi

echo "Relay PID: $RELAY_PID"
echo "Relay log: $RESULTS_DIR/relay.log"

# =============================================================================
# Step 1b: Local Go benchmark profiles (no live endpoint needed)
# =============================================================================
echo ""
echo "=== Go benchmark profiles ==="
go test -bench=. -benchmem -run=NONE \
    -cpuprofile="$RESULTS_DIR/cpu.prof" \
    -memprofile="$RESULTS_DIR/heap.prof" \
    ./internal/... \
    2>&1 | tee "$RESULTS_DIR/go_bench.txt" || echo "Go benchmark profiles failed"

# =============================================================================
# Step 2: Run load test in background
# =============================================================================
echo ""
echo "=== Running load test ==="
if command -v hey &> /dev/null; then
    # hey has no CONNECT support: exercise the header-forward path
    # (x-target-url) through the proxy instead of the bare liveness path.
    hey -z "${DURATION}s" \
        -c 50 \
        -disable-keepalive \
        -H "x-target-url: http://api.ipify.org/" http://127.0.0.1:18080 \
        &> "$RESULTS_DIR/loadtest.log" &
    LOAD_PID=$!
elif command -v vegeta &> /dev/null; then
    echo "GET http://127.0.0.1:18080" | vegeta attack -header "x-target-url: http://api.ipify.org/" \
        -duration="${DURATION}s" \
        -rate=500 \
        -connections=50 \
        &> "$RESULTS_DIR/loadtest.log" &
    LOAD_PID=$!
else
    echo "WARNING: No load test tool found (hey or vegeta). Install one for meaningful profiles."
    LOAD_PID=""
fi

# =============================================================================
# Step 3: Collect live profiles (--pprof only)
# =============================================================================
echo ""
echo "=== Collecting profiles ==="

# Wait for load to ramp up
sleep 5

if [ "$PPROF" -eq 1 ]; then
    echo "Starting local pprof listener on :$PPROF_PORT..."
    cat > "$RESULTS_DIR/pprof_helper.go" <<EOF
package main

import (
	"net/http"

	_ "net/http/pprof"
)

func main() {
	_ = http.ListenAndServe("127.0.0.1:$PPROF_PORT", nil)
}
EOF
    go run "$RESULTS_DIR/pprof_helper.go" &> "$RESULTS_DIR/pprof_helper.log" &
    PPROF_PID=$!
    sleep 2

    # CPU Profile (30 seconds)
    echo "Collecting CPU profile (30s)..."
    curl -s "http://127.0.0.1:$PPROF_PORT/debug/pprof/profile?seconds=30" \
        -o "$RESULTS_DIR/cpu_live.prof" 2>/dev/null || echo "CPU profile failed"

    # Memory Profile
    echo "Collecting memory profile..."
    curl -s "http://127.0.0.1:$PPROF_PORT/debug/pprof/heap" \
        -o "$RESULTS_DIR/heap_live.prof" 2>/dev/null || echo "Heap profile failed"

    # Goroutine Profile
    echo "Collecting goroutine profile..."
    curl -s "http://127.0.0.1:$PPROF_PORT/debug/pprof/goroutine" \
        -o "$RESULTS_DIR/goroutine.prof" 2>/dev/null || echo "Goroutine profile failed"

    # Block Profile
    echo "Collecting block profile..."
    curl -s "http://127.0.0.1:$PPROF_PORT/debug/pprof/block" \
        -o "$RESULTS_DIR/block.prof" 2>/dev/null || echo "Block profile failed"

    # Mutex Profile
    echo "Collecting mutex profile..."
    curl -s "http://127.0.0.1:$PPROF_PORT/debug/pprof/mutex" \
        -o "$RESULTS_DIR/mutex.prof" 2>/dev/null || echo "Mutex profile failed"

    # Threadcreate Profile
    echo "Collecting threadcreate profile..."
    curl -s "http://127.0.0.1:$PPROF_PORT/debug/pprof/threadcreate" \
        -o "$RESULTS_DIR/threadcreate.prof" 2>/dev/null || echo "Threadcreate profile failed"

    # 5-second CPU profile for flamegraph
    echo "Collecting 5s CPU profile for flamegraph..."
    curl -s "http://127.0.0.1:$PPROF_PORT/debug/pprof/profile?seconds=5" \
        -o "$RESULTS_DIR/flamegraph.prof" 2>/dev/null || echo "Flamegraph profile failed"

    kill $PPROF_PID 2>/dev/null || true
    wait $PPROF_PID 2>/dev/null || true
else
    echo "Skipping live pprof collection (relay exposes no pprof endpoint; re-run with --pprof to start a local listener and collect)."
fi

# =============================================================================
# Step 4: Generate reports
# =============================================================================
echo ""
echo "=== Generating reports ==="

if command -v go &> /dev/null; then
    # CPU profile text report
    if [ -f "$RESULTS_DIR/cpu.prof" ]; then
        echo "CPU Profile (top 30):"
        go tool pprof -text -nodecount=30 "$RESULTS_DIR/cpu.prof" \
            | tee "$RESULTS_DIR/cpu_report.txt"
        echo ""
    fi

    # Heap profile text report
    if [ -f "$RESULTS_DIR/heap.prof" ]; then
        echo "Heap Profile (top 30):"
        go tool pprof -text -nodecount=30 "$RESULTS_DIR/heap.prof" \
            | tee "$RESULTS_DIR/heap_report.txt"
        echo ""
    fi

    # Goroutine profile text report
    if [ -f "$RESULTS_DIR/goroutine.prof" ]; then
        echo "Goroutine Profile (top 30):"
        go tool pprof -text -nodecount=30 "$RESULTS_DIR/goroutine.prof" \
            | tee "$RESULTS_DIR/goroutine_report.txt"
        echo ""
    fi

    # Block profile text report
    if [ -f "$RESULTS_DIR/block.prof" ]; then
        echo "Block Profile (top 30):"
        go tool pprof -text -nodecount=30 "$RESULTS_DIR/block.prof" \
            | tee "$RESULTS_DIR/block_report.txt"
        echo ""
    fi
fi

# =============================================================================
# Step 5: Generate flamegraph (if pprof is available)
# =============================================================================
echo ""
echo "=== Generating flamegraph ==="
if command -v go &> /dev/null && [ -f "$RESULTS_DIR/flamegraph.prof" ]; then
    # Generate SVG flamegraph
    go tool pprof -svg "$RESULTS_DIR/flamegraph.prof" \
        > "$RESULTS_DIR/flamegraph.svg" 2>/dev/null || echo "SVG flamegraph failed"

    # Generate PNG flamegraph
    go tool pprof -png "$RESULTS_DIR/flamegraph.prof" \
        > "$RESULTS_DIR/flamegraph.png" 2>/dev/null || echo "PNG flamegraph failed"

    echo "Flamegraph saved to: $RESULTS_DIR/flamegraph.svg"
fi

# =============================================================================
# Step 6: Cleanup
# =============================================================================
echo ""
echo "=== Cleanup ==="

# Stop load test
if [ -n "${LOAD_PID:-}" ]; then
    kill $LOAD_PID 2>/dev/null || true
    wait $LOAD_PID 2>/dev/null || true
fi

# Stop relay
kill $RELAY_PID 2>/dev/null || true
wait $RELAY_PID 2>/dev/null || true

echo "Relay stopped."
echo ""

# =============================================================================
# Step 7: Summary
# =============================================================================
echo "=== Profiling Complete ==="
echo ""
echo "Results directory: $RESULTS_DIR"
echo ""
echo "Files:"
ls -la "$RESULTS_DIR/"
echo ""
echo "To view CPU profile interactively:"
echo "  go tool pprof -http=:8080 $RESULTS_DIR/cpu.prof"
echo ""
echo "To view heap profile interactively:"
echo "  go tool pprof -http=:8080 $RESULTS_DIR/heap.prof"
echo ""
echo "To view flamegraph:"
echo "  open $RESULTS_DIR/flamegraph.svg"
echo ""
echo "To compare profiles (before/after optimization):"
echo "  go tool pprof -base old.prof new.prof"
