#!/usr/bin/env bash
# =============================================================================
# profile.sh — CPU, memory, and goroutine profiling for local-relay
#
# Prerequisites:
#   go install github.com/google/pprof@latest
#   go install golang.org/x/tools/cmd/pprof@latest
#
# Usage:
#   ./bench/profile.sh [binary_path] [duration_seconds]
#
# Examples:
#   ./bench/profile.sh ./relay 30
#   ./bench/profile.sh ./relay 60
#
# This script:
#   1. Starts the relay with pprof enabled on :6060
#   2. Runs a load test against it
#   3. Collects CPU, memory, goroutine, and block profiles
#   4. Generates flamegraphs
#   5. Opens the pprof web UI
# =============================================================================

set -euo pipefail

BINARY="${1:-./relay}"
DURATION="${2:-30}"
PPROF_PORT=6060
RESULTS_DIR="bench/profiles/$(date +%Y%m%d_%H%M%S)"

mkdir -p "$RESULTS_DIR"

echo "=== Profiling Configuration ==="
echo "Binary:   $BINARY"
echo "Duration: ${DURATION}s"
echo "Pprof:    :$PPROF_PORT"
echo "Results:  $RESULTS_DIR"
echo ""

# =============================================================================
# Step 1: Start the relay with pprof
# =============================================================================
echo "=== Starting relay with pprof ==="
GOEXPERIMENT=synctest $BINARY \
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
# Step 2: Run load test in background
# =============================================================================
echo ""
echo "=== Running load test ==="
if command -v hey &> /dev/null; then
    hey -z "${DURATION}s" \
        -c 50 \
        -disable-keepalive \
        http://127.0.0.1:18080 \
        &> "$RESULTS_DIR/loadtest.log" &
    LOAD_PID=$!
elif command -v vegeta &> /dev/null; then
    echo "GET http://127.0.0.1:18080" | vegeta attack \
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
# Step 3: Collect profiles
# =============================================================================
echo ""
echo "=== Collecting profiles ==="

# Wait for load to ramp up
sleep 5

# CPU Profile (30 seconds)
echo "Collecting CPU profile (30s)..."
curl -s "http://127.0.0.1:$PPROF_PORT/debug/pprof/profile?seconds=30" \
    -o "$RESULTS_DIR/cpu.prof" 2>/dev/null || echo "CPU profile failed"

# Memory Profile
echo "Collecting memory profile..."
curl -s "http://127.0.0.1:$PPROF_PORT/debug/pprof/heap" \
    -o "$RESULTS_DIR/heap.prof" 2>/dev/null || echo "Heap profile failed"

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
