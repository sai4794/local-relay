#!/usr/bin/env bash
# =============================================================================
# run_all.sh — Run the complete benchmark and profiling suite
#
# Usage:
#   ./bench/run_all.sh
#
# This script:
#   1. Builds the relay binary
#   2. Runs Go benchmarks (with allocation and CPU profiling)
#   3. Starts the relay and runs load tests
#   4. Collects CPU, memory, goroutine, and block profiles
#   5. Generates flamegraphs
#   6. Analyzes results and produces recommendations
# =============================================================================

set -euo pipefail

cd "$(dirname "$0")/.."

RESULTS_DIR="bench/results/$(date +%Y%m%d_%H%M%S)"
PROFILES_DIR="bench/profiles/$(date +%Y%m%d_%H%M%S)"

mkdir -p "$RESULTS_DIR" "$PROFILES_DIR"

echo "============================================"
echo "  local-relay Benchmark & Profiling Suite"
echo "============================================"
echo ""
echo "Results:   $RESULTS_DIR"
echo "Profiles:  $PROFILES_DIR"
echo ""

# =============================================================================
# Step 1: Build
# =============================================================================
echo "=== Step 1: Building ==="
go build -ldflags '-s -w' -o relay ./cmd/relay
echo "Binary: ./relay"
echo ""

# =============================================================================
# Step 2: Go Benchmarks
# =============================================================================
echo "=== Step 2: Go Benchmarks ==="
echo "Running benchmarks with allocation profiling..."
go test -bench=. -benchmem -count=1 \
    -cpuprofile="$RESULTS_DIR/go_cpu.prof" \
    -memprofile="$RESULTS_DIR/go_mem.prof" \
    ./bench/... \
    2>&1 | tee "$RESULTS_DIR/go_bench.txt"
echo ""

# Run benchmarks 3 times for statistical significance
echo "Running benchmarks 3x for variance analysis..."
for i in 1 2 3; do
    echo "--- Run $i ---"
    go test -bench=. -benchmem -count=1 \
        ./bench/... \
        2>&1 | tee "$RESULTS_DIR/go_bench_run${i}.txt"
done
echo ""

# =============================================================================
# Step 3: Profile the running proxy
# =============================================================================
echo "=== Step 3: Profiling Running Proxy ==="
echo "Starting relay for profiling..."
./relay -c config.yaml -v &> "$PROFILES_DIR/relay.log" &
RELAY_PID=$!
sleep 3

# Check if relay is running
if ! kill -0 $RELAY_PID 2>/dev/null; then
    echo "ERROR: Relay failed to start"
    cat "$PROFILES_DIR/relay.log"
    kill $RELAY_PID 2>/dev/null || true
    exit 1
fi

echo "Relay PID: $RELAY_PID"

# Run load test in background
echo "Starting load test..."
if command -v hey &> /dev/null; then
    hey -z 30s -c 50 -disable-keepalive http://127.0.0.1:18080 \
        &> "$PROFILES_DIR/loadtest.log" &
    LOAD_PID=$!
elif command -v vegeta &> /dev/null; then
    echo "GET http://127.0.0.1:18080" | vegeta attack \
        -duration=30s -rate=500 -connections=50 \
        &> "$PROFILES_DIR/loadtest.log" &
    LOAD_PID=$!
else
    echo "WARNING: No load test tool found. Install hey or vegeta."
    LOAD_PID=""
fi

# Wait for load to stabilize
sleep 5

# Collect profiles
echo "Collecting CPU profile (30s)..."
curl -s "http://127.0.0.1:6060/debug/pprof/profile?seconds=30" \
    -o "$PROFILES_DIR/cpu.prof" 2>/dev/null || echo "CPU profile failed"

echo "Collecting heap profile..."
curl -s "http://127.0.0.1:6060/debug/pprof/heap" \
    -o "$PROFILES_DIR/heap.prof" 2>/dev/null || echo "Heap profile failed"

echo "Collecting goroutine profile..."
curl -s "http://127.0.0.1:6060/debug/pprof/goroutine" \
    -o "$PROFILES_DIR/goroutine.prof" 2>/dev/null || echo "Goroutine profile failed"

echo "Collecting block profile..."
curl -s "http://127.0.0.1:6060/debug/pprof/block" \
    -o "$PROFILES_DIR/block.prof" 2>/dev/null || echo "Block profile failed"

echo "Collecting 5s CPU profile for flamegraph..."
curl -s "http://127.0.0.1:6060/debug/pprof/profile?seconds=5" \
    -o "$PROFILES_DIR/flamegraph.prof" 2>/dev/null || echo "Flamegraph profile failed"

# Cleanup
if [ -n "${LOAD_PID:-}" ]; then
    kill $LOAD_PID 2>/dev/null || true
    wait $LOAD_PID 2>/dev/null || true
fi
kill $RELAY_PID 2>/dev/null || true
wait $RELAY_PID 2>/dev/null || true
echo "Relay stopped."
echo ""

# =============================================================================
# Step 4: Generate Reports
# =============================================================================
echo "=== Step 4: Generating Reports ==="

if [ -f "$PROFILES_DIR/cpu.prof" ]; then
    echo "CPU Profile (top 30):"
    go tool pprof -text -nodecount=30 "$PROFILES_DIR/cpu.prof" \
        | tee "$PROFILES_DIR/cpu_report.txt"
    echo ""
fi

if [ -f "$PROFILES_DIR/heap.prof" ]; then
    echo "Heap Profile (top 30):"
    go tool pprof -text -nodecount=30 "$PROFILES_DIR/heap.prof" \
        | tee "$PROFILES_DIR/heap_report.txt"
    echo ""
fi

if [ -f "$PROFILES_DIR/goroutine.prof" ]; then
    echo "Goroutine Profile (top 30):"
    go tool pprof -text -nodecount=30 "$PROFILES_DIR/goroutine.prof" \
        | tee "$PROFILES_DIR/goroutine_report.txt"
    echo ""
fi

# Generate flamegraph
if [ -f "$PROFILES_DIR/flamegraph.prof" ]; then
    go tool pprof -svg "$PROFILES_DIR/flamegraph.prof" \
        > "$PROFILES_DIR/flamegraph.svg" 2>/dev/null || echo "SVG flamegraph failed"
    go tool pprof -png "$PROFILES_DIR/flamegraph.prof" \
        > "$PROFILES_DIR/flamegraph.png" 2>/dev/null || echo "PNG flamegraph failed"
    echo "Flamegraph: $PROFILES_DIR/flamegraph.svg"
fi

# =============================================================================
# Step 5: Analysis
# =============================================================================
echo ""
echo "=== Step 5: Analysis ==="
./bench/analyze.sh "$RESULTS_DIR" "$PROFILES_DIR"

# =============================================================================
# Summary
# =============================================================================
echo ""
echo "============================================"
echo "  Benchmark Suite Complete"
echo "============================================"
echo ""
echo "Results:   $RESULTS_DIR"
echo "Profiles:  $PROFILES_DIR"
echo ""
echo "Key files:"
echo "  - $RESULTS_DIR/go_bench.txt        (Go benchmark results)"
echo "  - $PROFILES_DIR/cpu.prof            (CPU profile)"
echo "  - $PROFILES_DIR/heap.prof           (Memory profile)"
echo "  - $PROFILES_DIR/goroutine.prof      (Goroutine profile)"
echo "  - $PROFILES_DIR/block.prof          (Block profile)"
echo "  - $PROFILES_DIR/flamegraph.svg      (Flamegraph)"
echo ""
echo "To view profiles interactively:"
echo "  go tool pprof -http=:8080 $PROFILES_DIR/cpu.prof"
echo ""
echo "To compare before/after:"
echo "  go tool pprof -base old.prof new.prof"
