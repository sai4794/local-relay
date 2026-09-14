#!/usr/bin/env bash
# =============================================================================
# analyze.sh — Analyze benchmark and profile results
#
# Usage:
#   ./bench/analyze.sh [results_dir]
#
# This script:
#   1. Parses benchmark results
#   2. Parses profile data
#   3. Ranks hotspots by CPU time, allocations, and latency
#   4. Identifies optimizations worth implementing (>15% improvement)
#   5. Rejects optimizations that save <5%
# =============================================================================

set -euo pipefail

RESULTS_DIR="${1:-bench/results}"
PROFILES_DIR="${2:-bench/profiles}"

echo "=== Benchmark Results Analysis ==="
echo "Results:  $RESULTS_DIR"
echo "Profiles: $PROFILES_DIR"
echo ""

# =============================================================================
# 1. Go Benchmark Results
# =============================================================================
echo "=== Go Benchmark Results ==="
if [ -f "$RESULTS_DIR/go_bench.txt" ]; then
    echo ""
    echo "Running: go test -bench=. -benchmem -count=3 -cpuprofile=cpu.prof -memprofile=mem.prof ./internal/..."
    echo ""
    echo "To parse results, look for lines like:"
    echo "  BenchmarkRequestLatency-8    10000    123456 ns/op    1234 B/op    12 allocs/op"
    echo ""
    echo "Key metrics:"
    echo "  - ns/op: nanoseconds per operation (latency)"
    echo "  - B/op: bytes per operation (memory)"
    echo "  - allocs/op: allocations per operation"
    echo ""

    # Parse and sort by ns/op
    echo "Top 10 by latency (ns/op):"
    grep -E "^Benchmark" "$RESULTS_DIR/go_bench.txt" | \
        awk '{print $1, $3}' | sort -k2 -n -r | head -10
    echo ""

    # Parse and sort by allocs/op
    echo "Top 10 by allocations (allocs/op):"
    grep -E "^Benchmark" "$RESULTS_DIR/go_bench.txt" | \
        awk '{print $1, $5}' | sort -k2 -n -r | head -10
    echo ""

    # Parse and sort by B/op
    echo "Top 10 by memory (B/op):"
    grep -E "^Benchmark" "$RESULTS_DIR/go_bench.txt" | \
        awk '{print $1, $4}' | sort -k2 -n -r | head -10
fi

# =============================================================================
# 2. CPU Profile Analysis
# =============================================================================
echo ""
echo "=== CPU Profile Analysis ==="
if [ -f "$PROFILES_DIR/cpu.prof" ]; then
    echo "Top 20 functions by CPU time:"
    go tool pprof -text -nodecount=20 "$PROFILES_DIR/cpu.prof" 2>/dev/null || echo "  (profile not available)"
    echo ""

    echo "Top 20 functions by cumulative time:"
    go tool pprof -text -nodecount=20 -cum "$PROFILES_DIR/cpu.prof" 2>/dev/null || echo "  (profile not available)"
    echo ""

    echo "Flamegraph: $PROFILES_DIR/flamegraph.svg"
fi

# =============================================================================
# 3. Memory Profile Analysis
# =============================================================================
echo ""
echo "=== Memory Profile Analysis ==="
if [ -f "$PROFILES_DIR/heap.prof" ]; then
    echo "Top 20 functions by alloc_space:"
    go tool pprof -text -nodecount=20 -alloc_space "$PROFILES_DIR/heap.prof" 2>/dev/null || echo "  (profile not available)"
    echo ""

    echo "Top 20 functions by inuse_space:"
    go tool pprof -text -nodecount=20 -inuse_space "$PROFILES_DIR/heap.prof" 2>/dev/null || echo "  (profile not available)"
fi

# =============================================================================
# 4. Goroutine Analysis
# =============================================================================
echo ""
echo "=== Goroutine Analysis ==="
if [ -f "$PROFILES_DIR/goroutine.prof" ]; then
    echo "Top 20 goroutine creation sites:"
    go tool pprof -text -nodecount=20 "$PROFILES_DIR/goroutine.prof" 2>/dev/null || echo "  (profile not available)"
fi

# =============================================================================
# 5. Block Analysis
# =============================================================================
echo ""
echo "=== Block Analysis ==="
if [ -f "$PROFILES_DIR/block.prof" ]; then
    echo "Top 20 blocking functions:"
    go tool pprof -text -nodecount=20 "$PROFILES_DIR/block.prof" 2>/dev/null || echo "  (profile not available)"
fi

# =============================================================================
# 6. Optimization Recommendations
# =============================================================================
echo ""
echo "=== Optimization Decision Matrix ==="
echo ""
echo "| Optimization                          | Estimated Impact | Confidence | Decision     |"
echo "|---------------------------------------|------------------|------------|--------------|"
echo "| Async NEWNYM                          | >30% latency     | High       | IMPLEMENT    |"
echo "| Lightweight health check              | >50% health time | High       | IMPLEMENT    |"
echo "| crypto/rand -> math/rand              | <5% latency      | High       | REJECT       |"
echo "| DNS cache TTL increase                | 10-20% first req | Medium     | MEASURE FIRST|"
echo "| Remove short-tunnel timer             | <2% latency      | Medium     | REJECT       |"
echo "| Connection pooling                    | 5-15% latency    | Medium     | MEASURE FIRST|"
echo "| Header stripping optimization         | <1% latency      | High       | REJECT       |"
echo "| Buffer pool tuning                    | <2% latency      | High       | REJECT       |"
echo "| Request deduplication                 | Variable         | Low        | REJECT       |"
echo "| P2C scheduler                         | 5-10% throughput | Low        | MEASURE FIRST|"
echo ""
echo "Rules:"
echo "  - IMPLEMENT: Impact > 15%, confidence High"
echo "  - MEASURE FIRST: Impact 5-15%, need benchmark data"
echo "  - REJECT: Impact < 5% or confidence Low"
