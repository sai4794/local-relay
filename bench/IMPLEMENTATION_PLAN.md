# Benchmark & Profiling Implementation Plan

---

## Implementation Order

### Phase 1: Setup (30 minutes)

1. **Run Go benchmarks** — establish baseline
   ```bash
   cd /home/stb/local-relay
   go test -bench=. -benchmem -count=3 ./bench/... 2>&1 | tee bench/results/baseline.txt
   ```

2. **Build relay binary** — ready for profiling
   ```bash
   go build -ldflags '-s -w' -o relay ./cmd/relay
   ```

3. **Verify benchmark infrastructure** — all tests pass
   ```bash
   go test -v ./bench/...
   ```

### Phase 2: CPU Profiling (1 hour)

1. **Run relay with pprof enabled**
   ```bash
   # Add to main.go or use GOEXPERIMENT
   go build -race -o relay ./cmd/relay
   ./relay -c config.yaml -v &
   ```

2. **Collect CPU profile under load**
   ```bash
   # Install hey if not present
   go install github.com/rakyll/hey@latest

   # Run load test
   hey -z 30s -c 50 -disable-keepalive http://127.0.0.1:18080 &

   # Collect CPU profile
   curl -s http://127.0.0.1:6060/debug/pprof/profile?seconds=30 > cpu.prof

   # Analyze
   go tool pprof -text -nodecount=30 cpu.prof
   ```

3. **Identify top 10 CPU hotspots**
   - Look for functions consuming >1% of total CPU time
   - Focus on functions in the request path (DialContext, SOCKS5 handshake, relay)

### Phase 3: Memory Profiling (1 hour)

1. **Collect heap profile**
   ```bash
   curl -s http://127.0.0.1:6060/debug/pprof/heap > heap.prof

   # Analyze allocations
   go tool pprof -text -alloc_space -nodecount=30 heap.prof

   # Analyze inuse
   go tool pprof -text -inuse_space -nodecount=30 heap.prof
   ```

2. **Identify top 10 allocation hotspots**
   - Look for functions allocating >1KB per request
   - Focus on per-request allocations (buffers, slices, maps)

### Phase 4: Goroutine & Block Profiling (1 hour)

1. **Collect goroutine profile**
   ```bash
   curl -s http://127.0.0.1:6060/debug/pprof/goroutine > goroutine.prof
   go tool pprof -text -nodecount=30 goroutine.prof
   ```

2. **Collect block profile**
   ```bash
   curl -s http://127.0.0.1:6060/debug/pprof/block > block.prof
   go tool pprof -text -nodecount=30 block.prof
   ```

3. **Identify goroutine leaks and contention**
   - Look for goroutines stuck in channel operations
   - Look for mutex contention in hot paths

### Phase 5: Flamegraph Analysis (30 minutes)

1. **Generate flamegraph**
   ```bash
   curl -s http://127.0.0.1:6060/debug/pprof/profile?seconds=5 > flame.prof
   go tool pprof -svg flame.prof > flamegraph.svg
   ```

2. **Identify wide stacks** — functions with high cumulative time
   - Wide stacks in the request path = optimization targets
   - Narrow stacks = already efficient

### Phase 6: Load Testing (1 hour)

1. **Run external load tests**
   ```bash
   # Vegeta
   echo "GET http://127.0.0.1:18080" | vegeta attack -duration=30s -rate=500 | vegeta report

   # Hey
   hey -z 30s -c 50 -disable-keepalive http://127.0.0.1:18080

   # Wrk
   wrk -t4 -c50 -d30s --latency http://127.0.0.1:18080
   ```

2. **Record baseline metrics**
   - P50, P95, P99 latency
   - Requests/sec
   - Error rate
   - Memory usage
   - Goroutine count

---

## Stop Conditions

### Stop profiling when:

1. **CPU hotspots are identified** — top 10 functions consuming >80% of CPU time
2. **Memory hotspots are identified** — top 10 functions responsible for >80% of allocations
3. **Goroutine patterns are clear** — no unexpected goroutine growth
4. **Block patterns are clear** — no unexpected contention

### Stop benchmarking when:

1. **Variance is low** — coefficient of variation <10% across 3 runs
2. **Results are reproducible** — same top 10 hotspots across runs
3. **Baseline is established** — all metrics recorded with confidence intervals

### Stop analysis when:

1. **Optimization candidates are ranked** — by expected impact and confidence
2. **Decision matrix is complete** — IMPLEMENT / MEASURE FIRST / REJECT for each candidate
3. **No more data is needed** — additional profiling would not change decisions

---

## Expected Hotspots (Hypotheses — To Be Measured)

These are hypotheses. Do NOT optimize until measured.

| Hypothesis | Expected Impact | Measurement |
|------------|-----------------|-------------|
| NEWNYM blocks request path | 100-500ms per rotation | CPU profile of DialContext |
| crypto/rand is slow | 1-10μs per request | BenchmarkCryptoRandInt vs BenchmarkMathRandInt |
| SOCKS5 handshake allocates | 2-4 allocs per connection | BenchmarkSOCKS5Handshake |
| sanitizeURL rebuilds query | 3-5 allocs per request | BenchmarkSanitizeURL |
| Header cloning allocates | 1-2 allocs per request | BenchmarkHeaderStripping |
| Buffer pool is inefficient | 1 alloc per request | BenchmarkBufferPool |
| Short-tunnel timer wastes goroutines | 2-3 allocs per CONNECT | Goroutine profile |
| DNS lookup on first request | 50-200ms latency | DNSResolution benchmark |

---

## Decision Framework

For each measured hotspot:

```
IF measured_improvement > 15%:
    IMPLEMENT (high confidence)
ELIF measured_improvement > 5%:
    MEASURE FIRST (need more data)
ELIF measured_improvement > 2%:
    REJECT (not worth complexity)
ELSE:
    REJECT (noise)
```

### What counts as "15% improvement"?

- 15% reduction in P99 latency for the request path
- 15% reduction in allocations per request
- 15% reduction in CPU time for the hot path
- 15% increase in throughput (req/s)

### What does NOT count?

- Theoretical improvement without measurement
- Improvement in a synthetic benchmark that does not reflect real usage
- Improvement that requires external dependencies
- Improvement that reduces code clarity

---

## Files to Create

| File | Purpose |
|------|---------|
| `bench/bench_test.go` | Core benchmark suite |
| `bench/bench_latency_test.go` | Latency and throughput benchmarks |
| `bench/loadtest.sh` | External load testing script |
| `bench/profile.sh` | Profiling collection script |
| `bench/analyze.sh` | Results analysis script |
| `bench/run_all.sh` | Complete benchmark pipeline |
| `bench/metrics_schema.md` | Prometheus metrics schema |
| `bench/grafana_dashboard.json` | Grafana dashboard |
| `bench/IMPLEMENTATION_PLAN.md` | This file |
