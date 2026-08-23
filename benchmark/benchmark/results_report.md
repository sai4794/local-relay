# Rate Limit Benchmark Report

**Date:** 2026-07-31 22:01:08

**API Endpoint:** http://localhost:20128/v1

**Model:** oc/deepseek-v4-flash-free(max)

**API Key:** sk-4...e9be

## Executive Summary

| Metric | Value |
|--------|-------|
| Test configurations | 1 |

## Key Findings

### IP-Based Rate Limiting: **UNLIKELY**

429 responses are distributed across exit IPs proportionally, suggesting limits are NOT tied to IP.

### Tor Instance Scaling

| Tor Instances | RPS (best) | 429 Rate | P50 Latency |
|---------------|------------|----------|-------------|
| 3 | 1.33 | 0.0% | 0ms |

## Detailed Results

### 3-tor-http-c1 (mode=http_proxy, concurrency=1)

| Metric | Value |
|--------|-------|
| Total requests | 3 |
| Success | 3 (100.0%) |
| 429 (rate limited) | 0 (0.0%) |
| 403 (forbidden) | 0 (0.0%) |
| Timeout | 0 (0.0%) |
| Error | 0 (0.0%) |
| P50 latency | 2005ms |
| P95 latency | 2250ms |
| P99 latency | 2250ms |
| Average latency | 2064ms |
| Requests/sec | 1.33 |
| Duration | 2.251s |
| Unique exit IPs | 1 |

**Exit IP Breakdown:**

| Exit IP | Requests | 429 Rate |
|---------|----------|----------|
| 185.220.100.254 | 3 | 0.0% |

## Exit IP Analysis

| Exit IP | Total Requests | Total 429s | 429 Rate |
|---------|----------------|------------|----------|
| 185.220.100.254 | 3 | 0 | 0.0% |

## Rate Limit Analysis

### Are limits tied to exit IP?

**NO.** 429s are evenly distributed across IPs.

### Are limits tied to the API key?

All tests use the same API key `sk-4...e9be`. No 429s observed — cannot determine API key contribution.

### Does increasing Tor instances increase throughput?

### What is the maximum sustainable requests/sec?

**1.33 RPS** (observed across all configurations).

## Recommendations

### Best Configuration

**3-tor-http-c1** — http_proxy mode, concurrency 1

- RPS: 1.33
- 429 rate: 0.0%
- P50 latency: 2005ms

### Bottleneck

No major bottleneck detected. The system is operating within acceptable limits.

