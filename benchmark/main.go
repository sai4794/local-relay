package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------- Config ----------

const (
	defaultBaseURL   = "http://localhost:20128/v1"
	defaultAPIKey    = "" // empty: require -key flag or BENCH_API_KEY env
	defaultModel     = "oc/deepseek-v4-flash-free(max)"
	defaultRelayHTTP = "http://127.0.0.1:18080"
	defaultRelayS5   = "socks5://127.0.0.1:11080"
	exitIPService    = "http://api.ipify.org"
	requestBody      = `{"model":"%s","messages":[{"role":"user","content":"Say hello in exactly 3 words."}],"max_tokens":20,"temperature":0}`
)

// ---------- Data types ----------

// RequestRecord is one benchmarked request. TorInstance/ExitIP are
// approximate: a single exit IP is cached per proxy configuration
// (see refreshExitIP) and stamped on every record, and TorInstance is
// derived as requestID % torCount rather than the instance that served it.
type RequestRecord struct {
	RequestID   int       `json:"request_id"`
	Timestamp   time.Time `json:"timestamp"`
	TorInstance int       `json:"tor_instance"` // approximate: idx % TorCount, not observed
	ExitIP      string    `json:"exit_ip"`      // approximate: single cached IP per config
	HTTPStatus  int       `json:"http_status"`
	LatencyMs   float64   `json:"latency_ms"`
	Is429       bool      `json:"is_429"`
	Is403       bool      `json:"is_403"`
	IsTimeout   bool      `json:"is_timeout"`
	IsError     bool      `json:"is_error"`
	ErrorMsg    string    `json:"error_msg,omitempty"`
	Path        string    `json:"path"`
}

type BenchConfig struct {
	BaseURL     string
	APIKey      string
	Model       string
	ProxyURL    string
	Concurrency int
	TotalReqs   int
	Mode        string // "direct", "http_proxy", "socks5_proxy"
	TorCount    int
	Label       string
}

type Summary struct {
	Config        BenchConfig
	Records       []RequestRecord
	TotalRequests int
	SuccessCount  int
	Count429      int
	Count403      int
	CountTimeout  int
	CountError    int
	P50           float64
	P95           float64
	P99           float64
	AvgLatency    float64
	RPS           float64
	Duration      time.Duration
	UniqueIPs     []string
	IPCounts      map[string]int
	IP429Rates    map[string]float64
}

// ---------- Exit IP cache ----------

var (
	// exitIPCache holds ONE cached exit IP per proxy address. Records stamp
	// this single value, so per-record TorInstance/ExitIP columns are
	// approximate, not per-request observations.
	exitIPCache   = make(map[string]string) // proxyAddr -> exitIP
	exitIPCacheMu sync.Mutex
)

func getExitIP(proxyAddr string) string {
	exitIPCacheMu.Lock()
	defer exitIPCacheMu.Unlock()
	if ip, ok := exitIPCache[proxyAddr]; ok {
		return ip
	}
	return ""
}

func refreshExitIP(proxyAddr string) string {
	var client *http.Client
	if proxyAddr == "" || proxyAddr == "direct" {
		client = &http.Client{Timeout: 10 * time.Second}
	} else {
		proxyURL, err := url.Parse(proxyAddr)
		if err != nil {
			return ""
		}
		client = &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
			},
		}
	}

	resp, err := client.Get(exitIPService)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	ip := strings.TrimSpace(string(body))

	// Validate it's an IP
	if net.ParseIP(ip) == nil {
		return ""
	}

	exitIPCacheMu.Lock()
	exitIPCache[proxyAddr] = ip
	exitIPCacheMu.Unlock()
	return ip
}

// ---------- HTTP client factory ----------

func makeClient(proxyAddr string) *http.Client {
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	if proxyAddr != "" && proxyAddr != "direct" {
		proxyURL, err := url.Parse(proxyAddr)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	return &http.Client{
		Timeout:   60 * time.Second,
		Transport: transport,
	}
}

// ---------- Benchmark runner ----------

func runBenchmark(cfg BenchConfig) Summary {
	fmt.Printf("\n=== Benchmark: %s | concurrency=%d | total=%d | mode=%s ===\n",
		cfg.Label, cfg.Concurrency, cfg.TotalReqs, cfg.Mode)

	// Refresh exit IP
	exitIP := refreshExitIP(cfg.ProxyURL)
	fmt.Printf("  Exit IP: %s\n", exitIP)

	client := makeClient(cfg.ProxyURL)
	body := fmt.Sprintf(requestBody, cfg.Model)

	records := make([]RequestRecord, cfg.TotalReqs)
	var wg sync.WaitGroup
	var sem chan struct{}
	if cfg.Concurrency > 1 {
		sem = make(chan struct{}, cfg.Concurrency)
	}

	var (
		successCount atomic.Int64
		count429     atomic.Int64
		count403     atomic.Int64
		countTimeout atomic.Int64
		countError   atomic.Int64
	)

	startTime := time.Now()

	for i := 0; i < cfg.TotalReqs; i++ {
		if sem != nil {
			sem <- struct{}{}
		}
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if sem != nil {
				defer func() { <-sem }()
			}

			record := makeRequest(idx, client, cfg, body, exitIP)
			records[idx] = record

			switch {
			case record.Is429:
				count429.Add(1)
			case record.Is403:
				count403.Add(1)
			case record.IsTimeout:
				countTimeout.Add(1)
			case record.IsError:
				countError.Add(1)
			default:
				successCount.Add(1)
			}

			if (idx+1)%50 == 0 || idx == cfg.TotalReqs-1 {
				fmt.Printf("  [%s] Progress: %d/%d | 429=%d 403=%d timeout=%d err=%d ok=%d\n",
					cfg.Label, idx+1, cfg.TotalReqs,
					count429.Load(), count403.Load(), countTimeout.Load(),
					countError.Load(), successCount.Load())
			}
		}(i)
	}

	wg.Wait()
	duration := time.Since(startTime)

	// Build summary
	latencies := make([]float64, 0, cfg.TotalReqs)
	ipCounts := make(map[string]int)
	for _, r := range records {
		if !r.IsError && !r.IsTimeout {
			latencies = append(latencies, r.LatencyMs)
		}
		if r.ExitIP != "" {
			ipCounts[r.ExitIP]++
		}
	}

	sort.Float64s(latencies)
	p50 := percentile(latencies, 50)
	p95 := percentile(latencies, 95)
	p99 := percentile(latencies, 99)
	avg := mean(latencies)

	uniqueIPs := make([]string, 0, len(ipCounts))
	for ip := range ipCounts {
		uniqueIPs = append(uniqueIPs, ip)
	}
	sort.Strings(uniqueIPs)

	ip429Rates := make(map[string]float64)
	ipReqs := make(map[string]int)
	for _, r := range records {
		if r.ExitIP != "" {
			ipReqs[r.ExitIP]++
			if r.Is429 {
				ip429Rates[r.ExitIP]++
			}
		}
	}
	for ip, count := range ip429Rates {
		if ipReqs[ip] > 0 {
			ip429Rates[ip] = count / float64(ipReqs[ip]) * 100
		}
	}

	rps := float64(cfg.TotalReqs) / duration.Seconds()

	summary := Summary{
		Config:        cfg,
		Records:       records,
		TotalRequests: cfg.TotalReqs,
		SuccessCount:  int(successCount.Load()),
		Count429:      int(count429.Load()),
		Count403:      int(count403.Load()),
		CountTimeout:  int(countTimeout.Load()),
		CountError:    int(countError.Load()),
		P50:           p50,
		P95:           p95,
		P99:           p99,
		AvgLatency:    avg,
		RPS:           rps,
		Duration:      duration,
		UniqueIPs:     uniqueIPs,
		IPCounts:      ipCounts,
		IP429Rates:    ip429Rates,
	}

	printSummary(summary)
	return summary
}

func makeRequest(idx int, client *http.Client, cfg BenchConfig, body string, cachedExitIP string) RequestRecord {
	record := RequestRecord{
		RequestID:   idx,
		Timestamp:   time.Now(),
		TorInstance: idx % cfg.TorCount,
		ExitIP:      cachedExitIP,
		Path:        cfg.Mode,
	}

	start := time.Now()
	req, err := http.NewRequest("POST", cfg.BaseURL+"/chat/completions", bytes.NewBufferString(body))
	if err != nil {
		record.IsError = true
		record.ErrorMsg = err.Error()
		return record
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)

	resp, err := client.Do(req)
	record.LatencyMs = float64(time.Since(start).Milliseconds())

	if err != nil {
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline") {
			record.IsTimeout = true
		} else {
			record.IsError = true
			record.ErrorMsg = err.Error()
		}
		return record
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	record.HTTPStatus = resp.StatusCode
	record.Is429 = resp.StatusCode == 429
	record.Is403 = resp.StatusCode == 403

	return record
}

func printSummary(s Summary) {
	fmt.Printf("\n--- Summary: %s ---\n", s.Config.Label)
	fmt.Printf("  Total: %d | Success: %d | 429: %d | 403: %d | Timeout: %d | Error: %d\n",
		s.TotalRequests, s.SuccessCount, s.Count429, s.Count403, s.CountTimeout, s.CountError)
	fmt.Printf("  Latency P50=%.0fms P95=%.0fms P99=%.0fms Avg=%.0fms\n",
		s.P50, s.P95, s.P99, s.AvgLatency)
	fmt.Printf("  RPS: %.2f | Duration: %s\n", s.RPS, s.Duration.Round(time.Millisecond))
	fmt.Printf("  Unique exit IPs: %d\n", len(s.UniqueIPs))
	for _, ip := range s.UniqueIPs {
		fmt.Printf("    %s: %d reqs, 429 rate: %.1f%%\n", ip, s.IPCounts[ip], s.IP429Rates[ip])
	}
}

// ---------- Statistics ----------

func percentile(sorted []float64, p int) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(math.Ceil(float64(p)/100*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func mean(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range vals {
		sum += v
	}
	return sum / float64(len(vals))
}

// ---------- CSV writer ----------

// openResultFile creates a result file owner-only (0600): benchmark outputs
// derive from runs that handle API keys, so results must never be
// world-readable.
func openResultFile(filename string) (*os.File, error) {
	return os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
}

func writeCSV(filename string, summaries []Summary) error {
	f, err := openResultFile(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	w.Write([]string{
		"label", "mode", "concurrency", "total_reqs",
		"success", "count_429", "count_403", "count_timeout", "count_error",
		"p50_ms", "p95_ms", "p99_ms", "avg_ms", "rps",
		"unique_ips", "duration_s",
	})

	for _, s := range summaries {
		w.Write([]string{
			s.Config.Label,
			s.Config.Mode,
			fmt.Sprintf("%d", s.Config.Concurrency),
			fmt.Sprintf("%d", s.TotalRequests),
			fmt.Sprintf("%d", s.SuccessCount),
			fmt.Sprintf("%d", s.Count429),
			fmt.Sprintf("%d", s.Count403),
			fmt.Sprintf("%d", s.CountTimeout),
			fmt.Sprintf("%d", s.CountError),
			fmt.Sprintf("%.1f", s.P50),
			fmt.Sprintf("%.1f", s.P95),
			fmt.Sprintf("%.1f", s.P99),
			fmt.Sprintf("%.1f", s.AvgLatency),
			fmt.Sprintf("%.2f", s.RPS),
			fmt.Sprintf("%d", len(s.UniqueIPs)),
			fmt.Sprintf("%.1f", s.Duration.Seconds()),
		})
	}
	return nil
}

func writeDetailCSV(filename string, summaries []Summary) error {
	f, err := openResultFile(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	w.Write([]string{
		"label", "request_id", "timestamp", "tor_instance",
		"exit_ip", "http_status", "latency_ms",
		"is_429", "is_403", "is_timeout", "is_error", "error_msg",
	})

	for _, s := range summaries {
		for _, r := range s.Records {
			w.Write([]string{
				s.Config.Label,
				fmt.Sprintf("%d", r.RequestID),
				r.Timestamp.Format(time.RFC3339Nano),
				fmt.Sprintf("%d", r.TorInstance),
				r.ExitIP,
				fmt.Sprintf("%d", r.HTTPStatus),
				fmt.Sprintf("%.1f", r.LatencyMs),
				fmt.Sprintf("%t", r.Is429),
				fmt.Sprintf("%t", r.Is403),
				fmt.Sprintf("%t", r.IsTimeout),
				fmt.Sprintf("%t", r.IsError),
				r.ErrorMsg,
			})
		}
	}
	return nil
}

// ---------- Report generator ----------

func writeReport(filename string, summaries []Summary) error {
	f, err := openResultFile(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Fprintf(f, "# Rate Limit Benchmark Report\n\n")
	fmt.Fprintf(f, "**Date:** %s\n\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(f, "**API Endpoint:** %s\n\n", summaries[0].Config.BaseURL)
	fmt.Fprintf(f, "**Model:** %s\n\n", summaries[0].Config.Model)
	fmt.Fprintf(f, "**API Key:** %s\n\n", maskKey(summaries[0].Config.APIKey))

	// Executive Summary
	fmt.Fprintf(f, "## Executive Summary\n\n")
	fmt.Fprintf(f, "| Metric | Value |\n|--------|-------|\n")

	totals := aggregateByTorCount(summaries)
	fmt.Fprintf(f, "| Test configurations | %d |\n", len(summaries))

	// Key findings
	fmt.Fprintf(f, "\n## Key Findings\n\n")

	// Check if 429s are IP-correlated
	ipCorrelated := checkIPCorrelation(summaries)
	if ipCorrelated {
		fmt.Fprintf(f, "### IP-Based Rate Limiting: **YES**\n\n")
		fmt.Fprintf(f, "429 responses cluster around specific exit IPs, confirming IP-based rate limiting.\n\n")
	} else {
		fmt.Fprintf(f, "### IP-Based Rate Limiting: **UNLIKELY**\n\n")
		fmt.Fprintf(f, "429 responses are distributed across exit IPs proportionally, suggesting limits are NOT tied to IP.\n\n")
	}

	// Tor instance scaling
	fmt.Fprintf(f, "### Tor Instance Scaling\n\n")
	fmt.Fprintf(f, "| Tor Instances | RPS (best) | 429 Rate | P50 Latency |\n")
	fmt.Fprintf(f, "|---------------|------------|----------|-------------|\n")
	for _, t := range totals {
		bestRPS := 0.0
		best429Rate := 100.0
		bestP50 := 0.0
		for _, s := range t.summaries {
			if s.RPS > bestRPS {
				bestRPS = s.RPS
			}
			rate := float64(s.Count429) / float64(s.TotalRequests) * 100
			if rate < best429Rate {
				best429Rate = rate
			}
			if s.P50 < bestP50 || bestP50 == 0 {
				bestP50 = s.P50
			}
		}
		fmt.Fprintf(f, "| %d | %.2f | %.1f%% | %.0fms |\n",
			t.torCount, bestRPS, best429Rate, bestP50)
	}

	fmt.Fprintf(f, "\n> Note: TorInstance/ExitIP columns are approximate (single cached IP per configuration, instance derived as requestID %% TorCount).\n\n")

	// Detailed results per configuration
	fmt.Fprintf(f, "\n## Detailed Results\n\n")
	for _, s := range summaries {
		fmt.Fprintf(f, "### %s (mode=%s, concurrency=%d)\n\n", s.Config.Label, s.Config.Mode, s.Config.Concurrency)
		fmt.Fprintf(f, "| Metric | Value |\n|--------|-------|\n")
		fmt.Fprintf(f, "| Total requests | %d |\n", s.TotalRequests)
		fmt.Fprintf(f, "| Success | %d (%.1f%%) |\n", s.SuccessCount, pct(s.SuccessCount, s.TotalRequests))
		fmt.Fprintf(f, "| 429 (rate limited) | %d (%.1f%%) |\n", s.Count429, pct(s.Count429, s.TotalRequests))
		fmt.Fprintf(f, "| 403 (forbidden) | %d (%.1f%%) |\n", s.Count403, pct(s.Count403, s.TotalRequests))
		fmt.Fprintf(f, "| Timeout | %d (%.1f%%) |\n", s.CountTimeout, pct(s.CountTimeout, s.TotalRequests))
		fmt.Fprintf(f, "| Error | %d (%.1f%%) |\n", s.CountError, pct(s.CountError, s.TotalRequests))
		fmt.Fprintf(f, "| P50 latency | %.0fms |\n", s.P50)
		fmt.Fprintf(f, "| P95 latency | %.0fms |\n", s.P95)
		fmt.Fprintf(f, "| P99 latency | %.0fms |\n", s.P99)
		fmt.Fprintf(f, "| Average latency | %.0fms |\n", s.AvgLatency)
		fmt.Fprintf(f, "| Requests/sec | %.2f |\n", s.RPS)
		fmt.Fprintf(f, "| Duration | %s |\n", s.Duration.Round(time.Millisecond))
		fmt.Fprintf(f, "| Unique exit IPs | %d |\n", len(s.UniqueIPs))

		if len(s.UniqueIPs) > 0 {
			fmt.Fprintf(f, "\n**Exit IP Breakdown:**\n\n")
			fmt.Fprintf(f, "| Exit IP | Requests | 429 Rate |\n|---------|----------|----------|\n")
			for _, ip := range s.UniqueIPs {
				fmt.Fprintf(f, "| %s | %d | %.1f%% |\n", ip, s.IPCounts[ip], s.IP429Rates[ip])
			}
		}
		fmt.Fprintf(f, "\n")
	}

	// Exit IP Analysis
	fmt.Fprintf(f, "## Exit IP Analysis\n\n")
	allIPs := make(map[string]map[string]int) // ip -> {label -> count}
	allIP429 := make(map[string]map[string]int)
	for _, s := range summaries {
		for ip, count := range s.IPCounts {
			if allIPs[ip] == nil {
				allIPs[ip] = make(map[string]int)
				allIP429[ip] = make(map[string]int)
			}
			allIPs[ip][s.Config.Label] += count
		}
		for _, r := range s.Records {
			if r.Is429 && r.ExitIP != "" {
				if allIP429[r.ExitIP] == nil {
					allIP429[r.ExitIP] = make(map[string]int)
				}
				allIP429[r.ExitIP][s.Config.Label]++
			}
		}
	}

	sortedIPs := make([]string, 0, len(allIPs))
	for ip := range allIPs {
		sortedIPs = append(sortedIPs, ip)
	}
	sort.Strings(sortedIPs)

	fmt.Fprintf(f, "| Exit IP | Total Requests | Total 429s | 429 Rate |\n")
	fmt.Fprintf(f, "|---------|----------------|------------|----------|\n")
	for _, ip := range sortedIPs {
		totalReqs := 0
		total429 := 0
		for _, c := range allIPs[ip] {
			totalReqs += c
		}
		for _, c := range allIP429[ip] {
			total429 += c
		}
		rate := 0.0
		if totalReqs > 0 {
			rate = float64(total429) / float64(totalReqs) * 100
		}
		fmt.Fprintf(f, "| %s | %d | %d | %.1f%% |\n", ip, totalReqs, total429, rate)
	}

	// Rate Limit Analysis
	fmt.Fprintf(f, "\n## Rate Limit Analysis\n\n")
	fmt.Fprintf(f, "### Are limits tied to exit IP?\n\n")
	if ipCorrelated {
		fmt.Fprintf(f, "**YES.** 429 responses cluster on specific exit IPs.\n\n")
	} else {
		fmt.Fprintf(f, "**NO.** 429s are evenly distributed across IPs.\n\n")
	}

	fmt.Fprintf(f, "### Are limits tied to the API key?\n\n")
	fmt.Fprintf(f, "All tests use the same API key `%s`. ", maskKey(summaries[0].Config.APIKey))
	if totals[0].summaries[0].Count429 > 0 {
		fmt.Fprintf(f, "Rate limits are triggered even through different IPs, suggesting API key is also a limiting factor.\n\n")
	} else {
		fmt.Fprintf(f, "No 429s observed — cannot determine API key contribution.\n\n")
	}

	fmt.Fprintf(f, "### Does increasing Tor instances increase throughput?\n\n")
	if len(totals) > 1 {
		best0 := totals[0].bestRPS
		bestLast := totals[len(totals)-1].bestRPS
		if bestLast > best0*1.1 {
			fmt.Fprintf(f, "**YES.** RPS increased from %.2f (%d Tor) to %.2f (%d Tor) — %.1fx improvement.\n\n",
				best0, totals[0].torCount, bestLast, totals[len(totals)-1].torCount, bestLast/best0)
		} else {
			fmt.Fprintf(f, "**NO significant improvement.** RPS: %.2f (%d Tor) → %.2f (%d Tor).\n\n",
				best0, totals[0].torCount, bestLast, totals[len(totals)-1].torCount)
		}
	}

	fmt.Fprintf(f, "### What is the maximum sustainable requests/sec?\n\n")
	bestRPS := 0.0
	for _, s := range summaries {
		if s.RPS > bestRPS {
			bestRPS = s.RPS
		}
	}
	fmt.Fprintf(f, "**%.2f RPS** (observed across all configurations).\n\n", bestRPS)

	// Recommendations
	fmt.Fprintf(f, "## Recommendations\n\n")
	fmt.Fprintf(f, "### Best Configuration\n\n")
	best := findBestConfig(summaries)
	fmt.Fprintf(f, "**%s** — %s mode, concurrency %d\n\n", best.Config.Label, best.Config.Mode, best.Config.Concurrency)
	fmt.Fprintf(f, "- RPS: %.2f\n", best.RPS)
	fmt.Fprintf(f, "- 429 rate: %.1f%%\n", pct(best.Count429, best.TotalRequests))
	fmt.Fprintf(f, "- P50 latency: %.0fms\n", best.P50)

	fmt.Fprintf(f, "\n### Bottleneck\n\n")
	if best.Count429 > best.TotalRequests/10 {
		fmt.Fprintf(f, "Primary bottleneck: **rate limiting (429s)**. The upstream API limits by IP and/or API key.\n\n")
	} else if best.CountTimeout > best.TotalRequests/10 {
		fmt.Fprintf(f, "Primary bottleneck: **timeouts**. Tor latency is causing request timeouts.\n\n")
	} else if best.CountError > best.TotalRequests/10 {
		fmt.Fprintf(f, "Primary bottleneck: **errors**. Network or relay issues causing failures.\n\n")
	} else {
		fmt.Fprintf(f, "No major bottleneck detected. The system is operating within acceptable limits.\n\n")
	}

	return nil
}

func maskKey(key string) string {
	if key == "" {
		return ""
	}
	return "[REDACTED]"
}

// redactRecords drops per-record error text (may echo key material) before
// persisting benchmark results to disk.
func redactRecords(records []RequestRecord) []RequestRecord {
	out := make([]RequestRecord, len(records))
	for i, r := range records {
		r.ErrorMsg = ""
		out[i] = r
	}
	return out
}

func pct(part, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(part) / float64(total) * 100
}

type torGroup struct {
	torCount  int
	summaries []Summary
	bestRPS   float64
}

func aggregateByTorCount(summaries []Summary) []torGroup {
	groups := make(map[int]*torGroup)
	for _, s := range summaries {
		tc := s.Config.TorCount
		if groups[tc] == nil {
			groups[tc] = &torGroup{torCount: tc}
		}
		groups[tc].summaries = append(groups[tc].summaries, s)
		if s.RPS > groups[tc].bestRPS {
			groups[tc].bestRPS = s.RPS
		}
	}
	result := make([]torGroup, 0, len(groups))
	for _, g := range groups {
		result = append(result, *g)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].torCount < result[j].torCount
	})
	return result
}

func checkIPCorrelation(summaries []Summary) bool {
	// Count 429s per IP, check if distribution is skewed
	ip429 := make(map[string]int)
	ipTotal := make(map[string]int)
	for _, s := range summaries {
		for _, r := range s.Records {
			if r.ExitIP != "" {
				ipTotal[r.ExitIP]++
				if r.Is429 {
					ip429[r.ExitIP]++
				}
			}
		}
	}

	if len(ipTotal) <= 1 {
		return false // Can't determine with 0 or 1 IP
	}

	total429 := 0
	for _, c := range ip429 {
		total429 += c
	}
	if total429 == 0 {
		return false
	}

	// Check if any single IP has >60% of 429s
	for _, c := range ip429 {
		if float64(c) > float64(total429)*0.6 {
			return true
		}
	}
	return false
}

func findBestConfig(summaries []Summary) Summary {
	best := summaries[0]
	for _, s := range summaries[1:] {
		// Prefer higher RPS, lower 429 rate
		bestRate := float64(best.Count429) / float64(best.TotalRequests)
		sRate := float64(s.Count429) / float64(s.TotalRequests)
		if sRate < bestRate || (sRate == bestRate && s.RPS > best.RPS) {
			best = s
		}
	}
	return best
}

// ---------- Chart generator ----------

func writeChartHTML(filename string, summaries []Summary) error {
	f, err := openResultFile(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	// Group by concurrency for side-by-side comparison
	byConc := make(map[int][]Summary)
	for _, s := range summaries {
		byConc[s.Config.Concurrency] = append(byConc[s.Config.Concurrency], s)
	}

	fmt.Fprintf(f, `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Benchmark Charts</title>
<style>
body { font-family: -apple-system, sans-serif; max-width: 1200px; margin: 40px auto; padding: 0 20px; }
h1 { color: #333; }
table { border-collapse: collapse; width: 100%%; margin: 20px 0; }
th, td { border: 1px solid #ddd; padding: 8px 12px; text-align: right; }
th { background: #f5f5f5; }
.bar { display: inline-block; height: 20px; background: #4CAF50; margin-right: 4px; vertical-align: middle; }
.bar429 { background: #f44336; }
.section { margin: 40px 0; }
</style></head><body>
<h1>Rate Limit Benchmark Results</h1>
<p>Generated: %s</p>
`, time.Now().Format("2006-01-02 15:04:05"))

	// Summary table
	fmt.Fprintf(f, `<div class="section"><h2>Summary</h2>
<table><tr><th>Label</th><th>Mode</th><th>Concurrency</th><th>Total</th><th>Success</th><th>429</th><th>403</th><th>Timeout</th><th>Error</th><th>P50ms</th><th>P95ms</th><th>P99ms</th><th>RPS</th><th>Exit IPs</th></tr>`)
	for _, s := range summaries {
		fmt.Fprintf(f, "<tr><td>%s</td><td>%s</td><td>%d</td><td>%d</td><td>%d</td><td style='color:red'>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%.0f</td><td>%.0f</td><td>%.0f</td><td>%.2f</td><td>%d</td></tr>\n",
			s.Config.Label, s.Config.Mode, s.Config.Concurrency,
			s.TotalRequests, s.SuccessCount, s.Count429, s.Count403,
			s.CountTimeout, s.CountError, s.P50, s.P95, s.P99, s.RPS, len(s.UniqueIPs))
	}
	fmt.Fprintf(f, "</table></div>\n")

	// RPS comparison bar chart
	fmt.Fprintf(f, `<div class="section"><h2>Requests/sec by Configuration</h2>`)
	for _, s := range summaries {
		barWidth := s.RPS * 50 // scale
		fmt.Fprintf(f, `<div style="margin:4px 0"><span style="display:inline-block;width:300px;font-size:13px">%s</span><div class="bar" style="width:%.0fpx"></div> %.2f RPS</div>\n`,
			s.Config.Label, math.Max(barWidth, 1), s.RPS)
	}
	fmt.Fprintf(f, "</div>\n")

	// 429 rate comparison
	fmt.Fprintf(f, `<div class="section"><h2>429 Rate by Configuration</h2>`)
	for _, s := range summaries {
		rate := pct(s.Count429, s.TotalRequests)
		barWidth := rate * 5
		fmt.Fprintf(f, `<div style="margin:4px 0"><span style="display:inline-block;width:300px;font-size:13px">%s</span><div class="bar bar429" style="width:%.0fpx"></div> %.1f%%</div>\n`,
			s.Config.Label, math.Max(barWidth, 1), rate)
	}
	fmt.Fprintf(f, "</div>\n")

	fmt.Fprintf(f, `</body></html>`)
	return nil
}

// ---------- Main ----------

func main() {
	baseURL := flag.String("url", defaultBaseURL, "API base URL")
	apiKey := flag.String("key", defaultAPIKey, "API key (or BENCH_API_KEY env)")
	model := flag.String("model", defaultModel, "Model name")
	totalReqs := flag.Int("n", 500, "Total requests per test")
	conc := flag.String("conc", "1,5,20", "Comma-separated concurrency levels")
	torCounts := flag.String("tor", "3", "Comma-separated Tor instance counts")
	mode := flag.String("mode", "direct", "Test mode: direct, http_proxy, socks5_proxy, all")
	outputDir := flag.String("out", "benchmark/results", "Output directory prefix")
	flag.Parse()

	// API key must come from -key or BENCH_API_KEY; never bake a default.
	if *apiKey == "" {
		*apiKey = os.Getenv("BENCH_API_KEY")
	}
	if *apiKey == "" {
		fmt.Fprintf(os.Stderr, "missing API key: provide -key flag or BENCH_API_KEY env\n")
		os.Exit(2)
	}

	os.MkdirAll(*outputDir, 0755)

	// Parse concurrency levels
	var concLevels []int
	for _, c := range strings.Split(*conc, ",") {
		var v int
		fmt.Sscanf(strings.TrimSpace(c), "%d", &v)
		if v > 0 {
			concLevels = append(concLevels, v)
		}
	}

	// Parse Tor counts
	var torCountList []int
	for _, tc := range strings.Split(*torCounts, ",") {
		var v int
		fmt.Sscanf(strings.TrimSpace(tc), "%d", &v)
		if v > 0 {
			torCountList = append(torCountList, v)
		}
	}

	// Determine modes
	var modes []string
	switch *mode {
	case "all":
		modes = []string{"direct", "http_proxy"}
	case "direct", "http_proxy", "socks5_proxy":
		modes = []string{*mode}
	default:
		modes = []string{"direct"}
	}

	var allSummaries []Summary

	for _, tc := range torCountList {
		for _, m := range modes {
			for _, c := range concLevels {
				proxyURL := ""
				label := fmt.Sprintf("%d-tor-%s-c%d", tc, m, c)
				switch m {
				case "http_proxy":
					proxyURL = defaultRelayHTTP
					label = fmt.Sprintf("%d-tor-http-c%d", tc, c)
				case "socks5_proxy":
					proxyURL = defaultRelayS5
					label = fmt.Sprintf("%d-tor-s5-c%d", tc, c)
				default:
					label = fmt.Sprintf("%d-tor-direct-c%d", tc, c)
				}

				cfg := BenchConfig{
					BaseURL:     *baseURL,
					APIKey:      *apiKey,
					Model:       *model,
					ProxyURL:    proxyURL,
					Concurrency: c,
					TotalReqs:   *totalReqs,
					Mode:        m,
					TorCount:    tc,
					Label:       label,
				}

				summary := runBenchmark(cfg)
				allSummaries = append(allSummaries, summary)

				// Small cooldown between tests
				fmt.Println("  Cooling down 5s...")
				time.Sleep(5 * time.Second)
			}
		}
	}

	// Write outputs
	csvFile := *outputDir + "_summary.csv"
	detailCSVFile := *outputDir + "_detail.csv"
	reportFile := *outputDir + "_report.md"
	chartFile := *outputDir + "_charts.html"

	if err := writeCSV(csvFile, allSummaries); err != nil {
		fmt.Fprintf(os.Stderr, "CSV error: %v\n", err)
	}
	if err := writeDetailCSV(detailCSVFile, allSummaries); err != nil {
		fmt.Fprintf(os.Stderr, "Detail CSV error: %v\n", err)
	}
	if err := writeReport(reportFile, allSummaries); err != nil {
		fmt.Fprintf(os.Stderr, "Report error: %v\n", err)
	}
	if err := writeChartHTML(chartFile, allSummaries); err != nil {
		fmt.Fprintf(os.Stderr, "Chart error: %v\n", err)
	}

	// Also write raw JSON. Persist a redacted copy: Summary embeds the full
	// BenchConfig (incl. Config.APIKey), so strip key material before writing
	// and keep result files owner-only.
	jsonFile := *outputDir + "_raw.json"
	redacted := make([]Summary, len(allSummaries))
	for i, s := range allSummaries {
		s.Config.APIKey = ""
		s.Records = redactRecords(s.Records)
		redacted[i] = s
	}
	jsonData, _ := json.MarshalIndent(redacted, "", "  ")
	os.WriteFile(jsonFile, jsonData, 0600)

	fmt.Printf("\n=== ALL OUTPUTS ===\n")
	fmt.Printf("  Summary CSV:    %s\n", csvFile)
	fmt.Printf("  Detail CSV:     %s\n", detailCSVFile)
	fmt.Printf("  Report:         %s\n", reportFile)
	fmt.Printf("  Charts:         %s\n", chartFile)
	fmt.Printf("  Raw JSON:       %s\n", jsonFile)
}
