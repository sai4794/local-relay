package security

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

type tokenBucket struct {
	tokens     float64
	lastUpdate time.Time
}

// idleBucketTTL is how long an unused rate-limit bucket survives before
// eviction by the cleanup loop.
const idleBucketTTL = 10 * time.Minute

type Firewall struct {
	blockedRanges []*net.IPNet
	mu            sync.RWMutex
	resolver      *resolver
	rateLimit     float64
	rateBurst     float64
	limiters      map[string]*tokenBucket
	limiterMu     sync.Mutex
}

type FirewallConfig struct {
	RateLimit int
	RateBurst int
}

func NewFirewall(cfg FirewallConfig) *Firewall {
	fw := &Firewall{
		blockedRanges: getDefaultBlockedRanges(),
		resolver:      newResolver(),
		rateLimit:     float64(cfg.RateLimit),
		rateBurst:     float64(cfg.RateBurst),
		limiters:      make(map[string]*tokenBucket),
	}
	return fw
}

func getDefaultBlockedRanges() []*net.IPNet {
	cidrs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"127.0.0.0/8",
		"0.0.0.0/8",
		"100.64.0.0/10",
		"198.18.0.0/15",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}

	var ranges []*net.IPNet
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			ranges = append(ranges, ipNet)
		}
	}
	return ranges
}

func (fw *Firewall) allowRateLimit(host string) bool {
	if fw.rateLimit <= 0 {
		return true
	}
	fw.limiterMu.Lock()
	defer fw.limiterMu.Unlock()

	now := time.Now()
	tb, exists := fw.limiters[host]
	if !exists {
		burst := fw.rateBurst
		if burst <= 0 {
			burst = fw.rateLimit * 2
		}
		fw.limiters[host] = &tokenBucket{
			tokens:     burst - 1,
			lastUpdate: now,
		}
		return true
	}

	elapsed := now.Sub(tb.lastUpdate).Seconds()
	tb.lastUpdate = now

	burst := fw.rateBurst
	if burst <= 0 {
		burst = fw.rateLimit * 2
	}

	tb.tokens += elapsed * fw.rateLimit
	if tb.tokens > burst {
		tb.tokens = burst
	}

	if tb.tokens >= 1.0 {
		tb.tokens -= 1.0
		return true
	}

	return false
}

func (fw *Firewall) AllowHost(host string) bool {
	hostname := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostname = h
	}
	if !fw.allowRateLimit(hostname) {
		return false
	}
	ip := net.ParseIP(hostname)
	if ip == nil {
		lower := strings.ToLower(hostname)
		if lower == "localhost" || strings.HasSuffix(lower, ".localhost") || strings.HasSuffix(lower, ".local") {
			return false
		}
		if strings.HasSuffix(lower, ".onion") {
			return true
		}
		ips := fw.resolver.Lookup(hostname)
		// If we cannot resolve the host locally, allow it rather than fail-closed.
		// In the Tor context the destination is resolved by Tor/its exit nodes, so a
		// local DNS miss (e.g. a restricted resolver) must not make otherwise-routable
		// domains unreachable. This matches the SSRF blocker, which also allows on
		// unresolvable hosts. Any IP we CAN see that is private is still blocked below.
		fw.mu.RLock()
		defer fw.mu.RUnlock()
		for _, resolvedIP := range ips {
			if ip4 := resolvedIP.To4(); ip4 != nil {
				resolvedIP = ip4
			}
			for _, blocked := range fw.blockedRanges {
				if blocked.Contains(resolvedIP) {
					return false
				}
			}
		}
		return true
	}

	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	fw.mu.RLock()
	defer fw.mu.RUnlock()
	for _, blocked := range fw.blockedRanges {
		if blocked.Contains(ip) {
			return false
		}
	}
	return true
}

// StartCleanup periodically evicts expired DNS entries and idle rate-limit
// buckets. Without eviction the limiter map grows one bucket per unique
// destination host for the lifetime of the process.
func (fw *Firewall) StartCleanup(ctx context.Context, interval time.Duration) {
	fw.resolver.StartCleanup(ctx, interval)

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				fw.evictIdleLimiters(idleBucketTTL)
			}
		}
	}()
}

// Stop halts all background cleanup goroutines.
func (fw *Firewall) Stop() {
	fw.resolver.Stop()
}

func (fw *Firewall) evictIdleLimiters(maxIdle time.Duration) {
	fw.limiterMu.Lock()
	defer fw.limiterMu.Unlock()
	now := time.Now()
	for host, tb := range fw.limiters {
		if now.Sub(tb.lastUpdate) > maxIdle {
			delete(fw.limiters, host)
		}
	}
}

func (fw *Firewall) AddBlockedRange(cidr string) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	fw.mu.Lock()
	defer fw.mu.Unlock()
	fw.blockedRanges = append(fw.blockedRanges, ipNet)
	return nil
}
