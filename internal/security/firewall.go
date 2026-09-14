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
	resolver      *Resolver
	rateLimit     float64
	rateBurst     float64
	limiters      map[string]*tokenBucket
	limiterMu     sync.Mutex
	cancel        context.CancelFunc
	// FailClosedDNS, when true, blocks hosts with an empty/nil local
	// resolution instead of the default advisory fail-open for Tor.
	FailClosedDNS bool
}

type FirewallConfig struct {
	RateLimit int
	RateBurst int
	// FailClosedDNS, when true, blocks unresolvable hosts instead of
	// allowing them (default false keeps advisory fail-open for Tor).
	FailClosedDNS bool
}

func NewFirewall(cfg FirewallConfig) *Firewall {
	return NewFirewallWithResolver(cfg, NewResolver())
}

func NewFirewallWithResolver(cfg FirewallConfig, r *Resolver) *Firewall {
	fw := &Firewall{
		blockedRanges: getDefaultBlockedRanges(),
		resolver:      r,
		rateLimit:     float64(cfg.RateLimit),
		rateBurst:     float64(cfg.RateBurst),
		limiters:      make(map[string]*tokenBucket),
		FailClosedDNS: cfg.FailClosedDNS,
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
		// IPv6 transition / special-use and multicast ranges, mirroring the
		// TS relay SSRF/firewall enforcement. Tor-routed public traffic
		// (global unicast, .onion) is unaffected — these never carry it.
		"fec0::/10",     // site-local (deprecated, still seen in the wild)
		"2002::/16",     // 6to4 transition
		"2001::/32",     // Teredo (includes 2001::/32 tunnelled clients)
		"2001:db8::/32", // documentation (must never be routable)
		"224.0.0.0/4",   // IPv4 multicast
		"ff00::/8",      // IPv6 multicast
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

// RateLimitExceeded reports whether host currently has no rate-limit tokens
// left, without consuming one. Proxy layers use it to log rate-limit denials
// with a distinct reason field from SSRF/range blocks (LOW-2) while keeping
// the denial codes (HTTP 403, SOCKS5 0x02) unchanged: after AllowIPs returns
// ok==false, RateLimitExceeded(host) true means "rate_limited", false means
// "ssrf_block". The check is read-only — it never consumes a token.
func (fw *Firewall) RateLimitExceeded(host string) bool {
	if fw == nil || fw.rateLimit <= 0 {
		return false
	}
	fw.limiterMu.Lock()
	defer fw.limiterMu.Unlock()
	tb, exists := fw.limiters[normalizeHostKey(host)]
	if !exists {
		return false
	}
	burst := fw.rateBurst
	if burst <= 0 {
		burst = fw.rateLimit * 2
	}
	tokens := tb.tokens + time.Since(tb.lastUpdate).Seconds()*fw.rateLimit
	if tokens > burst {
		tokens = burst
	}
	return tokens < 1.0
}

func (fw *Firewall) AllowHost(host string) bool {
	_, ok := fw.AllowIPs(host)
	return ok
}

// AllowIPs reports whether host is permitted and returns the single shared
// Resolver.Lookup result so SSRF checks can reuse it (see CheckHost). Fail-
// open semantics are the default: unresolvable hosts are allowed, since the
// destination is finally resolved by Tor/exit nodes. A nil slice means
// "unknown", not "no addresses". With FailClosedDNS=true, an empty/nil
// resolution is blocked instead.
//
// A nil receiver (disabled component) is a no-op allow, matching CheckHost
// and the proxy's singleLookupVerdict nil-component path.
//
// The returned verdict distinguishes the denial cause for logging without
// changing enforcement: rate-limit denials come back as (nil, false) with an
// empty slice, SSRF/range blocks as (resolved, false). Callers use ok==false
// identically; the slice shape is what lets them log "rate_limited" vs
// "ssrf_block" distinctly (LOW-2).
func (fw *Firewall) AllowIPs(host string) ([]net.IP, bool) {
	if fw == nil {
		return nil, true
	}
	hostname := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostname = h
	}
	// One shared normalizer (lowercase, strip brackets, one trailing dot) for
	// the rate key, cache key, and bypass pin map (LOW-5).
	rlKey := normalizeHostKey(hostname)
	if !fw.allowRateLimit(rlKey) {
		return nil, false
	}
	trimmed := normalizeHostKey(hostname)
	// Strict-reject numeric-looking hosts that fail canonical parsing (same
	// rule as the SSRF blocker): deferring to DNS/fail-open would let the
	// verdict depend on resolver quirks instead of a deterministic block.
	if looksNumericHost(trimmed) && parseNumericIP(trimmed) == nil {
		return nil, false
	}
	if ip := parseNumericIP(trimmed); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			ip = ip4
		}
		fw.mu.RLock()
		defer fw.mu.RUnlock()
		for _, blocked := range fw.blockedRanges {
			if blocked.Contains(ip) {
				return []net.IP{ip}, false
			}
		}
		return []net.IP{ip}, true
	}
	lower := trimmed
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") || strings.HasSuffix(lower, ".local") {
		loopback := net.ParseIP("127.0.0.1")
		// Honor AllowLoopbackForTest: the hardcoded loopback verdict must not
		// bypass the configured ranges, or the test seam silently stops
		// working (loopback-looking names stay blocked however ranges change).
		fw.mu.RLock()
		defer fw.mu.RUnlock()
		for _, blocked := range fw.blockedRanges {
			if blocked.Contains(loopback) {
				return []net.IP{loopback}, false
			}
		}
		return []net.IP{loopback}, true
	}
	if strings.HasSuffix(lower, ".onion") {
		return nil, true
	}
	ips := fw.resolver.Lookup(hostname)
	if len(ips) == 0 && fw.FailClosedDNS {
		return ips, false
	}
	// If we cannot resolve the host locally, allow it rather than fail-closed
	// (unless FailClosedDNS is set, handled above).
	// In the Tor context the destination is resolved by Tor/exit nodes, so a
	// local DNS miss (e.g. a restricted resolver) must not make otherwise-routable
	// domains unreachable. This matches the SSRF blocker, which also allows on
	// unresolvable hosts. Any IP we CAN see that is private is still blocked below.
	ips, blocked := fw.checkResolved(ips)
	return ips, !blocked
}

// IsBlockedIPs reports whether host resolves into a blocked range and returns
// the shared lookup result for SSRF reuse. It delegates to AllowIPs, so it
// applies the same verdict (including the FailClosedDNS verdict on empty
// resolutions) at the cost of the same single Lookup and rate-limit charge.
// Charge-free re-verdicts over an already-shared slice go through CheckHost
// (firewall) and SSRFBlocker.CheckHost instead: the proxy layer calls AllowIPs
// once per request (single Lookup, rate key normalized once) and consults the
// SSRF blocker via CheckHost with the returned slice.
func (fw *Firewall) IsBlockedIPs(host string) ([]net.IP, bool) {
	ips, ok := fw.AllowIPs(host)
	return ips, !ok
}

// CheckHost applies the firewall verdict over a pre-resolved IP set without
// another Lookup or rate charge (the per-request AllowIPs call already did
// both). Unknown (nil) resolutions stay fail-open, matching AllowIPs, unless
// FailClosedDNS is set (then they are blocked).
func (fw *Firewall) CheckHost(ips []net.IP) ([]net.IP, bool) {
	if fw == nil {
		return ips, true
	}
	if len(ips) == 0 && fw.FailClosedDNS {
		return ips, false
	}
	resolved, blocked := fw.checkResolved(ips)
	return resolved, !blocked
}

// AllowIPsNoLookup applies the firewall verdict over a pre-resolved IP set
// WITHOUT another Lookup or rate charge: ips is authoritative (nil means
// "unknown", fail-open by default and blocked with FailClosedDNS). It exists
// so a caller that already holds a verified single shared-Lookup result (the
// proxy's bypass pin path) can re-state the block verdict at dial time over
// exactly those IPs instead of trusting a fresh resolution.
func (fw *Firewall) AllowIPsNoLookup(host string, ips []net.IP) ([]net.IP, bool) {
	if fw == nil {
		return ips, true
	}
	_ = host // verdict is over the supplied IPs only; host kept for API symmetry with AllowIPs
	if len(ips) == 0 && fw.FailClosedDNS {
		return ips, false
	}
	resolved, blocked := fw.checkResolved(ips)
	return resolved, !blocked
}

func (fw *Firewall) checkResolved(ips []net.IP) ([]net.IP, bool) {
	fw.mu.RLock()
	defer fw.mu.RUnlock()
	for _, resolvedIP := range ips {
		if ip4 := resolvedIP.To4(); ip4 != nil {
			resolvedIP = ip4
		}
		for _, blocked := range fw.blockedRanges {
			if blocked.Contains(resolvedIP) {
				return ips, true
			}
		}
	}
	return ips, false
}

// StartCleanup periodically evicts expired DNS entries and idle rate-limit
// buckets. Without eviction the limiter map grows one bucket per unique
// destination host for the lifetime of the process. The limiter goroutine is
// owned by the Firewall (Stop cancels it); the resolver is shared with the
// SSRF blocker and is intentionally NOT stopped here.
func (fw *Firewall) StartCleanup(ctx context.Context, interval time.Duration) {
	fw.resolver.StartCleanup(ctx, interval)

	fw.limiterMu.Lock()
	if fw.cancel != nil {
		fw.limiterMu.Unlock()
		return
	}
	ctx, fw.cancel = context.WithCancel(ctx)
	fw.limiterMu.Unlock()

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

// Stop halts the firewall's own cleanup goroutine. The shared resolver is
// left running: it is co-owned with the SSRF blocker, which may still need
// DNS cleanup after the firewall stops.
func (fw *Firewall) Stop() {
	fw.limiterMu.Lock()
	defer fw.limiterMu.Unlock()
	if fw.cancel != nil {
		fw.cancel()
		fw.cancel = nil
	}
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

// AllowLoopbackForTest removes the loopback ranges from the firewall so tests
// can run real local upstreams through paths whose verdicts would otherwise
// block 127.0.0.0/8 and ::1/128. Production code never calls this: shipped
// loopback blocking comes from getDefaultBlockedRanges plus the configured
// blocked_networks list.
func (fw *Firewall) AllowLoopbackForTest() {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	kept := fw.blockedRanges[:0]
	for _, r := range fw.blockedRanges {
		s := r.String()
		if s == "127.0.0.0/8" || s == "::1/128" {
			continue
		}
		kept = append(kept, r)
	}
	fw.blockedRanges = kept
}
