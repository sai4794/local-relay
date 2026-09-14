package security

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

// Resolver TTL is intentionally ~5m: longer pinning turns a stale DNS answer
// into an SSRF hole (host re-bound to a private IP after initial check).
// Final resolution is done by the Tor exit — this cache is advisory only.
const (
	dnsTTL         = 5 * time.Minute
	negativeDNSTTL = 30 * time.Second
	// dnsLookupTimeout bounds a single leader lookup AND a follower's wait so
	// one wedged resolver cannot park request goroutines indefinitely.
	dnsLookupTimeout = 5 * time.Second
)

type inFlightCall struct {
	done chan struct{}
	ips  []net.IP
}

type dnsEntry struct {
	ips     []net.IP
	expires time.Time
}

// Resolver is a shared, mutex-guarded DNS cache with singleflight deduplication
// used by both the SSRF blocker and the firewall so a single request never
// triggers duplicate lookups of the same host.
type Resolver struct {
	cache    map[string]dnsEntry
	inFlight map[string]*inFlightCall
	mu       sync.RWMutex
	cancel   context.CancelFunc
}

// NewResolver constructs a new shared DNS resolver cache.
func NewResolver() *Resolver {
	return &Resolver{
		cache:    make(map[string]dnsEntry),
		inFlight: make(map[string]*inFlightCall),
	}
}

// newResolver provides package-internal compatibility.
func newResolver() *Resolver {
	return NewResolver()
}

// normalizeHostKey lowercases a host and strips any port, IPv6 brackets, and
// one trailing dot, so firewall rate keys, DNS cache keys, and the bypass pin
// map agree on one canonical form. Bracket-stripping matters for bare IPv6
// literals ("[::1]" with no port): without it the same address keys two cache
// entries ("[::1]" vs "::1") and pin lookups miss their check-time entries.
func normalizeHostKey(host string) string {
	hostOnly := strings.ToLower(host)
	if h, _, err := net.SplitHostPort(hostOnly); err == nil {
		hostOnly = h
	}
	// Strip brackets in either order: "[v6]." leaves a trailing "]" after
	// dot-stripping, and "[v6]" has none — both must reach "v6".
	hostOnly = strings.TrimSuffix(hostOnly, ".")
	hostOnly = strings.TrimPrefix(strings.TrimSuffix(hostOnly, "]"), "[")
	return strings.TrimSuffix(hostOnly, ".")
}

// Lookup returns cached results when fresh; otherwise performs a deduplicated
// lookup and caches it. Failed lookups are negatively cached for negativeDNSTTL
// (30s) to prevent repetitive timeouts during bursts.
func (r *Resolver) Lookup(host string) []net.IP {
	hostOnly := normalizeHostKey(host)

	if ip := net.ParseIP(hostOnly); ip != nil {
		return []net.IP{ip}
	}

	if hostOnly == "localhost" || strings.HasSuffix(hostOnly, ".localhost") {
		return []net.IP{net.ParseIP("127.0.0.1")}
	}

	// Never perform local DNS resolution on .onion addresses
	if strings.HasSuffix(hostOnly, ".onion") {
		return nil
	}

	// Fast path: check cache under read lock
	r.mu.RLock()
	entry, ok := r.cache[hostOnly]
	r.mu.RUnlock()

	if ok && time.Now().Before(entry.expires) {
		return entry.ips
	}

	// Slow path: singleflight deduplication
	r.mu.Lock()
	// Recheck cache after acquiring write lock
	if entry, ok = r.cache[hostOnly]; ok && time.Now().Before(entry.expires) {
		r.mu.Unlock()
		return entry.ips
	}

	// If another goroutine is already resolving this host, wait for its result
	// — bounded, so a wedged leader cannot park followers forever.
	if call, active := r.inFlight[hostOnly]; active {
		r.mu.Unlock()
		select {
		case <-call.done:
			return call.ips
		case <-time.After(dnsLookupTimeout):
			return nil
		}
	}

	// Register leader call for this host
	call := &inFlightCall{done: make(chan struct{})}
	r.inFlight[hostOnly] = call
	r.mu.Unlock()

	// Perform actual DNS lookup outside lock, bounded so a wedged resolver
	// cannot park the leader (and every same-host follower) indefinitely.
	ips, err := lookupIPTimeout(hostOnly, dnsLookupTimeout)

	r.mu.Lock()
	ttl := dnsTTL
	if err != nil || len(ips) == 0 {
		ttl = negativeDNSTTL
		ips = nil
	}
	r.cache[hostOnly] = dnsEntry{ips: ips, expires: time.Now().Add(ttl)}
	delete(r.inFlight, hostOnly)
	call.ips = ips
	close(call.done)
	r.mu.Unlock()

	return ips
}

// lookupIPTimeout resolves host with a hard deadline. Callers treat a nil
// result as "unknown" (fail-open, same as NXDOMAIN today) — the timeout only
// prevents a wedged resolver from parking goroutines, it never blocks traffic
// by itself.
func lookupIPTimeout(host string, timeout time.Duration) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var resolver net.Resolver
	return resolver.LookupIP(ctx, "ip", host)
}

// StartCleanup evicts expired entries every interval until the returned
// context is cancelled (or Stop is called). It is safe to call multiple times.
func (r *Resolver) StartCleanup(ctx context.Context, interval time.Duration) {
	r.mu.Lock()
	if r.cancel != nil {
		r.mu.Unlock()
		return
	}
	ctx, r.cancel = context.WithCancel(ctx)
	r.mu.Unlock()

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.mu.Lock()
				now := time.Now()
				for host, entry := range r.cache {
					if now.After(entry.expires) {
						delete(r.cache, host)
					}
				}
				r.mu.Unlock()
			}
		}
	}()
}

// Stop terminates the cleanup goroutine.
func (r *Resolver) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel != nil {
		r.cancel()
		r.cancel = nil
	}
}
