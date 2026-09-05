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

// Lookup returns cached results when fresh; otherwise performs a deduplicated
// lookup and caches it. Failed lookups are negatively cached for negativeDNSTTL
// (30s) to prevent repetitive timeouts during bursts.
func (r *Resolver) Lookup(host string) []net.IP {
	hostOnly := strings.ToLower(host)
	if h, _, err := net.SplitHostPort(hostOnly); err == nil {
		hostOnly = h
	}

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
	if call, active := r.inFlight[hostOnly]; active {
		r.mu.Unlock()
		<-call.done
		return call.ips
	}

	// Register leader call for this host
	call := &inFlightCall{done: make(chan struct{})}
	r.inFlight[hostOnly] = call
	r.mu.Unlock()

	// Perform actual DNS lookup outside lock
	ips, err := net.LookupIP(hostOnly)

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
