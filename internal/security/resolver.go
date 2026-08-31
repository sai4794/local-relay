package security

import (
	"context"
	"net"
	"sync"
	"time"
)

// Resolver TTL is intentionally ~5m: longer pinning turns a stale DNS answer
// into an SSRF hole (host re-bound to a private IP after initial check).
// Final resolution is done by the Tor exit — this cache is advisory only.
const dnsTTL = 5 * time.Minute

// resolver is a shared, mutex-guarded DNS cache used by both the SSRF
// blocker and the firewall so a single request never triggers two
// independent lookups of the same host.
type resolver struct {
	cache  map[string]dnsEntry
	mu     sync.RWMutex
	cancel context.CancelFunc
}

type dnsEntry struct {
	ips     []net.IP
	expires time.Time
}

func newResolver() *resolver {
	return &resolver{cache: make(map[string]dnsEntry)}
}

// Lookup returns cached results when fresh; otherwise performs a blocking
// lookup and caches it. A failed or empty lookup returns nil and is NOT
// cached (transient resolver failures must not poison the cache).
func (r *resolver) Lookup(host string) []net.IP {
	r.mu.RLock()
	entry, ok := r.cache[host]
	r.mu.RUnlock()

	if ok && time.Now().Before(entry.expires) {
		return entry.ips
	}

	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return nil
	}

	r.mu.Lock()
	r.cache[host] = dnsEntry{ips: ips, expires: time.Now().Add(dnsTTL)}
	r.mu.Unlock()

	return ips
}

// StartCleanup evicts expired entries every interval until the returned
// context is cancelled (or Stop is called).
func (r *resolver) StartCleanup(ctx context.Context, interval time.Duration) {
	ctx, r.cancel = context.WithCancel(ctx)
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
func (r *resolver) Stop() {
	if r.cancel != nil {
		r.cancel()
	}
}
