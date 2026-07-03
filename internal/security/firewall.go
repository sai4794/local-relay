package security

import (
	"context"
	"net"
	"sync"
	"time"
)

type Firewall struct {
	blockedRanges []*net.IPNet
	mu            sync.RWMutex
	dnsCache      map[string]dnsCacheEntry
	dnsMu         sync.RWMutex
}

type dnsCacheEntry struct {
	ips      []net.IP
	expires  time.Time
}

type FirewallConfig struct {
	RateLimit int
	RateBurst int
}

func NewFirewall(cfg FirewallConfig) *Firewall {
	fw := &Firewall{
		blockedRanges: getDefaultBlockedRanges(),
		dnsCache:       make(map[string]dnsCacheEntry),
	}
	_ = cfg.RateLimit
	_ = cfg.RateBurst
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

func (fw *Firewall) AllowHost(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		ips := fw.resolveHost(host)
		if len(ips) == 0 {
			return false
		}
		fw.mu.RLock()
		defer fw.mu.RUnlock()
		for _, resolvedIP := range ips {
			for _, blocked := range fw.blockedRanges {
				if blocked.Contains(resolvedIP) {
					return false
				}
			}
		}
		return true
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

// resolveHost returns cached DNS results or performs a fresh lookup.
// Cache TTL is 5 minutes to balance freshness vs performance.
func (fw *Firewall) resolveHost(host string) []net.IP {
	fw.dnsMu.RLock()
	if entry, ok := fw.dnsCache[host]; ok {
		if time.Now().Before(entry.expires) {
			fw.dnsMu.RUnlock()
			return entry.ips
		}
	}
	fw.dnsMu.RUnlock()

	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return nil
	}

	fw.dnsMu.Lock()
	fw.dnsCache[host] = dnsCacheEntry{
		ips:     ips,
		expires: time.Now().Add(5 * time.Minute),
	}
	fw.dnsMu.Unlock()

	return ips
}

func (fw *Firewall) StartCleanup(ctx context.Context, interval time.Duration) {
	// Periodically clean expired DNS cache entries
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				fw.cleanupDNSCache()
			}
		}
	}()
}

func (fw *Firewall) cleanupDNSCache() {
	fw.dnsMu.Lock()
	defer fw.dnsMu.Unlock()
	now := time.Now()
	for host, entry := range fw.dnsCache {
		if now.After(entry.expires) {
			delete(fw.dnsCache, host)
		}
	}
}

func (fw *Firewall) StopCleanup() {}

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
