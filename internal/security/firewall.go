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
}

type FirewallConfig struct {
	RateLimit int
	RateBurst int
}

func NewFirewall(cfg FirewallConfig) *Firewall {
	fw := &Firewall{
		blockedRanges: getDefaultBlockedRanges(),
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
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
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

func (fw *Firewall) StartCleanup(ctx context.Context, interval time.Duration) {
	// Rate-limiter cleanup removed — not currently wired.
	// Kept as no-op so main.go can call without conditional.
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
