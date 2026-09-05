package security

import (
	"net"
	"testing"
)

func TestFirewall_AllowHost(t *testing.T) {
	fw := NewFirewall(FirewallConfig{})

	tests := []struct {
		host string
		want bool
	}{
		// Private IPs (covered by default blocked ranges)
		{"127.0.0.1", false},
		{"127.0.0.1:8080", false},
		{"10.0.0.1", false},
		{"10.0.0.1:443", false},
		{"192.168.1.1", false},
		{"192.168.1.1:80", false},
		{"172.16.0.1", false},
		{"::1", false},
		{"[::1]:8080", false},

		// Local domains
		{"localhost", false},
		{"localhost:8080", false},
		{"sub.localhost", false},
		{"router.local", false},

		// Onion domains (must be allowed through without DNS query)
		{"duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion", true},
		{"duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion:443", true},

		// Public IP
		{"1.1.1.1", true},
		{"8.8.8.8:53", true},
	}

	for _, tt := range tests {
		got := fw.AllowHost(tt.host)
		if got != tt.want {
			t.Errorf("AllowHost(%q) = %v; want %v", tt.host, got, tt.want)
		}
	}
}

func TestFirewall_RateLimit(t *testing.T) {
	fw := NewFirewall(FirewallConfig{
		RateLimit: 10,
		RateBurst: 2,
	})

	// Burst of 2 for a single host
	if !fw.AllowHost("1.1.1.1") {
		t.Error("expected first request to be allowed")
	}
	if !fw.AllowHost("1.1.1.1") {
		t.Error("expected second request to be allowed (burst=2)")
	}

	// Third request immediately after should be rate-limited
	if fw.AllowHost("1.1.1.1") {
		t.Error("expected third request to be rate-limited")
	}

	// Different host should not be limited
	if !fw.AllowHost("8.8.8.8") {
		t.Error("expected request to different host to be allowed")
	}
}

func TestResolver_Lookup(t *testing.T) {
	r := newResolver()

	// Onion domain should return nil (no DNS query)
	ips := r.Lookup("testsite.onion")
	if len(ips) != 0 {
		t.Errorf("expected nil for onion domain, got %v", ips)
	}

	ips = r.Lookup("testsite.onion:443")
	if len(ips) != 0 {
		t.Errorf("expected nil for onion domain with port, got %v", ips)
	}

	// Localhost should resolve statically to 127.0.0.1
	ips = r.Lookup("localhost:8080")
	if len(ips) == 0 || !ips[0].Equal(net.IPv4(127, 0, 0, 1)) {
		t.Errorf("expected 127.0.0.1 for localhost, got %v", ips)
	}
}

func TestSSRFBlocker_IsBlocked(t *testing.T) {
	blocker := NewSSRFBlocker([]string{"127.0.0.0/8", "10.0.0.0/8"})

	if !blocker.IsBlocked("127.0.0.1:8080") {
		t.Error("127.0.0.1:8080 should be blocked")
	}
	if !blocker.IsBlocked("10.0.0.1:443") {
		t.Error("10.0.0.1:443 should be blocked")
	}
	if !blocker.IsBlocked("localhost") {
		t.Error("localhost should be blocked")
	}
	if !blocker.IsBlocked("app.local") {
		t.Error("app.local should be blocked")
	}
	if blocker.IsBlocked("example.onion") {
		t.Error("example.onion should not be blocked")
	}
	if blocker.IsBlocked("example.onion:80") {
		t.Error("example.onion:80 should not be blocked")
	}
}
