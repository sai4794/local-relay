package security

import (
	"net"
	"strings"
)

// SSRFBlocker blocks requests to private/internal IP ranges.
type SSRFBlocker struct {
	blockedNets []*net.IPNet
}

// NewSSRFBlocker creates a blocker from CIDR strings.
func NewSSRFBlocker(cidrs []string) *SSRFBlocker {
	blocked := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		blocked = append(blocked, ipNet)
	}
	return &SSRFBlocker{blockedNets: blocked}
}

// IsBlocked checks if a host resolves to a blocked network.
// For domain names, it resolves and checks each IP.
// For IP addresses, it checks directly.
func (s *SSRFBlocker) IsBlocked(host string) bool {
	if s == nil || len(s.blockedNets) == 0 {
		return false
	}

	// Strip port
	hostname := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostname = h
	}

	// Check if it's already an IP
	if ip := net.ParseIP(hostname); ip != nil {
		return s.isIPBlocked(ip)
	}

	// Resolve domain
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return false
	}

	for _, ip := range ips {
		if s.isIPBlocked(ip) {
			return true
		}
	}
	return false
}

func (s *SSRFBlocker) isIPBlocked(ip net.IP) bool {
	for _, blocked := range s.blockedNets {
		if blocked.Contains(ip) {
			return true
		}
	}
	return false
}

// IsSchemeBlocked checks if a URL scheme should be blocked.
func (s *SSRFBlocker) IsSchemeBlocked(scheme string) bool {
	scheme = strings.ToLower(scheme)
	switch scheme {
	case "file", "gopher", "javascript", "data":
		return true
	}
	return false
}
