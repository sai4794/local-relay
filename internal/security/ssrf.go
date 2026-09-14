package security

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"
)

// SSRFBlocker blocks requests to private/internal IP ranges.
type SSRFBlocker struct {
	blockedNets []*net.IPNet
	resolver    *Resolver
	// FailClosedDNS, when true, treats nil/empty local resolutions as blocked
	// instead of the default advisory fail-open for Tor.
	FailClosedDNS bool
}

// NewSSRFBlocker creates a blocker from CIDR strings with a default resolver.
func NewSSRFBlocker(cidrs []string) *SSRFBlocker {
	return NewSSRFBlockerWithResolver(cidrs, NewResolver())
}

// NewSSRFBlockerWithResolver creates a blocker from CIDR strings with a shared resolver.
func NewSSRFBlockerWithResolver(cidrs []string, r *Resolver) *SSRFBlocker {
	blocked := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		blocked = append(blocked, ipNet)
	}
	return &SSRFBlocker{
		blockedNets: blocked,
		resolver:    r,
	}
}

// IsBlocked checks if a host resolves to a blocked network.
// For domain names, it resolves and checks each IP.
// For IP addresses, it checks directly.
// Results are cached to avoid blocking DNS on every request.
func (s *SSRFBlocker) IsBlocked(host string) bool {
	_, blocked := s.checkHost(host, nil)
	return blocked
}

// IsBlockedIPs reports whether host resolves to a blocked network and also
// returns the resolved IPs so callers can reuse them instead of issuing a
// second Lookup. A nil slice means "unknown" (fail-open by default: the same
// verdict IsBlocked gives for unresolvable hosts; with FailClosedDNS it is
// blocked instead); callers must not treat it as an
// empty allow-list proof. The boolean reports the blocked verdict.
func (s *SSRFBlocker) IsBlockedIPs(host string) ([]net.IP, bool) {
	return s.checkHost(host, nil)
}

// AllowIPs reports whether host is permitted (the inverse of IsBlocked) and
// returns the resolved IPs for reuse. It shares one Resolver.Lookup with the
// firewall path via CheckHost below; a nil slice means "unknown" (fail-open
// by default, blocked with FailClosedDNS).
func (s *SSRFBlocker) AllowIPs(host string) ([]net.IP, bool) {
	ips, blocked := s.checkHost(host, nil)
	return ips, !blocked
}

// AllowIPsNoLookup applies the SSRF verdict over a pre-resolved IP set
// WITHOUT another Lookup: ips is authoritative (nil means "unknown",
// fail-open by default and blocked with FailClosedDNS). It exists so a
// caller that already holds a verified single shared-Lookup result (the
// proxy's bypass pin path) can re-state the block verdict at dial time over
// exactly those IPs instead of trusting a fresh resolution.
func (s *SSRFBlocker) AllowIPsNoLookup(host string, ips []net.IP) ([]net.IP, bool) {
	resolved, blocked := s.CheckHost(host, ips)
	return resolved, !blocked
}

// CheckHost applies the SSRF verdict over a pre-resolved IP set without
// another Lookup: ips is authoritative (nil means "unknown", fail-open by
// default and blocked with FailClosedDNS,
// matching IsBlocked on unresolvable hosts). It returns (resolvedIPs,
// blocked). Callers pass the single Resolver.Lookup result from the
// firewall's AllowIPs so firewall plus SSRF share one lookup per request;
// each still applies its own blocked ranges.
func (s *SSRFBlocker) CheckHost(host string, ips []net.IP) ([]net.IP, bool) {
	return s.checkHostResolved(host, ips, true)
}

// checkHost implements the shared verdict: with hasIPs=false the resolver
// is consulted once; with hasIPs=true the supplied slice is authoritative
// and no Lookup occurs.
func (s *SSRFBlocker) checkHost(host string, ips []net.IP) ([]net.IP, bool) {
	return s.checkHostResolved(host, ips, false)
}

func (s *SSRFBlocker) checkHostResolved(host string, ips []net.IP, hasIPs bool) ([]net.IP, bool) {
	if s == nil {
		return ips, false
	}

	// Strip port
	hostname := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostname = h
	}

	// Check if it's already an IP, including non-canonical numeric forms
	// (decimal 2130706433, octal 0177.0.0.1, hex 0x7f.0.0.1, short 127.1,
	// trailing dot) that net.ParseIP rejects but dialers may interpret.
	// One shared normalizer (lowercase, strip brackets, one trailing dot) so
	// the SSRF verdict, the firewall rate key, and the DNS cache agree.
	hostname = normalizeHostKey(hostname)
	// Strict-reject hosts that look numeric but fail canonical parsing
	// (e.g. octal-invalid "0128.0.0.1", IPv6 zones "fe80::1%eth0"): falling
	// through to hostname lookup would defer the verdict to fail-open DNS
	// instead of deterministically blocking.
	if looksNumericHost(hostname) {
		if ip := parseNumericIP(hostname); ip != nil {
			return []net.IP{ip}, s.isIPBlocked(ip)
		}
		// Looks numeric but unparseable — block rather than resolve.
		return nil, true
	}
	if ip := parseNumericIP(hostname); ip != nil {
		return []net.IP{ip}, s.isIPBlocked(ip)
	}

	lower := hostname
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") || strings.HasSuffix(lower, ".local") {
		loopback := net.ParseIP("127.0.0.1")
		return []net.IP{loopback}, s.isIPBlocked(loopback)
	}
	if strings.HasSuffix(lower, ".onion") {
		return nil, false
	}

	// Resolve domain with caching, unless the caller supplied a resolution.
	resolved := ips
	if !hasIPs {
		resolved = s.resolver.Lookup(hostname)
	}
	// Fail-closed DNS: an unresolvable host is blocked instead of allowed.
	if len(resolved) == 0 && s.FailClosedDNS {
		return resolved, true
	}
	if len(s.blockedNets) == 0 {
		return resolved, false
	}
	for _, ip := range resolved {
		if s.isIPBlocked(ip) {
			return resolved, true
		}
	}
	return resolved, false
}

// StartCleanup runs a background goroutine that evicts expired DNS cache entries.
func (s *SSRFBlocker) StartCleanup(ctx context.Context, interval time.Duration) {
	s.resolver.StartCleanup(ctx, interval)
}

func (s *SSRFBlocker) isIPBlocked(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	for _, blocked := range s.blockedNets {
		if blocked.Contains(ip) {
			return true
		}
	}
	return false
}

// looksNumericHost reports whether host has the shape of a numeric-IP
// spelling (digits, dots, hex markers, colons for IPv6, and % for zones).
// Such hosts must resolve to a canonical IP via parseNumericIP; anything else
// in this shape is rejected rather than DNS-resolved.
//
// A bare all-hex DNS name (no ASCII digit, no colon, no zone) is NOT numeric:
// "cafe", "dead.beef", and "cafe.cafe" fall through to the normal DNS +
// range verdict. The digit/colon/% anchor keeps strict-reject for genuinely
// numeric but unparseable forms (octal-invalid "0128.0.0.1", IPv6 zones
// "fe80::1%eth0") while ending the over-match on hex-only hostnames.
func looksNumericHost(host string) bool {
	if host == "" {
		return false
	}
	if strings.Contains(host, "%") {
		return true
	}
	anchored := false
	for _, c := range host {
		switch {
		case c >= '0' && c <= '9':
			anchored = true
		case c == ':':
			anchored = true
		case c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F':
		case c == '.' || c == 'x' || c == 'X':
		default:
			return false
		}
	}
	return anchored
}

// parseNumericIP parses dotted-decimal, decimal/octal/hex integer, short-form
// (127.1), and trailing-dot IPv4 spellings that net.ParseIP rejects but
// dialers and Tor exits may still interpret as loopback/private addresses.
// Returns nil when the host is not any numeric-IP form.
func parseNumericIP(host string) net.IP {
	if ip := net.ParseIP(host); ip != nil {
		return ip
	}
	// Pure integer form: 2130706433 == 127.0.0.1
	if n, err := parseIntBase(host); err == nil && n <= 0xFFFFFFFF {
		return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	parts := strings.Split(host, ".")
	if len(parts) < 2 || len(parts) > 4 {
		return nil
	}
	nums := make([]uint64, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			return nil
		}
		n, err := parseIntBase(p)
		if err != nil || n > 0xFFFFFFFF {
			return nil
		}
		nums = append(nums, n)
	}
	// Last part may absorb multiple trailing octets (short forms).
	var b [4]byte
	switch len(nums) {
	case 2:
		if nums[0] > 255 || nums[1] > 0xFFFFFF {
			return nil
		}
		b[0] = byte(nums[0])
		b[1] = byte(nums[1] >> 16)
		b[2] = byte(nums[1] >> 8)
		b[3] = byte(nums[1])
	case 3:
		if nums[0] > 255 || nums[1] > 255 || nums[2] > 0xFFFF {
			return nil
		}
		b[0] = byte(nums[0])
		b[1] = byte(nums[1])
		b[2] = byte(nums[2] >> 8)
		b[3] = byte(nums[2])
	case 4:
		for i, n := range nums {
			if n > 255 {
				return nil
			}
			b[i] = byte(n)
		}
	default:
		return nil
	}
	return net.IPv4(b[0], b[1], b[2], b[3])
}

// parseIntBase accepts decimal, 0x-hex, and leading-0 octal spellings.
func parseIntBase(s string) (uint64, error) {
	base := 10
	if len(s) > 2 && (s[:2] == "0x" || s[:2] == "0X") {
		base = 16
		s = s[2:]
	} else if len(s) > 1 && s[0] == '0' {
		base = 8
		s = s[1:]
	}
	if s == "" {
		return 0, strconv.ErrSyntax
	}
	return strconv.ParseUint(s, base, 32)
}

// IsSchemeBlocked checks if a URL scheme should be blocked.
func (s *SSRFBlocker) IsSchemeBlocked(scheme string) bool {
	scheme = strings.ToLower(scheme)
	switch scheme {
	case "http", "https":
		return false
	}
	return true
}
