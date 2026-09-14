package security

import (
	"net"
	"testing"
)

// Pure-letter hex-shaped hostnames must NOT be treated as numeric: they fall
// through to the normal DNS + range verdict (fail-open allow when the local
// resolver cannot see them), never strict-reject.
func TestRegression_LooksNumericHexNamesFallThrough(t *testing.T) {
	ssrf := NewSSRFBlocker([]string{"127.0.0.0/8", "10.0.0.0/8"})
	for _, h := range []string{"cafe", "dead.beef", "cafe.cafe", "CAFE", "Dead.Beef"} {
		if looksNumericHost(h) {
			t.Errorf("looksNumericHost(%q) = true; want false (hex-only name is not numeric)", h)
		}
		if ssrf.IsBlocked(h) {
			t.Errorf("IsBlocked(%q) = true; want false (unresolvable hex name stays fail-open)", h)
		}
		fw := NewFirewall(FirewallConfig{})
		if !fw.AllowHost(h) {
			t.Errorf("AllowHost(%q) = false; want true (unresolvable hex name stays fail-open)", h)
		}
	}
}

// The anchored matcher must still treat genuinely numeric spellings as
// numeric, and strict-reject for unparseable numeric, %zone, and
// octal-invalid forms is preserved.
func TestRegression_LooksNumericAnchoredStrictReject(t *testing.T) {
	for _, h := range []string{
		"2130706433", "0x7f.0.0.1", "0177.0.0.1", "127.1", "127.0.0.1",
		"::1", "fe80::1", "fe80::1%eth0", "127.0.0.1%lo", "0128.0.0.1",
		"1.2.3.4", "8.8.8.8", "cafe123", "123cafe",
	} {
		if !looksNumericHost(h) {
			t.Errorf("looksNumericHost(%q) = false; want true (numeric anchor present)", h)
		}
	}
	for _, h := range []string{"", "example.com", "cafe", "zz-top", "hello_world"} {
		if looksNumericHost(h) {
			t.Errorf("looksNumericHost(%q) = true; want false", h)
		}
	}
	fw := NewFirewall(FirewallConfig{})
	ssrf := NewSSRFBlocker([]string{"127.0.0.0/8", "10.0.0.0/8", "169.254.0.0/16"})
	for _, h := range []string{"0128.0.0.1", "0192.168.1.1", "fe80::1%eth0", "127.0.0.1%lo"} {
		if fw.AllowHost(h) {
			t.Errorf("AllowHost(%q) = true; want false (strict numeric reject)", h)
		}
		if !ssrf.IsBlocked(h) {
			t.Errorf("IsBlocked(%q) = false; want true (strict numeric reject)", h)
		}
	}
}

// FailClosedDNS=true must block unresolvable hosts on both guards; the
// .onion exemption precedes the check and stays allowed.
func TestRegression_FailClosedDNSBlocksUnresolvable(t *testing.T) {
	ssrf := NewSSRFBlocker(nil)
	ssrf.FailClosedDNS = true
	if !ssrf.IsBlocked("nonexistent.invalid") {
		t.Error("IsBlocked(unresolvable) with FailClosedDNS = false; want true")
	}
	if ssrf.IsBlocked("example.onion") {
		t.Error("IsBlocked(.onion) with FailClosedDNS = true; want false (.onion exemption precedes)")
	}

	fw := NewFirewall(FirewallConfig{FailClosedDNS: true})
	if fw.AllowHost("nonexistent.invalid") {
		t.Error("AllowHost(unresolvable) with FailClosedDNS = false; want true (blocked)")
	}
	if _, ok := fw.AllowIPs("nonexistent.invalid"); ok {
		t.Error("AllowIPs(unresolvable) with FailClosedDNS = true; want blocked")
	}
	if !fw.AllowHost("example.onion") {
		t.Error("AllowHost(.onion) with FailClosedDNS = false; want true (.onion exemption precedes)")
	}

	// Default stays fail-open.
	if NewSSRFBlocker(nil).IsBlocked("nonexistent.invalid") {
		t.Error("IsBlocked(unresolvable) default = true; want false (fail-open preserved)")
	}
	if !NewFirewall(FirewallConfig{}).AllowHost("nonexistent.invalid") {
		t.Error("AllowHost(unresolvable) default = false; want true (fail-open preserved)")
	}
}

// One shared normalizer (LOW-5): lowercase, strip brackets, one trailing dot.
func TestRegression_NormalizeHostKeyShared(t *testing.T) {
	cases := map[string]string{
		"Example.COM.":      "example.com",
		"EXAMPLE.com:8080":  "example.com",
		"[::1]:8080":        "::1",
		"[2001:DB8::1].":    "2001:db8::1",
		"LOCALHOST:80":      "localhost",
		"sub.LOCALHOST.":    "sub.localhost",
		"Example.COM.:8443": "example.com",
	}
	for in, want := range cases {
		if got := normalizeHostKey(in); got != want {
			t.Errorf("normalizeHostKey(%q) = %q; want %q", in, got, want)
		}
	}
	// The firewall rate key, SSRF verdict, and DNS cache must agree over
	// bracketed/FQDN spellings of a blocked literal.
	fw := NewFirewall(FirewallConfig{})
	for _, h := range []string{"127.0.0.1", "127.0.0.1.", "[127.0.0.1]"} {
		if fw.AllowHost(h) {
			t.Errorf("AllowHost(%q) = true; want false (normalized loopback blocked)", h)
		}
	}
	ssrf := NewSSRFBlocker([]string{"127.0.0.0/8"})
	for _, h := range []string{"127.0.0.1", "127.0.0.1.", "[127.0.0.1]"} {
		if !ssrf.IsBlocked(h) {
			t.Errorf("IsBlocked(%q) = false; want true (normalized loopback blocked)", h)
		}
	}
}

// Rate-limit denial (LOW-2) is distinguishable from an SSRF block without
// changing enforcement codes: per-destination 403/0x02 behavior is unchanged.
func TestRegression_RateLimitDenialDistinctFromSSRFBlock(t *testing.T) {
	fw := NewFirewall(FirewallConfig{RateLimit: 1000, RateBurst: 1})
	if _, ok := fw.AllowIPs("8.8.8.8"); !ok {
		t.Fatal("first AllowIPs(8.8.8.8) denied; want allow")
	}
	ips, ok := fw.AllowIPs("8.8.8.8")
	if ok {
		t.Fatal("second AllowIPs(8.8.8.8) allowed; want rate-limit denial")
	}
	if len(ips) != 0 {
		t.Errorf("rate-limit denial returned %v; want nil slice (SSRF blocks return the resolved IPs)", ips)
	}
	if !fw.RateLimitExceeded("8.8.8.8") {
		t.Error("RateLimitExceeded(8.8.8.8) = false after denial; want true")
	}
	if fw.RateLimitExceeded("1.1.1.1") {
		t.Error("RateLimitExceeded(1.1.1.1) = true on a fresh host; want false (SSRF-block denials log separately)")
	}
	blocked := []net.IP{net.ParseIP("127.0.0.1")}
	if _, ok := fw.AllowIPsNoLookup("h", blocked); ok {
		t.Error("AllowIPsNoLookup(private) = allow; want block")
	}
}
