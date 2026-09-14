package security

import (
	"net"
	"testing"
)

// Regression: numeric-IP spellings that net.ParseIP rejects must still be
// blocked when they denote loopback/private addresses.
func TestRegression_NumericIPSSRFBlocked(t *testing.T) {
	blocker := NewSSRFBlocker([]string{"127.0.0.0/8", "10.0.0.0/8", "192.168.0.0/16"})
	blocked := []string{
		"2130706433", // decimal 127.0.0.1
		"0x7f.0.0.1", // hex first octet
		"0177.0.0.1", // octal first octet
		"127.1",      // short form
		"127.0.0.1.", // trailing dot
		"3232235521", // decimal 192.168.0.1
		"10.1",       // short private
		"0x0a.0.0.1", // hex 10.0.0.1
	}
	for _, h := range blocked {
		if !blocker.IsBlocked(h) {
			t.Errorf("IsBlocked(%q) = false; want true (numeric-IP SSRF)", h)
		}
		fw := NewFirewall(FirewallConfig{})
		if fw.AllowHost(h) {
			t.Errorf("AllowHost(%q) = true; want false (numeric-IP SSRF)", h)
		}
	}
	// Public numeric forms must stay allowed.
	for _, h := range []string{"16885952", "134744072"} { // 1.2.3.64, 8.8.8.8
		if blocker.IsBlocked(h) {
			t.Errorf("IsBlocked(%q) = true; want false (public numeric IP)", h)
		}
	}
}

// The no-Lookup re-verdict helpers (used by the bypass pin path) must apply
// the same verdicts as the Lookup path over the same IPs, with no DNS and no
// rate charge: blocked stays blocked, public stays allowed, nil stays
// fail-open (matching FailClosedDNS=false default).
func TestRegression_NoLookupReverdictMatchesLookup(t *testing.T) {
	cidrs := []string{"127.0.0.0/8", "10.0.0.0/8"}
	blocker := NewSSRFBlocker(cidrs)
	fw := NewFirewall(FirewallConfig{})
	priv := []net.IP{net.ParseIP("127.0.0.1")}
	pub := []net.IP{net.ParseIP("8.8.8.8")}

	if _, ok := blocker.AllowIPsNoLookup("anything.example", priv); ok {
		t.Error("SSRF AllowIPsNoLookup(private) = allow; want block")
	}
	if _, ok := blocker.AllowIPsNoLookup("anything.example", pub); !ok {
		t.Error("SSRF AllowIPsNoLookup(public) = block; want allow")
	}
	if _, ok := blocker.AllowIPsNoLookup("anything.example", nil); !ok {
		t.Error("SSRF AllowIPsNoLookup(nil) = block; want fail-open allow")
	}
	if _, ok := fw.AllowIPsNoLookup("anything.example", priv); ok {
		t.Error("firewall AllowIPsNoLookup(private) = allow; want block")
	}
	if _, ok := fw.AllowIPsNoLookup("anything.example", pub); !ok {
		t.Error("firewall AllowIPsNoLookup(public) = block; want allow")
	}
	if _, ok := fw.AllowIPsNoLookup("anything.example", nil); !ok {
		t.Error("firewall AllowIPsNoLookup(nil) = block; want fail-open allow")
	}
	// Nil receivers must not panic (CONNECT/SOCKS5 paths call through
	// possibly-nil firewall/ssrf when components are disabled).
	var nilFw *Firewall
	if _, ok := nilFw.AllowIPsNoLookup("h", priv); !ok {
		t.Error("nil firewall AllowIPsNoLookup = block; want allow (no-op)")
	}
	var nilBlocker *SSRFBlocker
	if _, ok := nilBlocker.AllowIPsNoLookup("h", priv); !ok {
		t.Error("nil SSRF AllowIPsNoLookup = block; want allow (no-op)")
	}
}
