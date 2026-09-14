package security

import (
	"net"
	"testing"
)

// Parity: CheckHost/AllowIPsNoLookup over a pre-resolved slice must match the
// Lookup-path verdict on the same host (blocked stays blocked, public
// allowed, nil fail-open honoring FailClosedDNS). Nil receivers must not
// panic. Loopback/test ports only — no external dials.
func TestRegression_CheckHostParityVsLookup(t *testing.T) {
	cidrs := []string{"127.0.0.0/8", "10.0.0.0/8"}
	newBlocker := func(failClosed bool) *SSRFBlocker {
		b := NewSSRFBlockerWithResolver(cidrs, NewResolver())
		b.FailClosedDNS = failClosed
		return b
	}
	newFW := func(failClosed bool) *Firewall {
		return NewFirewallWithResolver(FirewallConfig{FailClosedDNS: failClosed}, NewResolver())
	}

	// IP-literal hosts: same verdict on Lookup path and NoLookup path.
	for _, h := range []string{"127.0.0.1", "10.1.2.3", "8.8.8.8", "1.1.1.1"} {
		fw := newFW(false)
		lookupIPs, lookupOK := fw.AllowIPs(h)
		nolookupIPs, nolookupOK := fw.AllowIPsNoLookup(h, lookupIPs)
		if lookupOK != nolookupOK {
			t.Errorf("firewall %q: AllowIPs=%v vs AllowIPsNoLookup=%v (want equal)", h, lookupOK, nolookupOK)
		}
		if len(lookupIPs) != len(nolookupIPs) {
			t.Errorf("firewall %q: slice len %d vs %d (want equal)", h, len(lookupIPs), len(nolookupIPs))
		}
		if _, ok := fw.CheckHost(lookupIPs); ok != lookupOK {
			t.Errorf("firewall %q: CheckHost=%v vs AllowIPs=%v (want equal)", h, ok, lookupOK)
		}

		b := newBlocker(false)
		bIPs, bBlocked := b.IsBlockedIPs(h)
		_, bOK := b.AllowIPs(h)
		if bBlocked == bOK {
			t.Errorf("ssrf %q: IsBlocked=%v vs AllowIPs=%v (want inverse)", h, bBlocked, bOK)
		}
		if _, blocked := b.CheckHost(h, bIPs); blocked != bBlocked {
			t.Errorf("ssrf %q: CheckHost=%v vs IsBlockedIPs=%v (want equal)", h, blocked, bBlocked)
		}
		if _, ok := b.AllowIPsNoLookup(h, bIPs); ok != bOK {
			t.Errorf("ssrf %q: AllowIPsNoLookup=%v vs AllowIPs=%v (want equal)", h, ok, bOK)
		}
	}

	// Unknown (nil-slice) handling must honor FailClosedDNS on both paths.
	for _, failClosed := range []bool{false, true} {
		fw := newFW(failClosed)
		if _, ok := fw.AllowIPsNoLookup("anything.invalid", nil); ok == failClosed {
			t.Errorf("firewall nil failClosed=%v: AllowIPsNoLookup=%v (want %v)", failClosed, ok, !failClosed)
		}
		if _, ok := fw.CheckHost(nil); ok == failClosed {
			t.Errorf("firewall nil failClosed=%v: CheckHost=%v (want %v)", failClosed, ok, !failClosed)
		}
		b := newBlocker(failClosed)
		if _, blocked := b.CheckHost("anything.invalid", nil); blocked != failClosed {
			t.Errorf("ssrf nil failClosed=%v: CheckHost=%v (want %v)", failClosed, blocked, failClosed)
		}
		if _, ok := b.AllowIPsNoLookup("anything.invalid", nil); ok == failClosed {
			t.Errorf("ssrf nil failClosed=%v: AllowIPsNoLookup=%v (want %v)", failClosed, ok, !failClosed)
		}
	}

	// Blocked stays blocked, public stays allowed over the same shared slice.
	fw := newFW(false)
	b := newBlocker(false)
	priv := []net.IP{net.ParseIP("127.0.0.1")}
	pub := []net.IP{net.ParseIP("8.8.8.8")}
	if _, ok := fw.AllowIPsNoLookup("h", priv); ok {
		t.Error("firewall AllowIPsNoLookup(private) = allow; want block")
	}
	if _, blocked := b.CheckHost("h", priv); !blocked {
		t.Error("ssrf CheckHost(private) = allow; want block")
	}
	if _, ok := fw.AllowIPsNoLookup("h", pub); !ok {
		t.Error("firewall AllowIPsNoLookup(public) = block; want allow")
	}
	if _, blocked := b.CheckHost("h", pub); blocked {
		t.Error("ssrf CheckHost(public) = block; want allow")
	}

	// Nil receivers (disabled components) stay no-op allows, never panics.
	var nilFw *Firewall
	if _, ok := nilFw.AllowIPsNoLookup("h", priv); !ok {
		t.Error("nil firewall AllowIPsNoLookup = block; want allow (no-op)")
	}
	if _, ok := nilFw.CheckHost(priv); !ok {
		t.Error("nil firewall CheckHost = block; want allow (no-op)")
	}
	var nilBlocker *SSRFBlocker
	if _, ok := nilBlocker.AllowIPsNoLookup("h", priv); !ok {
		t.Error("nil SSRF AllowIPsNoLookup = block; want allow (no-op)")
	}
	if _, blocked := nilBlocker.CheckHost("h", priv); blocked {
		t.Error("nil SSRF CheckHost = block; want allow (no-op)")
	}
}
