package security

import "testing"

// Regression: hosts that look numeric but fail canonical parsing must be
// blocked deterministically, never deferred to DNS/fail-open. Covers
// octal-invalid spellings ("0128.0.0.1") and IPv6 zone suffixes
// ("fe80::1%eth0"), which no dialer should receive from this proxy.
func TestRegression_StrictNumericReject(t *testing.T) {
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
	// Genuine numeric IPs keep their verdicts.
	if fw.AllowHost("2130706433") {
		t.Error("AllowHost(decimal loopback) = true; want false")
	}
	if !fw.AllowHost("134744072") {
		t.Error("AllowHost(decimal 8.8.8.8) = false; want true")
	}
	// Normal hostnames keep fail-open behavior.
	if !fw.AllowHost("example.com") {
		t.Error("AllowHost(example.com) = false; want true (fail-open preserved)")
	}
}
