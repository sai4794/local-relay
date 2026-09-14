package security

import (
	"sort"
	"strings"
	"testing"
)

// Firewall default ranges must stay in sync with internal/config/defaults.go
// and config.yaml (the yaml list replaces, not merges with, the defaults, so
// drift means file-loaded runtime enforcement silently differs from
// default-loaded enforcement). Ranges checked as strings; order-insensitive.
func TestBlockedRanges_MatchConfigDefaults(t *testing.T) {
	want := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"127.0.0.0/8",
		"0.0.0.0/8",
		"100.64.0.0/10",
		"198.18.0.0/15",
		"::1/128",
		"::/128",
		"fc00::/7",
		"fe80::/10",
		"fec0::/10",
		"2002::/16",
		"2001::/32",
		"2001:db8::/32",
		"224.0.0.0/4",
		"ff00::/8",
	}
	var got []string
	for _, r := range getDefaultBlockedRanges() {
		got = append(got, r.String())
	}
	sort.Strings(want)
	sort.Strings(got)
	if strings.Join(want, ",") != strings.Join(got, ",") {
		t.Errorf("firewall default ranges drift:\nwant: %v\ngot:  %v", want, got)
	}
}
