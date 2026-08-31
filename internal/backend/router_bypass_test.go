package backend

import "testing"

// Guards against the LastIndex regression where only exact hostnames matched
// and every subdomain (any depth) failed to bypass.
func TestIsBypassHost_SuffixAllDepths(t *testing.T) {
	r := NewRouter(NewDirectBackend(0), NewDirectBackend(0))
	r.SetBypassHosts([]string{"example.com", "FOO.org"})

	cases := map[string]bool{
		"example.com":          true,
		"www.example.com":      true,
		"a.b.example.com":      true,
		"EXAMPLE.COM":          true,
		"foo.org":              true,
		"bar.foo.org":          true,
		"notexample.com":       false,
		"example.com.evil.org": false,
		"ample.com":            false,
		"":                     false,
	}
	for host, want := range cases {
		if got := r.isBypassHost(host); got != want {
			t.Errorf("isBypassHost(%q) = %v, want %v", host, got, want)
		}
	}
}
