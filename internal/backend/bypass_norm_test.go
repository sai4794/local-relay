package backend

import "testing"

// L-01: bypass host normalization must strip IPv6 brackets on BOTH the
// config path and the lookup path. Configuring "[::1]" previously never
// matched the dial path's bracket-stripped "::1".
func TestBypassHosts_IPV6BracketNormalization(t *testing.T) {
	r := NewRouter(NewDirectBackend(0))
	r.SetBypassHosts([]string{"[::1]", "Example.COM."})
	for _, host := range []string{"::1", "[::1]", "[::1]:443", "example.com", "EXAMPLE.COM."} {
		if !r.IsBypassHost(host) {
			t.Errorf("IsBypassHost(%q) = false, want true", host)
		}
	}
	if r.IsBypassHost("::2") {
		t.Error("IsBypassHost(::2) = true, want false")
	}
}
