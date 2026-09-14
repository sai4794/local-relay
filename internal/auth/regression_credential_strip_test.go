package auth

import (
	"net/http/httptest"
	"testing"
)

// Regression: the proxy's own credential must be detectable (so the forward
// path can strip it) while an unrelated upstream Authorization token is
// preserved. MatchesProxyKey is the predicate the forwarder uses.
func TestRegression_CredentialStripPredicate(t *testing.T) {
	const key = "test-key-0123456789abcdef"
	a := NewAPIKeyAuth(key)

	proxyCreds := []string{
		key,
		"Bearer " + key,
		"Basic " + key,
	}
	for _, c := range proxyCreds {
		if !a.MatchesProxyKey(c) {
			t.Errorf("MatchesProxyKey(%q) = false; want true (proxy credential must be stripped)", c)
		}
	}
	upstream := []string{
		"Bearer upstream-token-openai",
		"Basic dXNlcjpwYXNzd29yZA==", // user:password
		"Bearer wrong-key",
	}
	for _, c := range upstream {
		if a.MatchesProxyKey(c) {
			t.Errorf("MatchesProxyKey(%q) = true; want false (upstream token must be preserved)", c)
		}
	}

	// Proxy-Authorization carrying the key authenticates, while a request
	// bearing only an upstream Authorization token does not.
	r := httptest.NewRequest("GET", "http://x/", nil)
	r.Header.Set("Authorization", "Bearer upstream-token-openai")
	if a.Check(httptest.NewRecorder(), r) {
		t.Error("upstream-only Authorization must not authenticate the proxy")
	}
	r.Header.Set("Proxy-Authorization", "Bearer "+key)
	if !a.Check(httptest.NewRecorder(), r) {
		t.Error("Proxy-Authorization with proxy key must authenticate")
	}
}
