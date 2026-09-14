package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Regression: Header.Get returns element 0 only, so a proxy key in a
// non-first Authorization value must still authenticate (key holders only),
// and the forward-path strip must remove only matching values while
// preserving the rest — in both orders.
func TestRegression_MultiValueAuthorization(t *testing.T) {
	const key = "test-key-0123456789abcdef"
	a := NewAPIKeyAuth(key)
	upstream := "Bearer upstream-token-openai"
	proxy := "Bearer " + key

	orders := []struct {
		name   string
		values []string
	}{
		{"proxy-first", []string{proxy, upstream}},
		{"proxy-second", []string{upstream, proxy}},
	}
	for _, o := range orders {
		t.Run("auth/"+o.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://x/", nil)
			for _, v := range o.values {
				r.Header.Add("Authorization", v)
			}
			if !a.Check(httptest.NewRecorder(), r) {
				t.Errorf("Check with Authorization %q = false; want true (proxy key present in %s)", o.values, o.name)
			}
		})
		t.Run("strip/"+o.name, func(t *testing.T) {
			h := http.Header{}
			for _, v := range o.values {
				h.Add("Authorization", v)
			}
			a.StripProxyAuthorization(h)
			got := h.Values("Authorization")
			if len(got) != 1 || got[0] != upstream {
				t.Errorf("StripProxyAuthorization(%q) = %q; want [%q] (proxy value removed, upstream preserved)", o.values, got, upstream)
			}
		})
	}

	// Mirror case: no proxy key present — Del-equivalent must not run, so the
	// legit upstream token survives untouched.
	t.Run("strip/upstream-only-preserved", func(t *testing.T) {
		h := http.Header{}
		h.Add("Authorization", upstream)
		h.Add("Authorization", "Bearer another-upstream-token")
		a.StripProxyAuthorization(h)
		got := h.Values("Authorization")
		if len(got) != 2 || got[0] != upstream || got[1] != "Bearer another-upstream-token" {
			t.Errorf("StripProxyAuthorization upstream-only = %q; want both values preserved", got)
		}
	})

	// Upstream-only Authorization (any position) must not authenticate.
	t.Run("auth/upstream-only-rejected", func(t *testing.T) {
		r := httptest.NewRequest("GET", "http://x/", nil)
		r.Header.Add("Authorization", upstream)
		r.Header.Add("Authorization", "Bearer another-upstream-token")
		if a.Check(httptest.NewRecorder(), r) {
			t.Error("upstream-only multi-value Authorization authenticated; want rejection")
		}
	})

	// Previously-valid single-value requests still pass.
	t.Run("auth/single-value-unchanged", func(t *testing.T) {
		r := httptest.NewRequest("GET", "http://x/", nil)
		r.Header.Set("Authorization", proxy)
		if !a.Check(httptest.NewRecorder(), r) {
			t.Error("single-value proxy Authorization rejected; want acceptance")
		}
	})
}

// Regression: Proxy-Authorization and X-Api-Key scan ALL header values
// (Header.Get returns element 0 only), consistent with the Authorization path.
// A proxy key in a non-first value must authenticate; wrong-key-only
// multi-values must stay fail-closed.
func TestRegression_MultiValueProxyKeyHeaders(t *testing.T) {
	const key = "test-key-0123456789abcdef"
	a := NewAPIKeyAuth(key)
	upstream := "Bearer upstream-token-openai"
	proxy := "Bearer " + key

	for _, hdr := range []string{"Proxy-Authorization", "X-Api-Key"} {
		for _, order := range []struct {
			name   string
			values []string
		}{
			{"proxy-first", []string{proxy, upstream}},
			{"proxy-second", []string{upstream, proxy}},
		} {
			t.Run("auth/"+hdr+"/"+order.name, func(t *testing.T) {
				r := httptest.NewRequest("GET", "http://x/", nil)
				for _, v := range order.values {
					r.Header.Add(hdr, v)
				}
				if !a.Check(httptest.NewRecorder(), r) {
					t.Errorf("Check with %s %q = false; want true (proxy key present in %s)", hdr, order.values, order.name)
				}
			})
		}
		// Wrong-key-only multi-values must not authenticate.
		t.Run("auth/"+hdr+"/wrong-only-rejected", func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://x/", nil)
			r.Header.Add(hdr, upstream)
			r.Header.Add(hdr, "Bearer another-upstream-token")
			if a.Check(httptest.NewRecorder(), r) {
				t.Errorf("wrong-key-only multi-value %s authenticated; want rejection", hdr)
			}
		})
		// Single-value proxy key still passes.
		t.Run("auth/"+hdr+"/single-value-unchanged", func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://x/", nil)
			r.Header.Set(hdr, proxy)
			if !a.Check(httptest.NewRecorder(), r) {
				t.Errorf("single-value proxy %s rejected; want acceptance", hdr)
			}
		})
	}
}
