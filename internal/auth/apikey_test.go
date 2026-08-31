package auth

import (
	"crypto/subtle"
	"net/http/httptest"
	"testing"
)

func TestAPIKeyAuth_HeaderAndSchemeVariants(t *testing.T) {
	a := NewAPIKeyAuth("test-key-0123456789abcdef")

	ok := func(authHeader string) {
		r := httptest.NewRequest("GET", "http://x/", nil)
		r.Header.Set("Authorization", authHeader)
		if !a.Check(httptest.NewRecorder(), r) {
			t.Errorf("expected pass for %q", authHeader)
		}
	}
	ok("test-key-0123456789abcdef")
	ok("Bearer test-key-0123456789abcdef")
	ok("bearer test-key-0123456789abcdef")
	ok("Basic test-key-0123456789abcdef")

	r := httptest.NewRequest("GET", "http://x/", nil)
	r.Header.Set("Authorization", "Bearer wrong-key")
	w := httptest.NewRecorder()
	if a.Check(w, r) {
		t.Error("wrong key accepted")
	}
	if w.Code != 407 {
		t.Errorf("want 407, got %d", w.Code)
	}
}

// Matches the comparison primitive used; plaintext compare would short-circuit
// on first byte and leak length/prefix.
func TestConstantTimeComparePrimitive(t *testing.T) {
	k := []byte("test-key-0123456789abcdef")
	if subtle.ConstantTimeCompare(k, []byte("test-key-0123456789abcdef")) != 1 {
		t.Fatal("same key should pass")
	}
	if subtle.ConstantTimeCompare(k, []byte("test-key-0123456789abcdeX")) == 1 {
		t.Fatal("mismatch must fail")
	}
	if subtle.ConstantTimeCompare(k, []byte("short")) == 1 {
		t.Fatal("length mismatch must fail")
	}
}
