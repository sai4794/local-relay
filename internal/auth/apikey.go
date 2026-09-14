package auth

import (
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
)

type APIKeyAuth struct {
	apiKey      string
	headerName  string
	queryParam  string
	proxyHeader string
}

func NewAPIKeyAuth(apiKey string) *APIKeyAuth {
	return &APIKeyAuth{
		apiKey:      apiKey,
		headerName:  "X-Api-Key",
		queryParam:  "api_key",
		proxyHeader: "Proxy-Authorization",
	}
}

func (a *APIKeyAuth) Check(w http.ResponseWriter, r *http.Request) bool {
	if a.verifyKey(r) {
		return true
	}

	w.Header().Set("Proxy-Authenticate", `Basic realm="proxy"`)
	http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
	return false
}

// MatchesProxyKey reports whether the given Authorization header value
// carries the proxy's own key (any accepted scheme). The proxy uses this
// after authentication to strip its credential before forwarding upstream,
// while preserving an unrelated upstream Authorization token.
func (a *APIKeyAuth) MatchesProxyKey(raw string) bool {
	return a.compareCredential(raw)
}

// MatchesQueryKey reports whether the given query parameter VALUE carries the
// proxy's own key (MatchesProxyKey predicate). Query api_key values are
// normally raw tokens, but the same predicate authentication uses is applied
// so any accepted credential form is stripped before forwarding upstream.
func (a *APIKeyAuth) MatchesQueryKey(value string) bool {
	return a.MatchesProxyKey(value)
}

// StripProxyQueryKey removes only the query parameter values that carry the
// proxy's own key (per MatchesProxyKey), preserving non-matching values and
// all other parameters. q is the parsed query of the request URL about to be
// forwarded; the caller re-encodes it via q.Encode().
func (a *APIKeyAuth) StripProxyQueryKey(q url.Values) {
	vals, ok := q[a.queryParam]
	if !ok {
		return
	}
	kept := vals[:0]
	stripped := false
	for _, v := range vals {
		if a.MatchesQueryKey(v) {
			stripped = true
			continue
		}
		kept = append(kept, v)
	}
	if !stripped {
		return
	}
	if len(kept) == 0 {
		q.Del(a.queryParam)
		return
	}
	q[a.queryParam] = kept
}

// MatchesAnyProxyKey reports whether any of the given Authorization header
// values carries the proxy's own key. Header.Get returns element 0 only, so
// callers must use Header.Values (all elements) with this helper — otherwise
// a proxy key in a non-first value would fail to authenticate here yet be
// forwarded upstream (or a Del would drop a legit upstream token).
func (a *APIKeyAuth) MatchesAnyProxyKey(values []string) bool {
	for _, v := range values {
		if a.compareCredential(v) {
			return true
		}
	}
	return false
}

// StripProxyAuthorization removes only the Authorization values that carry
// the proxy's own key, preserving unrelated upstream tokens. When no value
// matches, the header block is left untouched.
func (a *APIKeyAuth) StripProxyAuthorization(h http.Header) {
	values := h.Values("Authorization")
	if len(values) == 0 {
		return
	}
	kept := make([]string, 0, len(values))
	stripped := false
	for _, v := range values {
		if a.compareCredential(v) {
			stripped = true
			continue
		}
		kept = append(kept, v)
	}
	if !stripped {
		return
	}
	h.Del("Authorization")
	for _, v := range kept {
		h.Add("Authorization", v)
	}
}

func (a *APIKeyAuth) verifyKey(r *http.Request) bool {
	// Parse the query once: url.Query parses RawQuery on every call, and
	// verifyKey previously parsed it separately from the caller's own
	// Query() use. One parse, reused for the api_key check below.
	query := r.URL.Query()

	// 1. Proxy-Authorization header takes highest precedence for proxy auth.
	// Scan every value: Header.Get returns element 0 only (the same pitfall
	// the Authorization path already handles via MatchesAnyProxyKey), so a
	// proxy key in a non-first value must still authenticate. A
	// present-but-wrong value falls through to the checks below; rejection
	// stays fail-closed at the end.
	for _, proxyAuth := range r.Header.Values(a.proxyHeader) {
		if a.compareCredential(proxyAuth) {
			return true
		}
	}

	// 2. Custom header X-Api-Key takes second precedence (all values scanned,
	// same rationale as above).
	for _, key := range r.Header.Values(a.headerName) {
		if a.compareCredential(key) {
			return true
		}
	}

	// 3. Query parameter
	if key := query.Get(a.queryParam); key != "" {
		if subtle.ConstantTimeCompare([]byte(key), []byte(a.apiKey)) == 1 {
			return true
		}
	}

	// 4. Fallback to Authorization header if not already consumed by proxy auth.
	// Inspect every value: Header.Get returns element 0 only, so a proxy key
	// in a non-first value must still authenticate (key holders only).
	if a.MatchesAnyProxyKey(r.Header.Values("Authorization")) {
		return true
	}

	return false
}

func (a *APIKeyAuth) compareCredential(raw string) bool {
	raw = strings.TrimSpace(raw)
	// Check direct match
	if subtle.ConstantTimeCompare([]byte(raw), []byte(a.apiKey)) == 1 {
		return true
	}

	// Check Bearer scheme
	if bare := stripScheme(raw); bare != raw {
		token := strings.TrimSpace(bare)
		if subtle.ConstantTimeCompare([]byte(token), []byte(a.apiKey)) == 1 {
			return true
		}
	}

	// Check Basic scheme
	if len(raw) > 6 && strings.EqualFold(raw[:6], "Basic ") {
		val := stripScheme(raw)
		val = strings.TrimSpace(val)
		// Could be raw unencoded key in informal usage
		if subtle.ConstantTimeCompare([]byte(val), []byte(a.apiKey)) == 1 {
			return true
		}
		// Base64-encoded username:password or user:apiKey or :apiKey.
		// Accept unpadded encodings too (RFC 7617 clients sometimes omit '=').
		if decoded, err := decodeBase64Flexible(val); err == nil {
			s := string(decoded)
			if subtle.ConstantTimeCompare(decoded, []byte(a.apiKey)) == 1 {
				return true
			}
			if idx := strings.Index(s, ":"); idx >= 0 {
				user := s[:idx]
				pass := s[idx+1:]
				if subtle.ConstantTimeCompare([]byte(pass), []byte(a.apiKey)) == 1 ||
					subtle.ConstantTimeCompare([]byte(user), []byte(a.apiKey)) == 1 {
					return true
				}
			}
		}
	}

	return false
}

// stripScheme removes a leading "Bearer " or "Basic " scheme marker.
func stripScheme(v string) string {
	for _, scheme := range []string{"Bearer ", "Basic "} {
		if len(v) > len(scheme) && strings.EqualFold(v[:len(scheme)], scheme) {
			return v[len(scheme):]
		}
	}
	return v
}

// decodeBase64Flexible decodes standard base64, tolerating missing padding.
func decodeBase64Flexible(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return base64.StdEncoding.DecodeString(s)
}
