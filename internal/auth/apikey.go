package auth

import (
	"crypto/subtle"
	"encoding/base64"
	"net/http"
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

func (a *APIKeyAuth) verifyKey(r *http.Request) bool {
	// 1. Proxy-Authorization header takes highest precedence for proxy auth
	if proxyAuth := r.Header.Get(a.proxyHeader); proxyAuth != "" {
		if a.compareCredential(proxyAuth) {
			return true
		}
	}

	// 2. Custom header X-Api-Key takes second precedence
	if key := r.Header.Get(a.headerName); key != "" {
		if a.compareCredential(key) {
			return true
		}
	}

	// 3. Query parameter
	if key := r.URL.Query().Get(a.queryParam); key != "" {
		if subtle.ConstantTimeCompare([]byte(key), []byte(a.apiKey)) == 1 {
			return true
		}
	}

	// 4. Fallback to Authorization header if not already consumed by proxy auth
	if auth := r.Header.Get("Authorization"); auth != "" {
		if a.compareCredential(auth) {
			return true
		}
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
	if len(raw) > 7 && strings.EqualFold(raw[:7], "Bearer ") {
		token := strings.TrimSpace(raw[7:])
		if subtle.ConstantTimeCompare([]byte(token), []byte(a.apiKey)) == 1 {
			return true
		}
	}

	// Check Basic scheme
	if len(raw) > 6 && strings.EqualFold(raw[:6], "Basic ") {
		val := strings.TrimSpace(raw[6:])
		// Could be raw unencoded key in informal usage
		if subtle.ConstantTimeCompare([]byte(val), []byte(a.apiKey)) == 1 {
			return true
		}
		// Base64-encoded username:password or user:apiKey or :apiKey
		if decoded, err := base64.StdEncoding.DecodeString(val); err == nil {
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
