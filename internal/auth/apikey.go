package auth

import (
	"crypto/subtle"
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
	if key := a.extractKey(r); key != "" {
		if subtle.ConstantTimeCompare([]byte(key), []byte(a.apiKey)) == 1 {
			return true
		}
	}

	w.Header().Set("Proxy-Authenticate", `Basic realm="proxy"`)
	http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
	return false
}

func (a *APIKeyAuth) extractKey(r *http.Request) string {
	if auth := r.Header.Get("Authorization"); auth != "" {
		return stripScheme(auth)
	}

	if key := r.Header.Get(a.headerName); key != "" {
		return stripScheme(key)
	}

	// The proxy advertises "Proxy-Authenticate: Basic", so honor
	// Proxy-Authorization credentials as well. Previously non-Bearer
	// values were read but silently dropped, making this path unusable.
	if proxyAuth := r.Header.Get(a.proxyHeader); proxyAuth != "" {
		return stripScheme(proxyAuth)
	}

	if key := r.URL.Query().Get(a.queryParam); key != "" {
		return key
	}

	return ""
}

// stripScheme removes a leading "Bearer " or "Basic " scheme marker,
// leaving the raw credential for constant-time comparison.
func stripScheme(v string) string {
	for _, scheme := range []string{"Bearer ", "Basic "} {
		if len(v) > len(scheme) && strings.EqualFold(v[:len(scheme)], scheme) {
			return v[len(scheme):]
		}
	}
	return v
}
