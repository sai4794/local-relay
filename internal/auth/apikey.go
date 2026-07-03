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
	if key := r.Header.Get(a.headerName); key != "" {
		return strings.TrimPrefix(key, "Bearer ")
	}

	if proxyAuth := r.Header.Get(a.proxyHeader); proxyAuth != "" {
		if strings.HasPrefix(proxyAuth, "Bearer ") {
			return strings.TrimPrefix(proxyAuth, "Bearer ")
		}
	}

	if key := r.URL.Query().Get(a.queryParam); key != "" {
		return key
	}

	return ""
}
