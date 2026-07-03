package proxy

import (
	"net/url"
	"testing"
)

func TestSanitizeURL(t *testing.T) {
	tests := []struct {
		name     string
		rawURL   string
		want     string // empty means expect no change
		wantMask string // non-empty means expect this substring
	}{
		{"empty", "", "", ""},
		{"no query", "/path", "/path", ""},
		{"api_key lower", "/path?api_key=secret123", "", "api_key=%2A%2A%2A"},
		{"API_KEY upper", "/path?API_KEY=secret123", "", "API_KEY=%2A%2A%2A"},
		{"Api_Key mixed", "/path?Api_Key=secret123", "", "Api_Key=%2A%2A%2A"},
		{"token", "/path?token=abc123", "", "token=%2A%2A%2A"},
		{"TOKEN upper", "/path?TOKEN=abc123", "", "TOKEN=%2A%2A%2A"},
		{"not sensitive", "/path?name=john&age=30", "", "name=john"},
		{"mixed sensitive+ok", "/path?key=abc&name=john", "", "key=%2A%2A%2A&name=john"},
		{"password", "/path?password=hunter2", "", "password=%2A%2A%2A"},
		{"bearer token", "/path?bearer=eyJhbGci", "", "bearer=%2A%2A%2A"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, _ := url.Parse(tt.rawURL)
			got := sanitizeURL(u)
			if tt.want != "" && got != tt.want {
				t.Errorf("sanitizeURL(%q) = %q, want %q", tt.rawURL, got, tt.want)
			}
			if tt.wantMask != "" && !contains(got, tt.wantMask) {
				t.Errorf("sanitizeURL(%q) = %q, want containing %q", tt.rawURL, got, tt.wantMask)
			}
		})
	}
}

func TestSanitizeURLCaseInsensitive(t *testing.T) {
	// Same parameter name in different cases — all should be masked
	variants := []string{"api_key", "API_KEY", "Api_Key", "aPi_KeY"}
	for _, v := range variants {
		raw := "/path?" + v + "=secret"
		u, _ := url.Parse(raw)
		got := sanitizeURL(u)
		if contains(got, "=secret") {
			t.Errorf("sanitizeURL(%q) = %q, should not contain '=secret'", raw, got)
		}
		if !contains(got, "%2A%2A%2A") {
			t.Errorf("sanitizeURL(%q) = %q, should contain '***'", raw, got)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && containsStr(s, substr)
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
