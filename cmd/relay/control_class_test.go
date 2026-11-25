package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/local-relay/proxy/internal/backend"
)

// M-14: startup classification must use typed errors, not substrings of the
// message text. Test errors deliberately use different outer wording so a
// regression to strings.Contains fails.
func TestClassifyControlError_UsesSentinels(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want controlClass
	}{
		{"not-configured", fmt.Errorf("rewritten: %w", backend.ErrControlNotConfigured), controlSkip},
		{"auth-rejected", fmt.Errorf("rewritten: %w", backend.ErrControlAuthRejected), controlFail},
		{"unreachable", fmt.Errorf("rewritten: %w", backend.ErrControlUnreachable), controlDegrade},
		{"auth-failed", fmt.Errorf("rewritten: %w", backend.ErrControlAuthFailed), controlDegrade},
		{"timeout", &net.OpError{Op: "read", Err: os.ErrDeadlineExceeded}, controlDegrade},
		{"unclassified", errors.New("brand new error text"), controlFail},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyControlError(tc.err); got != tc.want {
				t.Errorf("classifyControlError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
