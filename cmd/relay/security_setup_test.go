package main

import (
	"context"
	"testing"

	"github.com/local-relay/proxy/internal/config"
)

// M-03: an empty blocked_networks list must not disable the SSRF blocker
// entirely. Scheme gating and defense-in-depth stay active; only the CIDR
// list is empty (the firewall keeps its own defaults).
func TestSetupSecurity_EmptyBlockedNetworksKeepsSSRFBlocker(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := &config.Config{}
	cfg.Security.BlockedNetworks = []string{}
	fw, blocker := setupSecurity(ctx, cfg, discardLogger())
	if fw == nil {
		t.Fatal("firewall is nil")
	}
	if blocker == nil {
		t.Fatal("SSRF blocker is nil with empty blocked_networks")
	}
	for _, scheme := range []string{"file", "gopher", "ftp"} {
		if !blocker.IsSchemeBlocked(scheme) {
			t.Errorf("IsSchemeBlocked(%q) = false, want true", scheme)
		}
	}
	if blocker.IsSchemeBlocked("https") {
		t.Error("IsSchemeBlocked(https) = true, want false")
	}
}
