package backend

import (
	"context"
	"testing"
	"time"
)

// One refused upstream must not fail-close single-tor: healthy flips only
// after consecutive dial failures (daemon likely down), and any success
// resets the streak.
func TestTorBackend_ConsecutiveDialGate(t *testing.T) {
	b := NewTorBackend(TorConfig{Address: "127.0.0.1:1", Timeout: time.Second})
	ctx := context.Background()
	if _, err := b.DialContext(ctx, "tcp", "example.com:443"); err == nil {
		t.Fatal("expected dial failure against closed port, got nil")
	}
	if !b.IsHealthy() {
		t.Fatal("unhealthy after 1 dial failure; want healthy until 3 consecutive")
	}
	if _, err := b.DialContext(ctx, "tcp", "example.com:443"); err == nil {
		t.Fatal("expected dial failure, got nil")
	}
	if !b.IsHealthy() {
		t.Fatal("unhealthy after 2 dial failures; want healthy until 3 consecutive")
	}
	if _, err := b.DialContext(ctx, "tcp", "example.com:443"); err == nil {
		t.Fatal("expected dial failure, got nil")
	}
	if b.IsHealthy() {
		t.Fatal("healthy after 3 consecutive dial failures; want unhealthy")
	}
}
