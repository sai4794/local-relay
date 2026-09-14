package main

import (
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/local-relay/proxy/internal/backend"
)

// startFakeSocks5 serves a minimal SOCKS5 no-auth greeting handshake on a
// test-only loopback port: it answers {0x05,0x00} to any greeting then
// closes. No real Tor is spawned.
func startFakeSocks5(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake socks5: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 3)
				if _, err := io.ReadFull(conn, buf[:2]); err != nil {
					return
				}
				n := int(buf[1])
				if _, err := io.ReadFull(conn, buf[:n]); err != nil {
					return
				}
				_, _ = conn.Write([]byte{0x05, 0x00})
			}(c)
		}
	}()
	return ln.Addr().String()
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// A healthy single-tor backend must not be re-probed (no dials, no state
// change); only an unhealthy one gets the CheckHealth re-probe.
func TestProbeSingleTorRecoverySkipsHealthy(t *testing.T) {
	addr := startFakeSocks5(t)
	tb := backend.NewTorBackend(backend.TorConfig{Address: addr})
	if !tb.IsHealthy() {
		t.Fatal("fresh TorBackend should start healthy")
	}
	probeSingleTorRecovery(testLogger(), &backendStack{torBackend: tb})
	if !tb.IsHealthy() {
		t.Fatal("healthy backend must stay healthy")
	}
}

// An unhealthy single-tor backend recovers when its Tor endpoint answers
// the greeting handshake again (CheckHealth flips cached healthy=true).
func TestProbeSingleTorRecoveryRevives(t *testing.T) {
	addr := startFakeSocks5(t)
	tb := backend.NewTorBackend(backend.TorConfig{Address: addr})
	_ = tb.CheckHealth() // healthy baseline against the fake
	tb.Close()           // force unhealthy without touching the endpoint
	if tb.IsHealthy() {
		t.Fatal("Close should mark unhealthy")
	}
	probeSingleTorRecovery(testLogger(), &backendStack{torBackend: tb})
	if !tb.IsHealthy() {
		t.Fatal("backend should recover once the endpoint answers again")
	}
}

// An unhealthy pool stays degraded while Tor is unreachable (fail-closed,
// no routing change), and probePoolRecovery is a no-op for healthy pools.
func TestProbePoolRecoveryUnreachableStaysDegraded(t *testing.T) {
	p := backend.NewCircuitPoolBackend(backend.PoolConfig{
		TorAddress:   "127.0.0.1:1", // closed test port: nothing listening
		CircuitCount: 2,
	})
	p.Close() // all slots unhealthy, like startup Close() on unreachable Tor
	if p.IsHealthy() {
		t.Fatal("closed pool should be unhealthy")
	}
	probePoolRecovery(testLogger(), &backendStack{pool: p})
	if p.IsHealthy() {
		t.Fatal("unreachable Tor must keep the pool degraded (fail-closed)")
	}

	healthy := backend.NewCircuitPoolBackend(backend.PoolConfig{
		TorAddress:   "127.0.0.1:1",
		CircuitCount: 2,
	})
	if !healthy.IsHealthy() {
		t.Fatal("fresh pool should be healthy")
	}
	probePoolRecovery(testLogger(), &backendStack{pool: healthy})
	if !healthy.IsHealthy() {
		t.Fatal("healthy pool must be untouched by the probe")
	}
}

// Router health reflects backend health: degraded router (all proxied
// backends unhealthy) is what gates the new degraded-ready Warn line.
func TestRouterIsHealthyGatesDegradedReady(t *testing.T) {
	direct := backend.NewDirectBackend(time.Second)
	dead := backend.NewTorBackend(backend.TorConfig{Address: "127.0.0.1:1"})
	_ = dead.CheckHealth()
	r := backend.NewRouter(direct, dead)
	if r.IsHealthy() {
		t.Fatal("router with only an unhealthy proxied backend must be unhealthy")
	}
}
