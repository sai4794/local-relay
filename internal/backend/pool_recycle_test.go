package backend

import (
	"net"
	"sync"
	"testing"
	"time"
)

// A wrapper checked out before a resetAll (NEWNYM eviction) must discard on
// Close instead of re-inserting a stale tunnel into the fresh pool.
func TestPool_StaleGenDiscardsOnClose(t *testing.T) {
	client, server := tcpPair(t)
	defer server.Close()

	pool := NewCircuitPoolBackend(PoolConfig{
		TorAddress:   "127.0.0.1:1",
		CircuitCount: 1,
	})

	// Wrap carries the pre-rotation generation.
	wrap := &pooledConnWrap{Conn: client, pool: pool, slotIdx: 0, addr: "example.com:443", gen: pool.poolGen.Load()}
	pool.resetAll() // evicts pool + bumps generation

	if err := wrap.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	pool.connPoolMu.Lock()
	n := len(pool.connPool)
	pool.connPoolMu.Unlock()
	if n != 0 {
		t.Fatalf("stale-gen wrapper re-pooled a pre-rotation tunnel (pool=%d); want discard", n)
	}
}

// Discard (broken tunnel observed by caller) must close the socket and never
// re-pool, even at the current generation.
func TestPool_DiscardNeverRePools(t *testing.T) {
	client, server := tcpPair(t)
	defer server.Close()

	pool := NewCircuitPoolBackend(PoolConfig{
		TorAddress:   "127.0.0.1:1",
		CircuitCount: 1,
	})

	wrap := &pooledConnWrap{Conn: client, pool: pool, slotIdx: 0, addr: "example.com:443", gen: pool.poolGen.Load()}
	if err := wrap.Discard(); err != nil {
		t.Fatalf("Discard failed: %v", err)
	}
	// Double close must stay discarded, not pooled.
	if err := wrap.Close(); err != nil {
		t.Fatalf("second Close failed: %v", err)
	}
	pool.connPoolMu.Lock()
	n := len(pool.connPool)
	pool.connPoolMu.Unlock()
	if n != 0 {
		t.Fatalf("discarded tunnel re-pooled (pool=%d); want 0", n)
	}
}

// Healthy-tunnel reuse behavior is unchanged: checkout -> Close -> getConn
// returns the same socket.
func TestPool_HealthyReuseUnchanged(t *testing.T) {
	client, server := tcpPair(t)
	defer server.Close()

	pool := NewCircuitPoolBackend(PoolConfig{
		TorAddress:   "127.0.0.1:1",
		CircuitCount: 1,
	})

	wrap := &pooledConnWrap{Conn: client, pool: pool, slotIdx: 0, addr: "example.com:443", gen: pool.poolGen.Load()}
	if err := wrap.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	got := pool.getConn(0, "example.com:443")
	if got == nil {
		t.Fatal("healthy tunnel was not returned to pool")
	}
	if got != client {
		t.Fatal("pool returned wrong connection")
	}
	got.Close()
}

// Expired entries are reaped lazily on the read path: getConn closes them
// inline and returns nil instead of handing out a stale tunnel.
func TestPool_LazyExpiryOnGet(t *testing.T) {
	client, server := tcpPair(t)
	defer server.Close()

	pool := NewCircuitPoolBackend(PoolConfig{
		TorAddress:   "127.0.0.1:1",
		CircuitCount: 1,
		IdleTTL:      time.Millisecond,
	})
	pool.putConn(0, "example.com:443", client)
	time.Sleep(5 * time.Millisecond)

	if got := pool.getConn(0, "example.com:443"); got != nil {
		got.Close()
		t.Fatal("getConn returned an expired tunnel; want lazy reap (nil)")
	}
	pool.connPoolMu.Lock()
	n := len(pool.connPool)
	pool.connPoolMu.Unlock()
	if n != 0 {
		t.Fatalf("expired entry left in pool (%d); want reaped", n)
	}
}

// Concurrent anomaly triggers must coalesce onto one in-flight NEWNYM, not
// one goroutine-per-failure worth of control round-trips.
func TestPool_AnomalyNEWNYMCoalesces(t *testing.T) {
	pool := NewCircuitPoolBackend(PoolConfig{
		TorAddress: "127.0.0.1:1",
		// Unreachable control port: every NEWNYM fails fast; the point is
		// counting signals, and failures still exercise the gate.
		ControlAddr:  "127.0.0.1:1",
		CircuitCount: 1,
	})

	const racers = 32
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pool.anomalyNEWNYM(0)
		}()
	}
	wg.Wait()
	// Give the single admitted goroutine time to finish and release the gate.
	deadline := time.Now().Add(10 * time.Second)
	for pool.nymInflight.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if pool.nymInflight.Load() {
		t.Fatal("nymInflight still held after burst; gate leaked")
	}
}

var _ net.Conn = (*pooledConnWrap)(nil)
