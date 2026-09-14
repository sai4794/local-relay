package backend

import (
	"net"
	"testing"
)

// A pooled tunnel checked out across a resetAll bump must carry the
// pre-rotation generation so its wrapper discards instead of re-pooling.
// Pre-fix DialContext loaded poolGen AFTER getConn removed the entry, so a
// resetAll interleaving tagged the stale tunnel with the new generation.
func TestPool_CheckoutCarriesEntryGeneration(t *testing.T) {
	pool := NewCircuitPoolBackend(PoolConfig{
		TorAddress:   "127.0.0.1:1",
		CircuitCount: 1,
	})
	c1, c2 := net.Pipe()
	defer c2.Close()
	pool.putConn(0, "example.com:443", c1)

	conn, gen := pool.getConn(0, "example.com:443")
	if conn == nil {
		t.Fatal("expected pooled conn")
	}
	defer conn.Close()
	if gen != 1 {
		t.Fatalf("fresh-pool entry gen = %d, want 1 (poolGen starts at 1; Gen 0 is the exempt unknown)", gen)
	}

	// Re-pool, rotate, then check out: entry stamped pre-bump must come
	// back stale.
	c3, c4 := net.Pipe()
	defer c4.Close()
	pool.putConn(0, "example.com:443", c3)
	pool.resetAll()
	conn2, gen2 := pool.getConn(0, "example.com:443")
	if conn2 != nil {
		conn2.Close()
		t.Fatal("resetAll must evict pooled conns; got one back")
	}
	_ = gen2

	// Direct unit: entry put at gen G checked out after bump to G+1 keeps G.
	pool.poolGen.Store(10)
	c5, c6 := net.Pipe()
	defer c6.Close()
	pool.putConn(0, "example.com:443", c5)
	pool.poolGen.Store(11) // simulate interleaved resetAll bump
	conn3, gen3 := pool.getConn(0, "example.com:443")
	if conn3 == nil {
		t.Fatal("expected pooled conn")
	}
	defer conn3.Close()
	if gen3 != 10 {
		t.Fatalf("entry gen = %d, want 10 (put-time, not checkout-time)", gen3)
	}
}
