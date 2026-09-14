package backend

import (
	"context"
	"math"
	"testing"
	"time"
)

// Regression: evictConns must not alias the live pool's backing array.
// Old code did `conns := p.connPool; p.connPool = p.connPool[:0]`, so a
// putConn appending during/after the unlock window overwrote the evicted
// slice (use-after-evict: the evictor could close a just-pooled tunnel).
func TestPool_EvictConnsNoBackingAlias(t *testing.T) {
	pool := NewCircuitPoolBackend(PoolConfig{
		TorAddress:   "127.0.0.1:1",
		CircuitCount: 1,
		MaxIdle:      4,
	})

	c1, s1 := tcpPair(t)
	defer s1.Close()
	c2, s2 := tcpPair(t)
	defer s2.Close()
	pool.putConn(0, "a:1", c1)
	pool.putConn(0, "b:1", c2)

	// Pin the old backing array: address of slot 0 plus a live reference
	// so the allocator cannot recycle it for the post-evict put.
	pool.connPoolMu.Lock()
	oldBacking := pool.connPool
	oldSlot0 := &pool.connPool[0]
	pool.connPoolMu.Unlock()

	pool.evictConns()

	c3, s3 := tcpPair(t)
	defer s3.Close()
	pool.putConn(0, "c:1", c3)

	pool.connPoolMu.Lock()
	newSlot0 := &pool.connPool[0]
	pool.connPoolMu.Unlock()

	// Old code reset with p.connPool[:0] (same backing array), so the put
	// wrote into slot 0 of the array the evictor was closing from.
	if newSlot0 == oldSlot0 {
		t.Fatal("evictConns aliased backing array: post-evict put reused the evicted array; want fresh allocation")
	}
	_ = oldBacking // keep the old array alive so the address comparison is valid

	// The newly pooled tunnel must be intact and usable.
	got := pool.getConn(0, "c:1")
	if got == nil {
		t.Fatal("newly pooled conn missing after evict")
	}
	defer got.Close()
	if _, err := got.Write([]byte("x")); err != nil {
		t.Fatalf("new conn unusable after evict+put: %v", err)
	}
}

// Regression: DialContext round-robin must survive int64 wrap of p.current.
// Old code `p.current.Add(1) % total` goes negative on wrap, panicking on
// p.slots[negative].
func TestPool_DialContextRoundRobinOverflow(t *testing.T) {
	pool := NewCircuitPoolBackend(PoolConfig{
		TorAddress:   "127.0.0.1:1",
		ControlAddr:  "127.0.0.1:1",
		CircuitCount: 3,
		Timeout:      50 * time.Millisecond,
	})
	pool.current.Store(math.MaxInt64) // next Add(1) wraps to MinInt64

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("DialContext panicked on int64 wrap: %v", r)
		}
	}()
	_, err := pool.DialContext(context.Background(), "tcp", "example.com:443")
	if err == nil {
		t.Fatal("expected circuit-pool-exhausted error after wrap, got nil")
	}
}
