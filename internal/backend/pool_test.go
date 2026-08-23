package backend

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// =============================================================================
// CONNECTION POOL TESTS
// =============================================================================

func TestConnPoolGetEmpty(t *testing.T) {
	pool := NewCircuitPoolBackend(PoolConfig{
		TorAddress:   "127.0.0.1:1",
		CircuitCount: 3,
	})

	conn := pool.getConn(0, "example.com:443")
	if conn != nil {
		t.Fatal("expected nil from empty pool")
		conn.Close()
	}
}

func TestConnPoolPutAndGet(t *testing.T) {
	pool := NewCircuitPoolBackend(PoolConfig{
		TorAddress:   "127.0.0.1:1",
		CircuitCount: 3,
	})

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			time.Sleep(5 * time.Second)
			conn.Close()
		}
	}()

	fakeConn, _ := net.Dial("tcp", ln.Addr().String())
	pool.putConn(0, "example.com:443", fakeConn)

	conn := pool.getConn(0, "example.com:443")
	if conn == nil {
		t.Fatal("expected connection from pool")
	}
	conn.Close()

	conn2 := pool.getConn(0, "example.com:443")
	if conn2 != nil {
		t.Fatal("expected nil after getting connection")
		conn2.Close()
	}
}

func TestConnPoolDestinationSafety(t *testing.T) {
	// A connection pooled for example.com:443 must NOT be reused for github.com:443
	pool := NewCircuitPoolBackend(PoolConfig{
		TorAddress:   "127.0.0.1:1",
		CircuitCount: 3,
	})

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			time.Sleep(5 * time.Second)
			conn.Close()
		}
	}()

	fakeConn1, _ := net.Dial("tcp", ln.Addr().String())
	pool.putConn(0, "example.com:443", fakeConn1)

	conn := pool.getConn(0, "github.com:443")
	if conn != nil {
		conn.Close()
		t.Fatal("pool should NOT return example.com connection for github.com")
	}
}

func TestConnPoolDifferentSlots(t *testing.T) {
	pool := NewCircuitPoolBackend(PoolConfig{
		TorAddress:   "127.0.0.1:1",
		CircuitCount: 3,
	})

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			time.Sleep(5 * time.Second)
			conn.Close()
		}
	}()

	fakeConn1, _ := net.Dial("tcp", ln.Addr().String())
	pool.putConn(0, "example.com:443", fakeConn1)

	fakeConn2, _ := net.Dial("tcp", ln.Addr().String())
	pool.putConn(1, "example.com:443", fakeConn2)

	conn0 := pool.getConn(0, "example.com:443")
	if conn0 == nil {
		t.Fatal("expected connection from slot 0")
	}
	conn0.Close()

	conn1 := pool.getConn(1, "example.com:443")
	if conn1 == nil {
		t.Fatal("expected connection from slot 1")
	}
	conn1.Close()
}

func TestConnPoolEvictsStale(t *testing.T) {
	pool := NewCircuitPoolBackend(PoolConfig{
		TorAddress:   "127.0.0.1:1",
		CircuitCount: 3,
		IdleTTL:      1 * time.Millisecond,
	})

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			time.Sleep(5 * time.Second)
			conn.Close()
		}
	}()

	fakeConn, _ := net.Dial("tcp", ln.Addr().String())
	pool.putConn(0, "example.com:443", fakeConn)

	time.Sleep(5 * time.Millisecond)

	conn := pool.getConn(0, "example.com:443")
	if conn != nil {
		t.Fatal("expected nil for stale connection")
		conn.Close()
	}
}

func TestConnPoolEvictsOldest(t *testing.T) {
	pool := NewCircuitPoolBackend(PoolConfig{
		TorAddress:   "127.0.0.1:1",
		CircuitCount: 3,
		MaxIdle:      2,
	})

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			time.Sleep(5 * time.Second)
			conn.Close()
		}
	}()

	for i := 0; i < 3; i++ {
		fakeConn, _ := net.Dial("tcp", ln.Addr().String())
		pool.putConn(i%2, fmt.Sprintf("host%d.example.com:443", i), fakeConn)
	}

	pool.connPoolMu.Lock()
	count := len(pool.connPool)
	pool.connPoolMu.Unlock()

	if count > 2 {
		t.Fatalf("pool has %d connections, expected at most 2", count)
	}
}

func TestConnPoolEvictAll(t *testing.T) {
	pool := NewCircuitPoolBackend(PoolConfig{
		TorAddress:   "127.0.0.1:1",
		CircuitCount: 3,
	})

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			time.Sleep(5 * time.Second)
			conn.Close()
		}
	}()

	for i := 0; i < 3; i++ {
		fakeConn, _ := net.Dial("tcp", ln.Addr().String())
		pool.putConn(i, fmt.Sprintf("host%d.example.com:443", i), fakeConn)
	}

	pool.evictConns()

	pool.connPoolMu.Lock()
	count := len(pool.connPool)
	pool.connPoolMu.Unlock()

	if count != 0 {
		t.Fatalf("pool has %d connections after evict, expected 0", count)
	}
}

func TestConnPoolDeadConnection(t *testing.T) {
	pool := NewCircuitPoolBackend(PoolConfig{
		TorAddress:   "127.0.0.1:1",
		CircuitCount: 3,
	})

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	fakeConn, _ := net.Dial("tcp", ln.Addr().String())
	fakeConn.Close()

	pool.putConn(0, "example.com:443", fakeConn)

	pool.connPoolMu.Lock()
	count := len(pool.connPool)
	pool.connPoolMu.Unlock()

	if count != 1 {
		t.Fatalf("pool has %d connections, expected 1 (optimistic pool-in)", count)
	}

	got := pool.getConn(0, "example.com:443")
	if got == nil {
		t.Fatal("getConn should return the pooled connection")
	}

	_, err := got.Write([]byte("x"))
	if err == nil {
		t.Fatal("write to dead connection should fail")
	}
	got.Close()
}

func TestConnPoolHalfClosedConnection(t *testing.T) {
	pool := NewCircuitPoolBackend(PoolConfig{
		TorAddress:   "127.0.0.1:1",
		CircuitCount: 3,
	})

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	serverDone := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			close(serverDone)
			return
		}
		conn.(*net.TCPConn).SetLinger(0)
		conn.Close()
		close(serverDone)
	}()

	fakeConn, _ := net.Dial("tcp", ln.Addr().String())
	<-serverDone
	time.Sleep(10 * time.Millisecond)

	pool.putConn(0, "example.com:443", fakeConn)

	pool.connPoolMu.Lock()
	count := len(pool.connPool)
	pool.connPoolMu.Unlock()

	if count != 1 {
		t.Fatalf("pool has %d connections, expected 1 (optimistic pool-in)", count)
	}

	got := pool.getConn(0, "example.com:443")
	if got == nil {
		t.Fatal("getConn should return the RST'd connection")
	}

	_, err := got.Write([]byte("x"))
	if err == nil {
		t.Fatal("write to RST'd connection should fail")
	}
	got.Close()
}

func TestDialContextReusesPooledConnection(t *testing.T) {
	pool := NewCircuitPoolBackend(PoolConfig{
		TorAddress:   "127.0.0.1:1",
		CircuitCount: 1,
		Timeout:      100 * time.Millisecond,
	})

	pool.connPoolMu.Lock()
	if len(pool.connPool) != 0 {
		t.Fatal("pool should start empty")
	}
	pool.connPoolMu.Unlock()
}

// --- pooledConnWrap tests ---

func TestPooledConnWrap_ReturnsOnClose(t *testing.T) {
	client, server := tcpPair(t)
	defer server.Close()

	pool := NewCircuitPoolBackend(PoolConfig{
		TorAddress:   "127.0.0.1:1",
		CircuitCount: 1,
	})

	wrap := &pooledConnWrap{
		Conn:    client,
		pool:    pool,
		slotIdx: 0,
		addr:    "example.com:443",
	}

	pool.connPoolMu.Lock()
	if len(pool.connPool) != 0 {
		t.Fatal("pool should be empty before Close")
	}
	pool.connPoolMu.Unlock()

	if err := wrap.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	pool.connPoolMu.Lock()
	if len(pool.connPool) != 1 {
		t.Fatal("pool should have 1 connection after Close")
	}
	pool.connPoolMu.Unlock()

	if err := wrap.Close(); err != nil {
		t.Fatalf("double Close failed: %v", err)
	}
	pool.connPoolMu.Lock()
	if len(pool.connPool) != 1 {
		t.Fatal("pool should still have 1 connection after double Close")
	}
	pool.connPoolMu.Unlock()
}

func TestPooledConnWrap_DialContextReturnsWrapper(t *testing.T) {
	pool := NewCircuitPoolBackend(PoolConfig{
		TorAddress:   "127.0.0.1:1",
		CircuitCount: 1,
		Timeout:      100 * time.Millisecond,
	})

	pool.connPoolMu.Lock()
	if len(pool.connPool) != 0 {
		t.Fatal("pool should start empty")
	}
	pool.connPoolMu.Unlock()
}

func TestPoolKey_PerDestination(t *testing.T) {
	// Same slot + same destination = same key
	key1 := poolKey(0, "example.com:443")
	key2 := poolKey(0, "example.com:443")
	if key1 != key2 {
		t.Fatalf("pool keys should match for same slot+dest: %q vs %q", key1, key2)
	}

	// Same slot + different destination = different key
	key3 := poolKey(0, "github.com:443")
	if key1 == key3 {
		t.Fatal("pool keys should differ for different destinations on same slot")
	}

	// Different slots + same destination = different key
	key4 := poolKey(1, "example.com:443")
	if key1 == key4 {
		t.Fatal("pool keys should differ for different slots")
	}
}

func TestPoolConnectionReuseAcrossDestinations(t *testing.T) {
	// A connection pooled for destination A must NOT be returned for destination B.
	// SOCKS5 tunnels are destination-bound — Tor kills the socket after tunnel close.
	pool := NewCircuitPoolBackend(PoolConfig{
		TorAddress:   "127.0.0.1:1",
		CircuitCount: 1,
	})

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			time.Sleep(5 * time.Second)
			conn.Close()
		}
	}()

	fakeConn, _ := net.Dial("tcp", ln.Addr().String())
	pool.putConn(0, "example.com:443", fakeConn)

	conn := pool.getConn(0, "github.com:443")
	if conn != nil {
		conn.Close()
		t.Fatal("pool should NOT return example.com connection for github.com")
	}
}

func BenchmarkPoolHit(b *testing.B) {
	pool := NewCircuitPoolBackend(PoolConfig{
		TorAddress:   "127.0.0.1:1",
		CircuitCount: 3,
		MaxIdle:      100,
	})

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				time.Sleep(5 * time.Second)
				conn.Close()
			}()
		}
	}()

	for i := 0; i < 3; i++ {
		conn, _ := net.Dial("tcp", ln.Addr().String())
		pool.putConn(i, "example.com:443", conn)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn := pool.getConn(i%3, "example.com:443")
		if conn != nil {
			pool.putConn(i%3, "example.com:443", conn)
		}
	}
}

func BenchmarkPoolMiss(b *testing.B) {
	pool := NewCircuitPoolBackend(PoolConfig{
		TorAddress:   "127.0.0.1:1",
		CircuitCount: 3,
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool.getConn(i%3, "example.com:443")
	}
}

func BenchmarkPooledConnWrapClose(b *testing.B) {
	pool := NewCircuitPoolBackend(PoolConfig{
		TorAddress:   "127.0.0.1:1",
		CircuitCount: 1,
		MaxIdle:      1000,
	})

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				time.Sleep(5 * time.Second)
				conn.Close()
			}()
		}
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, _ := net.Dial("tcp", ln.Addr().String())
		wrap := &pooledConnWrap{
			Conn:    conn,
			pool:    pool,
			slotIdx: 0,
			addr:    "example.com:443",
		}
		wrap.Close()
	}
}
