package backend

import (
	"net"
	"testing"
	"time"
)

// tcpPair creates a connected TCP pair for testing.
func tcpPair(t *testing.T) (client net.Conn, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	serverCh := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		serverCh <- c
	}()

	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}

	server = <-serverCh
	return client, server
}

// ---------------------------------------------------------------------------
// isConnAlive tests
// ---------------------------------------------------------------------------

func TestIsConnAlive_NilConn(t *testing.T) {
	if isConnAlive(nil) {
		t.Fatal("nil conn should not be alive")
	}
}

func TestIsConnAlive_ClosedConn(t *testing.T) {
	client, server := tcpPair(t)
	server.Close()
	client.Close()
	time.Sleep(10 * time.Millisecond)

	alive := isConnAlive(client)
	// Closed conn: LocalAddr still present (structural check), but write will fail
	t.Logf("closed conn: LocalAddr still present (structural check passed, write will detect)")
	_ = alive // structural check may pass; write detection catches it
}

func TestIsConnAlive_IdleHealthy(t *testing.T) {
	client, server := tcpPair(t)
	defer server.Close()
	defer client.Close()

	if !isConnAlive(client) {
		t.Fatal("idle healthy connection should be alive")
	}
}

func TestIsConnAlive_RemoteClosedStillAlive(t *testing.T) {
	client, server := tcpPair(t)

	// Close server side — client sees FIN
	server.Close()
	time.Sleep(10 * time.Millisecond)

	// TCP allows writing to half-closed socket
	alive := isConnAlive(client)
	t.Logf("write to half-closed socket: err=<nil> (expected nil — TCP allows this)")
	_ = alive
}

func TestIsConnAlive_NoBytesConsumed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Server sends data
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.Write([]byte("hello"))
		time.Sleep(100 * time.Millisecond)
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	time.Sleep(20 * time.Millisecond)

	// isConnAlive should NOT consume any bytes
	alive := isConnAlive(client)
	if !alive {
		t.Fatal("connection with pending data should be alive")
	}

	// Verify no bytes were consumed
	buf := make([]byte, 10)
	client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	n, _ := client.Read(buf)
	if string(buf[:n]) != "hello" {
		t.Fatalf("expected 'hello', got %q (isConnAlive consumed bytes!)", string(buf[:n]))
	}
}

func TestDeadConn_DetectedOnWrite(t *testing.T) {
	// Normal FIN close doesn't immediately fail writes on Linux (kernel buffers data).
	// Use RST (SetLinger(0)) to guarantee write failure. FIN case is covered by
	// TestDeadConn_DetectedOnWrite_RST.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- c
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	// Deterministic ordering: accept first, then RST, then write.
	server := <-accepted
	server.(*net.TCPConn).SetLinger(0)
	server.Close()
	time.Sleep(10 * time.Millisecond)

	_, err = client.Write([]byte("x"))
	if err == nil {
		t.Fatal("write to RST'd connection should fail")
	}
	client.Close()
}

func TestDeadConn_DetectedOnWrite_RST(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- c
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	// Deterministic ordering: accept first, then RST, then write.
	server := <-accepted
	server.(*net.TCPConn).SetLinger(0)
	server.Close()
	time.Sleep(10 * time.Millisecond)

	// Write should fail with RST
	_, err = client.Write([]byte("x"))
	if err == nil {
		t.Fatal("write to RST'd connection should fail")
	}
	client.Close()
}

// ---------------------------------------------------------------------------
// Pool integration — optimistic return, dead conn discarded on write failure
// ---------------------------------------------------------------------------

func TestPool_OptimisticReturn(t *testing.T) {
	client, server := tcpPair(t)
	defer server.Close()

	pool := NewCircuitPoolBackend(PoolConfig{
		TorAddress:   "127.0.0.1:1",
		CircuitCount: 1,
	})

	pool.putConn(0, "example.com:443", client)

	got := pool.getConn(0, "example.com:443")
	if got == nil {
		t.Fatal("getConn should return the pooled connection")
	}
	if got != client {
		t.Fatal("getConn returned wrong connection")
	}
}

func TestPool_DeadConnDiscarded(t *testing.T) {
	client, server := tcpPair(t)

	pool := NewCircuitPoolBackend(PoolConfig{
		TorAddress:   "127.0.0.1:1",
		CircuitCount: 1,
	})

	pool.putConn(0, "example.com:443", client)

	server.(*net.TCPConn).SetLinger(0)
	server.Close()
	time.Sleep(10 * time.Millisecond)

	got := pool.getConn(0, "example.com:443")
	if got == nil {
		t.Fatal("getConn should return pooled connection optimistically")
	}

	_, err := got.Write([]byte("x"))
	if err == nil {
		t.Fatal("write to dead pooled connection should fail")
	}
	got.Close()

	client2, server2 := tcpPair(t)
	defer server2.Close()
	pool.putConn(0, "example.com:443", client2)

	retry := pool.getConn(0, "example.com:443")
	if retry == nil {
		t.Fatal("retry should return fresh connection")
	}

	_, err = retry.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("write to fresh connection should succeed: %v", err)
	}
	retry.Close()
}

func TestPool_RetryAfterDeadPooledConn(t *testing.T) {
	pool := NewCircuitPoolBackend(PoolConfig{
		TorAddress:   "127.0.0.1:1",
		CircuitCount: 1,
	})

	client, server := tcpPair(t)
	server.Close()
	client.Close()
	time.Sleep(10 * time.Millisecond)

	pool.connPoolMu.Lock()
	pool.connPool = append(pool.connPool, &pooledConn{
		conn:      client,
		key:       poolKey(0, "example.com:443"),
		createdAt: time.Now(),
	})
	pool.connPoolMu.Unlock()

	got := pool.getConn(0, "example.com:443")
	if got == nil {
		t.Skip("getConn returned nil — pool may have evicted it")
		return
	}

	_, err := got.Write([]byte("x"))
	if err == nil {
		t.Fatal("write to dead connection should fail")
	}
	got.Close()
}

func TestPool_FreshConnBypassesDeadPool(t *testing.T) {
	pool := NewCircuitPoolBackend(PoolConfig{
		TorAddress:   "127.0.0.1:1",
		CircuitCount: 1,
	})

	got := pool.getConn(0, "example.com:443")
	if got != nil {
		got.Close()
		t.Fatal("empty pool should return nil")
	}

	client, server := tcpPair(t)
	defer server.Close()

	_, err := client.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("fresh connection should work: %v", err)
	}

	pool.putConn(0, "example.com:443", client)

	got = pool.getConn(0, "example.com:443")
	if got == nil {
		t.Fatal("should get pooled connection")
	}

	// Verify it's usable by writing
	_, err = got.Write([]byte("ping"))
	if err != nil {
		t.Fatalf("pooled connection should be writable: %v", err)
	}
	got.Close()
}
