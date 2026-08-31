package transport

import (
	"context"
	"net"
	"testing"
	"time"
)

// Guards against regression of audit finding: SOCKS5 handshake had no read
// deadline and could pin goroutines forever on a wedged Tor.
func TestConnectHandshakeDeadline(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, _ := ln.Accept()
		time.Sleep(10 * time.Second) // never speaks
		c.Close()
	}()

	c := NewSOCKS5Client(500 * time.Millisecond)
	start := time.Now()
	_, err := c.Connect(context.Background(), ln.Addr().String(), "example.com:443", "")
	el := time.Since(start)
	if err == nil {
		t.Fatal("expected handshake timeout")
	}
	if el > 2*time.Second {
		t.Fatalf("handshake blocked %v — deadline missing", el)
	}
}
