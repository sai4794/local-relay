package proxy

import (
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestClassifyRealHeaderTimeout(t *testing.T) {
	// hold-silent server
	ln := newStallServer(t)
	client := &http.Client{Transport: &http.Transport{ResponseHeaderTimeout: 300 * time.Millisecond}}
	_, err := client.Get("http://" + ln.Addr().String() + "/")
	if err == nil {
		t.Fatal("expected error")
	}
	t.Logf("error type: %T, err: %v", err, err)
	got := isRetryableConnectError(err)
	t.Logf("isRetryableConnectError=%v", got)
	for _, m := range []string{"timeout awaiting response headers", "TLS handshake timeout", "connection reset", "broken pipe", "use of closed connection", "EOF"} {
		t.Logf("marker %q contains=%v", m, strings.Contains(err.Error(), m))
	}
	if !got {
		t.Fatalf("header timeout NOT classified retryable")
	}
}

func newStallServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { time.Sleep(5 * time.Second); c.Close() }(c) // accept, never write
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln
}
