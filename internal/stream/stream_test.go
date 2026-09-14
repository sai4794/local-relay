package stream

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	ch := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		ch <- conn
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	server := <-ch
	return client, server
}

func TestHasSSEContentType(t *testing.T) {
	h := http.Header{}
	if HasSSEContentType(h) {
		t.Error("expected false for empty header")
	}

	h.Set("Content-Type", "application/json")
	if HasSSEContentType(h) {
		t.Error("expected false for application/json")
	}

	h.Set("Content-Type", "text/event-stream")
	if !HasSSEContentType(h) {
		t.Error("expected true for text/event-stream")
	}

	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	if !HasSSEContentType(h) {
		t.Error("expected true for text/event-stream with charset")
	}

	// Live-path parity: the forward path lowercases before matching, so an
	// oddly-cased upstream Content-Type must also match here (RFC 2045).
	h.Set("Content-Type", "Text/Event-Stream; charset=utf-8")
	if !HasSSEContentType(h) {
		t.Error("expected true for mixed-case text/event-stream")
	}
}

func TestCopySSE(t *testing.T) {
	rec := httptest.NewRecorder()
	content := "data: hello world\n\n"
	body := io.NopCloser(strings.NewReader(content))

	CopySSE(rec, body, http.StatusOK)

	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("status code = %d; want %d", res.StatusCode, http.StatusOK)
	}
	if ct := res.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type = %q; want text/event-stream", ct)
	}
	if conn := res.Header.Get("Connection"); conn != "" {
		t.Errorf("Connection = %q; want unset (hop header must not be emitted)", conn)
	}
	if rec.Body.String() != content {
		t.Errorf("body = %q; want %q", rec.Body.String(), content)
	}
}

func TestCopyRaw(t *testing.T) {
	var buf bytes.Buffer
	content := "raw payload bytes"
	body := io.NopCloser(strings.NewReader(content))

	CopyRaw(&buf, body)

	if buf.String() != content {
		t.Errorf("body = %q; want %q", buf.String(), content)
	}
}

func TestRelay_Bidirectional(t *testing.T) {
	client1, client2 := tcpPair(t)
	defer client2.Close()
	server1, server2 := tcpPair(t)
	defer server2.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	relayDone := make(chan struct{})
	var srcToDst, dstToSrc int64
	go func() {
		// Relay between client1 and server1
		srcToDst, dstToSrc = Relay(ctx, client1, server1)
		close(relayDone)
	}()

	clientMsg := []byte("hello from client")
	serverMsg := []byte("hello from server")

	var clientReceived, serverReceived []byte
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		client2.Write(clientMsg)
		if cw, ok := client2.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		var err error
		clientReceived, err = io.ReadAll(client2)
		if err != nil && err != io.EOF {
			t.Errorf("client read error: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		server2.Write(serverMsg)
		if cw, ok := server2.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		var err error
		serverReceived, err = io.ReadAll(server2)
		if err != nil && err != io.EOF {
			t.Errorf("server read error: %v", err)
		}
	}()

	wg.Wait()
	<-relayDone

	if string(serverReceived) != string(clientMsg) {
		t.Errorf("serverReceived = %q; want %q", string(serverReceived), string(clientMsg))
	}
	if string(clientReceived) != string(serverMsg) {
		t.Errorf("clientReceived = %q; want %q", string(clientReceived), string(serverMsg))
	}
	if srcToDst != int64(len(serverMsg)) {
		t.Errorf("srcToDst = %d; want %d", srcToDst, len(serverMsg))
	}
	if dstToSrc != int64(len(clientMsg)) {
		t.Errorf("dstToSrc = %d; want %d", dstToSrc, len(clientMsg))
	}
}

func TestRelay_ContextCancelUnblocks(t *testing.T) {
	c1, c2 := tcpPair(t)
	defer c2.Close()
	s1, s2 := tcpPair(t)
	defer s2.Close()

	ctx, cancel := context.WithCancel(context.Background())

	relayDone := make(chan struct{})
	go func() {
		Relay(ctx, c1, s1)
		close(relayDone)
	}()

	// Cancel context after short delay without writing data
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-relayDone:
		// Succeeded in unblocking
	case <-time.After(1 * time.Second):
		t.Fatal("Relay failed to unblock on context cancellation")
	}
}
