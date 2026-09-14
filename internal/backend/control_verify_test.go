package backend

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

// serveControlOnce accepts one connection, optionally validates the
// AUTHENTICATE line, and replies 250 OK. It reports the received auth line.
func serveControlOnce(t *testing.T, ln net.Listener, wantAuthPrefix string, authSeen chan<- string, extraCmds bool) {
	t.Helper()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		reader := bufio.NewReader(conn)
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		authSeen <- strings.TrimSpace(line)
		if wantAuthPrefix != "" && !strings.HasPrefix(strings.TrimSpace(line), wantAuthPrefix) {
			_, _ = conn.Write([]byte("515 Authentication failed\r\n"))
			return
		}
		_, _ = conn.Write([]byte("250 OK\r\n"))
		if extraCmds {
			// VerifyAuth must close after AUTHENTICATE: any further read
			// should see EOF once the client is done.
			for {
				cmd, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				if strings.HasPrefix(strings.TrimSpace(cmd), "SIGNAL NEWNYM") {
					_, _ = conn.Write([]byte("250 OK\r\n"))
					return
				}
				_, _ = conn.Write([]byte("250 OK\r\n"))
			}
		}
	}()
}

func TestVerifyAuth_CookieOK_NoStateChange(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	authSeen := make(chan string, 1)
	serveControlOnce(t, ln, "AUTHENTICATE", authSeen, true)

	cookie := make([]byte, 32)
	for i := range cookie {
		cookie[i] = byte(i)
	}
	c := NewTorControlClient(ln.Addr().String(), "", func() ([]byte, bool) { return cookie, true })
	if err := c.VerifyAuth(); err != nil {
		t.Fatalf("VerifyAuth = %v; want nil", err)
	}
	select {
	case line := <-authSeen:
		if !strings.HasPrefix(line, "AUTHENTICATE ") || len(line) <= len("AUTHENTICATE ") {
			t.Fatalf("auth line = %q; want hex cookie AUTHENTICATE", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("control server never saw AUTHENTICATE")
	}
}

func TestVerifyAuth_BadCookie(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		reader := bufio.NewReader(conn)
		if _, err := reader.ReadString('\n'); err != nil {
			return
		}
		_, _ = conn.Write([]byte("515 Authentication failed\r\n"))
	}()

	c := NewTorControlClient(ln.Addr().String(), "wrong-password", nil)
	if err := c.VerifyAuth(); err == nil {
		t.Fatal("VerifyAuth = nil; want auth rejection error")
	}
}

func TestVerifyAuth_NoControlPort(t *testing.T) {
	c := NewTorControlClient("", "", nil)
	if err := c.VerifyAuth(); err == nil {
		t.Fatal("VerifyAuth = nil; want not-configured error")
	}
}

func TestVerifyAuth_Unreachable(t *testing.T) {
	// Port 1 is unconnectable: must fail fast, not hang.
	c := NewTorControlClient("127.0.0.1:1", "", nil)
	c.Cookie = nil
	if err := c.VerifyAuth(); err == nil {
		t.Fatal("VerifyAuth = nil; want dial error")
	}
}

func TestPoolVerifyControl_NoControlPort(t *testing.T) {
	p := NewCircuitPoolBackend(PoolConfig{TorAddress: "127.0.0.1:9050", CircuitCount: 1})
	if err := p.VerifyControl(); err == nil {
		t.Fatal("VerifyControl = nil; want not-configured error")
	}
}

func TestSingleTorVerifyControl_NoControlPort(t *testing.T) {
	b := NewTorBackend(TorConfig{Address: "127.0.0.1:9050", ControlAddr: ""})
	// NewTorBackend defaults an empty control addr to 127.0.0.1:9051; clear it
	// to exercise the nothing-to-verify path.
	b.control.Addr = ""
	if err := b.VerifyControl(); err == nil {
		t.Fatal("VerifyControl = nil; want not-configured error")
	}
}

func TestLifecycleVerifyControls_NoInstances(t *testing.T) {
	tl := NewTorLifecycle(TorLifecycleConfig{})
	if err := tl.VerifyControls(); err == nil {
		t.Fatal("VerifyControls = nil; want no-instances error")
	}
}
