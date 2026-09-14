package backend

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/local-relay/proxy/internal/transport"
)

// exitIdentityServer records the SOCKS5 isolation user of one dial.
func exitIdentityServer(t *testing.T) (addr string, userSeen chan string, cleanup func()) {
	t.Helper()
	userSeen = make(chan string, 4)
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
			go func(cc net.Conn) {
				defer cc.Close()
				_ = cc.SetDeadline(time.Now().Add(5 * time.Second))
				greet := make([]byte, 2)
				if _, err := readFullConn(cc, greet); err != nil {
					return
				}
				methods := make([]byte, int(greet[1]))
				if _, err := readFullConn(cc, methods); err != nil {
					return
				}
				offered := false
				for _, m := range methods {
					if m == 0x02 {
						offered = true
					}
				}
				if offered {
					_, _ = cc.Write([]byte{0x05, 0x02})
					ahdr := make([]byte, 2)
					if _, err := readFullConn(cc, ahdr); err != nil {
						return
					}
					uname := make([]byte, int(ahdr[1]))
					if _, err := readFullConn(cc, uname); err != nil {
						return
					}
					plen := make([]byte, 1)
					if _, err := readFullConn(cc, plen); err != nil {
						return
					}
					pass := make([]byte, int(plen[0]))
					if _, err := readFullConn(cc, pass); err != nil {
						return
					}
					userSeen <- string(uname)
					_, _ = cc.Write([]byte{0x01, 0x00})
					// Answer the CONNECT the transport sends next so its
					// handshake completes (reply success, IPv4 0.0.0.0:0).
					hdr := make([]byte, 4)
					if _, err := readFullConn(cc, hdr); err != nil {
						return
					}
					var skip int
					switch hdr[3] {
					case 0x01:
						skip = 4 + 2
					case 0x04:
						skip = 16 + 2
					case 0x03:
						l := make([]byte, 1)
						if _, err := readFullConn(cc, l); err != nil {
							return
						}
						skip = int(l[0]) + 2
					default:
						return
					}
					rest := make([]byte, skip)
					if _, err := readFullConn(cc, rest); err != nil {
						return
					}
					_, _ = cc.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				} else {
					_, _ = cc.Write([]byte{0x05, 0x00})
					userSeen <- ""
				}
			}(c)
		}
	}()
	return ln.Addr().String(), userSeen, func() { ln.Close() }
}

func readFullConn(c net.Conn, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := c.Read(b[n:])
		if err != nil {
			return n, err
		}
		n += m
	}
	return n, nil
}

// dialWithExitIdentity replays RefreshExitIP's SOCKS dial against a fake
// daemon and returns the isolation user it asserted. Pre-fix this was ""
// (daemon default circuit); fixed it must be the instance's own identity.
func dialWithExitIdentity(ctx context.Context, socksAddr string, inst *TorInstance) (string, error) {
	sc := transport.NewSOCKS5Client(5 * time.Second)
	c, err := sc.Connect(ctx, socksAddr, "check.torproject.org:443", exitProbeUser(inst))
	if err != nil {
		return "", err
	}
	c.Close()
	return exitProbeUser(inst), nil
}

// Regression: the exit-IP probe must assert the instance's own circuit
// identity ("relay:<id>:<gen>", same as production traffic), not the
// daemon's default circuit via an empty isolation user. Pre-fix the probe
// dialed with "", so the recorded exit could belong to another circuit.
func TestRefreshExitIP_UsesInstanceCircuitIdentity(t *testing.T) {
	socksAddr, userSeen, cleanup := exitIdentityServer(t)
	defer cleanup()

	inst := &TorInstance{ID: 7, SocksPort: 0, ControlPort: 0, Ready: true}
	inst.circuitGen.Store(42)
	want := "relay:7:42"

	if _, err := dialWithExitIdentity(context.Background(), socksAddr, inst); err != nil {
		t.Fatalf("probe dial failed: %v", err)
	}
	select {
	case got := <-userSeen:
		if got != want {
			t.Fatalf("probe isolation user = %q; want instance identity %q", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fake daemon saw no dial")
	}
}
