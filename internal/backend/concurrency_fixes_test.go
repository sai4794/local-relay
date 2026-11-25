package backend

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/local-relay/proxy/internal/transport"
)

// fakeSocks5CONNECT accepts the isolation-auth handshake and replies success.
// It records the ATYP byte and address payload so tests can assert encoding.
type socksRequest struct {
	atyp byte
	addr []byte
}

func fakeSocks5CONNECT(t *testing.T, seen chan<- socksRequest) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var conns []net.Conn
	t.Cleanup(func() {
		ln.Close()
		for _, c := range conns {
			c.Close()
		}
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns = append(conns, c)
			go func(c net.Conn) {
				defer c.Close()
				hdr := make([]byte, 2)
				if _, err := io.ReadFull(c, hdr); err != nil {
					return
				}
				methods := make([]byte, int(hdr[1]))
				if _, err := io.ReadFull(c, methods); err != nil {
					return
				}
				useAuth := false
				for _, m := range methods {
					if m == 0x02 {
						useAuth = true
					}
				}
				if useAuth {
					if _, err := c.Write([]byte{0x05, 0x02}); err != nil {
						return
					}
					ah := make([]byte, 2)
					if _, err := io.ReadFull(c, ah); err != nil {
						return
					}
					if _, err := io.ReadFull(c, make([]byte, int(ah[1])+1)); err != nil {
						return
					}
					if _, err := c.Write([]byte{0x01, 0x00}); err != nil {
						return
					}
				} else if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
					return
				}
				req := make([]byte, 4)
				if _, err := io.ReadFull(c, req); err != nil {
					return
				}
				var payload []byte
				switch req[3] {
				case 0x01:
					payload = make([]byte, net.IPv4len+2)
				case 0x04:
					payload = make([]byte, net.IPv6len+2)
				case 0x03:
					dl := make([]byte, 1)
					if _, err := io.ReadFull(c, dl); err != nil {
						return
					}
					payload = make([]byte, int(dl[0])+2)
				default:
					return
				}
				if _, err := io.ReadFull(c, payload); err != nil {
					return
				}
				if seen != nil {
					select {
					case seen <- socksRequest{atyp: req[3], addr: payload}:
					default:
					}
				}
				c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				// Hold the tunnel open until the test closes it.
				io.Copy(io.Discard, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// H-02 (multitor): candidate evaluation must not leave probe claims on
// instances that lost selection. Only the serving instance may hold the
// probation probe.
func TestSelect_ProbationLoserClaimReleased(t *testing.T) {
	var m *MultiTorBackend
	insts := selectTestLifecycle(t, &m)
	past := time.Now().Add(-time.Hour)
	for _, inst := range insts {
		if _, ok := inst.quar.enterQuarantine(past, time.Hour, time.Hour); !ok {
			t.Fatalf("setup: quarantine instance %d failed", inst.ID)
		}
	}
	got, _ := m.selectInstance(insts)
	if got == nil {
		t.Fatal("selection = nil; want a probated candidate")
	}
	held := 0
	for _, inst := range insts {
		if inst.quar.probeInFlight.Load() {
			held++
		}
	}
	if held != 1 {
		t.Errorf("probe claims after one selection = %d, want exactly 1 (winner only)", held)
	}
}

// H-02 (pool): the same loser-claim rule applies to circuit-pool slots.
func TestPool_ProbationLoserClaimReleased(t *testing.T) {
	socksAddr := fakeSocks5CONNECT(t, nil)
	pool := NewCircuitPoolBackend(PoolConfig{TorAddress: socksAddr, CircuitCount: 2})
	past := time.Now().Add(-time.Hour)
	for _, slot := range pool.slots {
		if _, ok := slot.quar.enterQuarantine(past, time.Hour, time.Hour); !ok {
			t.Fatalf("setup: quarantine slot %d failed", slot.id)
		}
	}
	conn, err := pool.DialContext(context.Background(), "tcp", "target.example:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	held := 0
	for _, slot := range pool.slots {
		if slot.quar.probeInFlight.Load() {
			held++
		}
	}
	if held != 1 {
		t.Errorf("pool probe claims after one dial = %d, want exactly 1 (served slot only)", held)
	}
}

// H-03: a tunnel checked out at generation G must be closed, not re-pooled,
// if a rotation bumped the pool generation to G+1 before Close.
func TestPool_PutConnStaleGenerationClosed(t *testing.T) {
	pool := NewCircuitPoolBackend(PoolConfig{TorAddress: "127.0.0.1:1", CircuitCount: 1})
	client, peer := net.Pipe()
	defer peer.Close()
	pool.poolGen.Store(2)
	pool.putConnGen(0, "example.com:443", client, 1) // stale checkout gen

	if got, _ := pool.getConn(0, "example.com:443"); got != nil {
		got.Close()
		t.Fatal("stale-generation connection was re-pooled; want closed")
	}
	if _, err := client.Write([]byte("probe")); err == nil {
		t.Error("stale connection stayed open; want closed")
	}
}

// L-02: outbound SOCKS5 must encode IPv6 literals with ATYP 0x04, not as a
// domain name that the SOCKS server cannot resolve.
func TestOutboundSOCKS5_IPv6LiteralUsesATYP4(t *testing.T) {
	seen := make(chan socksRequest, 2)
	addr := fakeSocks5CONNECT(t, seen)
	client := transport.NewSOCKS5Client(3 * time.Second)
	conn, err := client.Connect(context.Background(), addr, "[2001:db8::1]:443", "")
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer conn.Close()
	select {
	case req := <-seen:
		if req.atyp != 0x04 {
			t.Errorf("ATYP = 0x%02x, want 0x04 (IPv6)", req.atyp)
		}
		if len(req.addr) != net.IPv6len+2 {
			t.Errorf("IPv6 payload length = %d, want %d", len(req.addr), net.IPv6len+2)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SOCKS server never received a request")
	}
}
