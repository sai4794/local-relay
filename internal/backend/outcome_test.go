package backend

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

// claimCarrierConn is a foreign wrapper (no endpoint fields) that nests an
// inFlightConn one level down — the shape TuneTCP peels.
type claimCarrierConn struct {
	net.Conn
}

func (c *claimCarrierConn) Unwrap() net.Conn { return c.Conn }

func TestOutcome_ClaimHelpersRoundTrip(t *testing.T) {
	// No carrier attached: nil sink — direct dials report nothing.
	if got := ClaimFrom(context.Background()); got != nil {
		t.Fatalf("bare ctx claim = %+v, want nil", got)
	}
	// Nil sink carrier: attribution disabled, fill is a silent skip.
	ctx := WithEndpointClaim(context.Background(), nil)
	if got := ClaimFrom(ctx); got != nil {
		t.Fatalf("nil-sink claim = %+v, want nil", got)
	}
	fillClaimSink(ctx, "multitor", 2, 7, 300*time.Millisecond) // must not panic
	// Live sink: backend fill lands in the dialer's variable.
	var sink EndpointClaim
	filled := WithEndpointClaim(context.Background(), &sink)
	fillClaimSink(filled, "multitor", 2, 7, 300*time.Millisecond)
	got := ClaimFrom(filled)
	if got == nil || !got.OK || got.Backend != "multitor" || got.ID != 2 || got.Gen != 7 || got.Latency != 300*time.Millisecond {
		t.Fatalf("claim round-trip = %+v, want OK multitor 2/7 300ms", got)
	}
	// Nil ctx to fill: silent skip, no panic.
	fillClaimSink(nil, "multitor", 1, 1, time.Second)
}

func TestOutcome_EndpointFromConn(t *testing.T) {
	inner, outer := net.Pipe()
	defer inner.Close()
	defer outer.Close()

	inst := &TorInstance{ID: 3}
	inst.circuitGen.Store(9)
	wrapped := &inFlightConn{Conn: outer, inst: inst, endpointID: 3, endpointGen: 9, dialLatency: 150 * time.Millisecond}
	// Direct hit.
	if id, gen, lat, ok := EndpointFromConn(wrapped); !ok || id != 3 || gen != 9 || lat != 150*time.Millisecond {
		t.Fatalf("direct = (%d,%d,%v,%v), want (3,9,150ms,true)", id, gen, lat, ok)
	}
	// Nested under a foreign wrapper — same Unwrap walk as TuneTCP.
	nested := &claimCarrierConn{Conn: wrapped}
	if id, gen, _, ok := EndpointFromConn(nested); !ok || id != 3 || gen != 9 {
		t.Fatalf("nested = (%d,%d,%v), want (3,9,true)", id, gen, ok)
	}
	// Bare conn: no claim.
	if _, _, _, ok := EndpointFromConn(outer); ok {
		t.Fatal("bare conn reports ok=true, want false")
	}
	// Pooled wrap: slot index 0 is a valid ID (>= 0 gate, unlike multitor).
	pool := NewCircuitPoolBackend(PoolConfig{TorAddress: "127.0.0.1:1", CircuitCount: 1})
	pw := &pooledConnWrap{Conn: outer, pool: pool, slotIdx: 0, endpointID: 0, endpointGen: 4, dialLatency: time.Second}
	if id, gen, _, ok := EndpointFromConn(pw); !ok || id != 0 || gen != 4 {
		t.Fatalf("pooled = (%d,%d,%v), want (0,4,true)", id, gen, ok)
	}
	// Nil conn: no claim, no panic.
	if _, _, _, ok := EndpointFromConn(nil); ok {
		t.Fatal("nil conn reports ok=true, want false")
	}
}

func TestOutcome_MultiTorDialStampsEndpointFields(t *testing.T) {
	// One fake SOCKS5 listener answering the full user/pass + CONNECT
	// handshake (mirrors TestMultiTor_LeastInflightPicked's fake).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func(l net.Listener) {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(cc net.Conn) {
				defer cc.Close()
				buf := make([]byte, 4)
				if _, err := cc.Read(buf); err != nil {
					return
				}
				cc.Write([]byte{0x05, 0x02})
				ahdr := make([]byte, 2)
				if _, err := cc.Read(ahdr); err != nil {
					return
				}
				uname := make([]byte, int(ahdr[1]))
				if _, err := cc.Read(uname); err != nil {
					return
				}
				plen := make([]byte, 1)
				if _, err := cc.Read(plen); err != nil {
					return
				}
				pass := make([]byte, plen[0])
				if _, err := cc.Read(pass); err != nil {
					return
				}
				cc.Write([]byte{0x01, 0x00})
				hdr := make([]byte, 4)
				if _, err := cc.Read(hdr); err != nil {
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
					cc.Read(l)
					skip = int(l[0]) + 2
				}
				rest := make([]byte, skip)
				cc.Read(rest)
				cc.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				time.Sleep(300 * time.Millisecond)
			}(c)
		}
	}(ln)

	lc := NewTorLifecycle(TorLifecycleConfig{
		Binary: "true", DataDir: t.TempDir(),
		BasePort: 0, ControlBase: 0, MaxInstances: 1, Logf: func(string, ...interface{}) {},
	})
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port int
	fmt.Sscan(portStr, &port)
	lc.instances = append(lc.instances, &TorInstance{ID: 1, SocksPort: port, ControlPort: 0, Cmd: nil, DataDir: "", Ready: true, StartedAt: time.Now()})
	m := NewMultiTorBackend(lc, 2*time.Second, func(string, ...interface{}) {})

	conn, err := m.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()
	id, gen, lat, ok := EndpointFromConn(conn)
	if !ok || id != 1 {
		t.Fatalf("dial claim = (%d,%d,%v,%v), want id=1 ok=true", id, gen, lat, ok)
	}
	if gen != 1 {
		t.Fatalf("dial gen = %d, want 1 (fresh instance default)", gen)
	}
	if lat <= 0 {
		t.Fatalf("dial latency = %v, want > 0", lat)
	}
	// TuneTCP must still peel to the TCP conn through the new fields.
	TuneTCP(conn)
}
