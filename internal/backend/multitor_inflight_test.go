package backend

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

// fakeInstance satisfies the bits of TorInstance that DialContext touches
// via the lifecycle — we exercise selection through the real TorLifecycle
// by stubbing spawnInstance indirectly: simpler to drive selection directly.
func TestMultiTor_LeastInflightPicked(t *testing.T) {
	// Set up three fake SOCKS5 listeners immediately answering greeting.
	addrs := []string{}
	for i := 0; i < 3; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		addrs = append(addrs, ln.Addr().String())
		go func(l net.Listener) {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				// Respond to SOCKS5 greeting with user/pass auth (0x02):
				// production MultiTor always dials with an IsolateSOCKSAuth
				// identity, and the transport rejects a no-auth downgrade.
				// Read the full greeting first (2 offered methods).
				go func(cc net.Conn) {
					defer cc.Close()
					// Greeting
					buf := make([]byte, 4)
					if _, err := cc.Read(buf); err != nil {
						return
					}
					cc.Write([]byte{0x05, 0x02})
					// RFC1929 auth: ver=1, ulen, user, plen, pass(empty).
					ahdr := make([]byte, 2)
					if _, err := cc.Read(ahdr); err != nil {
						return
					}
					ulen := int(ahdr[1])
					uname := make([]byte, ulen)
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
					// CONNECT request: version+cmd+rsv+at. We read addr-type to know size.
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
					// Reply success: ver 5, rep 0, rsv 0, atyp IPv4 0.0.0.0:0
					cc.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
					time.Sleep(300 * time.Millisecond)
				}(c)
			}
		}(ln)
	}

	// Build instances directly and stash them in a lifecycle.
	lc := NewTorLifecycle(TorLifecycleConfig{
		Binary: "true", DataDir: t.TempDir(),
		BasePort: 0, ControlBase: 0, MaxInstances: 3, Logf: func(string, ...interface{}) {},
	})
	// Bypass Start (real tor not available) — inject instances.
	for i, addr := range addrs {
		host, portStr, _ := net.SplitHostPort(addr)
		var port int
		fmt.Sscan(portStr, &port)
		_ = host
		inst := &TorInstance{ID: i + 1, SocksPort: port, ControlPort: 0, Cmd: nil, DataDir: "", Ready: true, StartedAt: time.Now()}
		lc.instances = append(lc.instances, inst)
	}

	m := NewMultiTorBackend(lc, 2*time.Second, func(string, ...interface{}) {})

	// Load instance #1 with 5 in-flight; others have 0. Least-inflight pick
	// must NOT pick instance #1.
	lc.instances[0].IncInFlight()
	lc.instances[0].IncInFlight()
	lc.instances[0].IncInFlight()
	lc.instances[0].IncInFlight()
	lc.instances[0].IncInFlight()

	conn, err := m.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("dial via least-inflight failed: %v", err)
	}
	// The picked instance is identifiable BEFORE Close(): its InFlight rose by 1.
	pickedIdx := -1
	for i, inst := range lc.instances {
		if i == 0 {
			continue
		}
		if inst.InFlight() == 1 {
			pickedIdx = i
			break
		}
	}
	if pickedIdx < 0 {
		t.Errorf("least-inflight selection failed: no unloaded instance picked "+
			"(inst1 in-flight=%d, inst2=%d, inst3=%d)",
			lc.instances[0].InFlight(), lc.instances[1].InFlight(), lc.instances[2].InFlight())
	}
	// Instance #1's count must not have grown past the 5 we loaded.
	if lc.instances[0].InFlight() > 5 {
		t.Errorf("loaded instance picked despite least-inflight: %d", lc.instances[0].InFlight())
	}
	conn.Close()
}

// Guards the counter: wrap Close decrements.
func TestInFlightConn_CloseDecrements(t *testing.T) {
	inst := &TorInstance{}
	c1, c2 := net.Pipe()
	defer c2.Close()
	w := &inFlightConn{Conn: c1, inst: inst}
	inst.IncInFlight()
	if got := inst.InFlight(); got != 1 {
		t.Fatalf("want 1, got %d", got)
	}
	w.Close()
	if got := inst.InFlight(); got != 0 {
		t.Fatalf("want 0 after Close, got %d", got)
	}
	// Idempotent.
	w.Close()
	if got := inst.InFlight(); got != 0 {
		t.Fatalf("double Close changed to %d", got)
	}
}
