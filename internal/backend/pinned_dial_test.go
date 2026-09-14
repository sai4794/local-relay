package backend

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The bypass-direct path must dial the proxy-verified check-time IPs, not
// re-resolve the name: a bypass host flipping public→private between the
// proxy's single shared Lookup and the direct dialer's fresh Lookup must
// still connect to the VERIFIED address (the private flip never reaches the
// wire). flip.example.com is unresolvable in test/sandbox DNS, so a dial
// that re-resolved the hostname would fail — success proves the literal was
// dialed. (The pin logic lives in DirectBackend itself, so the test uses the
// real dialer: there is no seam where the hostname could "reach a dialer"
// other than the pinned-literal loop inside DirectBackend.DialContext.)

func TestPinnedDial_UsesVerifiedIPsDespiteDNSFlip(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		if c, err := upstream.Accept(); err == nil {
			c.Close()
			accepted <- struct{}{}
		}
	}()

	port := upstream.Addr().(*net.TCPAddr).Port
	verified := upstream.Addr().(*net.TCPAddr).IP

	// Router bypass-matches the name; the ONLY dialable address is the
	// verified one (a re-resolution here would return the "flipped" name).
	router := NewRouter(&DirectBackend{dialer: &net.Dialer{Timeout: 5 * time.Second}})
	router.SetBypassHosts([]string{"flip.example.com"})

	ctx := WithPinnedDial(context.Background(), "flip.example.com", []net.IP{verified})
	addr := "flip.example.com:" + portString(port)
	conn, err := router.DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("pinned bypass dial failed: %v", err)
	}
	conn.Close()
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("verified upstream never accepted the pinned dial")
	}
}

func TestPinnedDial_HostnameNeverReachesDialer(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		for {
			if c, err := upstream.Accept(); err == nil {
				c.Close()
			} else {
				return
			}
		}
	}()
	port := upstream.Addr().(*net.TCPAddr).Port
	verified := upstream.Addr().(*net.TCPAddr).IP

	router := NewRouter(NewDirectBackend(0))
	router.SetBypassHosts([]string{"flip.example.com"})
	ctx := WithPinnedDial(context.Background(), "FLIP.Example.COM.", []net.IP{verified})
	// flip.example.com does not resolve in test DNS: success proves the
	// verified literal was dialed, not the hostname re-resolved. Case and
	// trailing-dot variants must hit the same pin (proxy check path and dial
	// path normalize identically).
	conn, err := router.DialContext(ctx, "tcp", "flip.example.com:"+portString(port))
	if err != nil {
		t.Fatalf("pinned dial re-resolved instead of using the verified IP: %v", err)
	}
	conn.Close()
}

func TestPinnedDial_UnpinnedDialsUnchanged(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		for {
			if c, err := upstream.Accept(); err == nil {
				c.Close()
			} else {
				return
			}
		}
	}()

	router := NewRouter(NewDirectBackend(0))
	router.SetBypassHosts([]string{"localhost"})
	// No WithPinnedDial on ctx: legacy path must still reach 127.0.0.1.
	conn, err := router.DialContext(context.Background(), "tcp", upstream.Addr().String())
	if err != nil {
		t.Fatalf("unpinned dial regressed: %v", err)
	}
	conn.Close()
}

// Non-bypass names must ignore pins entirely: Tor/proxied paths hand the
// hostname to the exit node, and the pin must not rewrite or disturb them.
// Here the proxied backend records the exact addr it was asked to dial.
type recordingBackend struct{ got chan string }

func (b *recordingBackend) DialContext(_ context.Context, _, addr string) (net.Conn, error) {
	b.got <- addr
	return nil, context.DeadlineExceeded
}
func (b *recordingBackend) IsHealthy() bool { return true }
func (b *recordingBackend) Close() error    { return nil }

func TestPinnedDial_NonBypassIgnoresPin(t *testing.T) {
	rec := &recordingBackend{got: make(chan string, 1)}
	router := NewRouter(NewDirectBackend(0), rec)
	router.SetBypassHosts([]string{"bypass.example.com"})
	ctx := WithPinnedDial(context.Background(), "tor.example.com", []net.IP{net.ParseIP("9.9.9.9")})
	_, _ = router.DialContext(ctx, "tcp", "tor.example.com:443")
	select {
	case got := <-rec.got:
		if got != "tor.example.com:443" {
			t.Fatalf("proxied dial addr = %q; want hostname untouched", got)
		}
		if strings.Contains(got, "9.9.9.9") {
			t.Fatalf("pin leaked into proxied dial: %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("proxied backend never dialed")
	}
}

func portString(port int) string { return strconv.Itoa(port) }
