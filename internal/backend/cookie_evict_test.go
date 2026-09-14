package backend

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// Stale cookie must not wedge rotation forever: an auth-rejected NEWNYM
// evicts the cache so the next attempt re-reads disk (which now holds the
// rotated cookie), and repeated rejections mark the instance not-ready for
// CheckHealth recycle.
func TestCookieEvict_OnAuthRejected(t *testing.T) {
	lc := NewTorLifecycle(TorLifecycleConfig{
		Binary: "true", DataDir: t.TempDir(),
		BasePort: 0, ControlBase: 0, MaxInstances: 1, Logf: func(string, ...interface{}) {},
	})
	inst := &TorInstance{ID: 1, Ready: true, StartedAt: time.Now()}
	lc.instances = append(lc.instances, inst)
	lc.cookieCache[1] = []byte("stale-stale-stale-stale-stale!!")

	// Fake control port that rejects everything with 515.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(cc net.Conn) {
				defer cc.Close()
				_ = cc.SetDeadline(time.Now().Add(5 * time.Second))
				buf := make([]byte, 256)
				if _, err := cc.Read(buf); err != nil {
					return
				}
				_, _ = cc.Write([]byte("515 Authentication failed\r\n"))
			}(c)
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port int
	fmt.Sscan(portStr, &port)
	inst.ControlPort = port
	inst.SetLastRotated(time.Now().Add(-time.Minute))

	if _, err := lc.requestNewCircuitResult(inst); err == nil {
		t.Fatal("expected auth rejection, got nil")
	}
	// Cache evicted: next attempt re-reads disk, not the stale bytes.
	lc.cookieMu.RLock()
	_, stillCached := lc.cookieCache[1]
	lc.cookieMu.RUnlock()
	if stillCached {
		t.Fatal("stale cookie still cached after auth rejection; rotation would fail forever")
	}
	// Two more rejections trip the recycle gate.
	for i := 0; i < 2; i++ {
		inst.SetLastRotated(time.Now().Add(-time.Minute))
		_, _ = lc.requestNewCircuitResult(inst)
	}
	if inst.IsReady() {
		t.Fatal("instance still ready after 3 consecutive auth rejections; want not-ready for recycle")
	}
}

// Transport failures (connection refused) say nothing about the cookie:
// the cache must survive them.
func TestCookieEvict_TransportFailureKeepsCache(t *testing.T) {
	lc := NewTorLifecycle(TorLifecycleConfig{
		Binary: "true", DataDir: t.TempDir(),
		BasePort: 0, ControlBase: 0, MaxInstances: 1, Logf: func(string, ...interface{}) {},
	})
	inst := &TorInstance{ID: 1, ControlPort: 1, Ready: true, StartedAt: time.Now()}
	lc.instances = append(lc.instances, inst)
	good := make([]byte, 32)
	for i := range good {
		good[i] = byte(i)
	}
	lc.cookieCache[1] = good
	inst.SetLastRotated(time.Now().Add(-time.Minute))

	if _, err := lc.requestNewCircuitResult(inst); err == nil {
		t.Fatal("expected dial failure against closed port 1, got nil")
	}
	lc.cookieMu.RLock()
	cached, hit := lc.cookieCache[1]
	lc.cookieMu.RUnlock()
	if !hit || string(cached) != string(good) {
		t.Fatal("transport failure evicted a good cookie; only auth-rejected may evict")
	}
	if !inst.IsReady() {
		t.Fatal("transport failure marked not-ready; only repeated auth rejections may do that")
	}
}

// A not-ready instance whose SOCKS answers but whose control auth was
// rejected must recover via CheckHealth re-verification once the cookie
// heals on disk — not wedge out of selection forever. Pre-fix the not-ready
// branch only recycled SOCKS-dead daemons, so a healthy-daemon/wrong-cookie
// instance stayed not-ready permanently (total outage at MaxInstances=1).
func TestCookieEvict_CheckHealthReverifiesAndReReadies(t *testing.T) {
	lc := NewTorLifecycle(TorLifecycleConfig{
		Binary: "true", DataDir: t.TempDir(),
		BasePort: 0, ControlBase: 0, MaxInstances: 1, Logf: func(string, ...interface{}) {},
	})
	dir := t.TempDir()
	// Fake SOCKS greeting server (healthy daemon surface).
	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socksLn.Close()
	go func() {
		for {
			c, err := socksLn.Accept()
			if err != nil {
				return
			}
			go func(cc net.Conn) {
				defer cc.Close()
				_ = cc.SetDeadline(time.Now().Add(5 * time.Second))
				buf := make([]byte, 3)
				if _, err := io.ReadFull(cc, buf); err != nil {
					return
				}
				_, _ = cc.Write([]byte{0x05, 0x00})
			}(c)
		}
	}()
	_, socksPortStr, _ := net.SplitHostPort(socksLn.Addr().String())
	var socksPort int
	fmt.Sscan(socksPortStr, &socksPort)

	// Fake control port: reject first (stale cookie), accept after.
	var reject atomic.Bool
	reject.Store(true)
	ctrlLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ctrlLn.Close()
	go func() {
		for {
			c, err := ctrlLn.Accept()
			if err != nil {
				return
			}
			go func(cc net.Conn) {
				defer cc.Close()
				_ = cc.SetDeadline(time.Now().Add(5 * time.Second))
				r := bufio.NewReader(cc)
				if _, err := r.ReadString('\n'); err != nil {
					return
				}
				if reject.Load() {
					_, _ = cc.Write([]byte("515 Authentication failed\r\n"))
					return
				}
				_, _ = cc.Write([]byte("250 OK\r\n"))
			}(c)
		}
	}()
	_, ctrlPortStr, _ := net.SplitHostPort(ctrlLn.Addr().String())
	var ctrlPort int
	fmt.Sscan(ctrlPortStr, &ctrlPort)

	inst := &TorInstance{ID: 1, SocksPort: socksPort, ControlPort: ctrlPort, Cmd: nil, DataDir: dir, Ready: true, StartedAt: time.Now().Add(-time.Hour)}
	lc.instances = append(lc.instances, inst)

	// Drive 3 rejections via VerifyControls (same noteAuthResult path as NEWNYM).
	for i := 0; i < 3; i++ {
		_ = lc.VerifyControls()
	}
	if inst.IsReady() {
		t.Fatal("instance still ready after 3 auth rejections; want not-ready")
	}
	// Cookie heals: control now accepts. Next CheckHealth must re-ready.
	reject.Store(false)
	lc.CheckHealth(context.Background())
	if !inst.IsReady() {
		t.Fatal("instance not re-readied after cookie healed; CheckHealth must recover control-plane casualties")
	}
}
