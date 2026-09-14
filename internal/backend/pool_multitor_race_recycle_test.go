package backend

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// Regression: concurrent put/get/evict under -race must not trip the pool's
// slice handling. Demonstrated pre-fix with a use-after-evict race report:
// evictConns aliased the live backing array (`conns := p.connPool;
// p.connPool = p.connPool[:0]`), so a concurrent putConn append overwrote
// the slice the evictor was iterating/closing (pool.go putConn-append vs
// evictConns-iteration). Kept permanently: the putConn/evictStaleLocked
// single-lock refactor shares these paths.
func TestPool_ConcurrentPutEvictRace(t *testing.T) {
	pool := NewCircuitPoolBackend(PoolConfig{
		TorAddress:   "127.0.0.1:1",
		CircuitCount: 2,
		MaxIdle:      4,
		IdleTTL:      time.Millisecond,
	})
	var wg sync.WaitGroup
	for g := 0; g < 6; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				a, b := net.Pipe()
				pool.putConn(g%2, "h:1", a)
				_ = b.Close()
				if got, _ := pool.getConn(g%2, "h:1"); got != nil {
					_ = got.Close()
				}
				if i%25 == 0 {
					pool.evictConns()
				}
			}
		}(g)
	}
	wg.Wait()
}

// Regression: recycled-cold backends re-arm the cold gate. Previous
// generation served (everServed latched) but all live instances were
// replaced (fresh LastServed==0): a pre-serve anomaly must NOT dispatch
// NEWNYM — there is no culprit in the live generation. Demonstrated
// pre-fix: stale everServed=true forced a dispatch against a fresh,
// never-served generation.
func TestMultiTor_RecycleRearmsColdBackend(t *testing.T) {
	newnymSeen := make(chan string, 16)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveFakeControlNEWNYM(conn, newnymSeen)
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var ctrlPort int
	if _, err := fmt.Sscan(portStr, &ctrlPort); err != nil {
		t.Fatal(err)
	}

	lc := NewTorLifecycle(TorLifecycleConfig{
		Binary: "true", DataDir: t.TempDir(),
		BasePort: 0, ControlBase: 0, MaxInstances: 2,
		Logf: func(string, ...interface{}) {},
	})
	for _, id := range []int{1, 2} {
		inst := &TorInstance{ID: id, SocksPort: 0, ControlPort: ctrlPort, Ready: true, StartedAt: time.Now()}
		inst.SetLastRotated(time.Now().Add(-time.Hour))
		lc.instances = append(lc.instances, inst)
	}
	m := NewMultiTorBackend(lc, time.Second, func(string, ...interface{}) {})
	// Stale state: a previous instance generation served; current ones never did.
	m.everServed.Store(true)
	rotated := false
	m.OnRotate = func() { rotated = true }

	m.ReportAnomaly(-1)

	select {
	case cmd := <-newnymSeen:
		t.Fatalf("recycled-cold ReportAnomaly(-1) dispatched NEWNYM (%q); want no dispatch", cmd)
	case <-time.After(300 * time.Millisecond):
	}
	if rotated {
		t.Error("OnRotate fired on recycled-cold backend; want no churn")
	}
	// A genuinely warm backend still dispatches: serving stamps the live
	// generation, so attribution is unchanged.
	lc.instances[0].RecordServed()
	m.ReportAnomaly(-1)
	select {
	case <-newnymSeen:
	case <-time.After(5 * time.Second):
		t.Fatal("warm ReportAnomaly(-1) dispatched no NEWNYM; want dispatch (attribution unchanged)")
	}
}

// serveFakeControlNEWNYM answers AUTHENTICATE 250 OK and reports the first
// SIGNAL NEWNYM line on seen, mirroring the fake in cold_anomaly_test.go.
func serveFakeControlNEWNYM(c net.Conn, seen chan<- string) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(c)
	if _, err := reader.ReadString('\n'); err != nil {
		return
	}
	_, _ = c.Write([]byte("250 OK\r\n"))
	for {
		cmd, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		if strings.HasPrefix(strings.TrimSpace(cmd), "SIGNAL NEWNYM") {
			seen <- strings.TrimSpace(cmd)
			_, _ = c.Write([]byte("250 OK\r\n"))
			return
		}
		_, _ = c.Write([]byte("250 OK\r\n"))
	}
}
