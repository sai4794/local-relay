package backend

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

// Regression: ForceRotate resets (marks healthy) known-dead slots ONLY when
// a NEWNYM was actually issued — the dead verdict belonged to the pre-NEWNYM
// circuit generation, so resurrection after a real rotation is correct. A
// cooldown skip or signal failure must leave the dead slot dead (no phantom
// reset). Demonstrated against the pre-existing gate; locks in the semantics.
func TestForceRotate_DeadSlotSemantics(t *testing.T) {
	newnymCh := make(chan struct{}, 16)
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
			go func(c net.Conn) {
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
						select {
						case newnymCh <- struct{}{}:
						default:
						}
						_, _ = c.Write([]byte("250 OK\r\n"))
						return
					}
					_, _ = c.Write([]byte("250 OK\r\n"))
				}
			}(conn)
		}
	}()

	killSlot := func(p *CircuitPoolBackend, idx int) {
		for i := 0; i < 10; i++ {
			p.slots[idx].RecordFailure()
		}
		if p.slots[idx].IsHealthy() {
			t.Fatalf("slot %d still healthy after fail threshold", idx)
		}
	}

	t.Run("real NEWNYM resets dead slot (correct: new circuit generation)", func(t *testing.T) {
		p := NewCircuitPoolBackend(PoolConfig{
			TorAddress:   "127.0.0.1:1",
			ControlAddr:  ln.Addr().String(),
			CircuitCount: 2,
		})
		killSlot(p, 0)
		if err := p.ForceRotate(); err != nil {
			t.Fatalf("ForceRotate = %v; want nil (real NEWNYM)", err)
		}
		select {
		case <-newnymCh:
		case <-time.After(5 * time.Second):
			t.Fatal("fake control saw no SIGNAL NEWNYM")
		}
		for i, slot := range p.slots {
			if !slot.IsHealthy() {
				t.Errorf("slot %d unhealthy after real NEWNYM; want healthy (new generation)", i)
			}
		}
	})

	t.Run("cooldown skip keeps dead slot dead (no phantom reset)", func(t *testing.T) {
		p := NewCircuitPoolBackend(PoolConfig{
			TorAddress:   "127.0.0.1:1",
			ControlAddr:  ln.Addr().String(),
			CircuitCount: 2,
		})
		killSlot(p, 0)
		p.lastNymTime = time.Now() // force inside minNymGap window
		drain := len(newnymCh)
		for i := 0; i < drain; i++ {
			<-newnymCh
		}
		if err := p.ForceRotate(); err == nil {
			t.Fatal("ForceRotate during cooldown = nil; want ErrNymCooldown")
		}
		select {
		case <-newnymCh:
			t.Fatal("cooldown-skip ForceRotate issued SIGNAL NEWNYM; want no dispatch")
		case <-time.After(200 * time.Millisecond):
		}
		if p.slots[0].IsHealthy() {
			t.Error("dead slot resurrected on cooldown skip; want still unhealthy (no phantom reset)")
		}
		if !p.slots[1].IsHealthy() {
			t.Error("healthy slot changed on cooldown skip; want untouched")
		}
	})
}
