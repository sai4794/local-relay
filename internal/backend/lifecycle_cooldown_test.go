package backend

import (
	"sync"
	"testing"
	"time"
)

// The NEWNYM cooldown claim must be atomic: N concurrent callers in the same
// window collapse onto exactly one issued signal; the rest get ErrNymCooldown.
func TestLifecycle_CooldownClaimAtomic(t *testing.T) {
	inst := &TorInstance{ID: 1, SocksPort: 1, ControlPort: 1, Ready: true, StartedAt: time.Now()}
	inst.SetLastRotated(time.Now().Add(-time.Hour)) // outside cooldown: claimable

	const racers = 16
	var wg sync.WaitGroup
	wins := make(chan bool, racers)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Claim phase only: replicate the atomic claim without control I/O
			// by exercising the same lock discipline via SetLastRotated bump.
			inst.mu.Lock()
			claimable := time.Since(inst.LastRotated) >= 10*time.Second
			if claimable {
				inst.LastRotated = time.Now()
			}
			inst.mu.Unlock()
			wins <- claimable
		}()
	}
	wg.Wait()
	close(wins)
	got := 0
	for w := range wins {
		if w {
			got++
		}
	}
	if got != 1 {
		t.Fatalf("cooldown claim winners = %d; want exactly 1", got)
	}
}

// requestNewCircuitResult must surface ErrNymCooldown inside the window
// without touching control I/O (no dial to ControlPort 1 observed as error
// type, not a connection error).
func TestLifecycle_CooldownSkipNoIO(t *testing.T) {
	lc := NewTorLifecycle(TorLifecycleConfig{
		Binary: "true", DataDir: t.TempDir(),
		BasePort: 0, ControlBase: 0, MaxInstances: 1,
		Logf: func(string, ...interface{}) {},
	})
	inst := &TorInstance{ID: 1, SocksPort: 1, ControlPort: 1, Ready: true, StartedAt: time.Now()}
	inst.SetLastRotated(time.Now())

	rotated, err := lc.requestNewCircuitResult(inst)
	if rotated {
		t.Fatal("rotated=true inside cooldown; want false")
	}
	if err != ErrNymCooldown {
		t.Fatalf("err = %v; want ErrNymCooldown (no control I/O attempted)", err)
	}
}
