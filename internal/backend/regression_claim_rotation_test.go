package backend

import (
	"sync"
	"testing"
)

// Regression: ClaimRotation must be atomic — exactly one concurrent dialer
// wins each rotation window, so threshold crossings never stampede NEWNYM.
func TestRegression_ClaimRotationAtomicity(t *testing.T) {
	inst := &TorInstance{}
	inst.Requests.Store(10)

	const racers = 32
	var wg sync.WaitGroup
	wins := make(chan bool, racers)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wins <- inst.ClaimRotation(10)
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
		t.Fatalf("ClaimRotation winners = %d; want exactly 1 (atomic claim)", got)
	}
	if n := inst.GetRequests(); n != 0 {
		t.Fatalf("Requests after claim = %d; want 0 (reset by winner)", n)
	}
	// Threshold 0 disables rotation entirely.
	if (&TorInstance{}).ClaimRotation(0) {
		t.Fatal("ClaimRotation(0) = true; want false (0 disables threshold rotation)")
	}
}
