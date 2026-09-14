package backend

import (
	"sync"
	"testing"
	"time"
)

func TestScore_Defaults(t *testing.T) {
	p := DefaultScoreParams()
	if p.Alpha != 0.2 {
		t.Fatalf("Alpha = %v, want 0.2", p.Alpha)
	}
	if p.LatencyRef != 2*time.Second {
		t.Fatalf("LatencyRef = %v, want 2s", p.LatencyRef)
	}
	if p.MinSamples != 5 {
		t.Fatalf("MinSamples = %v, want 5", p.MinSamples)
	}
	if p.MinQuality != 0.1 {
		t.Fatalf("MinQuality = %v, want 0.1", p.MinQuality)
	}
}

func TestScore_FirstSampleDirectSet(t *testing.T) {
	var s EndpointStats
	s.Record(true, 800*time.Millisecond, 0.2)
	if got := s.LatencyEWMA(); got != 800*time.Millisecond {
		t.Fatalf("first sample EWMA = %v, want 800ms", got)
	}
	if s.Successes() != 1 || s.Failures() != 0 {
		t.Fatalf("counters = %d/%d, want 1/0", s.Successes(), s.Failures())
	}
}

func TestScore_AlphaConvergence(t *testing.T) {
	// alpha=0.2: old=1000ms, sample=2000ms -> 0.8*1000+0.2*2000 = 1200ms.
	var s EndpointStats
	s.Record(true, 1000*time.Millisecond, 0.2)
	s.Record(true, 2000*time.Millisecond, 0.2)
	if got := s.LatencyEWMA(); got != 1200*time.Millisecond {
		t.Fatalf("EWMA = %v, want 1200ms", got)
	}
}

func TestScore_FailureDoesNotMoveEWMA(t *testing.T) {
	var s EndpointStats
	s.Record(true, 500*time.Millisecond, 0.2)
	s.Record(false, 30*time.Second, 0.2)
	s.Record(false, time.Millisecond, 0.2)
	if got := s.LatencyEWMA(); got != 500*time.Millisecond {
		t.Fatalf("EWMA after failures = %v, want 500ms", got)
	}
	if s.Successes() != 1 || s.Failures() != 2 {
		t.Fatalf("counters = %d/%d, want 1/2", s.Successes(), s.Failures())
	}
}

func TestScore_ConcurrentCAS(t *testing.T) {
	var s EndpointStats
	const workers = 16
	const perWorker = 200
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				s.Record(true, time.Second, 0.2)
			}
		}()
	}
	wg.Wait()
	want := int64(workers * perWorker)
	if s.Successes() != want {
		t.Fatalf("successes = %d, want %d", s.Successes(), want)
	}
	if got := s.LatencyEWMA(); got != time.Second {
		t.Fatalf("EWMA = %v, want 1s (identical samples converge exactly)", got)
	}
}

func TestScore_ColdIsNeutral(t *testing.T) {
	p := DefaultScoreParams()
	if q := QualityScore(0, 0, 0, p); q != 1.0 {
		t.Fatalf("zero-sample quality = %v, want 1.0", q)
	}
	if q := QualityScore(0, 4, 0, p); q != 1.0 {
		t.Fatalf("4-sample quality = %v, want 1.0 (below minSamples)", q)
	}
}

func TestScore_Ordering(t *testing.T) {
	p := DefaultScoreParams()
	fast := QualityScore(10, 0, int64(500*time.Millisecond), p) // sr=1, lf=0.8
	slow := QualityScore(10, 0, int64(4*time.Second), p)        // sr=1, lf=1/3
	flaky := QualityScore(3, 7, int64(500*time.Millisecond), p) // sr=0.3, lf=0.8
	if !(fast > slow && slow > flaky) {
		t.Fatalf("ordering violated: fast=%v slow=%v flaky=%v", fast, slow, flaky)
	}
	// Spot values: fast ~= 0.8, slow ~= 0.333, flaky ~= 0.24.
	if fast < 0.79 || fast > 0.81 {
		t.Fatalf("fast quality = %v, want ~0.8", fast)
	}
	if slow < 0.33 || slow > 0.34 {
		t.Fatalf("slow quality = %v, want ~0.333", slow)
	}
}

func TestScore_EffectiveLoad(t *testing.T) {
	p := DefaultScoreParams()
	healthy := EffectiveLoad(0, 1.0, p.MinQuality)
	sick := EffectiveLoad(0, 0.05, p.MinQuality) // floored to 0.1 -> 10x
	if sick != 10*healthy {
		t.Fatalf("sick=%v healthy=%v, want 10x ratio", sick, healthy)
	}
	// Load still matters: 9 in-flight on healthy (10/1) ties idle-sick (1/0.1).
	if got := EffectiveLoad(9, 1.0, p.MinQuality); got != sick {
		t.Fatalf("loaded healthy = %v, want %v", got, sick)
	}
	// Non-positive minQ falls back to the default instead of dividing by zero.
	if got := EffectiveLoad(0, 0.0, 0); got != 10.0 {
		t.Fatalf("zero minQ load = %v, want 10.0", got)
	}
}

func TestScore_TieDeterminism(t *testing.T) {
	p := DefaultScoreParams()
	a := EffectiveLoad(2, QualityScore(6, 1, int64(time.Second), p), p.MinQuality)
	b := EffectiveLoad(2, QualityScore(6, 1, int64(time.Second), p), p.MinQuality)
	if a != b {
		t.Fatalf("identical inputs differ: %v vs %v", a, b)
	}
}
