package backend

import (
	"testing"
	"time"
)

// A 20s-spike among 0.5s dials must not flip the pick: one slow sample
// cannot outweigh an established healthy history (EWMA + minSamples gate).
func TestAdversarial_SpikeDoesNotFlipPick(t *testing.T) {
	p := DefaultScoreParams()
	var healthy, spiked EndpointStats
	for i := 0; i < 20; i++ {
		healthy.Record(true, 500*time.Millisecond, p.Alpha)
	}
	for i := 0; i < 20; i++ {
		spiked.Record(true, 500*time.Millisecond, p.Alpha)
	}
	spiked.Record(true, 20*time.Second, p.Alpha) // one spike

	qH := QualityScore(healthy.Successes(), healthy.Failures(), int64(healthy.LatencyEWMA()), p)
	qS := QualityScore(spiked.Successes(), spiked.Failures(), int64(spiked.LatencyEWMA()), p)
	if qS >= qH {
		t.Fatalf("spike flipped quality: spiked=%v healthy=%v", qS, qH)
	}
	if effS, effH := EffectiveLoad(0, qS, p.MinQuality), EffectiveLoad(0, qH, p.MinQuality); effS < effH {
		t.Fatalf("spike flipped pick: spiked eff=%v healthy eff=%v", effS, effH)
	}
	// And the gap is small: a single 20s sample moves EWMA only by alpha.
	if got := spiked.LatencyEWMA(); got > 5*time.Second {
		t.Fatalf("spike EWMA = %v, want <= 5s (alpha-damped)", got)
	}
}

// Sustained 8s dials flip the pick within ~5 dials: after minSamples slow
// samples the latency factor dominates and effective load separates.
func TestAdversarial_SustainedSlownessFlips(t *testing.T) {
	p := DefaultScoreParams()
	var fast, slow EndpointStats
	for i := 0; i < 5; i++ {
		fast.Record(true, 500*time.Millisecond, p.Alpha)
	}
	flippedAt := -1
	for i := 0; i < 10; i++ {
		slow.Record(true, 8*time.Second, p.Alpha)
		qF := QualityScore(fast.Successes(), fast.Failures(), int64(fast.LatencyEWMA()), p)
		qS := QualityScore(slow.Successes(), slow.Failures(), int64(slow.LatencyEWMA()), p)
		if EffectiveLoad(0, qS, p.MinQuality) > EffectiveLoad(0, qF, p.MinQuality) {
			flippedAt = i + 1
			break
		}
	}
	if flippedAt < 0 || flippedAt > 5 {
		t.Fatalf("slow endpoint flipped at dial %d, want within 5", flippedAt)
	}
}

// A flapping endpoint (alternating success/failure) trips the consecutive
// gate without oscillation: once quarantined, further failures suppress
// (no re-entry churn) until the hold expires.
func TestAdversarial_FlapQuarantinesWithoutOscillation(t *testing.T) {
	var q endpointQuarantine
	cfg := DefaultQuarantineConfig()
	entries := 0
	for i := 0; i < 20; i++ {
		if i%2 == 0 {
			if q.recordFailure(cfg.AfterFails) {
				if _, entered := q.enterQuarantine(time.Now(), cfg.Duration, cfg.MaxDuration); entered {
					entries++
				}
			}
		} else {
			q.recordSuccess()
			// Success while Active clears consec: flap never accumulates
			// to the gate while succeeding every other dial... unless the
			// burst below lands consecutively.
		}
	}
	// Interleaved singles never quarantine (consec resets each success).
	if entries != 0 {
		t.Fatalf("interleaved flap entered quarantine %d times, want 0", entries)
	}
	// A consecutive burst does — exactly once, then suppresses.
	for i := 0; i < int(cfg.AfterFails); i++ {
		if q.recordFailure(cfg.AfterFails) {
			if _, entered := q.enterQuarantine(time.Now(), cfg.Duration, cfg.MaxDuration); entered {
				entries++
			}
		}
	}
	if entries != 1 {
		t.Fatalf("burst entries = %d, want exactly 1", entries)
	}
	for i := 0; i < 10; i++ {
		if q.recordFailure(cfg.AfterFails) {
			if _, entered := q.enterQuarantine(time.Now(), cfg.Duration, cfg.MaxDuration); entered {
				entries++
			}
		}
	}
	if entries != 1 {
		t.Fatalf("post-entry storm entries = %d, want still 1 (no oscillation)", entries)
	}
}

// An all-sick pool still serves (never score-induced fail-closed): every
// candidate quarantined still yields the least-bad one from selectInstance.
func TestAdversarial_AllSickStillServes(t *testing.T) {
	lc := NewTorLifecycle(TorLifecycleConfig{
		Binary: "true", DataDir: t.TempDir(),
		BasePort: 0, ControlBase: 0, MaxInstances: 2, Logf: func(string, ...interface{}) {},
	})
	for i := 1; i <= 2; i++ {
		lc.instances = append(lc.instances, &TorInstance{ID: i, Ready: true, StartedAt: time.Now()})
	}
	m := NewMultiTorBackend(lc, time.Second, func(string, ...interface{}) {})
	p := DefaultScoreParams()
	m.SetScoreParams(p)
	// Sicken both hard: high failures + slow EWMA + quarantine entry.
	for _, inst := range lc.instances {
		for i := 0; i < 10; i++ {
			inst.RecordDialOutcome(false, 0, p.Alpha)
		}
		for i := 0; i < 10; i++ {
			inst.RecordDialOutcome(true, 8*time.Second, p.Alpha)
		}
		inst.quar.recordFailure(1)
		inst.quar.enterQuarantine(time.Now(), time.Hour, time.Hour)
	}
	got, _ := m.selectInstance(lc.instances)
	if got == nil {
		t.Fatal("all-sick selection = nil, want least-bad server (never score-induced fail-closed)")
	}
}
