package backend

import (
	"sync/atomic"
	"time"
)

// ScoreParams tunes latency/quality scoring for endpoint selection.
//
// Selection steers by effective load (see EffectiveLoad); quarantine excludes.
// The defaults below keep the steering gentle: a cold endpoint is neutral, a
// fully sick one costs at most 10x, and the score can never fail a dial
// closed (selection always serves the least-bad candidate).
type ScoreParams struct {
	// Alpha is the EWMA smoothing factor in (0,1]. 0.2 ~= 5-sample memory:
	// Tor dials are noisy (0.5-10s), so 0.5 flaps on one sample while 0.05
	// never adapts inside a rotate_after=50 window.
	Alpha float64
	// LatencyRef is the reference latency mapping to a latency factor of 0.5.
	// 2s centers the healthy band: 0.5s->0.8, 2s->0.5, 8s->0.2.
	LatencyRef time.Duration
	// MinSamples is the sample count below which quality reads neutral (1.0).
	// 5 reacts fast with N=3 without condemning on 1-2 samples.
	MinSamples int64
	// MinQuality floors quality inside EffectiveLoad, capping the steering
	// penalty at 1/MinQuality (default 10x). Score steers, quarantine excludes.
	MinQuality float64
}

// DefaultScoreParams returns the production scoring tuning.
func DefaultScoreParams() ScoreParams {
	return ScoreParams{
		Alpha:      0.2,
		LatencyRef: 2 * time.Second,
		MinSamples: 5,
		MinQuality: 0.1,
	}
}

// EndpointStats carries lock-free per-endpoint dial outcome counters plus a
// success-only EWMA of dial latency. All fields are atomics; the zero value
// is valid and reads cold (neutral). No locks, no I/O — safe on the hot
// dial path.
//
// Only successful dials feed the EWMA: failure latency mixes fast-refused
// with slow-timeout and would pollute the latency signal.
type EndpointStats struct {
	ewmaNs atomic.Int64
	ok     atomic.Int64
	err    atomic.Int64
}

// Record logs one dial outcome. On success the latency sample feeds the
// EWMA (first sample sets it directly via CAS, later samples blend with
// (1-alpha)*old + alpha*sample in a CAS loop). On failure only the error
// counter moves — the EWMA keeps its last success value. Out-of-range
// alpha values (>1 or <=0) fall back to 1.0 (direct set) so a misconfigured
// caller can never corrupt the accumulator.
func (s *EndpointStats) Record(success bool, latency time.Duration, alpha float64) {
	if success {
		s.ok.Add(1)
		sample := latency.Nanoseconds()
		if sample < 0 {
			sample = 0
		}
		if alpha <= 0 || alpha > 1 {
			alpha = 1.0
		}
		if alpha >= 1.0 {
			s.ewmaNs.Store(sample)
			return
		}
		for {
			old := s.ewmaNs.Load()
			var next int64
			if old <= 0 {
				// First sample (or a zero stored by a zero-latency first
				// sample): set directly so EWMA starts at the observation
				// instead of blending up from 0.
				next = sample
			} else {
				next = int64((1-alpha)*float64(old) + alpha*float64(sample))
			}
			if s.ewmaNs.CompareAndSwap(old, next) {
				return
			}
		}
	} else {
		s.err.Add(1)
	}
}

// Successes returns the recorded success count.
func (s *EndpointStats) Successes() int64 { return s.ok.Load() }

// Failures returns the recorded failure count.
func (s *EndpointStats) Failures() int64 { return s.err.Load() }

// LatencyEWMA returns the success-only EWMA dial latency (0 = no samples).
func (s *EndpointStats) LatencyEWMA() time.Duration { return time.Duration(s.ewmaNs.Load()) }

// QualityScore combines success rate and latency into a [0,1] quality.
//
// total < minSamples reads cold-neutral (1.0): thin data must not skew
// traffic with N=3. Otherwise q = sr * lf where sr = ok/total and
// lf = ref/(ref+ewma) — 0.5s->0.8, 2s->0.5, 8s->0.2 at the default ref.
// A zero ref (misconfiguration) disables the latency factor (lf=1) instead
// of dividing by zero. Result is clamped to [0,1].
func QualityScore(ok, err int64, ewmaNs int64, p ScoreParams) float64 {
	total := ok + err
	if total < p.MinSamples {
		return 1.0
	}
	if total <= 0 {
		return 1.0
	}
	sr := float64(ok) / float64(total)
	var lf float64
	ref := p.LatencyRef.Nanoseconds()
	if ref <= 0 || ewmaNs <= 0 {
		lf = 1.0
	} else {
		lf = float64(ref) / (float64(ref) + float64(ewmaNs))
	}
	q := sr * lf
	if q < 0 {
		return 0
	}
	if q > 1 {
		return 1
	}
	return q
}

// EffectiveLoad converts in-flight load and quality into a single number for
// selection comparison: smaller wins. (inFlight+1) so idle-sick (1/q) still
// compares worse than idle-healthy (1/1); quality floored at minQ so the
// steering penalty caps at 1/minQ (default 10x). A non-positive minQ falls
// back to DefaultScoreParams().MinQuality so the divisor can never be zero.
func EffectiveLoad(inFlight int64, quality float64, minQ float64) float64 {
	if minQ <= 0 {
		minQ = DefaultScoreParams().MinQuality
	}
	if quality < minQ {
		quality = minQ
	}
	load := inFlight
	if load < 0 {
		load = 0
	}
	return float64(load+1) / quality
}
