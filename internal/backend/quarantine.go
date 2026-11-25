package backend

import (
	"sync/atomic"
	"time"
)

// EndpointState is the quarantine/probation lifecycle of one endpoint.
// The zero value (Active) is the correct default for fresh instances.
type EndpointState int32

const (
	// StateActive serves normally and is eligible for scored selection.
	StateActive EndpointState = iota
	// StateQuarantined is excluded from selection until QuarantinedUntil;
	// promotion to Probation is lazy (time.Now comparison on the
	// selection/outcome paths) — no background timers or goroutines.
	StateQuarantined
	// StateProbation serves exactly one probe at a time: success returns to
	// Active, failure re-quarantines with doubled backoff (capped).
	StateProbation
	// StateDraining serves nothing and transitions to Closed on Close/kill.
	StateDraining
	// StateClosed is terminal (killed instance / closed pool).
	StateClosed
)

// String names the state for status output and metric labels.
func (s EndpointState) String() string {
	switch s {
	case StateActive:
		return "active"
	case StateQuarantined:
		return "quarantined"
	case StateProbation:
		return "probation"
	case StateDraining:
		return "draining"
	case StateClosed:
		return "closed"
	default:
		return "unknown"
	}
}

// QuarantineConfig tunes the quarantine/probation state machine.
type QuarantineConfig struct {
	// AfterFails is the consecutive-failure count entering quarantine.
	AfterFails int64
	// Duration is the base quarantine hold (doubled per consecutive
	// quarantine, capped at MaxDuration).
	Duration time.Duration
	// MaxDuration caps the exponential backoff.
	MaxDuration time.Duration
	// Probes is the number of successful probation probes returning to
	// Active (currently exactly 1; values > 1 reserve multi-probe).
	Probes int64
}

// DefaultQuarantineConfig returns the production quarantine tuning: 60s
// minimum sits well above the 10s NEWNYM cooldown and the 30s CheckHealth
// grace, so entry (which issues ONE attributed NEWNYM) never fights the
// existing rotation/health windows.
func DefaultQuarantineConfig() QuarantineConfig {
	return QuarantineConfig{
		AfterFails:  3,
		Duration:    60 * time.Second,
		MaxDuration: 300 * time.Second,
		Probes:      1,
	}
}

// endpointQuarantine is the lock-free quarantine state for one endpoint.
// All fields are atomics/CAS — no locks, no timers, no goroutines.
// Promotion is lazy: readers compare quarantinedUntil against time.Now and
// CAS-promote to Probation; an idle pool simply promotes late (harmless:
// idle endpoints lose nothing by promoting on next use).
type endpointQuarantine struct {
	state            atomic.Int32 // EndpointState
	consecFail       atomic.Int64
	quarantinedUntil atomic.Int64 // UnixNano; valid in Quarantined
	quarantineCount  atomic.Int64 // consecutive quarantines (backoff exponent)
	probeInFlight    atomic.Bool  // exactly one probation probe at a time
	probeAt          atomic.Int64 // UnixNano the current probe was claimed; expiry budget
}

// State returns the current lifecycle state.
func (q *endpointQuarantine) State() EndpointState {
	return EndpointState(q.state.Load())
}

// ConsecFails returns the consecutive failure count.
func (q *endpointQuarantine) ConsecFails() int64 { return q.consecFail.Load() }

// QuarantineCount returns the consecutive-quarantine backoff exponent.
func (q *endpointQuarantine) QuarantineCount() int64 { return q.quarantineCount.Load() }

// recordSuccess logs a success: clears consecutive failures AND backoff
// (a working endpoint re-earns the base duration), keeps EWMA (it decays
// on its own). In Probation, the first success returns to Active.
func (q *endpointQuarantine) recordSuccess() {
	q.consecFail.Store(0)
	q.quarantineCount.Store(0)
	q.probeInFlight.Store(false)
	q.state.CompareAndSwap(int32(StateProbation), int32(StateActive))
}

// recordFailure logs a failure and reports whether the caller must enter
// quarantine (transition Active->Quarantined performed by the caller via
// enterQuarantine). consecFails>=afterFails triggers; callers add the
// success-rate gate (total>=minSamples && sr<0.3) on top. While already
// quarantined, failures only bump the counter — no double-signal; the
// re-quarantine path (probation probe failure) doubles explicitly.
// Returns true when a fresh quarantine entry is required.
func (q *endpointQuarantine) recordFailure(afterFails int64) bool {
	if afterFails <= 0 {
		afterFails = DefaultQuarantineConfig().AfterFails
	}
	// Probation probe failure is handled by the caller (re-quarantine with
	// backoff); record the failure but don't trigger a fresh entry here.
	if q.State() == StateProbation {
		q.consecFail.Add(1)
		return false
	}
	n := q.consecFail.Add(1)
	if q.State() != StateActive {
		return false
	}
	return n >= afterFails
}

// enterQuarantine CAS-transitions Active->Quarantined, stamping until and
// bumping the backoff exponent. Returns true only to the winner (exactly
// one caller issues the entry NEWNYM). Duration is base<<count capped at
// max: first entry holds base, second 2x, then 4x... capped at max.
func (q *endpointQuarantine) enterQuarantine(now time.Time, base, max time.Duration) (until time.Time, entered bool) {
	if base <= 0 {
		base = DefaultQuarantineConfig().Duration
	}
	if max < base {
		max = base
	}
	if !q.state.CompareAndSwap(int32(StateActive), int32(StateQuarantined)) {
		return time.Time{}, false
	}
	n := q.quarantineCount.Add(1)
	d := base
	for i := int64(1); i < n && d < max; i++ {
		d *= 2
		if d > max || d <= 0 {
			d = max
			break
		}
	}
	until = now.Add(d)
	q.quarantinedUntil.Store(until.UnixNano())
	return until, true
}

// pollPromotion lazily promotes Quarantined->Probation once until has
// passed, WITHOUT claiming the probe slot: the caller that wins selection
// claims it via claimProbe (holder-only eligibility). Splitting promotion
// from claim is what makes the single-probe guarantee enforceable —
// otherwise every concurrent dialer sees probeInFlight=true and serves.
// Returns true only to the promoter (exactly one promoter per expiry).
func (q *endpointQuarantine) pollPromotion(now time.Time) bool {
	if q.State() != StateQuarantined {
		return false
	}
	if now.UnixNano() < q.quarantinedUntil.Load() {
		return false
	}
	return q.state.CompareAndSwap(int32(StateQuarantined), int32(StateProbation))
}

// claimProbe CAS-claims the single probation probe slot. Returns true only
// to the holder: exactly one dialer per probation window serves the sick
// endpoint; the rest must pick another candidate. The holder releases via
// recordSuccess (probe succeeded, back to Active) or requarantine path
// (probe failed). A holder that dies without reporting leaks the slot —
// callers must pair with probeExpiry (below).
func (q *endpointQuarantine) claimProbe(now time.Time) bool {
	if q.State() != StateProbation {
		return false
	}
	if !q.probeInFlight.CompareAndSwap(false, true) {
		return false
	}
	q.probeAt.Store(now.UnixNano())
	return true
}

// releaseClaim frees a probe slot this caller holds. Used when candidate
// evaluation claimed a probation probe but the candidate lost selection:
// without this, losing candidates keep probeInFlight=true until stale
// expiry and their only probe is suppressed (issue H-02).
func (q *endpointQuarantine) releaseClaim() {
	q.probeInFlight.CompareAndSwap(true, false)
}

// probeExpired reports whether the claimed probe slot outlived its budget
// without an outcome (holder died mid-dial). The budget is deliberately
// generous (2x the quarantine base, min 60s): dial-phase probes normally
// resolve in seconds, so expiry only fires for wedged holders. NOTE: the
// budget covers the DIAL + first-outcome window, not a full tunnel
// lifetime — established CONNECT/SOCKS tunnels hold their claim until
// their terminal outcome (relay close), and a second dialer must not
// steal the probe mid-tunnel. Long tunnels therefore extend the claim via
// renewProbe (heartbeat); expiry only fires when neither outcome nor
// heartbeat arrived within budget.
func (q *endpointQuarantine) probeExpired(now time.Time, base time.Duration) bool {
	if !q.probeInFlight.Load() {
		return false
	}
	if base <= 0 {
		base = DefaultQuarantineConfig().Duration
	}
	budget := 2 * base
	if budget < time.Minute {
		budget = time.Minute
	}
	return now.UnixNano()-q.probeAt.Load() > budget.Nanoseconds()
}

// releaseStaleProbe frees a wedged probe slot (holder died without
// reporting) so the endpoint can be re-probed instead of wedging in
// probation forever. Returns true only to the releaser. The endpoint stays
// in Probation — the next selection re-claims the slot for a fresh probe.
func (q *endpointQuarantine) releaseStaleProbe(now time.Time, base time.Duration) bool {
	if q.State() != StateProbation {
		return false
	}
	if !q.probeExpired(now, base) {
		return false
	}
	return q.probeInFlight.CompareAndSwap(true, false)
}

// renewProbe heartbeats a live probe claim (long tunnel still getting
// outcomes/bytes): extends the expiry budget so a legitimate slow probe
// is never mistaken for a wedged holder. Only the holder's path calls it;
// a non-holder's renew is a no-op returning false.
func (q *endpointQuarantine) renewProbe(now time.Time) bool {
	if q.State() != StateProbation || !q.probeInFlight.Load() {
		return false
	}
	q.probeAt.Store(now.UnixNano())
	return true
}

// eligibleForSelection is a conservative point-in-time predicate for
// non-selection callers (e.g. health summaries deciding whether an
// endpoint could serve right now). Active always; Probation only while a
// probe is actually held (claimed AND unexpired — an expired-but-unclaimed
// slot still needs releaseStaleProbe + claimProbe before serving);
// Quarantined only after expiry (promote first via pollPromotion).
// Draining/Closed never serve. NOTE: this is NOT the selection gate —
// selection must claim via claimProbe (holder-only), because this
// predicate returns true for every caller while a probe is held.
//
// Live callers: pool DialContext's complement fast path uses
// eligibleNoClaim instead (same verdict minus the Default-config probe
// budget — multitor's live quarCfg). This stays as the documented,
// unit-pinned semantic for external/advisory checks.
func (q *endpointQuarantine) eligibleForSelection(now time.Time) bool {
	switch q.State() {
	case StateActive:
		return true
	case StateProbation:
		return q.probeInFlight.Load() && !q.probeExpired(now, DefaultQuarantineConfig().Duration)
	case StateQuarantined:
		return now.UnixNano() >= q.quarantinedUntil.Load()
	default:
		return false
	}
}

// quarantineRemaining returns the hold left (<=0 when expired / not held).
func (q *endpointQuarantine) quarantineRemaining(now time.Time) time.Duration {
	return time.Unix(0, q.quarantinedUntil.Load()).Sub(now)
}
