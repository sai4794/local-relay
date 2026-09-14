package backend

import (
	"context"
	"net"
	"time"
)

// EndpointClaim carries the scored-selection attribution for one dial: which
// endpoint served it, in which circuit generation, and how long the dial
// took. The proxy layer attaches the claim at dial time (via ClaimFrom) and
// returns it with the outcome (via Outcome), so success AND failure samples
// attribute to the endpoint that actually served the request — replacing the
// legacy ReportAnomaly(-1) guess with an attributed sample.
type EndpointClaim struct {
	// OK is false for zero-value / direct-backend dials: callers must skip
	// outcome reporting when !OK so bypass traffic never pollutes Tor stats.
	OK bool
	// Backend names the serving backend ("multitor" or "pool"); "direct"
	// claims are never reported.
	Backend string
	// ID is the 1-based instance ID (multitor) or slot index (pool).
	ID int
	// Gen is the circuit generation at dial time; outcomes from a stale
	// generation are dropped (the endpoint has rotated since).
	Gen int64
	// Latency is the dial latency sample (time to established SOCKS tunnel).
	Latency time.Duration
	// DialedAt is the wall time the dial completed.
	DialedAt time.Time
}

// endpointClaimKey carries the per-attempt claim sink for outcome
// attribution. The proxy stores a *EndpointClaim before dialing; the serving
// backend fills it when the dial succeeds. Pointer (not value) semantics so
// the fill is visible to the dialer even when the conn itself is hidden
// inside http.Transport. Retries use a fresh sink per attempt so each
// attempt attributes separately.
type endpointClaimKey struct{}

// WithEndpointClaim stores sink as the claim carrier for the current attempt
// and returns the derived context. A nil sink disables attribution (the
// backend skips the fill). The sink must be attempt-scoped: sharing one
// across retries would let a later attempt overwrite an earlier sample.
func WithEndpointClaim(ctx context.Context, sink *EndpointClaim) context.Context {
	return context.WithValue(ctx, endpointClaimKey{}, sink)
}

// ClaimFrom returns the claim sink attached to ctx, or nil when none was
// recorded — e.g. direct-backend dials, which the proxy creates without a
// carrier so bypass traffic never pollutes Tor stats.
func ClaimFrom(ctx context.Context) *EndpointClaim {
	sink, _ := ctx.Value(endpointClaimKey{}).(*EndpointClaim)
	return sink
}

// fillClaimSink records the serving endpoint into the ctx carrier, if any.
// Called by backends on the serving instance after a successful dial; a nil
// ctx carrier (or nil ctx value) skips silently. Dial latency is measured by
// the caller from dial entry to established SOCKS tunnel.
func fillClaimSink(ctx context.Context, backend string, id int, gen int64, latency time.Duration) {
	if ctx == nil {
		return
	}
	sink, _ := ctx.Value(endpointClaimKey{}).(*EndpointClaim)
	if sink == nil {
		return
	}
	*sink = EndpointClaim{
		OK:       true,
		Backend:  backend,
		ID:       id,
		Gen:      gen,
		Latency:  latency,
		DialedAt: time.Now(),
	}
}

// Outcome is one attributed request result for ReportOutcome: the claim that
// served it plus whether the request proved the circuit works.
type Outcome struct {
	// ID/Gen re-state the serving claim (generation-stale outcomes drop).
	ID  int
	Gen int64
	// Success means the request proved the circuit works (dial + response
	// that is not a circuit signal). 429/503 and dead tunnels are failures;
	// other 4xx/5xx prove the circuit works and report success.
	Success bool
	// Latency is the dial latency sample, recorded on success only (failure
	// latency mixes fast-refused with slow-timeout and would pollute EWMA).
	Latency time.Duration
	// Status is the upstream HTTP status (0 when not HTTP / unknown).
	Status int
	// BytesUp/BytesDown count tunneled bytes for dead-tunnel heuristics.
	BytesUp   int64
	BytesDown int64
}

// OutcomeReporter is an optional interface backends implement to receive
// attributed outcomes from the proxy layer. ReportOutcome must be
// non-blocking (registry writes under mutex are fine off the hot path;
// control-port I/O must stay fire-and-forget as in ReportAnomaly) and must
// never panic on unknown IDs — drop them.
type OutcomeReporter interface {
	ReportOutcome(Outcome)
}

// EndpointFromConn walks the Unwrap() net.Conn chain exactly like TuneTCP
// (tcp.go) and returns the serving endpoint's ID, generation, and dial
// latency when the chain bottoms out at a scored wrapper (inFlightConn or
// pooledConnWrap). It reports ok=false for bare / foreign conns (e.g.
// direct-backend dials) so callers skip outcome reporting.
func EndpointFromConn(conn net.Conn) (id int, gen int64, latency time.Duration, ok bool) {
	for conn != nil {
		switch c := conn.(type) {
		case *inFlightConn:
			return c.endpointID, c.endpointGen, c.dialLatency, c.endpointID > 0
		case *pooledConnWrap:
			return c.endpointID, c.endpointGen, c.dialLatency, c.endpointID >= 0
		}
		u, isUnwrapper := conn.(interface{ Unwrap() net.Conn })
		if !isUnwrapper {
			break
		}
		conn = u.Unwrap()
	}
	return 0, 0, 0, false
}
