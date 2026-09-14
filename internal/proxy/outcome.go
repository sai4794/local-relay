package proxy

import (
	"context"
	"strings"
	"time"

	"github.com/local-relay/proxy/internal/backend"
)

// probeHeartbeatInterval is the probe-claim renewal tick for long-lived
// tunnels: 30s = default 120s expiry budget / 4, so a live tunnel renews
// several times per budget while a dead holder still expires within ~1
// budget (worst case one steal window late). renewProbe no-ops unless the
// endpoint is in Probation with the slot held, so the tick is behavior-free
// for all non-probation traffic — just one atomic store per 30s per tunnel.
const probeHeartbeatInterval = 30 * time.Second

// reportOutcome forwards one attributed outcome to the router, skipping
// everything that must never pollute Tor stats:
//
//   - claim == nil or !claim.OK: no serving endpoint recorded (direct/
//     bypass dials, unclaimed transports) — nothing to attribute.
//   - Backend == "direct": bypass traffic proves nothing about Tor exits.
//   - status == 413: client error (body over cap), not a dead circuit.
//
// ReportOutcome itself fan-outs to OutcomeReporter backends, which
// self-filter by ID/gen; unknown IDs drop without panic.
func reportOutcome(router *backend.Router, claim *backend.EndpointClaim, success bool, status int, up, down int64) {
	if router == nil || claim == nil || !claim.OK {
		return
	}
	if claim.Backend == "direct" {
		return
	}
	if status == 413 {
		return
	}
	router.ReportOutcome(backend.Outcome{
		ID:        claim.ID,
		Gen:       claim.Gen,
		Success:   success,
		Latency:   claim.Latency,
		Status:    status,
		BytesUp:   up,
		BytesDown: down,
	})
}

// reportAnomalyForTor rotates the Tor control plane after a failure on the
// Tor-served path. Dial failures never fill the claim sink (fillClaimSink
// runs only on successful dials, and the backend records the err sample
// itself), so the claim alone cannot tell Tor from direct on the failure
// path. Gate in two layers: a filled claim decides by its Backend
// ("direct" never rotates — a failing bypass/direct dial proves nothing
// about Tor exits); an unfilled claim falls back to the router bypass
// verdict on host (no fresh DNS — IsBypassHost is the normalized map
// lookup). host must be the hostname WITHOUT port (router.IsBypassHost
// does not strip ports); pass "" only when no hostname exists, which
// preserves the legacy rotate behavior. Nil router always skips.
func reportAnomalyForTor(router *backend.Router, host string, claim *backend.EndpointClaim) {
	if router == nil {
		return
	}
	if claim != nil && claim.OK {
		if claim.Backend == "direct" {
			return
		}
		router.ReportAnomaly(-1)
		return
	}
	if host != "" && router.IsBypassHost(host) {
		return
	}
	router.ReportAnomaly(-1)
}

// renewClaim heartbeats the serving probe claim while a tunnel is alive:
// same skip gates as reportOutcome (nil router, nil/!OK claim, direct
// backend never renews — bypass traffic holds no probe). A false return is
// fine (unknown ID, stale gen, or endpoint not in probation with a held
// slot): the terminal outcome still resolves the probe.
func renewClaim(router *backend.Router, claim *backend.EndpointClaim) {
	if router == nil || claim == nil || !claim.OK {
		return
	}
	if claim.Backend == "direct" {
		return
	}
	router.RenewProbe(claim.ID, claim.Gen)
}

// startProbeHeartbeat ticks renewClaim every probeHeartbeatInterval until
// ctx ends, returning a stop func. The constructor returns nil when the
// claim can hold no probe (nil/!OK/direct), so non-probation-eligible
// tunnels pay zero goroutines. The ticker's goroutine selects on ctx.Done —
// callers pass the already-cancelled relay ctx (relayConn's 30m timeout,
// SOCKS5's client-cancel ctx), so no goroutine outlives the tunnel; the
// deferred stop is belt-and-braces for early returns.
func startProbeHeartbeat(ctx context.Context, router *backend.Router, claim *backend.EndpointClaim) func() {
	if ctx == nil || router == nil || claim == nil || !claim.OK {
		return nil
	}
	if claim.Backend == "direct" {
		return nil
	}
	ctx, cancel := context.WithCancel(ctx)
	ticker := time.NewTicker(probeHeartbeatInterval)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				renewClaim(router, claim)
			}
		}
	}()
	return func() { cancel(); <-done }
}

// claimSuccess is the single terminal-status classifier: 429/503 are
// circuit signals (failure); every other status — including other 4xx/5xx —
// proves the circuit works (success). All live call sites go through it so
// the mapping cannot drift between the retry path, the terminal path, and
// the SSE path.
func claimSuccess(status int) bool {
	return status != 429 && status != 503
}

// claimOutcome converts a serving claim + request result into the success
// bit: 429/503 are circuit signals (failure); every other status —
// including other 4xx/5xx — proves the circuit works (success).
func claimOutcome(claim *backend.EndpointClaim, status int) (backend.Outcome, bool) {
	if claim == nil || !claim.OK {
		return backend.Outcome{}, false
	}
	o := backend.Outcome{
		ID:      claim.ID,
		Gen:     claim.Gen,
		Latency: claim.Latency,
		Status:  status,
	}
	o.Success = status != 429 && status != 503
	return o, true
}

// isDialFailureErr reports whether a dial error smells like a dead circuit
// (timeout/refused/reset/exhausted) rather than a client-side error (bad
// host, blocked target). Shared by the HTTP CONNECT and SOCKS5 dial-failure
// rotation gates so both front-ends churn on the same signals.
func isDialFailureErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	for _, marker := range []string{
		"timeout",
		"connection refused",
		"connection reset",
		"no healthy proxy",
	} {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return false
}
