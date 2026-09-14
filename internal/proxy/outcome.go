package proxy

import (
	"strings"

	"github.com/local-relay/proxy/internal/backend"
)

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
