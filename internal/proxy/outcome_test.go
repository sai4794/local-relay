package proxy

import (
	"testing"

	"github.com/local-relay/proxy/internal/backend"
)

// TestReportOutcome_Skips exercises every skip gate: none of these may
// forward (verified by the backend-attr test below using a fake
// OutcomeReporter through a real Router) or panic.
func TestReportOutcome_Skips(t *testing.T) {
	var none *backend.Router
	// Nil router / nil claim / !OK / direct / 413 all skip without panic.
	reportOutcome(none, nil, true, 200, 0, 0)
	reportOutcome(nil, &backend.EndpointClaim{OK: true, Backend: "multitor", ID: 1}, true, 200, 0, 0)
	reportOutcome(nil, &backend.EndpointClaim{}, true, 200, 0, 0)
	reportOutcome(nil, &backend.EndpointClaim{OK: true, Backend: "direct", ID: 1}, true, 200, 0, 0)
	reportOutcome(nil, &backend.EndpointClaim{OK: true, Backend: "multitor", ID: 1}, true, 413, 0, 0)
}

func TestClaimOutcome_StatusMapping(t *testing.T) {
	claim := &backend.EndpointClaim{OK: true, Backend: "multitor", ID: 2, Gen: 5}
	for _, tc := range []struct {
		status int
		wantOK bool
	}{
		{200, true},
		{500, true}, // upstream 5xx proves the circuit works
		{404, true},
		{429, false},
		{503, false},
	} {
		o, ok := claimOutcome(claim, tc.status)
		if !ok {
			t.Fatalf("status %d: ok=false, want true", tc.status)
		}
		if o.Success != tc.wantOK || o.ID != 2 || o.Gen != 5 || o.Status != tc.status {
			t.Fatalf("status %d: outcome=%+v, want success=%v id=2 gen=5", tc.status, o, tc.wantOK)
		}
	}
	if _, ok := claimOutcome(nil, 200); ok {
		t.Fatal("nil claim: ok=true, want false")
	}
	if _, ok := claimOutcome(&backend.EndpointClaim{}, 200); ok {
		t.Fatal("!OK claim: ok=true, want false")
	}
}
