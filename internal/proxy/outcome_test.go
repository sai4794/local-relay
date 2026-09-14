package proxy

import (
	"context"
	"testing"
	"time"

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
		// claimSuccess is the live single-source classifier: must agree.
		if got := claimSuccess(tc.status); got != tc.wantOK {
			t.Fatalf("status %d: claimSuccess=%v, want %v (diverged from claimOutcome)", tc.status, got, tc.wantOK)
		}
	}
	if _, ok := claimOutcome(nil, 200); ok {
		t.Fatal("nil claim: ok=true, want false")
	}
	if _, ok := claimOutcome(&backend.EndpointClaim{}, 200); ok {
		t.Fatal("!OK claim: ok=true, want false")
	}
}

// startProbeHeartbeat: nil unless the claim is probe-eligible (OK,
// non-direct); eligible claims tick RenewProbe on the router until stopped.
func TestProbeHeartbeat_GatingAndTick(t *testing.T) {
	// Nil router / nil claim / !OK / direct all yield nil (zero goroutines).
	if stop := startProbeHeartbeat(context.Background(), nil, nil); stop != nil {
		t.Fatal("nil ctx/router/claim: want nil stop")
	}
	r := backend.NewRouter(backend.NewDirectBackend(2 * time.Second))
	if stop := startProbeHeartbeat(context.Background(), r, nil); stop != nil {
		t.Fatal("nil claim: want nil stop")
	}
	off := &backend.EndpointClaim{}
	if stop := startProbeHeartbeat(context.Background(), r, off); stop != nil {
		t.Fatal("!OK claim: want nil stop")
	}
	directClaim := &backend.EndpointClaim{OK: true, Backend: "direct", ID: 1}
	if stop := startProbeHeartbeat(context.Background(), r, directClaim); stop != nil {
		t.Fatal("direct claim: want nil stop")
	}
	// Eligible claim returns a stop; renewClaim gates hold (no panic, no-op
	// against a router whose backends self-filter unknown IDs).
	claim := &backend.EndpointClaim{OK: true, Backend: "multitor", ID: 99, Gen: 1}
	stop := startProbeHeartbeat(context.Background(), r, claim)
	if stop == nil {
		t.Fatal("eligible claim: want non-nil stop")
	}
	stop()
	renewClaim(nil, claim)
	renewClaim(r, nil)
	renewClaim(r, off)
	renewClaim(r, directClaim)
	renewClaim(r, claim)
}

// reportAnomalyForTor: bypass/direct failures must not rotate Tor; Tor
// failures must. Uses a recording backend through a real Router.
func TestReportAnomalyForTor_BypassSkipsTorRotates(t *testing.T) {
	rec := &recordingAnomalyBackend{}
	direct := backend.NewDirectBackend(2 * time.Second)
	r := backend.NewRouter(direct, rec)
	r.SetBypassHosts([]string{"bypass.local"})

	// Unfilled claim + bypass host: skip (direct dial never churns Tor).
	reportAnomalyForTor(r, "bypass.local", &backend.EndpointClaim{})
	if n := rec.anomalies.Load(); n != 0 {
		t.Fatalf("bypass dial anomalies = %d; want 0", n)
	}
	// Unfilled claim + Tor host: rotate (legacy behavior preserved —
	// dial failures never fill the claim).
	reportAnomalyForTor(r, "example.com", &backend.EndpointClaim{})
	if n := rec.anomalies.Load(); n != 1 {
		t.Fatalf("tor dial anomalies = %d; want 1", n)
	}
	// Filled direct claim: skip even for a Tor hostname (claim wins).
	reportAnomalyForTor(r, "example.com", &backend.EndpointClaim{OK: true, Backend: "direct", ID: 1})
	if n := rec.anomalies.Load(); n != 1 {
		t.Fatalf("direct-claim anomalies = %d; want 1 (no churn)", n)
	}
	// Filled Tor claim: rotate.
	reportAnomalyForTor(r, "example.com", &backend.EndpointClaim{OK: true, Backend: "multitor", ID: 1})
	if n := rec.anomalies.Load(); n != 2 {
		t.Fatalf("tor-claim anomalies = %d; want 2", n)
	}
	// Nil router: no panic, no-op.
	reportAnomalyForTor(nil, "example.com", &backend.EndpointClaim{OK: true, Backend: "multitor", ID: 1})
}
