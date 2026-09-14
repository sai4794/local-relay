package metrics

import (
	"strings"
	"testing"
)

func TestRegistryIncRender(t *testing.T) {
	r := New()
	r.Inc("lano_requests_total", map[string]string{"instance": "1"})
	r.Inc("lano_requests_total", map[string]string{"instance": "1"})
	r.Inc("lano_rotations_total", map[string]string{"instance": "2", "trigger": "anomaly"})

	var sb strings.Builder
	r.Render(&sb)
	out := sb.String()

	for _, want := range []string{
		`lano_requests_total{instance="1"} 2`,
		`lano_rotations_total{instance="2",trigger="anomaly"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q\noutput:\n%s", want, out)
		}
	}
}

func TestLabelEscape(t *testing.T) {
	if got := escapeLabel(`a"b\c` + "\n"); got != `a\"b\\c\n` {
		t.Errorf("escape = %q", got)
	}
}

func TestSetGauge(t *testing.T) {
	r := New()
	r.Set("lano_in_flight", map[string]string{"instance": "1"}, 7)
	var sb strings.Builder
	r.Render(&sb)
	if !strings.Contains(sb.String(), `lano_in_flight{instance="1"} 7`) {
		t.Errorf("gauge missing:\n%s", sb.String())
	}
}

// Kind exclusivity: a series is either counter or gauge (first writer
// wins); mixing Set+Inc on one series must be visible in the TYPE line so
// mis-wiring fails loudly instead of silently corrupting a dashboard.
func TestKindExclusivity(t *testing.T) {
	r := New()
	r.Set("lano_endpoint_quality", map[string]string{"instance": "1"}, 800)
	r.Inc("lano_endpoint_quality", map[string]string{"instance": "1"})
	var sb strings.Builder
	r.Render(&sb)
	out := sb.String()
	if !strings.Contains(out, "# TYPE lano_endpoint_quality gauge") {
		t.Errorf("mixed-kind series lost gauge TYPE, output:\n%s", out)
	}
	if !strings.Contains(out, `lano_endpoint_quality{instance="1"} 801`) {
		t.Errorf("mixed-kind value wrong, output:\n%s", out)
	}
}
