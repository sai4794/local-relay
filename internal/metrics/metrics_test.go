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
