// Package metrics is a dependency-free Prometheus-style counter registry.
// The relay project avoids external metric deps; counters use atomics and
// the text exposition format is emitted directly by Render.
package metrics

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Registry holds labeled counters and gauges. Keys are pre-baked series names:
// "lano_requests_total{instance=\"1\",status=\"200\"}".
type Registry struct {
	mu   sync.Mutex
	vals map[string]*atomic.Int64
	// kinds records per-series kind: true = gauge (written via Set),
	// false/absent = counter (written via Inc/IncN). First writer wins;
	// production series are never mixed.
	kinds map[string]bool
}

// New returns a fresh registry.
func New() *Registry {
	return &Registry{vals: make(map[string]*atomic.Int64), kinds: make(map[string]bool)}
}

// Default is the process-wide registry used by backend and proxy layers.
var defaultRegistry = New()

// Default returns the process-wide registry.
func Default() *Registry { return defaultRegistry }

// Inc increments a labeled series by 1.
func (r *Registry) Inc(name string, labels map[string]string) {
	r.IncN(name, labels, 1)
}

// IncN increments by n.
func (r *Registry) IncN(name string, labels map[string]string, n int64) {
	r.IncKey(formatSeries(name, labels), n)
}

// IncKey increments a precomputed series key by n, skipping the
// formatSeries map/sort/escape work on hot paths where the key is stable
// (e.g. per-instance request counters with a single small label value).
func (r *Registry) IncKey(key string, n int64) {
	c := r.get(key, false)
	c.Add(n)
}

// Set installs a gauge value for a labeled series.
func (r *Registry) Set(name string, labels map[string]string, v int64) {
	c := r.get(formatSeries(name, labels), true)
	c.Store(v)
}

// get returns the counter for a pre-baked series key, creating it on first
// use. The mutex is held only for the map lookup/insert — never across I/O.
func (r *Registry) get(key string, gauge bool) *atomic.Int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.vals[key]
	if !ok {
		c = &atomic.Int64{}
		r.vals[key] = c
		r.kinds[key] = gauge
	}
	return c
}

type seriesSnapshot struct {
	name  string
	key   string
	gauge bool
	value int64
}

// Render writes all series in Prometheus text exposition format, sorted.
// Name/labels are opaque: help lines are emitted generically.
// The registry lock is held only while snapshotting values — never across
// network writes — so a slow scrape cannot stall hot-path Inc/Set callers.
func (r *Registry) Render(w io.Writer) {
	r.mu.Lock()
	snap := make([]seriesSnapshot, 0, len(r.vals))
	for k, c := range r.vals {
		name := k
		if i := strings.Index(k, "{"); i >= 0 {
			name = k[:i]
		}
		snap = append(snap, seriesSnapshot{name: name, key: k, gauge: r.kinds[k], value: c.Load()})
	}
	r.mu.Unlock()
	sort.Slice(snap, func(i, j int) bool { return snap[i].key < snap[j].key })
	lastType := ""
	for _, s := range snap {
		kind := "counter"
		if s.gauge {
			kind = "gauge"
		}
		if s.name != lastType {
			fmt.Fprintf(w, "# TYPE %s %s\n", s.name, kind)
			lastType = s.name
		}
		fmt.Fprintf(w, "%s %d\n", s.key, s.value)
	}
}

// formatSeries renders name{key="value",...} with sorted label keys.
func formatSeries(name string, labels map[string]string) string {
	if len(labels) == 0 {
		return name
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(name)
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(k)
		b.WriteString(`="`)
		b.WriteString(escapeLabel(labels[k]))
		b.WriteString(`"`)
	}
	b.WriteByte('}')
	return b.String()
}

func escapeLabel(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	return strings.ReplaceAll(v, "\n", `\n`)
}
