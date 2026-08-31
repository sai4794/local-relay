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

// Registry holds labeled counters. Keys are pre-baked series names:
// "lano_requests_total{instance=\"1\",status=\"200\"}".
type Registry struct {
	mu   sync.Mutex
	vals map[string]*atomic.Int64
}

// New returns a fresh registry.
func New() *Registry {
	return &Registry{vals: make(map[string]*atomic.Int64)}
}

// Default is the process-wide registry used by backend and proxy layers.
var defaultRegistry = New()

// Default returns the process-wide registry.
func Default() *Registry { return defaultRegistry }

// Inc increments a labeled series by 1.
func (r *Registry) Inc(name string, labels map[string]string) {
	key := formatSeries(name, labels)
	r.mu.Lock()
	c, ok := r.vals[key]
	if !ok {
		c = &atomic.Int64{}
		r.vals[key] = c
	}
	r.mu.Unlock()
	c.Add(1)
}

// IncN increments by n.
func (r *Registry) IncN(name string, labels map[string]string, n int64) {
	key := formatSeries(name, labels)
	r.mu.Lock()
	c, ok := r.vals[key]
	if !ok {
		c = &atomic.Int64{}
		r.vals[key] = c
	}
	r.mu.Unlock()
	c.Add(n)
}

// Set installs a gauge value for a labeled series.
func (r *Registry) Set(name string, labels map[string]string, v int64) {
	key := formatSeries(name, labels)
	r.mu.Lock()
	c, ok := r.vals[key]
	if !ok {
		c = &atomic.Int64{}
		r.vals[key] = c
	}
	r.mu.Unlock()
	c.Store(v)
}

// Render writes all series in Prometheus text exposition format, sorted.
// Name/labels are opaque: help lines are emitted generically.
func (r *Registry) Render(w io.Writer) {
	r.mu.Lock()
	keys := make([]string, 0, len(r.vals))
	for k := range r.vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		name := k
		if i := strings.Index(k, "{"); i >= 0 {
			name = k[:i]
		}
		fmt.Fprintf(w, "# TYPE %s counter\n", name)
		fmt.Fprintf(w, "%s %d\n", k, r.vals[k].Load())
	}
	r.mu.Unlock()
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
