package backend

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
)

type Backend interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	IsHealthy() bool
	Close() error
}

type Router struct {
	backends      []Backend
	directBackend Backend
	bypassHosts   []string
	bypassHostMap map[string]bool
	bypassMu      sync.RWMutex
	current       atomic.Int64
	hasBypass     atomic.Bool
}

// NewRouter creates a router with an explicit direct (bypass) backend
// and one or more proxied backends.
func NewRouter(direct Backend, backends ...Backend) *Router {
	return &Router{
		backends:      backends,
		directBackend: direct,
	}
}

func (r *Router) SetBypassHosts(hosts []string) {
	r.bypassMu.Lock()
	r.bypassHosts = make([]string, len(hosts))
	r.bypassHostMap = make(map[string]bool, len(hosts)*2)
	for i, h := range hosts {
		h = strings.ToLower(h)
		r.bypassHosts[i] = h
		r.bypassHostMap[h] = true
		r.bypassHostMap["."+h] = true
	}
	r.bypassMu.Unlock()
	r.hasBypass.Store(len(hosts) > 0)
}

func (r *Router) isBypassHost(host string) bool {
	if !r.hasBypass.Load() {
		return false
	}
	host = strings.ToLower(host)
	r.bypassMu.RLock()
	defer r.bypassMu.RUnlock()
	if r.bypassHostMap[host] {
		return true
	}
	// Walk every dot position so any sub-depth (www.example.com,
	// a.b.example.com) matches a bypass entry "example.com" via its
	// stored ".example.com" key.
	for i := 0; i < len(host); i++ {
		if host[i] == '.' && r.bypassHostMap[host[i:]] {
			return true
		}
	}
	return false
}

func (r *Router) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if len(r.backends) == 0 && r.directBackend == nil {
		return nil, fmt.Errorf("no backends available")
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	// Bypass hosts MUST go through direct backend — no fallback to Tor
	if r.isBypassHost(host) {
		if r.directBackend != nil {
			conn, err := r.directBackend.DialContext(ctx, network, addr)
			if err == nil {
				return conn, nil
			}
			return nil, fmt.Errorf("bypass host dial failed (no Tor fallback): %w", err)
		}
		// No direct backend configured — block bypass host to prevent leak
		return nil, fmt.Errorf("bypass host blocked: no direct backend configured")
	}

	total := int64(len(r.backends))
	if total == 0 {
		// No proxy backends — use direct
		if r.directBackend != nil {
			return r.directBackend.DialContext(ctx, network, addr)
		}
		return nil, fmt.Errorf("no backends available")
	}

	cur := r.current.Load()

	for i := int64(0); i < total; i++ {
		idx := (cur + i) % total
		backend := r.backends[idx]

		if !backend.IsHealthy() {
			continue
		}

		conn, err := backend.DialContext(ctx, network, addr)
		if err == nil {
			r.current.Store((idx + 1) % total)
			return conn, nil
		}
	}

	// FAIL CLOSED: all proxy backends failed, do NOT fall back to direct.
	// This prevents silent traffic leaks outside Tor when the circuit
	// pool is exhausted or Tor is unavailable.
	return nil, fmt.Errorf("no healthy proxy backends — connection blocked (fail-closed)")
}

func (r *Router) IsHealthy() bool {
	if len(r.backends) > 0 {
		for _, b := range r.backends {
			if b.IsHealthy() {
				return true
			}
		}
		return false
	}
	if r.directBackend != nil && r.directBackend.IsHealthy() {
		return true
	}
	return false
}

func (r *Router) Close() error {
	for _, b := range r.backends {
		b.Close()
	}
	return nil
}

// AnomalyReporter is an optional interface backends can implement to
// receive rate-limit and anomaly signals from the proxy layer.
type AnomalyReporter interface {
	ReportAnomaly(slotIdx int)
}

// ReportAnomaly signals an anomaly (e.g. rate-limit) to the backend
// that served the last request.
func (r *Router) ReportAnomaly(idx int) {
	if len(r.backends) == 0 {
		return
	}
	// If exactly one proxied backend exists (e.g. MultiTor or CircuitPool),
	// pass the slot/instance index directly to it.
	if len(r.backends) == 1 {
		if ar, ok := r.backends[0].(AnomalyReporter); ok {
			ar.ReportAnomaly(idx)
		}
		return
	}
	if idx >= 0 && idx < len(r.backends) {
		if ar, ok := r.backends[idx].(AnomalyReporter); ok {
			ar.ReportAnomaly(idx)
		}
		return
	}
	if ar, ok := r.backends[0].(AnomalyReporter); ok {
		ar.ReportAnomaly(-1)
	}
}

// Backends returns all proxied backends for inspection.
func (r *Router) Backends() []Backend {
	return r.backends
}
