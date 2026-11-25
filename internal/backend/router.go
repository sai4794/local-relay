package backend

import (
	"context"
	"errors"
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

// normalizeBypassHost is the single canonicalizer for both config entries
// and lookup/dial hosts: lowercase, one trailing dot and IPv6 brackets
// removed. Keeping one function prevents the config and lookup paths from
// disagreeing about "[::1]" (issue L-01).
func normalizeBypassHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(host)
	host = strings.TrimSuffix(host, ".")
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	return strings.TrimSuffix(host, ".")
}

func (r *Router) SetBypassHosts(hosts []string) {
	r.bypassMu.Lock()
	// Canonicalize entries the same way every lookup normalizes (lowercase,
	// one trailing dot stripped): without this, a config entry "Example.COM."
	// would never match, silently routing that host through Tor instead of
	// direct — a fail-open routing surprise, not a block.
	r.bypassHosts = make([]string, len(hosts))
	r.bypassHostMap = make(map[string]bool, len(hosts)*2)
	for i, h := range hosts {
		h = normalizeBypassHost(h)
		r.bypassHosts[i] = h
		r.bypassHostMap[h] = true
		r.bypassHostMap["."+h] = true
	}
	r.bypassMu.Unlock()
	r.hasBypass.Store(len(hosts) > 0)
}

func (r *Router) isBypassHost(host string) bool {
	if r == nil || !r.hasBypass.Load() {
		return false
	}
	// Normalize exactly like the dial path and the proxy check path
	// (lowercase, IPv6 brackets stripped, one trailing dot stripped): without
	// this, an FQDN "example.com." matches at dial time but misses here, so
	// the proxy's bypass verdict and the router's would diverge.
	host = normalizeBypassHost(host)
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

// IsBypassHost is the exported consultation point for the proxy layer:
// it reports whether host is configured as a direct (bypass) destination.
// Behavior is identical to the internal isBypassHost check (nil-safe,
// case-insensitive, subdomain-aware); it exists so front-ends consult the
// shipped Router config instead of hardcoding localhost spellings.
func (r *Router) IsBypassHost(host string) bool {
	return r.isBypassHost(host)
}

func (r *Router) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if len(r.backends) == 0 && r.directBackend == nil {
		return nil, fmt.Errorf("no backends available")
	}

	// Normalize once: every branch below (bypass match, direct dial, proxied
	// dial) uses the same lowercase host instead of re-parsing/lowercasing.
	// IPv6 literals arrive bracketed ("[::1]:443"): SplitHostPort strips the
	// brackets, but a bare-literal address (no port) would keep them and MISS the
	// bypass match — so strip brackets from that fallback too. Without this,
	// "[::1]"-style addresses silently skip bypass and route through Tor
	// (or fail closed) instead of direct.
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	host = normalizeBypassHost(host)

	// Bypass hosts MUST go through direct backend — no fallback to Tor.
	// The proxy layer attaches its verified single-Lookup resolution to ctx
	// (see WithPinnedDial); DirectBackend dials those verified addresses
	// instead of re-resolving, closing the check→dial DNS flip window. TLS
	// SNI/Host still derive from the request URL hostname (not the dialed
	// address), so the presented identity is unchanged; requests without
	// pins dial exactly as before.
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
	var errs []error
	for _, b := range r.backends {
		if err := b.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if r.directBackend != nil {
		if err := r.directBackend.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
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

// ReportOutcome forwards one attributed request outcome to every proxied
// backend implementing OutcomeReporter. Backends self-filter by ID/gen
// (unknown IDs drop), so fan-out is safe with multiple backends. Backends
// without the interface (e.g. DirectBackend) are skipped.
func (r *Router) ReportOutcome(o Outcome) {
	for _, b := range r.backends {
		if or, ok := b.(OutcomeReporter); ok {
			or.ReportOutcome(o)
		}
	}
}

// RenewProbe fans a probe heartbeat out to every proxied backend
// implementing RenewReporter. Backends self-filter by ID/gen (unknown IDs
// and stale gens drop), so fan-out is safe with multiple backends —
// mirroring ReportOutcome. Backends without the interface are skipped.
func (r *Router) RenewProbe(id int, gen int64) {
	for _, b := range r.backends {
		if rr, ok := b.(RenewReporter); ok {
			rr.RenewProbe(id, gen)
		}
	}
}

// HasAnomalyReporter reports whether dial-failure anomaly signals are
// handled by a backend. With a single proxied backend it reports whether
// that backend implements AnomalyReporter; with multiple backends it
// reports whether any of them does.
func (r *Router) HasAnomalyReporter() bool {
	if r == nil || len(r.backends) == 0 {
		return false
	}
	if len(r.backends) == 1 {
		_, ok := r.backends[0].(AnomalyReporter)
		return ok
	}
	for _, b := range r.backends {
		if _, ok := b.(AnomalyReporter); ok {
			return true
		}
	}
	return false
}

// Backends returns all proxied backends for inspection.
func (r *Router) Backends() []Backend {
	return r.backends
}
