package backend

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/local-relay/proxy/internal/transport"
)

// MultiTorBackend manages multiple Tor daemon instances and round-robins
// connections across them. Each instance runs on a separate SOCKS port,
// giving a different outbound IP address.
type MultiTorBackend struct {
	lifecycle   *TorLifecycle
	dialer      *net.Dialer
	socksClient *transport.SOCKS5Client
	counter     atomic.Int64
	mu          sync.RWMutex
	logf        func(string, ...interface{})
	OnRotate    func() // called after NEWNYM to clear connection pools
}

// NewMultiTorBackend creates a backend that routes through multiple Tor instances.
func NewMultiTorBackend(lifecycle *TorLifecycle, timeout time.Duration, logf func(string, ...interface{})) *MultiTorBackend {
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	if logf == nil {
		logf = func(string, ...interface{}) {}
	}
	return &MultiTorBackend{
		lifecycle:   lifecycle,
		dialer:      &net.Dialer{Timeout: timeout},
		socksClient: transport.NewSOCKS5Client(timeout),
		logf:        logf,
	}
}

// DialContext picks the next Tor instance round-robin and dials through its SOCKS port.
func (m *MultiTorBackend) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	instances := m.lifecycle.GetInstances()
	ready := make([]*TorInstance, 0)
	for _, inst := range instances {
		if inst.IsReady() {
			ready = append(ready, inst)
		}
	}

	if len(ready) == 0 {
		return nil, fmt.Errorf("no ready Tor instances")
	}

	// Avoid picking instance that was just rotated (still building new circuit)
	// Prefer fresh instances not rotated in last 5s; fallback to all if none fresh
	fresh := make([]*TorInstance, 0, len(ready))
	for _, inst := range ready {
		if time.Since(inst.GetLastRotated()) > 5*time.Second {
			fresh = append(fresh, inst)
		}
	}
	pickFrom := ready
	if len(fresh) > 0 {
		pickFrom = fresh
	}
	// Round-robin across pickable instances (mask sign bit to avoid negative index on overflow)
	idx := int((m.counter.Add(1)-1)&0x7fffffffffffffff) % len(pickFrom)
	inst := pickFrom[idx]
	// Map back to original ready idx for fallback loop if we used fresh subset.
	// Invariant: instance IDs are unique (derived from the spawn slot 1..N),
	// so the first ID match IS the picked instance.
	if len(fresh) > 0 {
		for i, r := range ready {
			if r.ID == inst.ID {
				idx = i
				break
			}
		}
	}

	// IsolateSOCKSAuth: per-request username ensures Tor builds distinct circuits
	// even with MaxCircuitDirtiness reuse; also prevents conflux mixing.
	isoUser := fmt.Sprintf("relay:%d:%d", inst.ID, time.Now().UnixNano())
	socksAddr := fmt.Sprintf("127.0.0.1:%d", inst.GetSocksPort())
	conn, err := m.socksClient.Connect(ctx, socksAddr, addr, isoUser)
	if err != nil {
		m.logf("multi-tor: dial instance %d failed: %v", inst.ID, err)
		// Try next instance with fresh isolation user
		for i := 1; i < len(ready); i++ {
			nextIdx := (idx + i) % len(ready)
			inst = ready[nextIdx]
			socksAddr = fmt.Sprintf("127.0.0.1:%d", inst.GetSocksPort())
			isoUser = fmt.Sprintf("relay:%d:%d", inst.ID, time.Now().UnixNano())
			conn, err = m.socksClient.Connect(ctx, socksAddr, addr, isoUser)
			if err == nil {
				break
			}
			m.logf("multi-tor: dial instance %d failed: %v", inst.ID, err)
		}
		if err != nil {
			return nil, fmt.Errorf("all Tor instances failed: %w", err)
		}
	}

	inst.IncRequests()

	// Check if this instance needs rotation (reset counter synchronously to prevent stampedes)
	if m.lifecycle.rotateAfter > 0 && inst.GetRequests() >= int64(m.lifecycle.rotateAfter) {
		inst.ResetRequests()

		m.logf("multi-tor: instance %d reached rotation threshold, rotating circuit", inst.ID)
		go func(target *TorInstance) {
			if err := m.lifecycle.RequestNewCircuit(target); err != nil {
				m.logf("multi-tor: auto-rotate NEWNYM failed for instance %d: %v", target.ID, err)
			}
		}(inst)
	}

	return conn, nil
}

// IsHealthy returns true if at least one Tor instance is ready.
func (m *MultiTorBackend) IsHealthy() bool {
	return m.lifecycle.GetReadyCount() > 0
}

// Close marks all instances as not ready.
func (m *MultiTorBackend) Close() error {
	return nil
}

// Status returns multi-tor backend status.
func (m *MultiTorBackend) Status() map[string]interface{} {
	instances := m.lifecycle.GetInstances()
	statuses := make([]map[string]interface{}, len(instances))
	for i, inst := range instances {
		statuses[i] = map[string]interface{}{
			"id":       inst.ID,
			"socks":    inst.GetSocksPort(),
			"ready":    inst.IsReady(),
			"requests": inst.GetRequests(),
		}
	}
	return map[string]interface{}{
		"type":      "multi-tor",
		"instances": statuses,
		"ready":     m.lifecycle.GetReadyCount(),
		"total":     len(instances),
	}
}

// ReportAnomaly triggers circuit rotation when a 429 or network error occurs on an instance.
// Only rotates the affected instance to prevent churning healthy circuits.
func (m *MultiTorBackend) ReportAnomaly(slotIdx int) {
	instances := m.lifecycle.GetInstances()
	if len(instances) == 0 {
		return
	}

	var target *TorInstance
	if slotIdx >= 0 && slotIdx < len(instances) {
		target = instances[slotIdx]
	} else {
		// If slotIdx is unknown (-1), prefer an instance that hasn't been rotated in the last 10s
		idx := int(m.counter.Load()&0x7fffffffffffffff) % len(instances)
		target = instances[idx]
		for i := 0; i < len(instances); i++ {
			cand := instances[(idx+i)%len(instances)]
			if time.Since(cand.GetLastRotated()) >= 10*time.Second {
				target = cand
				break
			}
		}
	}

	m.logf("multi-tor: anomaly reported (slot %d), triggering circuit rotation on instance %d", slotIdx, target.ID)
	if err := m.lifecycle.RequestNewCircuit(target); err != nil {
		m.logf("multi-tor: NEWNYM failed for instance %d: %v", target.ID, err)
	} else {
		m.logf("multi-tor: instance %d circuit rotated", target.ID)
		target.ResetRequests()
	}

	// Clear connection pool so new connections use new circuits
	if m.OnRotate != nil {
		m.OnRotate()
	}
}
