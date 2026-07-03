package backend

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// MultiTorBackend manages multiple Tor daemon instances with sticky+failover
// routing. All requests go to one instance until it gets a 429, then failover
// to the next instance while the blocked one rotates in the background.
type MultiTorBackend struct {
	lifecycle    *TorLifecycle
	dialer       *net.Dialer
	counter      atomic.Int64
	mu           sync.RWMutex
	logf         func(string, ...interface{})
	OnRotate     func() // called after NEWNYM to clear connection pools

	// Sticky+failover state
	primaryIdx   int   // index into instances slice for current primary
	failedIDs    map[int]bool // instances that got 429, pending rotation
	failedMu     sync.Mutex
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
		lifecycle: lifecycle,
		dialer:    &net.Dialer{Timeout: timeout},
		logf:      logf,
		failedIDs: make(map[int]bool),
	}
}

// DialContext sends the request to the PRIMARY instance.
// If primary is failed, picks the next healthy instance.
func (m *MultiTorBackend) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	instances := m.lifecycle.GetInstances()
	if len(instances) == 0 {
		return nil, fmt.Errorf("no Tor instances available")
	}

	// Find a healthy instance starting from primary
	m.failedMu.Lock()
	failed := make(map[int]bool)
	for k, v := range m.failedIDs {
		failed[k] = v
	}
	m.failedMu.Unlock()

	var inst *TorInstance
	for i := 0; i < len(instances); i++ {
		idx := (m.primaryIdx + i) % len(instances)
		candidate := instances[idx]
		if candidate.IsReady() && !failed[candidate.ID] {
			inst = candidate
			m.primaryIdx = idx
			break
		}
	}

	if inst == nil {
		// All instances failed — try any ready one
		for _, candidate := range instances {
			if candidate.IsReady() {
				inst = candidate
				break
			}
		}
	}

	if inst == nil {
		return nil, fmt.Errorf("no healthy Tor instances available")
	}

	conn, err := m.dialer.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", inst.GetSocksPort()))
	if err != nil {
		m.logf("multi-tor: dial instance %d failed: %v", inst.ID, err)
		return nil, fmt.Errorf("tor dial failed: %w", err)
	}

	TuneTCP(conn)

	if err := m.socks5Handshake(conn, addr); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 handshake failed: %w", err)
	}

	inst.IncRequests()
	return conn, nil
}

func (m *MultiTorBackend) socks5Handshake(conn net.Conn, targetAddr string) error {
	var buf [300]byte
	n := 0

	buf[n], buf[n+1], buf[n+2] = 0x05, 0x01, 0x00
	n += 3

	if _, err := conn.Write(buf[:n]); err != nil {
		return err
	}

	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return err
	}

	if resp[0] != 0x05 || resp[1] != 0x00 {
		return fmt.Errorf("socks5 auth failed: %x", resp)
	}

	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return err
	}

	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	n = 0
	buf[n], buf[n+1], buf[n+2], buf[n+3] = 0x05, 0x01, 0x00, 0x03
	n += 4
	hostLen := len(host)
	if hostLen > 255 {
		return fmt.Errorf("host too long: %d bytes", hostLen)
	}
	buf[n] = byte(hostLen)
	n++
	copy(buf[n:], host)
	n += hostLen
	buf[n], buf[n+1] = byte(port>>8), byte(port&0xff)
	n += 2

	if _, err := conn.Write(buf[:n]); err != nil {
		return err
	}

	var reply [10]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return err
	}

	if reply[1] != 0x00 {
		return fmt.Errorf("socks5 connect failed: %d", reply[1])
	}

	return nil
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
	m.failedMu.Lock()
	failedCount := len(m.failedIDs)
	m.failedMu.Unlock()
	return map[string]interface{}{
		"type":      "multi-tor",
		"instances": statuses,
		"ready":     m.lifecycle.GetReadyCount(),
		"total":     len(instances),
		"failed":    failedCount,
		"primary":   m.primaryIdx,
	}
}

// ReportAnomaly handles 429/503 by marking the current primary as failed
// and failover to the next healthy instance. The failed instance rotates
// its circuit in the background.
func (m *MultiTorBackend) ReportAnomaly(slotIdx int) {
	instances := m.lifecycle.GetInstances()
	if len(instances) == 0 {
		return
	}

	// Mark current primary as failed
	m.failedMu.Lock()
	currentIdx := m.primaryIdx % len(instances)
	currentInst := instances[currentIdx]
	m.failedIDs[currentInst.ID] = true
	m.failedMu.Unlock()

	m.logf("multi-tor: 429 on instance %d (port %d), failover to next", currentInst.ID, currentInst.GetSocksPort())

	// Rotate the failed instance in background
	go func(inst *TorInstance) {
		m.logf("multi-tor: rotating instance %d in background", inst.ID)
		if err := m.lifecycle.RequestNewCircuit(
			&TorInstance{ID: inst.ID, SocksPort: inst.SocksPort},
		); err != nil {
			m.logf("multi-tor: NEWNYM failed for instance %d: %v", inst.ID, err)
		} else {
			m.logf("multi-tor: instance %d circuit rotated", inst.ID)
			// Clear from failed list after rotation
			m.failedMu.Lock()
			delete(m.failedIDs, inst.ID)
			m.failedMu.Unlock()
		}
	}(currentInst)

	// Advance primary to next healthy instance
	m.advancePrimary(instances)

	// Clear connection pool
	if m.OnRotate != nil {
		m.OnRotate()
	}
}

// advancePrimary moves primary to the next healthy instance.
func (m *MultiTorBackend) advancePrimary(instances []*TorInstance) {
	m.failedMu.Lock()
	failed := make(map[int]bool)
	for k, v := range m.failedIDs {
		failed[k] = v
	}
	m.failedMu.Unlock()

	for i := 1; i <= len(instances); i++ {
		idx := (m.primaryIdx + i) % len(instances)
		inst := instances[idx]
		if inst.IsReady() && !failed[inst.ID] {
			m.logf("multi-tor: failover from instance %d to %d", m.primaryIdx, idx)
			m.primaryIdx = idx
			return
		}
	}
	m.logf("multi-tor: all instances failed, will retry primary")
}

// rotateAll rotates all instances (fallback when no specific instance tracked).
func (m *MultiTorBackend) rotateAll() {
	for _, inst := range m.lifecycle.GetInstances() {
		if err := m.lifecycle.RequestNewCircuit(
			&TorInstance{ID: inst.ID, SocksPort: inst.SocksPort},
		); err != nil {
			m.logf("multi-tor: NEWNYM failed for instance %d: %v", inst.ID, err)
		} else {
			m.logf("multi-tor: instance %d circuit rotated", inst.ID)
		}
	}
	if m.OnRotate != nil {
		m.OnRotate()
	}
}
