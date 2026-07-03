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

// MultiTorBackend manages multiple Tor daemon instances and round-robins
// connections across them. Each instance runs on a separate SOCKS port,
// giving a different outbound IP address.
type MultiTorBackend struct {
	lifecycle    *TorLifecycle
	dialer       *net.Dialer
	counter      atomic.Int64
	lastInstance int32 // tracks which instance served the last request
	mu           sync.RWMutex
	logf         func(string, ...interface{})
	OnRotate     func() // called after NEWNYM to clear connection pools
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

	// Round-robin across ready instances
	idx := int(m.counter.Add(1)-1) % len(ready)
	inst := ready[idx]

	conn, err := m.dialer.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", inst.GetSocksPort()))
	if err != nil {
		m.logf("multi-tor: dial instance %d failed: %v", inst.ID, err)
		// Try next instance
		for i := 1; i < len(ready); i++ {
			nextIdx := (idx + i) % len(ready)
			inst = ready[nextIdx]
			conn, err = m.dialer.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", inst.GetSocksPort()))
			if err == nil {
				break
			}
			m.logf("multi-tor: dial instance %d failed: %v", inst.ID, err)
		}
		if err != nil {
			return nil, fmt.Errorf("all Tor instances failed: %w", err)
		}
	}

	TuneTCP(conn)
	m.lastInstance = int32(inst.ID)

	if err := m.socks5Handshake(conn, addr); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 handshake failed: %w", err)
	}

	inst.IncRequests()

	// Check if this instance needs rotation
	if m.lifecycle.rotateAfter > 0 && inst.GetRequests() >= int64(m.lifecycle.rotateAfter) {
		m.logf("multi-tor: instance %d reached %d requests, rotating circuit", inst.ID, inst.GetRequests())
		go func() {
			if err := m.lifecycle.RequestNewCircuit(inst); err != nil {
				m.logf("multi-tor: NEWNYM failed for instance %d: %v", inst.ID, err)
			}
			inst.mu.Lock()
			inst.Requests = 0
			inst.mu.Unlock()
		}()
	}

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
			"id":        inst.ID,
			"socks":     inst.GetSocksPort(),
			"ready":     inst.IsReady(),
			"requests":  inst.GetRequests(),
		}
	}
	return map[string]interface{}{
		"type":      "multi-tor",
		"instances": statuses,
		"ready":     m.lifecycle.GetReadyCount(),
		"total":     len(instances),
	}
}

// ReportAnomaly triggers circuit rotation for the specific instance that
// received the 429/503 error. Only rotates that instance, leaving others
// untouched since they are working fine.
func (m *MultiTorBackend) ReportAnomaly(slotIdx int) {
	// Get the instance that served the request
	lastID := int(atomic.LoadInt32(&m.lastInstance))
	if lastID == 0 {
		m.logf("multi-tor: anomaly reported but no instance tracked, rotating all")
		m.rotateAll()
		return
	}

	inst, ok := m.lifecycle.GetInstance(lastID)
	if !ok {
		m.logf("multi-tor: instance %d not found, rotating all", lastID)
		m.rotateAll()
		return
	}

	m.logf("multi-tor: 429 on instance %d (port %d), rotating only this instance", inst.ID, inst.SocksPort)
	if err := m.lifecycle.RequestNewCircuit(
		&TorInstance{ID: inst.ID, SocksPort: inst.SocksPort},
	); err != nil {
		m.logf("multi-tor: NEWNYM failed for instance %d: %v", inst.ID, err)
	} else {
		m.logf("multi-tor: instance %d circuit rotated", inst.ID)
	}

	// Clear connection pool so next request uses new circuit
	if m.OnRotate != nil {
		m.OnRotate()
	}
}

// rotateAll rotates all instances (used when no specific instance is tracked).
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
