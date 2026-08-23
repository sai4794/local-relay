package backend

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/local-relay/proxy/internal/transport"
)

type TorBackend struct {
	addr          string
	control       *TorControlClient
	dialer        *net.Dialer
	socksClient   *transport.SOCKS5Client
	healthy       bool
	mu            sync.RWMutex
	circuitAge    int
	maxCircuitAge int
	lastCheck     time.Time
}

type TorConfig struct {
	Address           string
	ControlAddr       string
	ControlPass       string
	ControlCookiePath string
	Timeout           time.Duration
	MaxCircuitAge     int
}

func NewTorBackend(cfg TorConfig) *TorBackend {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.MaxCircuitAge == 0 {
		cfg.MaxCircuitAge = 100
	}
	if cfg.ControlAddr == "" {
		cfg.ControlAddr = "127.0.0.1:9051"
	}

	return &TorBackend{
		addr:          cfg.Address,
		control:       NewTorControlClient(cfg.ControlAddr, cfg.ControlPass, cookieFileProvider(cfg.ControlCookiePath)),
		dialer:        &net.Dialer{Timeout: cfg.Timeout},
		socksClient:   transport.NewSOCKS5Client(cfg.Timeout),
		healthy:       true,
		maxCircuitAge: cfg.MaxCircuitAge,
		lastCheck:     time.Now(),
	}
}

// cookieFileProvider adapts a static cookie path to the dynamic provider
// signature expected by TorControlClient.
func cookieFileProvider(path string) func() ([]byte, bool) {
	return func() ([]byte, bool) { return readCookieFile(path) }
}

func (t *TorBackend) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := t.socksClient.Connect(ctx, t.addr, addr, "")
	if err != nil {
		t.mu.Lock()
		t.healthy = false
		t.mu.Unlock()
		return nil, fmt.Errorf("tor dial failed: %w", err)
	}

	t.mu.Lock()
	t.circuitAge++
	t.healthy = true
	t.mu.Unlock()

	return conn, nil
}

// RequestNewCircuit signals NEWNYM over the control port, replacing the
// current circuit with a fresh one (new exit IP, subject to Tor's guard
// rotation policy).
func (t *TorBackend) RequestNewCircuit() error {
	if err := t.control.SignalNEWNYM(false); err != nil {
		return err
	}

	t.mu.Lock()
	t.circuitAge = 0
	t.mu.Unlock()

	return nil
}

func (t *TorBackend) IsHealthy() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.healthy
}

func (t *TorBackend) CheckHealth() bool {
	conn, err := net.DialTimeout("tcp", t.addr, 5*time.Second)
	if err != nil {
		t.mu.Lock()
		t.healthy = false
		t.mu.Unlock()
		return false
	}
	conn.Close()

	t.mu.Lock()
	t.healthy = true
	t.lastCheck = time.Now()
	t.mu.Unlock()
	return true
}

func (t *TorBackend) ShouldRotate() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.circuitAge >= t.maxCircuitAge
}

func (t *TorBackend) Close() error {
	t.mu.Lock()
	t.healthy = false
	t.mu.Unlock()
	return nil
}

type DirectBackend struct {
	dialer *net.Dialer
}

func NewDirectBackend(timeout time.Duration) *DirectBackend {
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return &DirectBackend{
		dialer: &net.Dialer{Timeout: timeout},
	}
}

func (d *DirectBackend) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := d.dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	TuneTCP(conn)

	return conn, nil
}

func (d *DirectBackend) IsHealthy() bool {
	return true
}

func (d *DirectBackend) Close() error {
	return nil
}
