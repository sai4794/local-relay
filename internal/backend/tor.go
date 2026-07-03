package backend

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type TorBackend struct {
	addr              string
	controlAddr       string
	controlPass       string
	controlCookiePath string
	dialer            *net.Dialer
	healthy           bool
	mu                sync.RWMutex
	circuitAge        int
	maxCircuitAge     int
	lastCheck         time.Time
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
		addr:              cfg.Address,
		controlAddr:       cfg.ControlAddr,
		controlPass:       cfg.ControlPass,
		controlCookiePath: cfg.ControlCookiePath,
		dialer:            &net.Dialer{Timeout: cfg.Timeout},
		healthy:       true,
		maxCircuitAge: cfg.MaxCircuitAge,
		lastCheck:     time.Now(),
	}
}

func (t *TorBackend) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := t.dialer.DialContext(ctx, "tcp", t.addr)
	if err != nil {
		t.mu.Lock()
		t.healthy = false
		t.mu.Unlock()
		return nil, fmt.Errorf("tor dial failed: %w", err)
	}

	TuneTCP(conn)

	if err := t.socks5Handshake(conn, addr); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 handshake failed: %w", err)
	}

	t.mu.Lock()
	t.circuitAge++
	t.healthy = true
	t.mu.Unlock()

	return conn, nil
}

func (t *TorBackend) socks5Handshake(conn net.Conn, targetAddr string) error {
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

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("invalid port: %s", portStr)
	}

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

func (t *TorBackend) RequestNewCircuit() error {
	if t.controlAddr == "" {
		return fmt.Errorf("control port not configured")
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(context.Background(), "tcp", t.controlAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to control port: %w", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Try cookie auth first, then password, then empty
	authSent := false
	if t.controlCookiePath != "" {
		if cookie, err := os.ReadFile(t.controlCookiePath); err == nil && len(cookie) == 32 {
			hexCookie := hex.EncodeToString(cookie)
			fmt.Fprintf(conn, "AUTHENTICATE %s\r\n", hexCookie)
			authSent = true
		}
	}
	if !authSent && t.controlPass != "" {
		fmt.Fprintf(conn, "AUTHENTICATE \"%s\"\r\n", t.controlPass)
		authSent = true
	}
	if !authSent {
		fmt.Fprintf(conn, "AUTHENTICATE\r\n")
	}

	resp, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("auth failed: %w", err)
	}
	if !strings.HasPrefix(resp, "250") {
		return fmt.Errorf("auth rejected: %s", strings.TrimSpace(resp))
	}

	fmt.Fprintf(conn, "SIGNAL NEWNYM\r\n")
	resp, err = reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("newnym failed: %w", err)
	}
	if !strings.HasPrefix(resp, "250") {
		return fmt.Errorf("newnym rejected: %s", strings.TrimSpace(resp))
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
