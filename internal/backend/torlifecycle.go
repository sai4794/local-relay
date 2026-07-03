package backend

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// TorInstance represents a single managed Tor daemon process.
type TorInstance struct {
	ID        int
	SocksPort int
	ControlPort int
	Cmd       *exec.Cmd
	DataDir   string
	Ready     bool
	StartedAt time.Time
	Requests  int64
	mu        sync.RWMutex
}

// GetSocksPort returns the SOCKS port (thread-safe).
func (i *TorInstance) GetSocksPort() int {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.SocksPort
}

// IsReady returns readiness status (thread-safe).
func (i *TorInstance) IsReady() bool {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.Ready
}

// SetReady sets readiness status (thread-safe).
func (i *TorInstance) SetReady(r bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.Ready = r
}

// IncRequests increments request counter (thread-safe).
func (i *TorInstance) IncRequests() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.Requests++
}

// GetRequests returns request count (thread-safe).
func (i *TorInstance) GetRequests() int64 {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.Requests
}

// TorLifecycle manages the lifecycle of multiple Tor daemon processes.
type TorLifecycle struct {
	binary    string
	dataDir   string
	basePort  int
	controlBase int
	maxInstances int
	rotateAfter  int
	instances    []*TorInstance
	mu           sync.RWMutex
	logf         func(string, ...interface{})
}

// TorLifecycleConfig configures the Tor lifecycle manager.
type TorLifecycleConfig struct {
	Binary       string
	DataDir      string
	BasePort     int
	ControlBase  int
	MaxInstances int
	RotateAfter  int
	Logf         func(string, ...interface{})
}

// NewTorLifecycle creates a new Tor lifecycle manager.
func NewTorLifecycle(cfg TorLifecycleConfig) *TorLifecycle {
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...interface{}) {}
	}
	return &TorLifecycle{
		binary:       cfg.Binary,
		dataDir:      cfg.DataDir,
		basePort:     cfg.BasePort,
		controlBase:  cfg.ControlBase,
		maxInstances: cfg.MaxInstances,
		rotateAfter:  cfg.RotateAfter,
		logf:         cfg.Logf,
	}
}

// Start launches all Tor instances and waits for bootstrap.
func (tl *TorLifecycle) Start(ctx context.Context) error {
	if err := os.MkdirAll(tl.dataDir, 0700); err != nil {
		return fmt.Errorf("create tor data dir: %w", err)
	}

	tl.logf("Starting %d Tor instance(s)...", tl.maxInstances)

	for i := 0; i < tl.maxInstances; i++ {
		inst, err := tl.spawnInstance()
		if err != nil {
			tl.logf("Failed to spawn Tor instance %d: %v", i, err)
			tl.ShutdownAll()
			return fmt.Errorf("spawn tor instance %d: %w", i, err)
		}
		tl.logf("Tor instance %d started on SOCKS port %d", inst.ID, inst.SocksPort)
	}

	// Wait for bootstrap by polling SOCKS ports
	tl.logf("Waiting for Tor instances to bootstrap...")
	deadline := time.After(60 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			tl.logf("Tor bootstrap timeout — marking instances ready anyway")
			tl.markAllReady()
			return nil
		case <-ticker.C:
			allReady := true
			tl.mu.RLock()
			for _, inst := range tl.instances {
				if !inst.IsReady() {
					if tl.isSocksPortReady(inst.GetSocksPort()) {
						inst.SetReady(true)
						tl.logf("Tor instance %d SOCKS port %d is ready", inst.ID, inst.GetSocksPort())
					} else {
						allReady = false
					}
				}
			}
			tl.mu.RUnlock()
			if allReady {
				tl.logf("All %d Tor instances bootstrapped", len(tl.instances))
				return nil
			}
		}
	}
}

func (tl *TorLifecycle) isSocksPortReady(port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 1*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (tl *TorLifecycle) spawnInstance() (*TorInstance, error) {
	tl.mu.Lock()
	id := len(tl.instances) + 1
	tl.mu.Unlock()

	socksPort := tl.basePort + id - 1
	controlPort := tl.controlBase + id - 1
	dataDir := filepath.Join(tl.dataDir, fmt.Sprintf("instance-%d", id))

	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	torrc := fmt.Sprintf(`SocksPort %d
DataDirectory %s
Log notice file %s/tor.log
ControlPort %d
`, socksPort, dataDir, dataDir, controlPort)

	torrcPath := filepath.Join(dataDir, "torrc")
	if err := os.WriteFile(torrcPath, []byte(torrc), 0600); err != nil {
		return nil, fmt.Errorf("write torrc: %w", err)
	}

	cmd := exec.Command(tl.binary, "-f", torrcPath)
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start tor: %w", err)
	}

	inst := &TorInstance{
		ID:          id,
		SocksPort:   socksPort,
		ControlPort: controlPort,
		Cmd:         cmd,
		DataDir:     dataDir,
		Ready:       false,
		StartedAt:   time.Now(),
	}

	tl.mu.Lock()
	tl.instances = append(tl.instances, inst)
	tl.mu.Unlock()

	return inst, nil
}

func (tl *TorLifecycle) markAllReady() {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	for _, inst := range tl.instances {
		inst.SetReady(true)
	}
}

// GetInstances returns a snapshot of all instances.
func (tl *TorLifecycle) GetInstances() []*TorInstance {
	tl.mu.RLock()
	defer tl.mu.RUnlock()
	result := make([]*TorInstance, len(tl.instances))
	copy(result, tl.instances)
	return result
}

// GetReadyCount returns the number of ready instances.
func (tl *TorLifecycle) GetReadyCount() int {
	tl.mu.RLock()
	defer tl.mu.RUnlock()
	count := 0
	for _, inst := range tl.instances {
		if inst.IsReady() {
			count++
		}
	}
	return count
}

// CheckHealth verifies all instances are alive and restarts dead ones.
func (tl *TorLifecycle) CheckHealth(ctx context.Context) int {
	tl.mu.RLock()
	var dead []*TorInstance
	for _, inst := range tl.instances {
		if inst.Cmd != nil && inst.Cmd.Process != nil {
			if err := inst.Cmd.Process.Signal(syscall.Signal(0)); err != nil {
				dead = append(dead, inst)
			}
		}
	}
	tl.mu.RUnlock()

	restarted := 0
	for _, inst := range dead {
		tl.logf("Tor instance %d (PID %d) is dead, restarting...", inst.ID, inst.Cmd.Process.Pid)
		tl.killInstance(inst)
		if _, err := tl.spawnInstance(); err != nil {
			tl.logf("Failed to restart Tor instance: %v", err)
		} else {
			restarted++
		}
	}
	return restarted
}

func (tl *TorLifecycle) killInstance(inst *TorInstance) {
	if inst.Cmd != nil && inst.Cmd.Process != nil {
		// SIGTERM first
		inst.Cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan error, 1)
		go func() { done <- inst.Cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			inst.Cmd.Process.Kill()
			<-done
		}
	}
	os.RemoveAll(inst.DataDir)

	tl.mu.Lock()
	defer tl.mu.Unlock()
	for i, existing := range tl.instances {
		if existing.ID == inst.ID {
			tl.instances = append(tl.instances[:i], tl.instances[i+1:]...)
			return
		}
	}
}

// ShutdownAll stops all Tor instances.
func (tl *TorLifecycle) ShutdownAll() {
	tl.mu.RLock()
	instances := make([]*TorInstance, len(tl.instances))
	copy(instances, tl.instances)
	tl.mu.RUnlock()

	for _, inst := range instances {
		tl.logf("Stopping Tor instance %d...", inst.ID)
		tl.killInstance(inst)
	}
}

// RequestNewCircuit sends SIGNAL NEWNYM to a specific instance.
// It reads the control_auth_cookie from the instance's data directory for authentication.
func (tl *TorLifecycle) RequestNewCircuit(inst *TorInstance) error {
	controlAddr := fmt.Sprintf("127.0.0.1:%d", inst.ControlPort)
	conn, err := net.DialTimeout("tcp", controlAddr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("connect to control port: %w", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Try to read control_auth_cookie from data directory
	cookiePath := filepath.Join(inst.DataDir, "control_auth_cookie")
	authSent := false
	if cookie, err := os.ReadFile(cookiePath); err == nil && len(cookie) == 32 {
		hexCookie := hex.EncodeToString(cookie)
		fmt.Fprintf(conn, "AUTHENTICATE %s\r\n", hexCookie)
		authSent = true
	}

	if !authSent {
		// Fallback: try empty auth (works if ControlPort is configured without auth)
		fmt.Fprintf(conn, "AUTHENTICATE\r\n")
	}

	resp, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("auth failed: %w", err)
	}
	if len(resp) < 3 || resp[0] != '2' {
		return fmt.Errorf("auth rejected: %s", resp)
	}

	fmt.Fprintf(conn, "SIGNAL NEWNYM\r\n")
	resp, err = reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("newnym failed: %w", err)
	}
	if len(resp) < 3 || resp[0] != '2' {
		return fmt.Errorf("newnym rejected: %s", resp)
	}

	return nil
}
