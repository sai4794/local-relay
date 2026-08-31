package backend

import (
	"context"
	"fmt"
	"io"
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
	ID          int
	SocksPort   int
	ControlPort int
	Cmd         *exec.Cmd
	DataDir     string
	Ready       bool
	StartedAt   time.Time
	Requests    int64
	FailCount   int
	LastRotated time.Time
	lastHealed  time.Time
	mu          sync.RWMutex
}

// GetSocksPort returns the SOCKS port (thread-safe).
func (i *TorInstance) GetSocksPort() int {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.SocksPort
}

// IsReady returns readiness status (thread-safe and checks process liveness).
func (i *TorInstance) IsReady() bool {
	i.mu.RLock()
	defer i.mu.RUnlock()
	if !i.Ready {
		return false
	}
	if i.Cmd != nil && i.Cmd.Process != nil {
		if err := i.Cmd.Process.Signal(syscall.Signal(0)); err != nil {
			return false
		}
	}
	return true
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

// ResetRequests zeroes the request counter (thread-safe). Used after a
// rotation so the next rotation window starts from zero.
func (i *TorInstance) ResetRequests() {
	i.mu.Lock()
	i.Requests = 0
	i.mu.Unlock()
}

// GetFailCount returns consecutive fail count (thread-safe).
func (i *TorInstance) GetFailCount() int {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.FailCount
}

// IncFailCount increments fail counter (thread-safe).
func (i *TorInstance) IncFailCount() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.FailCount++
	return i.FailCount
}

// ResetFailCount resets fail counter to 0 (thread-safe).
func (i *TorInstance) ResetFailCount() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.FailCount = 0
}

// SetLastRotated sets the rotation timestamp (thread-safe).
func (i *TorInstance) SetLastRotated(t time.Time) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.LastRotated = t
}

// GetStartedAt returns the spawn timestamp (thread-safe). StartedAt is
// written once under tl.mu during spawnInstance before the instance is
// published, but accessors keep the lock discipline uniform.
func (i *TorInstance) GetStartedAt() time.Time {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.StartedAt
}

// GetLastRotated gets the rotation timestamp (thread-safe).
func (i *TorInstance) GetLastRotated() time.Time {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.LastRotated
}

// TryStartHeal checks if auto-heal can run (enforcing a 2-minute cooldown).
func (i *TorInstance) TryStartHeal() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	if time.Since(i.lastHealed) < 2*time.Minute {
		return false
	}
	i.lastHealed = time.Now()
	return true
}

// TorLifecycle manages the lifecycle of multiple Tor daemon processes.
type TorLifecycle struct {
	binary       string
	dataDir      string
	basePort     int
	controlBase  int
	maxInstances int
	rotateAfter  int
	libraryPath  string
	instances    []*TorInstance
	mu           sync.RWMutex
	logf         func(string, ...interface{})
	cookieCache  map[int][]byte // instance ID -> cached control cookie
	cookieMu     sync.RWMutex
}

// TorLifecycleConfig configures the Tor lifecycle manager.
type TorLifecycleConfig struct {
	Binary       string
	DataDir      string
	BasePort     int
	ControlBase  int
	MaxInstances int
	RotateAfter  int
	// LibraryPath is exported as LD_LIBRARY_PATH on spawned Tor children
	// when non-empty (empty = inherit parent env).
	LibraryPath string
	Logf        func(format string, args ...interface{})
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
		libraryPath:  cfg.LibraryPath,
		logf:         cfg.Logf,
		cookieCache:  make(map[int][]byte),
	}
}

// Start launches all Tor instances in parallel and waits for bootstrap.
func (tl *TorLifecycle) Start(ctx context.Context) error {
	if err := os.MkdirAll(tl.dataDir, 0700); err != nil {
		return fmt.Errorf("create tor data dir: %w", err)
	}

	tl.logf("Starting %d Tor instance(s) in parallel...", tl.maxInstances)

	// Spawn all instances in parallel, each bound to a stable, unique slot.
	// The slot index (1..maxInstances) determines the instance ID and both the
	// SOCKS and control ports, so concurrent spawns can never collide.
	errCh := make(chan error, tl.maxInstances)
	var wg sync.WaitGroup
	for slot := 0; slot < tl.maxInstances; slot++ {
		wg.Add(1)
		go func(slot int) {
			defer wg.Done()
			id := slot + 1
			inst, err := tl.spawnInstance(id)
			if err != nil {
				tl.logf("Failed to spawn Tor instance %d: %v", id, err)
				errCh <- err
				return
			}
			tl.logf("Tor instance %d spawned on SOCKS port %d", inst.ID, inst.SocksPort)
		}(slot)
	}
	wg.Wait()
	close(errCh)

	if err := <-errCh; err != nil {
		tl.ShutdownAll()
		return fmt.Errorf("spawn tor instances: %w", err)
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
			tl.logf("Tor bootstrap timeout reached — proceeding with currently ready instances")
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

// isSocksPortReady checks if a SOCKS port is accepting connections
// by performing a fast SOCKS5 greeting handshake with a 5-second timeout.
func (tl *TorLifecycle) isSocksPortReady(port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	// SOCKS5 greeting
	conn.Write([]byte{0x05, 0x01, 0x00})
	resp := make([]byte, 2)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, resp); err != nil {
		return false
	}
	return resp[0] == 0x05 && resp[1] == 0x00
}

func (tl *TorLifecycle) spawnInstance(id int) (*TorInstance, error) {
	socksPort := tl.basePort + id - 1
	controlPort := tl.controlBase + id - 1
	dataDir := filepath.Join(tl.dataDir, fmt.Sprintf("instance-%d", id))

	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	torrc := fmt.Sprintf(`SocksPort %d IsolateSOCKSAuth
DataDirectory %s
Log notice file %s/tor.log
ControlPort %d
CookieAuthentication 1
DormantClientTimeout 30 days
DormantOnFirstStartup 0
DormantCanceledByStartup 1
KeepalivePeriod 60
MaxCircuitDirtiness 20
CircuitBuildTimeout 30
LearnCircuitBuildTimeout 1
NumEntryGuards 2
UseEntryGuards 1
SafeSocks 1
TestSocks 1
`, socksPort, dataDir, dataDir, controlPort)

	torrcPath := filepath.Join(dataDir, "torrc")
	if err := os.WriteFile(torrcPath, []byte(torrc), 0600); err != nil {
		return nil, fmt.Errorf("write torrc: %w", err)
	}

	cmd := exec.Command(tl.binary, "-f", torrcPath)
	if tl.libraryPath != "" {
		cmd.Env = append(os.Environ(), "LD_LIBRARY_PATH="+tl.libraryPath)
	}
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

// cachedCookie returns the instance's control-auth cookie from the in-memory
// cache, falling back to disk and populating the cache on success.
func (tl *TorLifecycle) cachedCookie(inst *TorInstance) func() ([]byte, bool) {
	return func() ([]byte, bool) {
		tl.cookieMu.RLock()
		cached, hit := tl.cookieCache[inst.ID]
		tl.cookieMu.RUnlock()
		if hit && len(cached) == cookieSize {
			return cached, true
		}

		cookie, ok := readCookieFile(filepath.Join(inst.DataDir, "control_auth_cookie"))
		if !ok {
			return nil, false
		}

		tl.cookieMu.Lock()
		tl.cookieCache[inst.ID] = cookie
		tl.cookieMu.Unlock()
		return cookie, true
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

// CheckHealth restarts instances whose SOCKS port is no longer accepting
// connections after multiple consecutive probe failures, while honoring a grace
// period after NEWNYM rotation so healthy instances aren't churned.
// Fixed: uses SOCKS5 handshake (not bare TCP) and checks consensus freshness
// to catch "circuit-established but no exit" stall observed at 15:54.
func (tl *TorLifecycle) CheckHealth(ctx context.Context) int {
	tl.mu.RLock()
	instances := make([]*TorInstance, len(tl.instances))
	copy(instances, tl.instances)
	tl.mu.RUnlock()

	var unhealthy []*TorInstance
	for _, inst := range instances {
		if !inst.IsReady() {
			continue
		}
		// 30s grace period after spawn or NEWNYM: Tor SOCKS port may be busy negotiating
		// a new circuit or initial bootstrap; do not probe or kill during this window.
		if time.Since(inst.GetStartedAt()) < 30*time.Second || time.Since(inst.GetLastRotated()) < 30*time.Second {
			continue
		}

		staleConsensus := tl.isConsensusStale(inst)
		socksReady := tl.isSocksPortReady(inst.GetSocksPort())
		if !socksReady || staleConsensus {
			reason := "SOCKS handshake failed"
			if staleConsensus {
				reason = "consensus stale >90m"
			}
			fails := inst.IncFailCount()
			tl.logf("Tor instance %d health failed (%s) (consecutive fails: %d/3)", inst.ID, reason, fails)
			if fails >= 3 {
				unhealthy = append(unhealthy, inst)
			} else if inst.TryStartHeal() {
				// Proactively clear stuck guards & trigger fresh circuit to auto-heal before hard restart
				go func(target *TorInstance) {
					if !target.IsReady() {
						return
					}
					tl.logf("Tor instance %d triggering proactive DROPGUARDS auto-heal (2m cooldown)...", target.ID)
					_ = tl.RequestNewCircuitWithDropGuards(target, true)
				}(inst)
			}
		} else {
			inst.ResetFailCount()
		}
	}

	restarted := 0
	for _, inst := range unhealthy {
		tl.logf("Tor instance %d SOCKS port %d down after 3 consecutive failures, restarting...", inst.ID, inst.GetSocksPort())
		deadID := inst.ID
		tl.killInstance(inst)
		if _, err := tl.spawnInstance(deadID); err != nil {
			tl.logf("Failed to restart Tor instance %d: %v", deadID, err)
			continue
		}
		restarted++
		// Mark the replacement ready once it starts answering on SOCKS.
		go tl.waitReady(deadID)
	}
	return restarted
}

// isConsensusStale reports true if the cached microdesc consensus is older than 90m.
// This catches instances that stopped fetching directory info (stale consensus
// leads to "waiting for circuit" with valid TCP/SOCKS handshake).
func (tl *TorLifecycle) isConsensusStale(inst *TorInstance) bool {
	path := filepath.Join(inst.DataDir, "cached-microdesc-consensus")
	info, err := os.Stat(path)
	if err != nil {
		return true
	}
	// Fresh-until is 1h, valid-until 3h. >90m indicates fetch stall.
	if time.Since(info.ModTime()) > 90*time.Minute {
		return true
	}
	// Also check that file is not empty/truncated
	if info.Size() < 1024*1024 {
		return true
	}
	return false
}

// waitReady polls a respawned instance until it can route through its SOCKS
// port, then marks it ready. Strictly avoids marking unbootstrapped instances ready.
func (tl *TorLifecycle) waitReady(id int) {
	port := tl.basePort + id - 1
	deadline := time.Now().Add(2 * time.Minute)
	for {
		if tl.isSocksPortReady(port) {
			if inst := tl.getInstance(id); inst != nil {
				inst.SetReady(true)
				inst.ResetFailCount()
				tl.logf("Tor instance %d ready after restart", id)
			}
			return
		}
		if time.Now().After(deadline) {
			tl.logf("Tor instance %d restart timed out after 2 minutes — keeping not-ready", id)
			return
		}
		time.Sleep(2 * time.Second)
	}
}

// getInstance returns the instance with the given ID, or nil.
func (tl *TorLifecycle) getInstance(id int) *TorInstance {
	tl.mu.RLock()
	defer tl.mu.RUnlock()
	for _, inst := range tl.instances {
		if inst.ID == id {
			return inst
		}
	}
	return nil
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
	// Preserve DataDir (entry guards, cached consensus). Wiping it on every
	// heal churned guard nodes and made the fresh instance look
	// consensus-stale to isConsensusStale, causing a follow-up false-positive
	// failure cycle. spawnInstance rewrites the torrc idempotently.

	tl.mu.Lock()
	defer tl.mu.Unlock()
	for i, existing := range tl.instances {
		if existing.ID == inst.ID {
			tl.instances = append(tl.instances[:i], tl.instances[i+1:]...)
			// Invalidate cached cookie for this instance
			tl.cookieMu.Lock()
			delete(tl.cookieCache, inst.ID)
			tl.cookieMu.Unlock()
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

// RequestNewCircuit rotates the instance's circuits: SIGNAL NEWNYM builds
// a fresh circuit (new exit IP) without dropping healthy guard nodes.
// A 10-second cooldown is enforced to match Tor's native NEWNYM rate-limit.
// Cookie auth uses the per-instance cache to avoid re-reading the cookie file on every rotation.
func (tl *TorLifecycle) RequestNewCircuit(inst *TorInstance) error {
	return tl.RequestNewCircuitWithDropGuards(inst, false)
}

// RequestNewCircuitWithDropGuards requests a new circuit, optionally clearing guards on recovery.
func (tl *TorLifecycle) RequestNewCircuitWithDropGuards(inst *TorInstance, dropGuards bool) error {
	if !dropGuards && time.Since(inst.GetLastRotated()) < 10*time.Second {
		return nil
	}

	controlAddr := fmt.Sprintf("127.0.0.1:%d", inst.ControlPort)
	client := NewTorControlClient(controlAddr, "", tl.cachedCookie(inst))
	client.Logf = tl.logf

	if err := client.SignalNEWNYM(dropGuards); err != nil {
		return err
	}

	inst.SetLastRotated(time.Now())
	return nil
}
