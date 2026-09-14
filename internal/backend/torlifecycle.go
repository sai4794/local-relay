package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/local-relay/proxy/internal/metrics"
	"github.com/local-relay/proxy/internal/transport"
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
	Requests    atomic.Int64
	FailCount   int
	LastRotated time.Time
	// nymClaim is the monotonic id of the cooldown-window claim that stamped
	// LastRotated (see claimNymWindow): guarded by TorLifecycle.nymMu with
	// the instance lock held. Only the owning claim may refund the window.
	nymClaim      int64
	lastHealed    time.Time
	inFlight      atomic.Int64
	circuitGen    atomic.Int64
	lastServed    atomic.Int64       // UnixNano of last DialContext serve; 0 = never served
	stats         EndpointStats      // lock-free dial latency/quality scoring (score.go); cold-zero is neutral
	quar          endpointQuarantine // lock-free quarantine/probation lifecycle (quarantine.go); zero = Active
	lastExitIP    string             // last observed Tor exit for this instance
	exitIPChecked time.Time          // when lastExitIP was last refreshed
	mu            sync.RWMutex
}

// GetSocksPort returns the SOCKS port (thread-safe).
func (i *TorInstance) GetSocksPort() int {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.SocksPort
}

// IsReady returns readiness status (thread-safe and checks process liveness).
// The kill(0) liveness syscall runs WITHOUT the instance lock held: only the
// Ready flag and process handle are snapshotted under RLock, so a slow or
// wedged syscall can never stall other readers/writers on the hot dial path.
// Semantics are identical — a dead process still reports not-ready.
// A zombie (exited but not yet reaped) still passes kill(0), so a
// non-blocking Wait4(WNOHANG) follows a successful kill(0): a reaped/exited
// PID reports not-ready. killInstance's Cmd.Wait error path is harmless when
// the child was already reaped here (Wait returns promptly with ECHILD, which
// unblocks the done channel without triggering the Kill branch).
func (i *TorInstance) IsReady() bool {
	i.mu.RLock()
	ready := i.Ready
	var proc *os.Process
	if i.Cmd != nil {
		proc = i.Cmd.Process
	}
	i.mu.RUnlock()
	if !ready {
		return false
	}
	if proc != nil && proc.Pid > 0 {
		if err := proc.Signal(syscall.Signal(0)); err != nil {
			return false
		}
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(proc.Pid, &ws, syscall.WNOHANG, nil)
		if err != nil {
			if err == syscall.ECHILD {
				// Already reaped (e.g. a prior IsReady reaped it, or
				// killInstance waited): no live process backs this instance.
				return false
			}
			// Any other Wait4 error leaves the kill(0) verdict intact.
		} else if pid == proc.Pid {
			// Child exited (now reaped): zombie means not-ready.
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

// IncRequests increments request counter (lock-free atomic: hot dial path).
func (i *TorInstance) IncRequests() {
	i.Requests.Add(1)
}

// GetRequests returns request count (lock-free atomic).
func (i *TorInstance) GetRequests() int64 {
	return i.Requests.Load()
}

// ResetRequests zeroes the request counter (lock-free atomic). Used after a
// rotation so the next rotation window starts from zero.
func (i *TorInstance) ResetRequests() {
	i.Requests.Store(0)
}

// ClaimRotation atomically checks the request counter against the threshold
// and zeroes it when reached, so exactly one concurrent dialer wins the
// rotation for each window (no NEWNYM stampede).
func (i *TorInstance) ClaimRotation(threshold int64) bool {
	// Lock-free CAS loop: the check-and-zero must be atomic so exactly one
	// concurrent dialer wins each rotation window (no NEWNYM stampede).
	// ClaimRotation is the only writer that zeroes on threshold (ResetRequests
	// zeroes unconditionally after a won rotation), so CAS retry is bounded.
	if threshold <= 0 {
		return false
	}
	for {
		cur := i.Requests.Load()
		if cur < threshold {
			return false
		}
		if i.Requests.CompareAndSwap(cur, 0) {
			return true
		}
	}
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

// claimNymWindow atomically claims the 10s NEWNYM cooldown window for one
// caller and returns its monotonic claim id (0 = cooldown skip, caller gets
// ErrNymCooldown). The health path (dropGuards=true) bypasses the cooldown
// check — stuck guards outrank rate-limit politeness — but still takes a
// claim so a concurrent anomaly failure cannot refund away its window.
// Exactly one non-bypass caller per window proceeds; losers skip.
func (tl *TorLifecycle) claimNymWindow(inst *TorInstance, dropGuards bool) int64 {
	tl.nymMu.Lock()
	defer tl.nymMu.Unlock()
	inst.mu.Lock()
	defer inst.mu.Unlock()
	if !dropGuards && time.Since(inst.LastRotated) < 10*time.Second {
		return 0
	}
	tl.nymNext++
	inst.LastRotated = time.Now()
	inst.nymClaim = tl.nymNext
	return inst.nymClaim
}

// refundNymWindow re-opens the cooldown window after a failed SIGNAL, but
// only when the failing caller still owns it (claim matches): a newer claim
// — including a dropGuards bypass that claimed after us — owns the window,
// and rolling it back would wrongly admit a third caller. A refunded window
// behaves exactly like natural expiry (lastRotated 11s ago).
func (tl *TorLifecycle) refundNymWindow(inst *TorInstance, claim int64) {
	// Claim 0 is the cooldown-skip sentinel, never owned: without this guard
	// a refund(0) would match the zero-value nymClaim of a fresh instance
	// and stamp a cooldown window nobody claimed.
	if claim == 0 {
		return
	}
	tl.nymMu.Lock()
	defer tl.nymMu.Unlock()
	inst.mu.Lock()
	defer inst.mu.Unlock()
	if inst.nymClaim == claim {
		inst.LastRotated = time.Now().Add(-11 * time.Second)
		inst.nymClaim = 0
	}
}

// GetStartedAt returns the spawn timestamp (thread-safe). StartedAt is
// written once under tl.mu during spawnInstance before the instance is
// published, but accessors keep the lock discipline uniform.
func (i *TorInstance) GetStartedAt() time.Time {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.StartedAt
}

// IncInFlight increments the in-flight (active long-lived request) counter
// used by least-inflight selection. DecInFlight MUST be called when the
// request finishes (typically via the dial wrapper's Close hook).
// Lock-free atomic: read on every dial during least-inflight selection.
func (i *TorInstance) IncInFlight() {
	i.inFlight.Add(1)
}

// DecInFlight decrements in-flight; clamps at zero (safe to call on zero).
func (i *TorInstance) DecInFlight() {
	for {
		cur := i.inFlight.Load()
		if cur <= 0 {
			return
		}
		if i.inFlight.CompareAndSwap(cur, cur-1) {
			return
		}
	}
}

// InFlight returns the current in-flight count (lock-free atomic).
func (i *TorInstance) InFlight() int64 {
	return i.inFlight.Load()
}

// CircuitGen returns the current circuit generation for SOCKS auth isolation.
func (i *TorInstance) CircuitGen() int64 {
	gen := i.circuitGen.Load()
	if gen == 0 {
		return 1
	}
	return gen
}

// NextCircuitGen increments and returns the next circuit generation.
func (i *TorInstance) NextCircuitGen() int64 {
	return i.circuitGen.Add(1)
}

// SetExitIP records the observed exit IP for the current circuit.
func (i *TorInstance) SetExitIP(ip string) {
	i.mu.Lock()
	i.lastExitIP = ip
	i.exitIPChecked = time.Now()
	i.mu.Unlock()
}

// LastExitIP returns the cached exit IP and when it was last observed.
func (i *TorInstance) LastExitIP() (string, time.Time) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.lastExitIP, i.exitIPChecked
}

// GetLastRotated gets the rotation timestamp (thread-safe).
func (i *TorInstance) GetLastRotated() time.Time {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.LastRotated
}

// --- additive served-recency tracking ---

// RecordServed stamps this instance as the most recently dialed target.
// Called on the picked instance in MultiTorBackend.DialContext so a later
// ReportAnomaly(-1) can attribute the error to the instance that served it.
func (i *TorInstance) RecordServed() {
	i.lastServed.Store(time.Now().UnixNano())
}

// LastServed returns the UnixNano timestamp of the last successful dial
// through this instance, or 0 when it has never served traffic.
func (i *TorInstance) LastServed() int64 {
	return i.lastServed.Load()
}

// --- additive latency/quality scoring (score.go) ---

// RecordDialOutcome logs one dial outcome into the lock-free scoring stats.
// Success samples feed the latency EWMA with the given alpha; failures move
// only the error counter. Safe on the hot dial path (atomics only, no I/O).
func (i *TorInstance) RecordDialOutcome(success bool, latency time.Duration, alpha float64) {
	i.stats.Record(success, latency, alpha)
}

// DialSuccesses returns the scored success count (cold = 0, neutral).
func (i *TorInstance) DialSuccesses() int64 { return i.stats.Successes() }

// DialFailures returns the scored failure count.
func (i *TorInstance) DialFailures() int64 { return i.stats.Failures() }

// DialLatencyEWMA returns the success-only EWMA dial latency (0 = no samples).
func (i *TorInstance) DialLatencyEWMA() time.Duration { return i.stats.LatencyEWMA() }

// --- additive quarantine/probation lifecycle (quarantine.go) ---

// QuarantineState returns the endpoint lifecycle state (Active cold default).
func (i *TorInstance) QuarantineState() EndpointState { return i.quar.State() }

// QuarantineConsecFails returns the consecutive failure count.
func (i *TorInstance) QuarantineConsecFails() int64 { return i.quar.ConsecFails() }

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
	// generation is bumped on every ShutdownAll/Start cycle. waitReady
	// goroutines and CheckHealth restarts capture the generation they were
	// spawned in and refuse to touch instances from another generation, so a
	// stale waiter can never mark a replacement instance ready after a full
	// stack restart. healthMu serializes CheckHealth restarts against
	// ShutdownAll/Start. generation is atomic because waitReady goroutines
	// read it without holding healthMu.
	generation atomic.Int64
	healthMu   sync.Mutex
	// stopMu/stopCh implement stop propagation for waitReady goroutines:
	// every ShutdownAll/Start cycle closes the previous channel and mints a
	// fresh one, so waiters spawned in an older generation wake up promptly
	// instead of polling a dead port for up to 2 minutes. The channel for a
	// generation is captured by waiters via stopChFor; the mutex only guards
	// the swap, never blocking probes.
	stopMu sync.RWMutex
	stopCh chan struct{}
	// notReadyObs counts consecutive CheckHealth observations in which a
	// ready instance's SOCKS greeting probe failed (keyed by instance ID).
	// A single failed probe is transient (NEWNYM churn, guard rebuild); the
	// persistent-failure path (kill/spawn) only fires after repeats.
	// Guarded by notReadyMu: CheckHealth probes run without healthMu, so the
	// counter map needs its own lock.
	notReadyObs map[int]int
	notReadyMu  sync.Mutex
	// nymMu serializes NEWNYM cooldown-window claims; nymNext mints the
	// monotonic claim ids recorded per instance (see claimNymWindow).
	nymMu   sync.Mutex
	nymNext int64
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
		notReadyObs:  make(map[int]int),
		stopCh:       make(chan struct{}),
	}
}

// stopChFor returns the stop channel belonging to generation gen's cycle.
// Callers must hold no locks; it returns the current channel when gen is the
// live generation, or an already-closed channel when gen is superseded (so a
// stale waiter exits immediately instead of hanging).
func (tl *TorLifecycle) stopChFor(gen int64) <-chan struct{} {
	tl.stopMu.RLock()
	defer tl.stopMu.RUnlock()
	if tl.generation.Load() != gen {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return tl.stopCh
}

// bumpStopLocked closes the current stop channel and mints a fresh one,
// waking every waiter from older generations. Callers must hold healthMu.
func (tl *TorLifecycle) bumpStopLocked() {
	tl.stopMu.Lock()
	close(tl.stopCh)
	tl.stopCh = make(chan struct{})
	tl.stopMu.Unlock()
}

// Start launches all Tor instances in parallel and waits for bootstrap.
// It returns an error when zero instances are ready after the 60s bootstrap
// timeout: proceeding with no egress would only serve fail-closed errors, so
// the caller must surface the failure instead of logging readiness.
//
// Lock scope: healthMu is taken only for the spawn phase (generation bump,
// instance registration). The 60s bootstrap poll runs WITHOUT healthMu so
// CheckHealth/ShutdownAll callers are never wedged behind a full-minute
// wait; the completion check re-takes the lock briefly at the deadline.
func (tl *TorLifecycle) Start(ctx context.Context) error {
	tl.healthMu.Lock()

	tl.generation.Add(1)
	tl.bumpStopLocked()

	if err := os.MkdirAll(tl.dataDir, 0700); err != nil {
		tl.healthMu.Unlock()
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

	var spawnErrs []error
	for err := range errCh {
		spawnErrs = append(spawnErrs, err)
	}
	if len(spawnErrs) > 0 {
		tl.shutdownAllLocked()
		tl.healthMu.Unlock()
		return fmt.Errorf("spawn tor instances: %w", errors.Join(spawnErrs...))
	}
	tl.healthMu.Unlock()

	// Wait for bootstrap by polling SOCKS ports.
	// Runs WITHOUT healthMu: the poll is up to 60s of blocking I/O plus a
	// Gen check on exit so a ShutdownAll/Start that raced us owns the result.
	// The ctx parameter lets the caller abort the wait (process shutdown);
	// when ctx fires we return its error without touching instance state.
	tl.logf("Waiting for Tor instances to bootstrap...")
	bootstrapGen := tl.generation.Load()
	deadline := time.After(60 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			tl.mu.RLock()
			ready := tl.readyCountLocked()
			total := len(tl.snapshotLocked())
			tl.mu.RUnlock()
			if ready == 0 {
				tl.logf("Tor bootstrap timeout with zero ready instances — failing startup")
				return fmt.Errorf("tor bootstrap timeout: zero of %d instances ready after 60s", total)
			}
			tl.logf("Tor bootstrap timeout reached — proceeding with currently ready instances")
			return nil
		case <-ticker.C:
			allReady := true
			for _, inst := range tl.GetInstances() {
				if tl.generation.Load() != bootstrapGen {
					// A ShutdownAll/Start recycled the stack mid-bootstrap:
					// these instances belong to a superseded generation, so
					// stop marking them ready and let the new cycle own it.
					tl.logf("Tor bootstrap superseded by newer generation — abandoning wait")
					return fmt.Errorf("tor bootstrap superseded by newer generation")
				}
				if !inst.IsReady() {
					if tl.isSocksPortReady(inst.GetSocksPort()) {
						inst.SetReady(true)
						tl.logf("Tor instance %d SOCKS port %d is ready", inst.ID, inst.GetSocksPort())
					} else {
						allReady = false
					}
				}
			}
			if allReady {
				tl.logf("All %d Tor instances bootstrapped", len(tl.GetInstances()))
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
	inst.circuitGen.Store(1)

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

// snapshotLocked returns a copy of the instance list. Callers must hold at
// least tl.mu.RLock.
func (tl *TorLifecycle) snapshotLocked() []*TorInstance {
	result := make([]*TorInstance, len(tl.instances))
	copy(result, tl.instances)
	return result
}

// readyCountLocked counts ready instances. Callers must hold at least
// tl.mu.RLock.
func (tl *TorLifecycle) readyCountLocked() int {
	count := 0
	for _, inst := range tl.instances {
		if inst.IsReady() {
			count++
		}
	}
	return count
}

// GetInstances returns a snapshot of all instances.
func (tl *TorLifecycle) GetInstances() []*TorInstance {
	tl.mu.RLock()
	defer tl.mu.RUnlock()
	return tl.snapshotLocked()
}

// GetReadyCount returns the number of ready instances.
func (tl *TorLifecycle) GetReadyCount() int {
	tl.mu.RLock()
	defer tl.mu.RUnlock()
	return tl.readyCountLocked()
}

// CheckHealth restarts instances whose SOCKS port is no longer accepting
// connections after multiple consecutive probe failures, while honoring a grace
// period after NEWNYM rotation so healthy instances aren't churned.
// Fixed: uses SOCKS5 handshake (not bare TCP) and checks consensus freshness
// to catch "circuit-established but no exit" stall observed at 15:54.
//
// Serialized against ShutdownAll/Start via healthMu so a restart cannot race
// a full stack recycle. Instances that stay not-ready across consecutive
// observations are healed via kill/spawn (not-ready observation counter in
// notReadyObs); transient single-probe failures only bump FailCount.
//
// Lock scope: healthMu is held only to snapshot the instance list (and the
// generation) plus the kill/spawn section at the end. All blocking probes
// (SOCKS handshakes, file stats) run WITHOUT healthMu so a wedged daemon
// cannot stall Start/ShutdownAll callers behind a 5s-per-instance probe.
func (tl *TorLifecycle) CheckHealth(ctx context.Context) int {
	tl.healthMu.Lock()
	instances := tl.GetInstances()
	gen := tl.generation.Load()
	tl.healthMu.Unlock()

	// bumpNotReady records one more consecutive not-ready observation for id
	// and reports the new count. resetNotReady clears it.
	bumpNotReady := func(id int) int {
		tl.notReadyMu.Lock()
		defer tl.notReadyMu.Unlock()
		tl.notReadyObs[id]++
		return tl.notReadyObs[id]
	}
	resetNotReady := func(id int) {
		tl.notReadyMu.Lock()
		tl.notReadyObs[id] = 0
		tl.notReadyMu.Unlock()
	}
	clearNotReady := func(id int) {
		tl.notReadyMu.Lock()
		delete(tl.notReadyObs, id)
		tl.notReadyMu.Unlock()
	}

	var unhealthy []*TorInstance
	for _, inst := range instances {
		// Heal not-ready instances: a ready instance that stops answering
		// (killed process, wedged daemon) flips IsReady() false via the
		// liveness check. Re-probe it here — a single miss is transient, but
		// consecutive not-ready observations re-run kill/spawn so a wedged
		// daemon is recycled instead of sitting not-ready forever.
		if !inst.IsReady() {
			if tl.isSocksPortReady(inst.GetSocksPort()) {
				resetNotReady(inst.ID)
				inst.ResetFailCount()
				continue
			}
			obs := bumpNotReady(inst.ID)
			tl.logf("Tor instance %d not-ready (consecutive not-ready observations: %d/3)", inst.ID, obs)
			if obs >= 3 {
				unhealthy = append(unhealthy, inst)
			}
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
				// Quarantined endpoints skip the proactive DROPGUARDS heal:
				// quarantine entry already issued ONE attributed NEWNYM, and
				// a second proactive signal would double-signal the same
				// sickness (plus fight the 60s hold). SOCKS liveness probes
				// above still run regardless of state.
				if inst.quar.State() == StateQuarantined || inst.quar.State() == StateProbation {
					continue
				}
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
			resetNotReady(inst.ID)
			// Opportunistic exit-IP refresh: priming at startup can race the
			// fresh-Tor bootstrap (SOCKS answers before the first circuit is
			// buildable), so backfill here until the exit is known and keep it
			// fresh on a 10-minute cycle.
			ip, checked := inst.LastExitIP()
			if ip == "" || time.Since(checked) > 10*time.Minute {
				go func(target *TorInstance) {
					tl.RefreshExitIP(target, 15*time.Second)
				}(inst)
			}
		}
	}

	restarted := 0
	// Kill/spawn is serialized against ShutdownAll/Start via healthMu so a
	// restart cannot race a full stack recycle. Probes above already ran
	// lock-free; only the mutation section takes the lock.
	tl.healthMu.Lock()
	defer tl.healthMu.Unlock()
	if tl.generation.Load() != gen {
		// A ShutdownAll/Start cycled while we were probing: the snapshot is
		// stale, and kill/spawn here would operate on a superseded stack.
		tl.logf("CheckHealth snapshot from superseded generation — skipping restarts")
		return 0
	}
	for _, inst := range unhealthy {
		tl.logf("Tor instance %d SOCKS port %d down after 3 consecutive failures, restarting...", inst.ID, inst.GetSocksPort())
		deadID := inst.ID
		// Capture the replacement pointer up front: waitReady validates
		// identity (plus generation) before SetReady so a stale waiter from a
		// superseded generation can never flip the wrong instance ready.
		tl.killInstance(inst)
		replacement, err := tl.spawnInstance(deadID)
		if err != nil {
			tl.logf("Failed to restart Tor instance %d: %v", deadID, err)
			continue
		}
		restarted++
		clearNotReady(deadID)
		// Mark the replacement ready once it answers two consecutive SOCKS5
		// greeting handshakes (a single success can be a half-open bootstrap
		// socket; two in a row means the daemon is actually serving).
		go tl.waitReady(replacement, gen)
	}
	return restarted
}

// isConsensusStale reports true if the cached microdesc consensus is older than 90m.
// This catches instances that stopped fetching directory info (stale consensus
// leads to "waiting for circuit" with valid TCP/SOCKS handshake).
//
// Fresh instances are exempt: a young Tor has no consensus file yet, which is
// normal bootstrap, not a stall. Flagging it stale here caused DROPGUARDS
// churn on brand-new guards (observed: rotations_total{trigger="health"} on
// fresh spawns).
func (tl *TorLifecycle) isConsensusStale(inst *TorInstance) bool {
	path := filepath.Join(inst.DataDir, "cached-microdesc-consensus")
	info, err := os.Stat(path)
	if err != nil {
		// No file at all — normal for a recently spawned instance.
		return time.Since(inst.GetStartedAt()) > 3*time.Minute
	}
	// Fresh-until is 1h, valid-until 3h. >90m indicates fetch stall.
	if time.Since(info.ModTime()) > 90*time.Minute {
		return true
	}
	// Also check that file is not empty/truncated — but only once the
	// instance is old enough that a full consensus should exist.
	if info.Size() < 1024*1024 && time.Since(inst.GetStartedAt()) > 3*time.Minute {
		return true
	}
	return false
}

// waitReady polls a respawned instance until it answers two consecutive
// SOCKS5 greeting handshakes, then marks it ready. It captures the
// *TorInstance pointer (not just the ID) plus the lifecycle generation and
// validates identity before SetReady: the pointer must still be the
// registered instance for that ID and the generation must be unchanged.
// Otherwise a stale waiter from a superseded Start/ShutdownAll cycle could
// flip an unrelated replacement ready. Strictly avoids marking
// unbootstrapped instances ready.
//
// Stop propagation: waiters also watch stopCh (closed by ShutdownAll/Start
// via bumpStopLocked). A waiter from a superseded generation exits promptly
// instead of polling for up to 2 minutes against a dead port.
func (tl *TorLifecycle) waitReady(target *TorInstance, gen int64) {
	id := target.ID
	port := target.GetSocksPort()
	stop := tl.stopChFor(gen)
	deadline := time.Now().Add(2 * time.Minute)
	consecutive := 0
	for {
		if tl.generation.Load() != gen {
			tl.logf("Tor instance %d ready probe from superseded generation — ignoring", id)
			return
		}
		select {
		case <-stop:
			tl.logf("Tor instance %d waiter stopped (stack recycled) — ignoring", id)
			return
		default:
		}
		if tl.isSocksPortReady(port) {
			consecutive++
			if consecutive >= 2 {
				if tl.generation.Load() != gen {
					tl.logf("Tor instance %d ready probe from superseded generation — ignoring", id)
					return
				}
				if inst := tl.getInstance(id); inst != nil {
					if inst != target {
						tl.logf("Tor instance %d replaced since restart — stale waiter ignoring", id)
						return
					}
					inst.SetReady(true)
					inst.ResetFailCount()
					tl.logf("Tor instance %d ready after restart", id)
				}
				return
			}
		} else {
			consecutive = 0
		}
		if time.Now().After(deadline) {
			tl.logf("Tor instance %d restart timed out after 2 minutes — keeping not-ready", id)
			return
		}
		select {
		case <-stop:
			tl.logf("Tor instance %d waiter stopped (stack recycled) — ignoring", id)
			return
		case <-time.After(2 * time.Second):
		}
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
	tl.healthMu.Lock()
	defer tl.healthMu.Unlock()
	tl.generation.Add(1)
	tl.bumpStopLocked()

	instances := tl.GetInstances()

	for _, inst := range instances {
		tl.logf("Stopping Tor instance %d...", inst.ID)
		tl.killInstance(inst)
	}
	tl.notReadyMu.Lock()
	tl.notReadyObs = make(map[int]int)
	tl.notReadyMu.Unlock()
}

// shutdownAllLocked stops all Tor instances. Callers must hold healthMu.
func (tl *TorLifecycle) shutdownAllLocked() {
	tl.generation.Add(1)
	tl.bumpStopLocked()

	tl.mu.RLock()
	instances := tl.snapshotLocked()
	tl.mu.RUnlock()

	for _, inst := range instances {
		tl.logf("Stopping Tor instance %d...", inst.ID)
		tl.killInstance(inst)
	}
	tl.notReadyMu.Lock()
	tl.notReadyObs = make(map[int]int)
	tl.notReadyMu.Unlock()
}

// RequestNewCircuit rotates the instance's circuits: SIGNAL NEWNYM builds
// a fresh circuit (new exit IP) without dropping healthy guard nodes.
// A 10-second cooldown is enforced to match Tor's native NEWNYM rate-limit.
// Cookie auth uses the per-instance cache to avoid re-reading the cookie file on every rotation.
func (tl *TorLifecycle) RequestNewCircuit(inst *TorInstance) error {
	_, err := tl.requestNewCircuitResult(inst)
	return err
}

// RequestNewCircuitWithDropGuards requests a new circuit, optionally clearing guards on recovery.
// A cooldown skip returns (false, ErrNymCooldown) — callers MUST NOT treat it
// as a rotation (no counter reset, no pool clear).
func (tl *TorLifecycle) RequestNewCircuitWithDropGuards(inst *TorInstance, dropGuards bool) error {
	_, err := tl.requestNewCircuitResultWithDropGuards(inst, dropGuards)
	return err
}

// requestNewCircuitResult is RequestNewCircuit reporting whether a NEWNYM was
// actually issued (true) or skipped by the cooldown (false, ErrNymCooldown).
func (tl *TorLifecycle) requestNewCircuitResult(inst *TorInstance) (bool, error) {
	return tl.requestNewCircuitResultWithDropGuards(inst, false)
}

func (tl *TorLifecycle) requestNewCircuitResultWithDropGuards(inst *TorInstance, dropGuards bool) (bool, error) {
	// Atomic cooldown claim: the read-then-act check admits a NEWNYM stampede
	// under concurrent anomaly reports (all pass the check before any one
	// stamps lastRotated). Claim under the instance write lock with a re-check
	// so exactly one caller per window proceeds; losers get ErrNymCooldown.
	// The cooldown claim records WHO owns the window (monotonic claim id),
	// not just when: on SIGNAL failure only the owning claim refunds, and
	// only its own claim — a newer claim (including the health path's
	// dropGuards bypass, which skips the cooldown check) always survives.
	// Rolling time back instead would re-open the window for a third caller
	// whenever claims interleave (anomaly T1 fails after health T2 claimed).
	claim := tl.claimNymWindow(inst, dropGuards)
	if claim == 0 {
		return false, ErrNymCooldown
	}

	controlAddr := fmt.Sprintf("127.0.0.1:%d", inst.ControlPort)
	client := NewTorControlClient(controlAddr, "", tl.cachedCookie(inst))
	client.Logf = tl.logf

	if err := client.SignalNEWNYM(dropGuards); err != nil {
		tl.refundNymWindow(inst, claim)
		return false, err
	}

	inst.NextCircuitGen()
	inst.SetLastRotated(time.Now())
	trigger := "anomaly"
	if dropGuards {
		trigger = "health"
	}
	metrics.Default().Inc("lano_rotations_total", map[string]string{
		"instance": strconv.Itoa(inst.ID),
		"trigger":  trigger,
	})

	// NOTE: with IsolateSOCKSAuth per-request there is no long-lived circuit
	// to drain — every dial mints its own circuit. The race concern from the
	// design note only applied to shared-circuit pooling. We simply verify
	// the exit IP changed after NEWNYM and record it for observability.
	go tl.RefreshExitIP(inst, 5*time.Second)

	return true, nil
}

// VerifyControls checks control-port authentication on every known instance
// without changing state: per instance it connects, AUTHENTICATEs with that
// instance's cached cookie provider, and closes. No SIGNAL is issued.
// It returns the first failure; callers run it at startup to fail fast on
// bad/stale control cookies instead of discovering them lazily on NEWNYM.
func (tl *TorLifecycle) VerifyControls() error {
	instances := tl.GetInstances()
	if len(instances) == 0 {
		return fmt.Errorf("tor control port not configured: no instances")
	}
	for _, inst := range instances {
		controlAddr := fmt.Sprintf("127.0.0.1:%d", inst.ControlPort)
		client := NewTorControlClient(controlAddr, "", tl.cachedCookie(inst))
		client.Logf = tl.logf
		if err := client.VerifyAuth(); err != nil {
			return fmt.Errorf("instance %d control auth: %w", inst.ID, err)
		}
	}
	return nil
}

// exitProbeUser builds the SOCKS5 isolation identity the exit-IP probe must
// assert: the SAME "relay:<id>:<gen>" identity production traffic dials with
// (see MultiTorBackend.DialContext). Dialing the probe with an empty user
// would ride the daemon's default circuit and misattribute that exit to this
// instance.
func exitProbeUser(inst *TorInstance) string {
	return "relay:" + strconv.Itoa(inst.ID) + ":" + strconv.FormatInt(inst.CircuitGen(), 10)
}

// RefreshExitIP dials through this instance's SOCKS port to the Tor Project
// self-check endpoint and records the observed exit. Any failure leaves the
// stale value intact and is logged but non-fatal.
func (tl *TorLifecycle) RefreshExitIP(inst *TorInstance, maxWait time.Duration) {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(inst.GetSocksPort()))
	isoUser := exitProbeUser(inst)
	client := &http.Client{
		Timeout: maxWait,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				sc := transport.NewSOCKS5Client(10 * time.Second)
				return sc.Connect(ctx, addr, "check.torproject.org:443", isoUser)
			},
			DisableKeepAlives: true,
		},
	}
	resp, err := client.Get("https://check.torproject.org/api/ip")
	if err != nil {
		tl.logf("exit-IP refresh failed for instance %d: %v", inst.ID, err)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2048))
	if err != nil {
		return
	}
	var parsed struct {
		IsTor bool   `json:"IsTor"`
		IP    string `json:"IP"`
	}
	if err := json.Unmarshal(body, &parsed); err == nil && parsed.IsTor && parsed.IP != "" {
		old, _ := inst.LastExitIP()
		inst.SetExitIP(parsed.IP)
		tl.logf("instance %d exit IP: %s (was %s)", inst.ID, parsed.IP, old)
	}
}
