package rotate

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

type Rotator struct {
	counter  atomic.Uint64
	interval atomic.Uint64
	onRotate func()
	logger   *slog.Logger
	mu       sync.RWMutex
	// lastForce bounds ForceRotate storms (dead-tunnel/anomaly bursts call it
	// per failed request): claims inside the 10s window are dropped, same
	// RLock-fast-path/write-claim pattern as TorBackend.ReportAnomaly. The
	// request-count ShouldRotate path is unaffected.
	lastForce time.Time
	wg        sync.WaitGroup
	// closed guards triggerRotation against Wait at shutdown: once closing,
	// new rotations are dropped instead of racing Add against a Wait that
	// may already have returned. Rotation semantics unchanged — shutdown
	// simply stops scheduling new work.
	closing atomic.Bool
}

func NewRotator(interval int, onRotate func(), logger *slog.Logger) *Rotator {
	r := &Rotator{
		onRotate: onRotate,
		logger:   logger,
	}
	r.interval.Store(clampInterval(interval))
	return r
}

func (r *Rotator) ShouldRotate() bool {
	interval := r.interval.Load()
	if interval == 0 {
		return false
	}

	count := r.counter.Add(1)
	if count%interval == 0 {
		r.logger.Info("IP rotation triggered",
			"request_count", count,
			"interval", interval,
		)

		r.triggerRotation()

		return true
	}

	return false
}

func (r *Rotator) GetCount() uint64 {
	return r.counter.Load()
}

func (r *Rotator) Reset() {
	r.counter.Store(0)
}

func (r *Rotator) SetInterval(interval int) {
	r.interval.Store(clampInterval(interval))
}

// clampInterval maps negative intervals to 0 (disabled): a uint64 cast would
// otherwise wrap a negative into a huge positive and silently re-enable.
func clampInterval(interval int) uint64 {
	if interval < 0 {
		return 0
	}
	return uint64(interval)
}

// forceCooldown is the minimum gap between ForceRotate rotations. It mirrors
// Tor's native NEWNYM rate limit (and TorBackend.ReportAnomaly's 10s window)
// so anomaly/dead-tunnel storms collapse onto one rotation.
const forceCooldown = 10 * time.Second

// ForceRotate triggers an immediate rotation regardless of request count.
// Calls inside the cooldown window are dropped (storm suppression); the
// request-count ShouldRotate path is unchanged.
func (r *Rotator) ForceRotate() {
	r.mu.RLock()
	if time.Since(r.lastForce) < forceCooldown {
		r.mu.RUnlock()
		return
	}
	r.mu.RUnlock()
	r.mu.Lock()
	if time.Since(r.lastForce) < forceCooldown {
		r.mu.Unlock()
		return
	}
	r.lastForce = time.Now()
	r.mu.Unlock()
	r.logger.Info("Forced IP rotation")
	r.triggerRotation()
}

// triggerRotation launches the rotation callback in a goroutine with WaitGroup tracking.
// Add is guarded by the closing flag so a rotation racing shutdown's Wait
// cannot Add after Wait returned (which would leak the goroutine untracked).
// The check-then-Add window is intentionally tiny and best-effort: the worst
// case is one dropped rotation at shutdown, never a panic or leak.
func (r *Rotator) triggerRotation() {
	if r.onRotate != nil {
		if r.closing.Load() {
			return
		}
		r.wg.Add(1)
		if r.closing.Load() {
			r.wg.Done()
			return
		}
		go func() {
			defer r.wg.Done()
			r.onRotate()
		}()
	}
}

// Wait blocks until all in-flight rotation goroutines complete.
// Call during shutdown to prevent goroutine leaks. It also arms the closing
// flag so concurrent ShouldRotate/ForceRotate calls stop scheduling new work.
func (r *Rotator) Wait() {
	r.closing.Store(true)
	r.wg.Wait()
}
