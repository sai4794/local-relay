package rotate

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

type Rotator struct {
	counter   atomic.Uint64
	interval  atomic.Uint64
	onRotate  func()
	logger    *slog.Logger
	lastTrade atomic.Int64
	wg        sync.WaitGroup
}

func NewRotator(interval int, onRotate func(), logger *slog.Logger) *Rotator {
	r := &Rotator{
		onRotate: onRotate,
		logger:   logger,
	}
	r.interval.Store(uint64(interval))
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

		if r.onRotate != nil {
			r.wg.Add(1)
			go func() {
				defer r.wg.Done()
				r.onRotate()
			}()
		}

		r.lastTrade.Store(time.Now().UnixNano())
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
	r.interval.Store(uint64(interval))
}

// ForceRotate triggers an immediate rotation regardless of request count.
func (r *Rotator) ForceRotate() {
	r.logger.Info("Forced IP rotation")
	if r.onRotate != nil {
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.onRotate()
		}()
	}
	r.lastTrade.Store(time.Now().UnixNano())
}

// Wait blocks until all in-flight rotation goroutines complete.
// Call during shutdown to prevent goroutine leaks.
func (r *Rotator) Wait() {
	r.wg.Wait()
}
