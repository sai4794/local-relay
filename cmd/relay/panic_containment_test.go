package main

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// H-01: a panic in a serving goroutine must cancel the process context so
// the supervisor can restart the relay instead of leaving a dead listener
// behind a live PID.
func TestStartServerGoroutine_PanicCancelsContext(t *testing.T) {
	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	startServerGoroutine("panic-test", discardLogger(), stop, func() error {
		panic("serving goroutine panic")
	})

	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("panic in serving goroutine did not cancel the process context")
	}
}

// The health/metrics components use runComponent; their panics must cancel
// the same process context for the same reason.
func TestRunComponent_PanicCancelsContext(t *testing.T) {
	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	go runComponent("panic-test", discardLogger(), stop, func() error {
		panic("component panic")
	})

	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("panic in component goroutine did not cancel the process context")
	}
}

// A normal serve error still stops the process (pre-existing behavior).
func TestStartServerGoroutine_ServeErrorCancelsContext(t *testing.T) {
	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	startServerGoroutine("error-test", discardLogger(), stop, func() error {
		return context.DeadlineExceeded
	})

	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("serve error did not cancel the process context")
	}
}
