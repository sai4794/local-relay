package main

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/local-relay/proxy/internal/backend"
	"github.com/local-relay/proxy/internal/rotate"
)

// M-07: cancelling Start while fake Tor children are spawned must clean up
// those children; orphans can collide with a later Start's ports.
func TestTorLifecycle_StartCancellationCleansUpChildren(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "tor.pid")
	script := filepath.Join(dir, "fake-tor.sh")
	body := "#!/bin/sh\necho $$ > \"$FAKE_TOR_PID_FILE\"\nexec sleep 300\n"
	if err := os.WriteFile(script, []byte(body), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_TOR_PID_FILE", pidFile)

	tl := backend.NewTorLifecycle(backend.TorLifecycleConfig{
		Binary: script, DataDir: filepath.Join(dir, "data"),
		BasePort: 0, ControlBase: 0, MaxInstances: 1,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- tl.Start(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(pidFile); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fake Tor child never spawned")
		}
		time.Sleep(10 * time.Millisecond)
	}
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { // safety net so a pre-fix orphan never outlives the test
		proc, err := os.FindProcess(pid)
		if err == nil {
			proc.Kill()
		}
	})

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}
	time.Sleep(200 * time.Millisecond) // allow kill/reap to finish
	proc, err := os.FindProcess(pid)
	if err != nil {
		t.Fatal(err)
	}
	if err := proc.Signal(syscall.Signal(0)); err == nil {
		t.Errorf("Tor child PID %d survived cancelled Start; orphan can collide with a later Start", pid)
	}
}

// M-13: a stuck rotation callback must not block shutdown indefinitely.
func TestWaitForRotator_Bounded(t *testing.T) {
	release := make(chan struct{})
	rot := rotate.NewRotator(1, func() { <-release }, discardLogger())
	rot.ShouldRotate() // starts a callback that blocks until released
	time.Sleep(50 * time.Millisecond)
	t.Cleanup(func() { close(release) })

	done := make(chan bool, 1)
	go func() { done <- waitForRotator(rot, 150*time.Millisecond) }()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("waitForRotator reported completion while the callback was still blocked")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("waitForRotator blocked past its timeout")
	}
}
