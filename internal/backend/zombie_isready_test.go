package backend

import (
	"os/exec"
	"testing"
	"time"
)

// Regression: IsReady must not report ready for a zombie (exited but not yet
// reaped) child — kill(0) passes on zombies, so a non-blocking Wait4(WNOHANG)
// check must follow. Does not touch the 3-strike kill/spawn gating.
func TestRegression_IsReadyZombieNotReady(t *testing.T) {
	if _, err := exec.LookPath("true"); err != nil {
		t.Skip("true binary not in PATH")
	}
	// Spawn a child that exits immediately; do not Wait on it here so it
	// becomes a zombie until IsReady's Wait4 reaps it (or init does).
	cmd := exec.Command("true")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	// Wait for the child to exit (become a zombie) without reaping it.
	deadline := time.Now().Add(5 * time.Second)
	for {
		var exited bool
		select {
		default:
			// Poll liveness without reaping: signal 0 succeeds for both
			// running and zombie states, so wait until enough time has
			// passed that "true" must have exited.
			exited = time.Since(deadline.Add(-5*time.Second)) > 500*time.Millisecond
		}
		if exited {
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	inst := &TorInstance{ID: 1, Cmd: cmd, Ready: true, StartedAt: time.Now()}
	if inst.IsReady() {
		// Either the zombie check missed, or init already reaped the child
		// (in which case Wait4 sees ECHILD — also not-ready). A true here
		// means kill(0) passed with no zombie/ECHILD detection.
		t.Fatal("IsReady = true for exited child; want false (zombie must not pass liveness)")
	}
	// Ensure the child is reaped so the test does not leak a zombie.
	_ = cmd.Wait()
}

// A live child must still report ready.
func TestRegression_IsReadyLiveChildReady(t *testing.T) {
	if _, err := exec.LookPath("sleep"); err != nil {
		t.Skip("sleep binary not in PATH")
	}
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	inst := &TorInstance{ID: 1, Cmd: cmd, Ready: true, StartedAt: time.Now()}
	if !inst.IsReady() {
		t.Fatal("IsReady = false for live child; want true")
	}
	// IsReady must not have reaped the live child: a second IsReady still
	// reports ready (a reaped live child would flip to not-ready).
	if !inst.IsReady() {
		t.Fatal("second IsReady = false for live child; IsReady must not reap a running process")
	}
}
