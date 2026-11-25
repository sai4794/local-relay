//go:build !windows

package backend

import (
	"os"
	"os/exec"
	"syscall"
)

// processStillAlive performs the POSIX kill(0) + non-blocking Wait4 zombie
// check. The exec.Cmd is unused here; it is needed only by the Windows build.
func processStillAlive(proc *os.Process, _ *exec.Cmd) bool {
	if proc == nil || proc.Pid <= 0 {
		return true
	}
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		return false
	}
	var ws syscall.WaitStatus
	pid, err := syscall.Wait4(proc.Pid, &ws, syscall.WNOHANG, nil)
	if err == syscall.ECHILD {
		return false // already reaped: no live process backs this instance
	}
	return pid != proc.Pid
}
