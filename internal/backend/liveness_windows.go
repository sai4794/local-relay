//go:build windows

package backend

import (
	"os"
	"os/exec"
)

// processStillAlive is the Windows counterpart of the POSIX liveness probe.
// Windows has neither kill(0) nor Wait4(WNOHANG); a reaped child has a
// non-nil ProcessState, which is the portable signal that it exited.
func processStillAlive(proc *os.Process, cmd *exec.Cmd) bool {
	if proc == nil || proc.Pid <= 0 {
		return true
	}
	return cmd == nil || cmd.ProcessState == nil
}
