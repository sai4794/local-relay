package backend

import (
	"fmt"
	"testing"
)

// M-06: a timeout/refusal between two auth rejections must NOT reset the
// consecutive-rejection counter, or the 3-strike recycle never fires.
func TestNoteAuthResult_TransientErrorDoesNotResetStreak(t *testing.T) {
	tl := NewTorLifecycle(TorLifecycleConfig{})
	inst := &TorInstance{ID: 1}
	inst.SetReady(true)
	reject := fmt.Errorf("control AUTHENTICATE: auth rejected")
	transient := fmt.Errorf("control read: i/o timeout")

	tl.noteAuthResult(inst, reject)
	tl.noteAuthResult(inst, reject)
	tl.noteAuthResult(inst, transient)
	tl.noteAuthResult(inst, reject)

	if inst.IsReady() {
		t.Error("instance still ready after 3 auth rejections with an interleaved timeout; streak was reset")
	}
}

// A successful auth operation still clears the streak (unchanged behavior).
func TestNoteAuthResult_SuccessResetsStreak(t *testing.T) {
	tl := NewTorLifecycle(TorLifecycleConfig{})
	inst := &TorInstance{ID: 2}
	inst.SetReady(true)
	reject := fmt.Errorf("control AUTHENTICATE: auth rejected")
	tl.noteAuthResult(inst, reject)
	tl.noteAuthResult(inst, reject)
	tl.noteAuthResult(inst, nil)
	tl.noteAuthResult(inst, reject)
	if !inst.IsReady() {
		t.Error("instance marked not-ready after only 2 consecutive rejections")
	}
}
