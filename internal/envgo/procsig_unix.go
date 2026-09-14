//go:build !windows

package envgo

import (
	"os/exec"
	"syscall"
)

func setProcGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killGroup signals the whole process group BY NUMBER (pgid ==
// the child's pid, since Setpgid makes it the group leader) — never via
// Getpgid: by timeout the direct child is often ALREADY REAPED by Go's
// Wait (wrapper exec'd out and exited), Getpgid ESRCHes, and the old
// corpse-Kill fallback let the pipe-holding grandchild survive while
// the record still said "was killed" (r22 F1). Returns whether the
// group had members to signal.
func killGroup(cmd *exec.Cmd) bool {
	if cmd.Process == nil {
		return false
	}
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) == nil
}
