//go:build linux

package sandbox

import (
	"os/exec"
	"syscall"
)

// r22 F1: kill the wrapper's GROUP by NUMBER — pgid == the child's pid
// because Setpgid made it the group leader. Never Getpgid: once Go's
// Wait reaps an EXITED wrapper the lookup ESRCHes and the old
// corpse-Kill fallback silently no-op'd the fix while the record still
// claimed "was killed". As long as any member lives the signal lands;
// an ESRCH means the group is already EMPTY (every member dead — which
// is also when the copiers saw EOF), so no false "unreached" survives.
// Members that setsid() OUT of the group are unreachable by any
// permissionless parent: those are the honest TimeoutNote arm.
func setProcGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func killGroup(cmd *exec.Cmd) bool {
	if cmd.Process == nil {
		return false
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err == nil {
		return true
	}
	_ = cmd.Process.Kill() // zombie/reaped: harmless, group was empty
	return false
}
