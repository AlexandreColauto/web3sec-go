//go:build windows

package sandbox

import "os/exec"

// setProcGroup / killGroup: windows has no POSIX groups — direct kill
// only (the pipe-hold class was reproduced on unix; windows keeps the
// r19 behavior and reports the kill as not group-confirmed).
func setProcGroup(cmd *exec.Cmd) {}

func killGroup(cmd *exec.Cmd) bool {
	if cmd.Process == nil {
		return false
	}
	return cmd.Process.Kill() == nil
}
