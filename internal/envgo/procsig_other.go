//go:build windows

package envgo

import "os/exec"

func setProcGroup(cmd *exec.Cmd) {}

// killGroup: windows has no POSIX groups; direct kill only.
func killGroup(cmd *exec.Cmd) bool {
	if cmd.Process == nil {
		return false
	}
	return cmd.Process.Kill() == nil
}
