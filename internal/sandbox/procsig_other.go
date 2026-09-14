//go:build windows

package sandbox

import "os/exec"

// setProcGroup / killGroup: windows fallback — without a POSIX group
// there is nothing more to do than the direct kill (the hang class was
// reproduced on unix; windows keeps the r19 behavior).
func setProcGroup(cmd *exec.Cmd) {}

func killGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
