//go:build !windows

package sandbox

import (
	"os/exec"
	"syscall"
)

// setProcGroup puts the probe in its own process group; killGroup then
// signals every survivor (r21 F1: wrapper scripts on PATH — uv shims,
// #!/bin/sh version printers — hold the stdout pipe through their
// children, which a direct-child Kill never reaches).
func setProcGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func killGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	pgid, err := syscall.Getpgid(cmd.Process.Pid)
	if err != nil {
		_ = cmd.Process.Kill()
		return
	}
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
}
