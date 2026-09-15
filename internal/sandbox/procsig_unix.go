//go:build linux

package sandbox

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
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

// r36 F1/F2 hooks: the timeout path needs to see the payload's process
// tree and kill escapees BY PID (a setsid() survivor is unreachable by
// the pgid kill but is still our same-uid descendant). procsig_other.go's
// platforms have no /proc; the vars stay nil there and the timeout note
// reports honestly that survivors could not be enumerated.
func init() {
	survivorsOfFn = survivorsOf
	killSurvivorFn = killSurvivor
	survivorAliveFn = survivorAlive
}

// procStatInfo is the /proc/<pid>/stat fields the tree walk needs.
type procStatInfo struct {
	state   byte
	ppid    int
	pgrp    int
	session int
}

// procStat parses /proc/<pid>/stat. The comm field may contain spaces and
// parentheses, so everything after the LAST ')' is the fixed field list:
// state ppid pgrp session ...
func procStat(pid int) (procStatInfo, error) {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return procStatInfo{}, err
	}
	i := strings.LastIndex(string(raw), ")")
	if i < 0 || i+2 >= len(raw) {
		return procStatInfo{}, os.ErrInvalid
	}
	f := strings.Fields(string(raw[i+2:]))
	if len(f) < 4 {
		return procStatInfo{}, os.ErrInvalid
	}
	ppid, err1 := strconv.Atoi(f[1])
	pgrp, err2 := strconv.Atoi(f[2])
	session, err3 := strconv.Atoi(f[3])
	if err1 != nil || err2 != nil || err3 != nil {
		return procStatInfo{}, os.ErrInvalid
	}
	return procStatInfo{state: f[0][0], ppid: ppid, pgrp: pgrp,
		session: session}, nil
}

// survivorsOf walks /proc and returns every pid in root's process tree:
// root itself, every descendant by the ppid chain, and every member of
// root's process group. A setsid() escapee keeps its ppid link to its
// parent until the parent dies, so the snapshot must be taken BEFORE the
// group kill reparents the orphans. ok=false when /proc cannot be read
// (the caller then reports honestly that it could not enumerate).
func survivorsOf(root int) (pids []int, ok bool) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, false
	}
	children := map[int][]int{}
	group := map[int][]int{}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		st, err := procStat(pid)
		if err != nil {
			continue
		}
		children[st.ppid] = append(children[st.ppid], pid)
		group[st.pgrp] = append(group[st.pgrp], pid)
	}
	seen := map[int]bool{}
	var out []int
	var bfs func(int)
	bfs = func(pid int) {
		if seen[pid] {
			return
		}
		seen[pid] = true
		out = append(out, pid)
		for _, c := range children[pid] {
			bfs(c)
		}
	}
	bfs(root)
	for _, g := range group[root] {
		bfs(g)
	}
	return out, true
}

// killSurvivor SIGKILLs one escaped pid. The escapee is our own
// same-uid descendant, so an unprivileged signal reaches it.
func killSurvivor(pid int) bool {
	return syscall.Kill(pid, syscall.SIGKILL) == nil
}

// survivorAlive reports whether pid is still live (a zombie counts as
// dead: the reaper will not resurrect it).
func survivorAlive(pid int) bool {
	st, err := procStat(pid)
	return err == nil && st.state != 'Z'
}
