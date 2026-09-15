package sandbox

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestWrapperExitSurvivorShapeIsKilled pins r22 F1: wrapper EXITED,
// background child holds the pipe — the shape where Getpgid ESRCH'd and
// the corpse-kill fallback no-op'd the fix. Now pgid==pid by number.
func TestWrapperExitSurvivorShapeIsKilled(t *testing.T) {
	argv := []string{"/bin/sh", "-c", "sleep 40 & echo start; wait"}
	// 'wait' keeps the wrapper alive though; use the exact critic shape:
	argv = []string{"/bin/sh", "-c", "sleep 40 & echo start"}
	// The window is sized for fork/exec under a LOADED box, not an idle
	// one: whole-package runs (docker tests hogging the pool beside this
	// one) once starved a 1s budget so badly that `echo start` never ran
	// and the pin blamed the killer for an empty capture. 3s of startup
	// slack keeps the assertion about the KILL, not about the scheduler;
	// the grace ceiling scales with it so "lands ~instantly" still bites.
	start := time.Now()
	res, err := realRunProc(argv, "", nil, 3*time.Second)
	el := time.Since(start)
	if err != errTimeout {
		t.Fatalf("want timeout: %v", err)
	}
	if el > 5500*time.Millisecond {
		t.Fatalf("grace tax: %v (group kill must land ~instantly)", el)
	}
	if !strings.Contains(res.Stdout, "start") {
		t.Fatalf("captured stdout destroyed (note=%q): %q", res.TimeoutNote, res.Stdout)
	}
	// The survivor check must not depend on the GLOBAL process table:
	// `pgrep -f "sleep 40"` matches any other sleep 40 on the box (a
	// docker-daemon neighbour, an earlier run's container) and fails this
	// pin over processes it never created. The law is that the survivor
	// does not KEEP RUNNING, so a SECOND run gives the background job a
	// marker to write on completion: the marker must never appear. The
	// subshell keeps the precedence explicit ((A; B) & C), unlike the
	// bare list form.
	marker := filepath.Join(t.TempDir(), "survived-"+strconv.Itoa(os.Getpid()))
	argv = []string{"/bin/sh", "-c",
		"(sleep 40; echo SURVIVED > " + marker + ") & echo start"}
	if _, err := realRunProc(argv, "", nil, 3*time.Second); err != errTimeout {
		t.Fatalf("want timeout: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, serr := os.Stat(marker); serr == nil {
			t.Fatalf("survivor escaped the group kill and completed: %s exists", marker)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
