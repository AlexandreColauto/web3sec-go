package sandbox

import (
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
	start := time.Now()
	res, err := realRunProc(argv, "", nil, 1*time.Second)
	el := time.Since(start)
	if err != errTimeout {
		t.Fatalf("want timeout: %v", err)
	}
	if el > 3200*time.Millisecond {
		t.Fatalf("grace tax: %v (group kill must land ~instantly)", el)
	}
	if !strings.Contains(res.Stdout, "start") {
		t.Fatalf("captured stdout destroyed (note=%q): %q", res.TimeoutNote, res.Stdout)
	}
	time.Sleep(200 * time.Millisecond)
	out, _ := realRunProc([]string{"/bin/pgrep", "-f", "sleep 40"}, "", nil, 2*time.Second)
	if strings.TrimSpace(out.Stdout) != "" {
		t.Fatalf("survivor escaped the group kill: %q", out.Stdout)
	}
}
