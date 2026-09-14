package sandbox

import (
	"strings"
	"testing"
	"time"
)

// TestGroupKillBoundsTheHangingWrapper pins r21 F1: a PATH probe that
// is a shell WRAPPER whose CHILD holds the stdout pipe (uv shims do
// exactly this) used to hang Wait forever; the r19 grace-return then
// read the shared Builders while a copier still wrote — a DATA RACE
// (reproduced under -race). Group-kill reaches the survivor; the
// race-arm returns empty, never racing bytes.
func TestGroupKillBoundsTheHangingWrapper(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	// (loop writing forever) & then exec sleep — the direct child
	// (sleep) dies on kill, the loop child holds the pipe: the exact
	// critic repro.
	argv := []string{"/bin/sh", "-c",
		"( while true; do echo spam; sleep 0.05; done ) & exec sleep 30"}
	start := time.Now()
	res, err := realRunProc(argv, "", nil, 1*time.Second)
	el := time.Since(start)
	if err != errTimeout {
		t.Fatalf("want errTimeout, got %v", err)
	}
	if el > 8*time.Second {
		t.Fatalf("timeout path unbounded: %v", el)
	}
	if el > 3500*time.Millisecond {
		t.Fatalf("group kill should land near-instantly, took %v (r19 "+
			"grace expiry is 5s: slow = the survivor escaped the group)",
			el)
	}
	// Bytes are either a clean snapshot or the documented empty arm —
	// never a torn read (the -race detector is the real assertion).
	_ = strings.Contains(res.Stdout, "spam")
}
