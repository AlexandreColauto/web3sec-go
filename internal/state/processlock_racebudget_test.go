package state

import (
	"testing"
	"time"
)

// raceLockBudgetFactor multiplies the cross-process lock budget in TEST
// binaries built with -race. It exists because the race detector inflates
// process teardown to roughly a second per worker: the concurrent lock
// tests spawn N worker processes that each hold the campaign lock until
// they exit, so the Nth worker's wait is ~N seconds even though every
// critical section is milliseconds (measured: last write → process reaped
// = 1.002s under -race, 7ms of actual work). Five seconds is therefore not
// a budget any honest HOLD could exceed, but it is a budget the detector's
// own overhead can exceed through no fault of the code under test —
// measured: 6 workers, 5s+ wait on the last one, deterministic failure.
//
// The factor is applied here, in test code, and nowhere else: production
// behavior is byte-identical (lockBudget stays 5s; a real stuck holder
// still fails loudly after five seconds). The r13/r14/r15 fail-loud law is
// untouched — the tests below still catch a genuinely lost update under
// -race, which is proven by mutation (drop one worker's write → red).
const raceLockBudgetFactor = 10

func init() {
	if raceEnabled {
		lockBudget *= raceLockBudgetFactor
	}
}

// TestLockBudgetMatchesBuild pins BOTH directions of the scaling: the
// shipped budget is exactly five seconds in a normal build, and the
// scaling happens only in a -race test build. Without this, "production
// behavior is byte-identical" would be an unverified claim.
func TestLockBudgetMatchesBuild(t *testing.T) {
	want := 5 * time.Second
	if raceEnabled {
		want *= raceLockBudgetFactor
	}
	if lockBudget != want {
		t.Fatalf("lockBudget = %s, want %s (raceEnabled=%v)",
			lockBudget, want, raceEnabled)
	}
}
