//go:build race

package state

// raceEnabled reports whether this binary was compiled with the race
// detector. It mirrors the standard library's internal/race pattern
// (race.go / norace.go): a compile-time constant, so the false branch
// costs nothing and production binaries cannot observe it. The only
// consumer is the -race test harness (processlock_racebudget_test.go),
// which needs a longer cross-process lock budget because the detector
// inflates process teardown — see lockBudget.
const raceEnabled = true
