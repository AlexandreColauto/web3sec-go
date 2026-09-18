// invariants_exec_relevance_test.go: Task 1 (defect 6) — the exec-relevance
// gate. A cited exec only counts as a check of an invariant when the command
// it RAN targeted one of the entry's applies_to contracts. The captured output
// cannot decide this: a Foundry full-suite run names every contract in its
// log, which is exactly how a generic suite exec "closed" an invariant it
// never touched.
package invariants

import (
	"path/filepath"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// seedBound seeds one invariant with an explicit applies_to binding.
func seedBound(t *testing.T, c *state.Campaign, invID, statement string,
	appliesTo ...string) {
	t.Helper()
	model := validation.VObj(kv("invariants", validation.VArr(validation.VObj(
		kv("id", validation.VStr(invID)),
		kv("statement", validation.VStr(statement)),
		kv("applies_to", strArr(appliesTo)),
	))))
	if _, err := SeedFromModel(c, model); err != nil {
		t.Fatalf("seed model: %v", err)
	}
}

// execRan is testExec with only the recorded command line in play.
func execRan(t *testing.T, c *state.Campaign, command string) validation.Value {
	t.Helper()
	return testExec(t, c, "docker-networkless", "", 0, "PASS\n", command)
}

// execWithoutCommand is an exec record that carries no command line at all.
func execWithoutCommand(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	rec := execRan(t, c, "forge test --match-contract Staking")
	rec.O = popKey(rec.O, "command")
	p := filepath.Join(c.ExecsDir, objStr(rec, "exec_id"), "exec_record.json")
	if err := validation.WriteJson(p, rec, ""); err != nil {
		t.Fatal(err)
	}
	return rec
}

// TestExecTouchesInvariant pins the binding matcher: a case-insensitive
// LEFT-boundary token match with no trailing boundary. The trailing side is
// deliberately open because Foundry's --match-contract is a regex/prefix
// filter — `\bStaking\b` would reject `--match-contract StakingTest`, exactly
// the targeted command the gate exists to accept — while the left boundary is
// what keeps `Unstaking` out.
func TestExecTouchesInvariant(t *testing.T) {
	c := invCamp(t)
	seedBound(t, c, "INV-3", "staking liveness", "Staking")
	for _, cmd := range []string{
		"forge test --match-contract Staking",
		"forge test --match-contract StakingTest",
		"forge test --match-path src/Staking.t.sol",
		"forge test --match-contract staking",
		"'forge test --match-contract Staking'",
		"forge test --match-contract Staking && forge test",
	} {
		ex := execRan(t, c, cmd)
		ok, reason := ExecTouchesInvariant(c, "INV-3", objStr(ex, "exec_id"))
		if !ok || reason != "" {
			t.Errorf("%q: ok=%v reason=%q, want true/\"\"", cmd, ok, reason)
		}
	}
	// Adversarial near-misses: the token sits inside another word (`n`
	// precedes), belongs to another contract, or is absent altogether.
	for _, cmd := range []string{
		"forge test --match-contract Unstaking",
		"forge test --match-contract OracleTest",
		"forge test",
	} {
		ex := execRan(t, c, cmd)
		ok, reason := ExecTouchesInvariant(c, "INV-3", objStr(ex, "exec_id"))
		if ok || reason != "no-target-match" {
			t.Errorf("%q: ok=%v reason=%q, want false/no-target-match", cmd, ok, reason)
		}
	}
	ok, reason := ExecTouchesInvariant(c, "INV-3", "EXEC-missing")
	if ok || reason != "no-exec-record" {
		t.Errorf("missing exec: ok=%v reason=%q, want false/no-exec-record", ok, reason)
	}
}

// TestExecTouchesInvariantIgnoresInvariantID: the id is bookkeeping, not a
// contract. referenceTokens prepends the invariant id (and its canonical
// spelling), so reusing it here would open a `--match-contract INV-3` bypass —
// a command naming only the id must never satisfy the gate.
func TestExecTouchesInvariantIgnoresInvariantID(t *testing.T) {
	c := invCamp(t)
	seedBound(t, c, "INV-003", "staking liveness", "Staking")
	for _, cmd := range []string{
		"forge test --match-contract INV-003",
		"forge test --match-contract INV-3",
		"forge test --match-path src/INV-003.t.sol",
	} {
		ex := execRan(t, c, cmd)
		ok, reason := ExecTouchesInvariant(c, "INV-003", objStr(ex, "exec_id"))
		if ok || reason != "no-target-match" {
			t.Errorf("%q: ok=%v reason=%q, want false/no-target-match "+
				"(the id is not an applies_to target)", cmd, ok, reason)
		}
	}
}

// TestExecTouchesInvariantEmptyAppliesTo: an invariant bound to nothing cannot
// be exec-verified. Empty applies_to is unbound, never a wildcard — the same
// law Task 4 pins for artifact references.
func TestExecTouchesInvariantEmptyAppliesTo(t *testing.T) {
	c := invCamp(t)
	seedBound(t, c, "INV-9", "unbound invariant")
	ex := execRan(t, c, "forge test --match-contract Staking")
	ok, reason := ExecTouchesInvariant(c, "INV-9", objStr(ex, "exec_id"))
	if ok || reason != "no-target-match" {
		t.Errorf("empty applies_to: ok=%v reason=%q, want false/no-target-match",
			ok, reason)
	}
}

// TestExecTouchesInvariantNoCommandRecord: a record with no command line (or
// an empty one) cannot show what the exec ran — refused with the named reason,
// never passed by default.
func TestExecTouchesInvariantNoCommandRecord(t *testing.T) {
	c := invCamp(t)
	seedBound(t, c, "INV-3", "staking liveness", "Staking")
	for _, ex := range []validation.Value{execRan(t, c, ""),
		execWithoutCommand(t, c)} {
		ok, reason := ExecTouchesInvariant(c, "INV-3", objStr(ex, "exec_id"))
		if ok || reason != "no-command-record" {
			t.Errorf("%s: ok=%v reason=%q, want false/no-command-record",
				objStr(ex, "exec_id"), ok, reason)
		}
	}
}
