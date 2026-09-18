package cli

// cmd_invariant_verify_exec_relevance_test.go: Task 1 (defect 6) — the CLI
// half of the exec-relevance gate. `invariant-verify --exec` only moves the
// verification axis when the cited exec's recorded command targeted one of the
// invariant's applies_to contracts; a generic full-suite run is refused before
// anything is written, however loudly its captured log names the invariant.

import (
	"os"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// relExec is one finished exec whose recorded command and captured log are
// both in play: the command decides the exec-relevance gate, the log decides
// Task 4's byte gate.
func relExec(t *testing.T, c *state.Campaign, execID, command,
	stdout string) validation.Value {
	t.Helper()
	rec := invExecRecord(t, c, execID, command)
	if err := os.WriteFile(validation.ObjStr(rec, "stdout_path"), []byte(stdout),
		0o644); err != nil {
		t.Fatal(err)
	}
	return rec
}

// relCamp is the exec-relevance fixture: INV-3 bound to the Staking contract,
// one exec whose command targeted it, and one whole-suite exec whose captured
// log names the invariant anyway.
func relCamp(t *testing.T) (c *state.Campaign, root, hit, suite string) {
	t.Helper()
	c, root = t15Campaign(t, "inv-exec-rel")
	t15SeedInvariant(t, c, "INV-3", "staking liveness", "Staking")
	log := "INV-3: staking liveness\nPASS: test_liveness\n"
	hit = validation.ObjStr(relExec(t, c, "EXEC-0000000001",
		"forge test --match-contract Staking", log), "exec_id")
	suite = validation.ObjStr(relExec(t, c, "EXEC-0000000002", "forge test", log),
		"exec_id")
	return c, root, hit, suite
}

// TestInvariantVerifyRefusesUntargetedExec: the cited exec ran a whole-suite
// `forge test` that targeted no applies_to contract. Its captured log names
// the invariant, so Task 4's byte gate would have waved it through — the
// exec-relevance gate refuses it, and nothing about the verification axis
// moves: no status change, no verified_by, no attestation label, no event.
func TestInvariantVerifyRefusesUntargetedExec(t *testing.T) {
	c, root, _, suite := relCamp(t)
	code, _, errS := run(t, "--root", root, "invariant-verify", c.CampaignID,
		"INV-3", "--exec", suite)
	if code != 2 {
		t.Fatalf("exit = %d, want 2 (%q)", code, errS)
	}
	if !strings.Contains(errS, "cited exec "+suite+
		" does not target any applies_to contract of INV-3 (no-target-match)") {
		t.Fatalf("stderr missing the refusal text: %q", errS)
	}
	entry := invEntry(t, c, "INV-3")
	if got := validation.ObjStr(entry, "status"); got != "UNVERIFIED" {
		t.Fatalf("status = %q, want UNVERIFIED", got)
	}
	if got := validation.ObjStr(entry, "verified_by"); got != "" {
		t.Fatalf("verified_by = %q, want empty on a refusal", got)
	}
	if got := validation.ObjStr(entry, "verification_method"); got != "" {
		t.Fatalf("verification_method = %q, want no attestation label", got)
	}
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range events {
		if validation.ObjStr(ev, "type") == "invariant.verified" {
			t.Fatal("a refusal must emit no invariant.verified event")
		}
	}
	// F-B: a refused citation mints no artifact row either. The row's note
	// ("invariant INV-3 checked against code") is a durable record asserting
	// the verification this gate just refused — the defect-6 record class.
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range objListAt(st, "artifacts") {
		if strings.Contains(validation.ObjStr(a, "note"), "INV-3") {
			t.Fatalf("refused citation minted artifact row %s: note %q",
				validation.ObjStr(a, "artifact_id"), validation.ObjStr(a, "note"))
		}
	}
}

// TestInvariantVerifyAcceptsTargetedExec: the exec's recorded command targeted
// the applies_to contract, so the citation lands end-to-end.
func TestInvariantVerifyAcceptsTargetedExec(t *testing.T) {
	c, root, hit, _ := relCamp(t)
	code, out, errS := run(t, "--root", root, "invariant-verify", c.CampaignID,
		"INV-3", "--exec", hit)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (%q)", code, errS)
	}
	if !strings.Contains(out, "INV-3: CHECKED_AGAINST_CODE") {
		t.Fatalf("output %q", out)
	}
	if got := validation.ObjStr(invEntry(t, c, "INV-3"), "status"); got !=
		"CHECKED_AGAINST_CODE" {
		t.Fatalf("status = %q, want CHECKED_AGAINST_CODE", got)
	}
}
