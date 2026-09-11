// Port of Task 4 step 1: the presence-gated eval audit section.
//
// A campaign whose program matches the eval suite (ES03BankReentrancy,
// one dev case in the real pack) renders the pinned ## eval lines; a
// campaign matching nothing returns ErrSkip (the gate is closed —
// AuditCampaign omits the section, so golden campaigns keep 14
// sections). The section is exercised directly (the sections package
// cannot import the audit package without an import cycle); the
// registry-level omission is pinned by internal/audit's own gate test.
package sections

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// evalFinding builds a synthetic live finding: only the anchor keys the
// scorer reads (root_cause.class, affected[0].path) are populated.
func evalFinding(class, path string) validation.Value {
	return validation.VObj(
		KV("root_cause", validation.VObj(KV("class", validation.VStr(class)))),
		KV("affected", validation.VArr(
			validation.VObj(KV("path", validation.VStr(path))),
		)),
	)
}

// evalCampaign opens a scratch campaign pinning the given program and
// writes the given live findings as raw finding docs (LoadLiveFindings
// reads them without schema validation).
func evalCampaign(t *testing.T, program string, live []validation.Value) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), program, state.InitOpts{})
	if err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	for i, f := range live {
		p := filepath.Join(c.FindingsDir,
			"F-eval000000000"+string(rune('0'+i))+".json")
		if err := validation.WriteJson(p, f, ""); err != nil {
			t.Fatalf("WriteJson: %v", err)
		}
	}
	return c
}

// evalLines reads the section's pinned markdown lines.
func evalLines(t *testing.T, sec validation.Value) []string {
	t.Helper()
	lv := objAt(sec, "lines")
	if lv.Kind != validation.Arr {
		t.Fatalf("no lines array: %s", validation.DumpIndented(sec))
	}
	var out []string
	for _, l := range lv.A {
		out = append(out, l.S)
	}
	return out
}

func TestEvalRendersPinnedLines(t *testing.T) {
	// ES03BankReentrancy matches exactly one real-pack case
	// (CASE-000000000003, dev, reentrancy @ ES03BankReentrancy.sol):
	// one anchored finding + one wrong-class FP.
	c := evalCampaign(t, "ES03BankReentrancy", []validation.Value{
		evalFinding("reentrancy", "src/ES03BankReentrancy.sol"),
		evalFinding("oracle-manipulation", "src/ES03BankReentrancy.sol"),
	})
	sec, err := Eval(c)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	// The exact five lines ARE the I1b byte walk: the shipped suite is
	// partition-clean (uniform parseable deployed_at, no held-out
	// duplicate of a dev row), so the presence-gated problem block adds
	// nothing here. A sixth line in this list is a regression.
	want := []string{
		"## eval",
		"- suite: 1 gold cases matched (1 dev, 0 held-out)",
		"- recall: 1/1 (95% CI 20.7–100.0%)",
		"- precision: 1/2 (95% CI 9.5–90.5%)",
		"- false positives (unanchored live findings): 1",
	}
	if got := evalLines(t, sec); !reflect.DeepEqual(got, want) {
		t.Fatalf("lines = %q\nwant %q", got, want)
	}
	if ok := objAt(sec, "ok"); ok.Kind != validation.Bool || !ok.B {
		t.Errorf("eval section must stay ok=true (informational): %s",
			validation.DumpIndented(sec))
	}
	if n := len(objAt(sec, "problems").A); n != 0 {
		t.Errorf("problems = %d, want 0", n)
	}
}

// partitionCase builds a minimal suite row: only the keys this section,
// evalscore and the I1b partition health actually read.
func partitionCase(caseID, partition, program, deployed, created,
	class, rootCause, file string) validation.Value {
	row := []validation.KV{
		KV("case_id", validation.VStr(caseID)),
		KV("partition", validation.VStr(partition)),
		KV("program", validation.VObj(KV("program", validation.VStr(program)))),
		KV("created_at", validation.VStr(created)),
		KV("gold", validation.VObj(
			KV("outcome", validation.VStr("confirmed-exploitable")),
			KV("bug_class", validation.VStr(class)),
			KV("severity", validation.VStr("high")),
			KV("root_cause", validation.VStr(rootCause)),
			KV("locations", validation.VArr(validation.VObj(
				KV("file", validation.VStr(file))))))),
		KV("code", validation.VObj(KV("repo", validation.VStr("internal://evalsuite")))),
	}
	if deployed != "" {
		row = append(row, KV("deployed_at", validation.VStr(deployed)))
	}
	return validation.VObj(row...)
}

// withEvalCases points the section's suite loader at a synthetic pack for
// one test. The shipped pack cannot exercise the I1b problem render: it is
// partition-clean by construction.
func withEvalCases(t *testing.T, cases []validation.Value) {
	t.Helper()
	restore := evalCases
	evalCases = func() ([]validation.Value, error) { return cases, nil }
	t.Cleanup(func() { evalCases = restore })
}

// TestEvalRendersPartitionProblemsWhenPresent: a suite row whose
// deployed_at cannot be parsed is excluded at scoring time, and the
// section says so — the block appears only when there is something to
// report, and the campaign's own ok stays true (a store defect is not a
// campaign defect; the run is fail-open).
func TestEvalRendersPartitionProblemsWhenPresent(t *testing.T) {
	withEvalCases(t, []validation.Value{
		partitionCase("CASE-0000000000d1", "dev", "ES03BankReentrancy",
			"2026-05-01", "2026-01-01T00:00:00+00:00", "reentrancy",
			"withdraw sends funds before the balance update",
			"src/ES03BankReentrancy.sol"),
		partitionCase("CASE-0000000000h1", "held-out", "Other", "2026-1-1",
			"2026-01-01T00:00:00+00:00", "oracle-manipulation",
			"spot reserves price the borrow limit", "src/Lender.sol"),
	})
	c := evalCampaign(t, "ES03BankReentrancy", []validation.Value{
		evalFinding("reentrancy", "src/ES03BankReentrancy.sol"),
	})
	sec, err := Eval(c)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	got := evalLines(t, sec)
	wantTail := []string{
		"- partition problems (rows excluded from the scorecard, never mutated): 1",
		"  - unparseable-deployed_at CASE-0000000000h1",
	}
	if len(got) != 7 {
		t.Fatalf("lines = %q\nwant the five pinned lines + %q", got, wantTail)
	}
	if !reflect.DeepEqual(got[5:], wantTail) {
		t.Fatalf("problem block = %q\nwant %q", got[5:], wantTail)
	}
	probs := objAt(sec, "problems")
	if probs.Kind != validation.Arr || len(probs.A) != 1 ||
		probs.A[0].S != "unparseable-deployed_at CASE-0000000000h1" {
		t.Fatalf("problems value = %s", validation.CanonCompact(probs))
	}
	if ok := objAt(sec, "ok"); ok.Kind != validation.Bool || !ok.B {
		t.Errorf("a store-side partition problem must not fail the campaign: %s",
			validation.DumpIndented(sec))
	}
}

// TestEvalOmitsProblemBlockWhenClean: the same synthetic pack minus the
// unusable date renders exactly the five pinned lines and an empty
// problems array — the presence gate, proven at the byte level.
func TestEvalOmitsProblemBlockWhenClean(t *testing.T) {
	withEvalCases(t, []validation.Value{
		partitionCase("CASE-0000000000d1", "dev", "ES03BankReentrancy",
			"2026-05-01", "2026-01-01T00:00:00+00:00", "reentrancy",
			"withdraw sends funds before the balance update",
			"src/ES03BankReentrancy.sol"),
	})
	c := evalCampaign(t, "ES03BankReentrancy", []validation.Value{
		evalFinding("reentrancy", "src/ES03BankReentrancy.sol"),
	})
	sec, err := Eval(c)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	want := []string{
		"## eval",
		"- suite: 1 gold cases matched (1 dev, 0 held-out)",
		"- recall: 1/1 (95% CI 20.7–100.0%)",
		"- precision: 1/1 (95% CI 20.7–100.0%)",
		"- false positives (unanchored live findings): 0",
	}
	if got := evalLines(t, sec); !reflect.DeepEqual(got, want) {
		t.Fatalf("lines = %q\nwant %q", got, want)
	}
	if n := len(objAt(sec, "problems").A); n != 0 {
		t.Fatalf("problems = %d, want 0", n)
	}
}

func TestEvalSkipsWhenNothingMatched(t *testing.T) {
	c := evalCampaign(t, "nothing-here", nil)
	_, err := Eval(c)
	if !errors.Is(err, ErrSkip) {
		t.Fatalf("Eval = %v, want ErrSkip (gate closed)", err)
	}
}

func TestEvalRegisteredLast(t *testing.T) {
	var names []string
	RegisterAll(func(name string, _ SectionFunc) { names = append(names, name) })
	if len(names) == 0 || names[len(names)-1] != "eval" {
		t.Fatalf("eval not registered last: %v", names)
	}
}
