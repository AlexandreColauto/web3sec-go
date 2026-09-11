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
