package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/validation"
)

// apWrite writes a bespoke report body to a fresh path.
func apWrite(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "r.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestR20SuspectGateIsCaseInsensitive(t *testing.T) { // F2
	c, root := mcCamp(t, "r20-f2")
	rep := apWrite(t, `{"schema_version": "1.0", "published": true,
		"publish_problems": [], "review_independent": true,
		"capabilities_missing": [], "flags": {"loop_bound": 4},
		"property_outcomes": {"p1": {"outcome": "PROVEN",
			"per_rule": {"inv_1": "PROVEN"}}},
		"review_findings": [{"property": "p1", "verdict": "SUSPECT",
			"reason": "rule can never fail"}]}`)
	code, _, errS := apVerify(t, root, c, "--property", "p1", "--report", rep)
	if code != 2 || !strings.Contains(errS, "SUSPECT") {
		t.Fatalf("uppercase SUSPECT verdict must gate: exit %d err %q",
			code, errS)
	}
}

func TestR20AutoproveBindsOnlyWithARealExec(t *testing.T) { // F7
	c, root := mcCamp(t, "r20-f7")
	rep := apWrite(t, `{"schema_version": "1.0", "published": true,
		"publish_problems": [], "review_independent": true,
		"capabilities_missing": [], "flags": {"loop_bound": 4},
		"property_outcomes": {"p1": {"outcome": "PROVEN",
			"per_rule": {"inv_1": "PROVEN"}}},
		"review_findings": []}`)
	code, _, errS := apVerify(t, root, c, "--property", "p1",
		"--report", rep, "--exec", "EXEC-DOESNOTEXIST")
	if code != 2 || !strings.Contains(errS, "EXEC-DOESNOTEXIST") {
		t.Fatalf("unknown --exec must refuse (fabricated witness): exit "+
			"%d err %q", code, errS)
	}
}

func TestR20ViolatedRollupNeedsAViolatedLine(t *testing.T) { // F5
	c, root := mcCamp(t, "r20-f5")
	rep := apWrite(t, `{"schema_version": "1.0", "published": true,
		"publish_problems": [], "review_independent": true,
		"capabilities_missing": [], "flags": {"loop_bound": 4},
		"property_outcomes": {"p1": {"outcome": "VIOLATED",
			"per_rule": {"inv_1": "PROVEN"}}},
		"review_findings": []}`)
	code, out, errS := apVerify(t, root, c, "--property", "p1", "--report", rep)
	if code != 0 {
		t.Fatalf("exit %d err %q", code, errS)
	}
	if !strings.Contains(out, "inconclusive") ||
		!strings.Contains(out, "no violated line") {
		t.Fatalf("contradictory VIOLATED rollup must demote: %q", out)
	}
}

func TestR20ScalarProblemsRefused(t *testing.T) { // F6
	c, root := mcCamp(t, "r20-f6")
	rep := apWrite(t, `{"schema_version": "1.0", "published": true,
		"publish_problems": "rule inv_1 is vacuous",
		"review_independent": true, "capabilities_missing": [],
		"flags": {"loop_bound": 4},
		"property_outcomes": {"p1": {"outcome": "PROVEN",
			"per_rule": {"inv_1": "PROVEN"}}},
		"review_findings": []}`)
	code, _, errS := apVerify(t, root, c, "--property", "p1", "--report", rep)
	if code != 2 || !strings.Contains(errS, "malformed") {
		t.Fatalf("scalar veto list must refuse: exit %d err %q", code, errS)
	}
}

func TestR20UnstatedBoundDisclosed(t *testing.T) { // F11
	c, root := mcCamp(t, "r20-f11")
	rep := apWrite(t, `{"schema_version": "1.0", "published": true,
		"publish_problems": [], "review_independent": true,
		"capabilities_missing": [], "flags": {},
		"property_outcomes": {"p1": {"outcome": "PROVEN",
			"per_rule": {"inv_1": "PROVEN"}}},
		"review_findings": []}`)
	code, out, errS := apVerify(t, root, c, "--property", "p1", "--report", rep)
	if code != 0 {
		t.Fatalf("exit %d err %q", code, errS)
	}
	if !strings.Contains(out, "bound UNSTATED") {
		t.Fatalf("'bounded' without a k must say the bound is absent: %q",
			out)
	}
}

func TestR20OnePropertyProvesOneInvariant(t *testing.T) { // F9
	c, root := mcCamp(t, "r20-f9")
	// Seed a SECOND invariant through the real path.
	model := validation.VObj(kvT("invariants", validation.VArr(
		validation.VObj(
			kvT("id", validation.VStr("INV-2")),
			kvT("statement", validation.VStr(
				"withdrawer never receives more than deposited")),
		))))
	if _, err := invariants.SeedFromModel(c, model); err != nil {
		t.Fatal(err)
	}
	rep := apWrite(t, `{"schema_version": "1.0", "published": true,
		"publish_problems": [], "review_independent": true,
		"capabilities_missing": [], "flags": {"loop_bound": 4},
		"property_outcomes": {"p1": {"outcome": "PROVEN",
			"per_rule": {"inv_1": "PROVEN"}}},
		"review_findings": []}`)
	code, _, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--autoprove", "INV-2", "--property", "p1", "--report", rep)
	if code != 0 {
		t.Fatalf("INV-2 needs a scaffold? use raw bind: %q", errS)
	}
	// Same report+property claimed for INV-1 as well: refused.
	code, _, errS = apVerify(t, root, c, "--property", "p1", "--report", rep)
	if code != 2 || !strings.Contains(errS, "already proves INV-2") {
		t.Fatalf("double credit for one proof must refuse: exit %d err %q",
			code, errS)
	}
}

func TestR20RefusedEventRollsBackTheRung(t *testing.T) { // F3
	c, root := mcCamp(t, "r20-f3")
	rep := apWrite(t, `{"schema_version": "1.0", "published": true,
		"publish_problems": [], "review_independent": true,
		"capabilities_missing": [], "flags": {"loop_bound": 4},
		"property_outcomes": {"p1": {"outcome": "PROVEN",
			"per_rule": {"inv_1": "PROVEN"}}},
		"review_findings": []}`)
	if code, _, errS := apVerify(t, root, c, "--property", "p1",
		"--report", rep); code != 0 {
		t.Fatalf("first bind: exit %d err %q", code, errS)
	}
	linksPath := filepath.Join(c.ArtifactsDir, "invariant_links.json")
	before, err := os.ReadFile(linksPath)
	if err != nil {
		t.Fatal(err)
	}
	// Break the ledger; a NEWER (weaker) bind must not half-land.
	viol := strings.Replace(string(mustRead(t, rep)), `"outcome": "PROVEN"`,
		`"outcome": "VIOLATED"`, 1)
	rep2 := apWrite(t, viol)
	if err := os.WriteFile(c.EventsPath, []byte("{\"garbage\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := apVerify(t, root, c, "--property", "p1",
		"--report", rep2); code == 0 {
		t.Fatal("bind on a dead ledger must fail")
	}
	after, err := os.ReadFile(linksPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatalf("refused bind moved the rung:\n%s\nvs\n%s", before, after)
	}
}

func TestR20RebindOverChangedReportWarns(t *testing.T) { // F10
	c, root := mcCamp(t, "r20-f10")
	body := `{"schema_version": "1.0", "published": true,
		"publish_problems": [], "review_independent": true,
		"capabilities_missing": [], "flags": {"loop_bound": 4},
		"property_outcomes": {"p1": {"outcome": "PROVEN",
			"per_rule": {"inv_1": "PROVEN"}}},
		"review_findings": []}`
	rep := apWrite(t, body)
	if code, _, errS := apVerify(t, root, c, "--property", "p1",
		"--report", rep); code != 0 {
		t.Fatalf("first bind: exit %d err %q", code, errS)
	}
	// Same report PATH, different bytes (substitution on disk).
	p2 := rep
	if err := os.WriteFile(p2, []byte(strings.Replace(body,
		`"per_rule": {"inv_1": "PROVEN"}`,
		`"per_rule": {"inv_1": "PROVEN", "inv_2": "PROVEN"}`, 1)),
		0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errS := apVerify(t, root, c, "--property", "p1", "--report", p2)
	if code != 0 {
		t.Fatalf("same-invariant refresh is legal: exit %d err %q out %q",
			code, errS, out)
	}
	if !strings.Contains(errS, "DIFFERENT report digest") {
		t.Fatalf("a substituted re-bind must warn on stderr: %q", errS)
	}
}

func TestR20HarnessRungAlsoRollsBack(t *testing.T) { // F3 (harness path)
	c, root := mcCamp(t, "r20-f3h")
	execID := "EXEC-F3H"
	mcHarnessExec(t, c, execID, mcProvenLine, "minicertora --rule inv_1",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c)}, 0)
	if code, _, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID); code != 0 {
		t.Fatalf("baseline bind: exit %d err %q", code, errS)
	}
	linksPath := filepath.Join(c.ArtifactsDir, "invariant_links.json")
	before, _ := os.ReadFile(linksPath)
	// A second, DIFFERENT-outcome exec; kill the ledger; refuse ⇒ no move.
	mcHarnessExec(t, c, "EXEC-F3H2", mcViolatedLine, "minicertora --rule inv_1",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c)}, 1)
	if err := os.WriteFile(c.EventsPath, []byte("{\"garbage\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", "EXEC-F3H2"); code == 0 {
		t.Fatal("harness bind on a dead ledger must fail")
	}
	after, _ := os.ReadFile(linksPath)
	if string(before) != string(after) {
		t.Fatal("harness rung moved under a refused event")
	}
}

var _ = state.Campaign{}
