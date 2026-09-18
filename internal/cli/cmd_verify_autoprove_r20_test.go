package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	if code != 2 || !strings.Contains(errS, "already bound to INV-2") {
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

// TestR21SuspectGateFailsClosed pins r21 F2: verdicts are LLM
// verbatim — " suspect " (padding) and string-shaped findings are the
// SAME flag; the gate may only fail toward refusal.
func TestR21SuspectGateFailsClosed(t *testing.T) {
	cases := []struct{ name, findings string }{
		{"padded", `[{"property": "p1", "verdict": " suspect ",
			"reason": "r"}]`},
		{"trailing-newline", `[{"property": "p1", "verdict": "SUSPECT\n",
			"reason": "r"}]`},
		{"string-shaped", `["the whole review was a mess"]`},
		{"unattributed-suspect", `[{"verdict": "suspect",
			"reason": "which property? all of them"}]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, root := mcCamp(t, "r21-f2-"+tc.name)
			rep := apWrite(t, `{"schema_version": "1.0", "published": true,
				"publish_problems": [], "review_independent": true,
				"capabilities_missing": [], "flags": {"loop_bound": 4},
				"property_outcomes": {"p1": {"outcome": "PROVEN",
					"per_rule": {"inv_1": "PROVEN"}}},
				"review_findings": `+tc.findings+`}`)
			code, _, errS := apVerify(t, root, c, "--property", "p1",
				"--report", rep)
			if code != 2 {
				t.Fatalf("%s must refuse the bind: exit %d err %q",
					tc.name, code, errS)
			}
		})
	}
}

// TestR21DigestChurnCannotReuseAProperty pins r21 F3: the rail is
// keyed on the property NAME — one byte of churn is not a new proof.
func TestR21DigestChurnCannotReuseAProperty(t *testing.T) {
	c, root := mcCamp(t, "r21-f3")
	model := validation.VObj(kvT("invariants", validation.VArr(
		validation.VObj(
			kvT("id", validation.VStr("INV-2")),
			kvT("statement", validation.VStr(
				"withdrawer never receives more than deposited")),
		))))
	if _, err := invariants.SeedFromModel(c, model); err != nil {
		t.Fatal(err)
	}
	body := `{"schema_version": "1.0", "published": true,
		"publish_problems": [], "review_independent": true,
		"capabilities_missing": [], "flags": {"loop_bound": 4},
		"property_outcomes": {"p1": {"outcome": "PROVEN",
			"per_rule": {"inv_1": "PROVEN"}}},
		"review_findings": []}`
	rep := apWrite(t, body)
	if code, _, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--autoprove", "INV-2", "--property", "p1", "--report", rep); code != 0 {
		t.Fatalf("first bind: %q", errS)
	}
	// Same property, DIFFERENT bytes (churn) aimed at INV-1: refused.
	rep2 := apWrite(t, body+"\n")
	code, _, errS := apVerify(t, root, c, "--property", "p1",
		"--report", rep2)
	if code != 2 || !strings.Contains(errS, "already bound to INV-2") {
		t.Fatalf("digest churn must not buy a second bind: exit %d err %q",
			code, errS)
	}
}

// TestR21AuditRefusesAnUnbackedHarnessRung pins r21 F7: docs §8 said
// the audit cross-checks claims against events — now it TRUELY does:
// a slot written without an event (hand edit here) burns.
func TestR21AuditRefusesAnUnbackedHarnessRung(t *testing.T) {
	c, root := mcCamp(t, "r21-f7")
	rep := apWrite(t, `{"schema_version": "1.0", "published": true,
		"publish_problems": [], "review_independent": true,
		"capabilities_missing": [], "flags": {"loop_bound": 4},
		"property_outcomes": {"p1": {"outcome": "PROVEN",
			"per_rule": {"inv_1": "PROVEN"}}},
		"review_findings": []}`)
	if code, _, errS := apVerify(t, root, c, "--property", "p1",
		"--report", rep); code != 0 {
		t.Fatalf("bind: %q", errS)
	}
	if code, _, errS := run(t, "--root", root, "audit", c.CampaignID); code != 0 {
		t.Fatalf("baseline audit must PASS: exit %d %q", code, errS)
	}
	// Hand-edit the slot: same event, stronger claim.
	linksPath := filepath.Join(c.ArtifactsDir, "invariant_links.json")
	raw, _ := os.ReadFile(linksPath)
	hand := strings.Replace(string(raw),
		`"summary": "autoproved bounded (k=4, 1 rules)"`,
		`"summary": "proved by angles and miracles"`, 1)
	if hand == string(raw) {
		t.Fatal("fixture drift: summary text not found")
	}
	if err := os.WriteFile(linksPath, []byte(hand), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "audit", c.CampaignID)
	if code == 0 || !strings.Contains(out, "does not match the LAST harness_run") {
		t.Fatalf("drifted slot must burn audit: exit %d out %q err %q",
			code, out, errS)
	}
}

// TestR22ReviewCrashNeverBlessed pins r22 F2 + F5: review_error means
// the gate NEVER RAN; null findings is a foreign contract. Neither is
// "no findings".
func TestR22ReviewCrashNeverBlessed(t *testing.T) {
	cases := []struct{ name, inject, want string }{
		{"crashed review", `"review_error": "review model call failed: boom",`,
			"NEVER RAN"},
		{"null findings", `"review_findings": null,`, "malformed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, root := mcCamp(t, "r22-"+strings.ReplaceAll(tc.name, " ", "-"))
			rep := apWrite(t, `{"schema_version": "1.0", "published": true,
				`+tc.inject+`
				"publish_problems": [], "review_independent": true,
				"capabilities_missing": [], "flags": {"loop_bound": 4},
				"property_outcomes": {"p1": {"outcome": "PROVEN",
					"per_rule": {"inv_1": "PROVEN"}}}}`)
			code, _, errS := apVerify(t, root, c, "--property", "p1",
				"--report", rep)
			if code != 2 || !strings.Contains(errS, tc.want) {
				t.Fatalf("%s: exit %d err %q", tc.name, code, errS)
			}
		})
	}
}

// TestR22CaseFoldedAttribution pins r22 F4: " suspect " on "P1" is the
// same flag on the same property; and one property proves one
// invariant ACROSS casings.
func TestR22CaseFoldedAttribution(t *testing.T) {
	c, root := mcCamp(t, "r22-f4a")
	rep := apWrite(t, `{"schema_version": "1.0", "published": true,
		"review_error": "",
		"publish_problems": [], "review_independent": true,
		"capabilities_missing": [], "flags": {"loop_bound": 4},
		"property_outcomes": {"P1": {"outcome": "PROVEN",
			"per_rule": {"inv_1": "PROVEN"}}},
		"review_findings": [{"property": "p1", "verdict": "Suspect",
			"reason": "case-dodged?"}]}`)
	code, _, errS := apVerify(t, root, c, "--property", "P1", "--report", rep)
	if code != 2 || !strings.Contains(errS, "SUSPECT") {
		t.Fatalf("case-slipped flag must gate: exit %d err %q", code, errS)
	}
	// Double-credit rail across cases.
	c2, root2 := mcCamp(t, "r22-f4b")
	model := validation.VObj(kvT("invariants", validation.VArr(
		validation.VObj(
			kvT("id", validation.VStr("INV-2")),
			kvT("statement", validation.VStr(
				"withdrawer never receives more than deposited")),
		))))
	if _, err := invariants.SeedFromModel(c2, model); err != nil {
		t.Fatal(err)
	}
	clean := `{"schema_version": "1.0", "published": true,
		"publish_problems": [], "review_independent": true,
		"capabilities_missing": [], "flags": {"loop_bound": 4},
		"property_outcomes": {"p1": {"outcome": "PROVEN",
			"per_rule": {"inv_1": "PROVEN"}}},
		"review_findings": []}`
	rep2 := apWrite(t, clean)
	if code, _, errS := run(t, "--root", root2, "verify", c2.CampaignID,
		"--autoprove", "INV-2", "--property", "p1", "--report", rep2); code != 0 {
		t.Fatalf("first bind: %q", errS)
	}
	code, _, errS = apVerify(t, root2, c2, "--property", "P1", "--report", rep2)
	if code != 2 || !strings.Contains(errS, "already bound to INV-2") {
		t.Fatalf("P1 is p1 for the rail: exit %d err %q", code, errS)
	}
}

// TestR22BackstopComparesTheBound pins r22 F3: k is the field the
// display trusts MOST — hand-editing it burns audit even when the
// summary stays true.
func TestR22BackstopComparesTheBound(t *testing.T) {
	c, root := mcCamp(t, "r22-f3k")
	rep := apWrite(t, `{"schema_version": "1.0", "published": true,
		"publish_problems": [], "review_independent": true,
		"capabilities_missing": [], "flags": {"loop_bound": 4},
		"property_outcomes": {"p1": {"outcome": "PROVEN",
			"per_rule": {"inv_1": "PROVEN"}}},
		"review_findings": []}`)
	if code, _, errS := apVerify(t, root, c, "--property", "p1",
		"--report", rep); code != 0 {
		t.Fatalf("bind: %q", errS)
	}
	linksPath := filepath.Join(c.ArtifactsDir, "invariant_links.json")
	raw, _ := os.ReadFile(linksPath)
	hand := strings.Replace(string(raw), `"bounded_k": 4,`,
		`"bounded_k": 999999,`, 1)
	if hand == string(raw) {
		t.Fatal("fixture drift: bounded_k not found")
	}
	if err := os.WriteFile(linksPath, []byte(hand), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ := run(t, "--root", root, "audit", c.CampaignID)
	if code == 0 || !strings.Contains(out, "bounded_k") {
		t.Fatalf("a 999999 hand-edit must burn on the k axis: exit %d",
			code)
	}
}

// TestR23ProofSubtreeIsBackedByTheEvent pins r23 F1: k= and poc: render
// from the proof subtree — the event now fingerprints it, and the
// backstop honors the digest both ways (drift AND invention).
func TestR23ProofSubtreeIsBackedByTheEvent(t *testing.T) {
	c, root := mcCamp(t, "r23-proof")
	rep := apWrite(t, `{"schema_version": "1.0", "published": true,
		"publish_problems": [], "review_independent": true,
		"capabilities_missing": [], "flags": {"loop_bound": 4},
		"property_outcomes": {"p1": {"outcome": "PROVEN",
			"per_rule": {"inv_1": "PROVEN"}}},
		"review_findings": []}`)
	if code, _, errS := apVerify(t, root, c, "--property", "p1",
		"--report", rep); code != 0 {
		t.Fatalf("bind: %q", errS)
	}
	linksPath := filepath.Join(c.ArtifactsDir, "invariant_links.json")
	raw, _ := os.ReadFile(linksPath)
	// (a) the autoprove event pinned the NULL-proof digest: inventing a
	// subtree on the slot is the hand-edit the digest exists for.
	hand := strings.Replace(string(raw),
		`"summary": "autoproved bounded (k=4, 1 rules)"`,
		`"summary": "autoproved bounded (k=4, 1 rules)", "proof": `+
			`{"bounds": {"loop_bound": 999999}}`, 1)
	if hand == string(raw) {
		t.Fatal("fixture drift: anchor not found")
	}
	if err := os.WriteFile(linksPath, []byte(hand), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ := run(t, "--root", root, "audit", c.CampaignID)
	if code == 0 || !strings.Contains(out, "does not match the LAST harness_run event's digest") {
		t.Fatalf("invented sidecar must burn: exit %d out %.200q", code, out)
	}
}

// TestR23SwapDuringMappingRefuses pins the r23 sharpest-idea rail: the
// event may only name bytes the registry will hold. Swap mid-run and
// the bind refuses BEFORE any ledger row exists.
func TestR23SwapDuringMappingRefuses(t *testing.T) {
	c, root := mcCamp(t, "r23-swap")
	rep := apWrite(t, `{"schema_version": "1.0", "published": true,
		"publish_problems": [], "review_independent": true,
		"capabilities_missing": [], "flags": {"loop_bound": 4},
		"property_outcomes": {"p1": {"outcome": "PROVEN",
			"per_rule": {"inv_1": "PROVEN"}}},
		"review_findings": []}`)
	// Wrap the real verify in nothing we can inject… the rail fires
	// between parse and bind INSIDE one process; simulate the swap by
	// racing a writer is nondeterministic — instead prove the refusal
	// text via the same sha the pre-bind check reads: bind once clean,
	// then churn bytes and rebind a DIFFERENT property so the pre-bind
	// check runs (F9 consumption would fire first on same property, so
	// use p2 in the swap file).
	swapped := rep + ".swap"
	if err := os.WriteFile(swapped, []byte(`{"schema_version": "1.0",
		"published": true, "publish_problems": [],
		"review_independent": true, "capabilities_missing": [],
		"flags": {"loop_bound": 4},
		"property_outcomes": {"p2": {"outcome": "PROVEN",
			"per_rule": {"inv_1": "PROVEN"}}},
		"review_findings": []}`), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errS := apVerify(t, root, c, "--property", "p2",
		"--report", swapped)
	if code != 0 {
		t.Fatalf("second distinct property binds clean: %q", errS)
	}
	// The deterministic swap: a writer lands NEW bytes after parse-time
	// mapping — the pre-bind recheck must refuse BEFORE any event
	// exists, so no unwind is ever needed. Fresh campaign: the seam
	// arms exactly p2's own clean bind, so the parse-time tree (with
	// p2) maps while the disk already holds the swapped bytes.
	c3, root3 := mcCamp(t, "r23-swap2")
	orig, _ := os.ReadFile(swapped)
	AutoproveSwapSeam = func() {
		_ = os.WriteFile(swapped, append(append([]byte{}, orig...),
			'\n'), 0o644)
	}
	defer func() { AutoproveSwapSeam = nil }()
	code, out, errS := run(t, "--root", root3, "verify", c3.CampaignID,
		"--autoprove", "INV-1", "--property", "p2", "--report", swapped)
	if code != 2 || !strings.Contains(errS,
		"changed on disk while being mapped") {
		t.Fatalf("mid-run swap must refuse the bind: exit %d err %q",
			code, errS)
	}
	if strings.Contains(out, "INV-1: proved") {
		t.Fatal("refused swap still printed a bind")
	}
	evLog := filepath.Join(root3, "campaigns", c3.CampaignID,
		"events.jsonl")
	if raw, _ := os.ReadFile(evLog); strings.Contains(string(raw),
		"harness_run") {
		t.Fatal("refused bind still left an event")
	}
}

// TestR24BoundIsReadTyped pins r24 F3: 4.5 is not a bound the run
// stated — truncation was a silent lie; a stated 0 IS stated (k=0),
// and UNSTATED means the report said nothing at all.
func TestR24BoundIsReadTyped(t *testing.T) {
	mk := func(body string) (int, string, string) {
		c, root := mcCamp(t, "r24-typed")
		model := validation.VObj(kvT("invariants", validation.VArr(
			validation.VObj(
				kvT("id", validation.VStr("INV-2")),
				kvT("statement", validation.VStr(
					"withdrawer never receives more than deposited")),
			))))
		if _, err := invariants.SeedFromModel(c, model); err != nil {
			t.Fatal(err)
		}
		rep := apWrite(t, body)
		return run(t, "--root", root, "verify", c.CampaignID,
			"--autoprove", "INV-2", "--property", "p1",
			"--report", rep)
	}
	base := `{"schema_version": "1.0", "published": true,
		"publish_problems": [], "review_independent": true,
		"capabilities_missing": [], "flags": {"loop_bound": %s},
		"property_outcomes": {"p1": {"outcome": "PROVEN",
			"per_rule": {"inv_1": "PROVEN"}}},
		"review_findings": []}`
	if code, _, errS := mk(fmt.Sprintf(base, "4.5")); code != 2 ||
		!strings.Contains(errS, "not an integer") {
		t.Fatalf("float bound must refuse: %d %q", code, errS)
	}
	if code, _, errS := mk(fmt.Sprintf(base, "-1")); code != 2 ||
		!strings.Contains(errS, "degenerate") {
		t.Fatalf("negative bound must refuse: %d %q", code, errS)
	}
	if code, _, errS := mk(fmt.Sprintf(base, `"4"`)); code != 2 ||
		!strings.Contains(errS, "not an integer") {
		t.Fatalf("string bound must refuse: %d %q", code, errS)
	}
	// Stated zero: the TWIN refuses degenerate flags (loop_bound<1
	// raises), so a report stating 0 is foreign — refuse (r25 F3).
	if code, _, errS := mk(fmt.Sprintf(base, "0")); code != 2 ||
		!strings.Contains(errS, "degenerate") {
		t.Fatalf("k=0 must refuse as the twin does: %d %q", code, errS)
	}
	// Null: the honest UNSTATED.
	code, out, _ := mk(fmt.Sprintf(base, "null"))
	if code != 0 || !strings.Contains(out, "bound UNSTATED") {
		t.Fatalf("null must render UNSTATED: %d out %q", code, out)
	}
}

// TestR24QuietReconcileBurnsAudit pins the r24 F1 end-state: bind,
// overwrite the report file on disk, reconcile refreshes the registry
// row — the event still names the MAPPED bytes and no row holds them
// anymore. The §8 promise "a substituted report file cannot ride a
// quiet refresh" now has a read-time witness.
func TestR24QuietReconcileBurnsAudit(t *testing.T) {
	c, root := mcCamp(t, "r24-reconcile")
	rep := apWrite(t, `{"schema_version": "1.0", "published": true,
		"publish_problems": [], "review_independent": true,
		"capabilities_missing": [], "flags": {"loop_bound": 4},
		"property_outcomes": {"p1": {"outcome": "PROVEN",
			"per_rule": {"inv_1": "PROVEN"}}},
		"review_findings": []}`)
	if code, _, errS := apVerify(t, root, c, "--property", "p1",
		"--report", rep); code != 0 {
		t.Fatalf("bind: %q", errS)
	}
	// r25 F4 changed the SHAPE of this attack: the bind stores a
	// content-addressed COPY, so mutating (or deleting) the operator
	// path after the bind is physically inert — the event's digest
	// lives in the campaign. The substituted-path attack now needs to
	// tamper the STORE (which the chain and the digest-named path
	// expose), not ride a quiet refresh.
	if err := os.WriteFile(rep, []byte(`{"schema_version": "1.0",
		"published": false}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, errS := run(t, "--root", root, "artifact-reconcile",
		c.CampaignID); code != 0 {
		t.Fatalf("reconcile: exit %d %q", code, errS)
	}
	if code, out, _ := run(t, "--root", root, "audit", c.CampaignID); code != 0 {
		t.Fatalf("post-bind mutation of the SOURCE path must not burn "+
			"(the copy is the evidence): exit %d out %q", code, out[:200])
	}
	// And a forged STORE copy DOES burn: flip a byte inside the bound
	// report copy — the row's sha vs the digest-named contents.
	dir := filepath.Join(c.ArtifactsDir, "reports")
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("expected one stored copy, got %d", len(ents))
	}
	cp := filepath.Join(dir, ents[0].Name())
	if err := os.Chmod(cp, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cp, []byte(`{"published": false}`), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ := run(t, "--root", root, "audit", c.CampaignID)
	if code == 0 || !strings.Contains(out, "artifacts=1 problem") {
		t.Fatalf("tampered store copy must burn audit: exit %d out "+
			"%.200q", code, out)
	}
	// The §11 leg: reconcile honestly re-hashes the (tampered) store
	// file into the row — after that, NO row holds the bytes the EVENT
	// pinned, and the report-recheck must say so too.
	if code, _, errS := run(t, "--root", root, "artifact-reconcile",
		c.CampaignID); code != 0 {
		t.Fatalf("reconcile #2: %q", errS)
	}
	code, out, _ = run(t, "--root", root, "audit", c.CampaignID)
	if code == 0 || !strings.Contains(out,
		"no registry artifact holds the report") {
		t.Fatalf("orphaned event digest must burn §11: exit %d out "+
			"%.300q", code, out)
	}
}

// TestR26FoldEqualKeysDoNotBurnHonestBinds pins critic r26 F1: the bind
// resolves --property by EXACT key (cli.fieldOf) while the audit
// resolved it by case-fold FIRST-HIT, so a report holding two fold-equal
// spellings let the audit read a truth the bind never used and burn an
// honest rung on a green bind.
func TestR26FoldEqualKeysDoNotBurnHonestBinds(t *testing.T) {
	c, root := mcCamp(t, "r26-f1")
	rep := apWrite(t, `{"schema_version": "1.0", "published": true,
		"publish_problems": [], "review_independent": true,
		"capabilities_missing": [], "flags": {"loop_bound": 4},
		"property_outcomes": {
			"p": {"outcome": "VIOLATED", "per_rule": {"inv_1": "VIOLATED"}},
			"P": {"outcome": "PROVEN", "per_rule": {"inv_1": "PROVEN",
				"inv_2": "PROVEN"}}},
		"review_findings": []}`)
	code, out, errS := apVerify(t, root, c, "--property", "P",
		"--report", rep)
	if code != 0 {
		t.Fatalf("bind must succeed: exit %d err %q", code, errS)
	}
	if !strings.Contains(out+errS, "proved-bounded") {
		t.Fatalf("the EXACT key's truth must bind: %q", out+errS)
	}
	if code, out, _ := run(t, "--root", root, "audit", c.CampaignID); code != 0 {
		t.Fatalf("audit must re-derive the BIND's truth (exact-first), "+
			"not the fold-first neighbour: exit %d out %.400q", code, out)
	}
}

// TestR26FoldAmbiguousReportRefusesAttribution: several fold-equal
// spellings and NO exact key can belong to no bind (the bind is
// exact-match only), so the auditor refuses attribution instead of
// picking one — a forged event cannot hide behind spelling soup.
func TestR26FoldAmbiguousReportRefusesAttribution(t *testing.T) {
	c, root := mcCamp(t, "r26-f1b")
	rep := apWrite(t, `{"schema_version": "1.0", "published": true,
		"publish_problems": [], "review_independent": true,
		"capabilities_missing": [], "flags": {"loop_bound": 4},
		"property_outcomes": {
			"p":  {"outcome": "PROVEN", "per_rule": {"inv_1": "PROVEN"}},
			"P ": {"outcome": "VIOLATED",
				"per_rule": {"inv_1": "VIOLATED"}}},
		"review_findings": []}`)
	code, _, errS := apVerify(t, root, c, "--property", "P",
		"--report", rep)
	if code != 2 || !strings.Contains(errS, "exact-match only") {
		t.Fatalf("no exact key must refuse at BIND time: exit %d err %q",
			code, errS)
	}
}

// r26F2Body is the clean report body the F2 crash-seam cases bind: its
// own bytes are the digest, so a test can place a tmp (or a foreign
// final file) at the exact path storeReportCopy computes.
const r26F2Body = `{"schema_version": "1.0", "published": true,
	"publish_problems": [], "review_independent": true,
	"capabilities_missing": [], "flags": {"loop_bound": 4},
	"property_outcomes": {"p1": {"outcome": "PROVEN",
		"per_rule": {"inv_1": "PROVEN"}}},
	"review_findings": []}`

// r26F2Paths: the digest-named store paths for a report body, computed
// the way storeReportCopy computes them (sha256 of the exact bytes).
func r26F2Paths(t *testing.T, c *state.Campaign, body string) (string, string, string) {
	t.Helper()
	digest := validation.Sha256Hex([]byte(body))
	dir := filepath.Join(c.ArtifactsDir, "reports")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	final := filepath.Join(dir, "report-"+digest+".json")
	return digest, final, final + ".tmp"
}

// r26F2WantFinal: the final copy exists, is 0444, and its bytes hash to
// the digest the event will name.
func r26F2WantFinal(t *testing.T, final, digest string) {
	t.Helper()
	got, err := os.ReadFile(final)
	if err != nil {
		t.Fatalf("final report copy missing: %v", err)
	}
	if validation.Sha256Hex(got) != digest {
		t.Fatalf("final copy bytes do not hash to the digest %s", digest)
	}
	st, err := os.Stat(final)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o444 {
		t.Fatalf("final evidence must be 0444, got %v", st.Mode().Perm())
	}
}

// TestR26CrashLeftoverTmpDoesNotWedgeTheBind pins the first half of r26
// F2: a 0444 tmp left by a kill -9 between write and rename used to make
// the next bind open it for writing, take EACCES as the owner, and exit 2
// on that digest FOREVER. A tmp is scratch — wrong bytes are swept, and
// the digest must bind.
func TestR26CrashLeftoverTmpDoesNotWedgeTheBind(t *testing.T) {
	c, root := mcCamp(t, "r26-f2-wedge")
	rep := apWrite(t, r26F2Body)
	digest, final, tmp := r26F2Paths(t, c, r26F2Body)
	if err := os.WriteFile(tmp, []byte(`{"stale": "scratch"}`), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tmp, 0o444); err != nil {
		t.Fatal(err)
	}
	code, _, errS := apVerify(t, root, c, "--property", "p1", "--report", rep)
	if code != 0 {
		t.Fatalf("a leftover 0444 tmp must be swept, not wedge the "+
			"digest: exit %d err %q", code, errS)
	}
	r26F2WantFinal(t, final, digest)
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatalf("the scratch tmp must not survive a successful store "+
			"(stat err %v)", err)
	}
}

// TestR26CrashLeftoverTmpWithHonestBytesIsRecovered pins the second half:
// a tmp whose bytes ALREADY hash to the digest is the crash-after-write
// case — recovering it by rename must produce the same final evidence
// without a redo.
func TestR26CrashLeftoverTmpWithHonestBytesIsRecovered(t *testing.T) {
	c, root := mcCamp(t, "r26-f2-recover")
	rep := apWrite(t, r26F2Body)
	digest, final, tmp := r26F2Paths(t, c, r26F2Body)
	if err := os.WriteFile(tmp, []byte(r26F2Body), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errS := apVerify(t, root, c, "--property", "p1", "--report", rep)
	if code != 0 {
		t.Fatalf("a tmp already holding the digest must bind: exit %d "+
			"err %q", code, errS)
	}
	r26F2WantFinal(t, final, digest)
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatalf("the recovered tmp must have been renamed into place "+
			"(stat err %v)", err)
	}
}

// TestR26ForeignBytesAtTheFinalPathStillRefuse: the sweep rail must not
// soften the load-bearing tamper arm — a digest-named FINAL file whose
// bytes do not hash to its own name is evidence substituted, and the
// bind still refuses loudly, naming the tampered path.
func TestR26ForeignBytesAtTheFinalPathStillRefuse(t *testing.T) {
	c, root := mcCamp(t, "r26-f2-final")
	rep := apWrite(t, r26F2Body)
	digest, final, _ := r26F2Paths(t, c, r26F2Body)
	forged := []byte(`{"published": false}`)
	if err := os.WriteFile(final, forged, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(final, 0o444); err != nil {
		t.Fatal(err)
	}
	code, _, errS := apVerify(t, root, c, "--property", "p1", "--report", rep)
	if code != 2 {
		t.Fatalf("foreign bytes at the digest-named final path must "+
			"refuse: exit %d err %q", code, errS)
	}
	if !strings.Contains(errS, final) {
		t.Fatalf("the refusal must name the tampered path %s: %q",
			final, errS)
	}
	got, err := os.ReadFile(final)
	if err != nil || string(got) != string(forged) {
		t.Fatalf("the refused store must leave the foreign final file "+
			"untouched: %q err %v", got, err)
	}
	if validation.Sha256Hex(got) == digest {
		t.Fatal("fixture is vacuous: the forged bytes hash to the digest")
	}
}

// r27Victim writes a 0644 file OUTSIDE the campaign whose bytes are the
// report body — the out-of-campaign object a link at a store path makes
// the store rewrite through.
func r27Victim(t *testing.T, body string) string {
	t.Helper()
	v := filepath.Join(t.TempDir(), "victim.json")
	if err := os.WriteFile(v, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(v, 0o644); err != nil {
		t.Fatal(err)
	}
	return v
}

// r27WantVictim: an out-of-campaign victim's bytes AND mode are exactly
// what they were before a refused store (r27 F2: os.Rename moves the
// LINK into place and os.Chmod FOLLOWS it — observed 0644 -> 0444).
func r27WantVictim(t *testing.T, v string) {
	t.Helper()
	got, err := os.ReadFile(v)
	if err != nil {
		t.Fatalf("victim unreadable: %v", err)
	}
	if string(got) != r26F2Body {
		t.Fatalf("victim bytes changed: %q", got)
	}
	st, err := os.Stat(v)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o644 {
		t.Fatalf("victim mode was rewritten through the link: got %v, "+
			"want 0644", st.Mode().Perm())
	}
}

// r27NoScratchLeft: a successful store leaves no scratch behind — not
// the legacy fixed tmp and not this call's per-call tmp (r27 F4).
func r27NoScratchLeft(t *testing.T, dir string) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.Contains(e.Name(), ".tmp") {
			t.Fatalf("scratch %s survived a successful store in %s",
				e.Name(), dir)
		}
	}
}

// r27OnlyCopy: the store holds exactly the one digest-named file.
func r27OnlyCopy(t *testing.T, dir, final string) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, e := range ents {
		names = append(names, e.Name())
	}
	if len(ents) != 1 || ents[0].Name() != filepath.Base(final) {
		t.Fatalf("exactly one digest-named copy expected in %s, got %v",
			dir, names)
	}
}

// TestR27SymlinkAtTmpRefusesAndLeavesVictimAlone: the audited r27 F2. A
// symlink at report-<digest>.json.tmp whose (out-of-campaign) target
// holds exactly the report bytes used to: bind, have os.Rename MOVE THE
// LINK into place, and then have os.Chmod FOLLOW it and rewrite the
// victim's mode 0644 -> 0444. The store must refuse naming the shape, and
// the victim's bytes and mode must be untouched.
func TestR27SymlinkAtTmpRefusesAndLeavesVictimAlone(t *testing.T) {
	c, root := mcCamp(t, "r27-f2")
	rep := apWrite(t, r26F2Body)
	_, final, tmp := r26F2Paths(t, c, r26F2Body)
	victim := r27Victim(t, r26F2Body)
	if err := os.Symlink(victim, tmp); err != nil {
		t.Fatalf("cannot build the fixture symlink: %v", err)
	}
	code, _, errS := apVerify(t, root, c, "--property", "p1",
		"--report", rep)
	if code != 2 {
		t.Fatalf("a symlink at the tmp path must refuse: exit %d err %q",
			code, errS)
	}
	if !strings.Contains(errS, tmp) || !strings.Contains(errS, "symlink") {
		t.Fatalf("the refusal must name the path %s and the shape "+
			"symlink: %q", tmp, errS)
	}
	r27WantVictim(t, victim)
	if fi, err := os.Lstat(tmp); err != nil ||
		fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the refused link must stay where it was (lstat %v %v)",
			fi, err)
	}
	if _, err := os.Lstat(final); !os.IsNotExist(err) {
		t.Fatalf("nothing may be published at %s (lstat err %v)",
			final, err)
	}
}

// TestR27SymlinkAtFinalPathRefuses: the audited r27 F3. A symlink at
// report-<digest>.json whose target holds matching bytes was accepted as
// the immutable copy (the early reuse arm never checked the shape);
// rewriting the target later made §11 burn the honest bind with "cannot
// be re-read from the store". Refuse instead — the final path must be a
// regular file the store itself owns.
func TestR27SymlinkAtFinalPathRefuses(t *testing.T) {
	c, root := mcCamp(t, "r27-f3")
	rep := apWrite(t, r26F2Body)
	_, final, tmp := r26F2Paths(t, c, r26F2Body)
	victim := r27Victim(t, r26F2Body)
	if err := os.Symlink(victim, final); err != nil {
		t.Fatalf("cannot build the fixture symlink: %v", err)
	}
	code, _, errS := apVerify(t, root, c, "--property", "p1",
		"--report", rep)
	if code != 2 {
		t.Fatalf("a symlink at the final path must refuse: exit %d err "+
			"%q", code, errS)
	}
	if !strings.Contains(errS, final) || !strings.Contains(errS, "symlink") {
		t.Fatalf("the refusal must name the path %s and the shape "+
			"symlink: %q", final, errS)
	}
	r27WantVictim(t, victim)
	if _, err := os.Lstat(tmp); !os.IsNotExist(err) {
		t.Fatalf("a refused store must leave no scratch at %s (lstat "+
			"err %v)", tmp, err)
	}
}

// TestR27DirectoryAtTmpRefuses: the audited r27 F5. A non-empty
// directory at report-<digest>.json.tmp is NOT crash scratch: the old
// sweep called os.Remove on it, took ENOTEMPTY, and wedged that digest
// forever behind a message that misdiagnosed it as interrupted-store
// scratch. A directory is the same refusal class as a symlink, and the
// refused directory must survive untouched.
func TestR27DirectoryAtTmpRefuses(t *testing.T) {
	c, root := mcCamp(t, "r27-f5-tmp")
	rep := apWrite(t, r26F2Body)
	_, final, tmp := r26F2Paths(t, c, r26F2Body)
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(tmp, "keep")
	if err := os.WriteFile(keep, []byte("not scratch"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errS := apVerify(t, root, c, "--property", "p1",
		"--report", rep)
	if code != 2 {
		t.Fatalf("a directory at the tmp path must refuse: exit %d err "+
			"%q", code, errS)
	}
	if !strings.Contains(errS, tmp) || !strings.Contains(errS, "directory") {
		t.Fatalf("the refusal must name the path %s and the shape "+
			"directory: %q", tmp, errS)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("a refused directory is not scratch and must survive: %v",
			err)
	}
	if _, err := os.Lstat(final); !os.IsNotExist(err) {
		t.Fatalf("nothing may be published at %s (lstat err %v)",
			final, err)
	}
}

// TestR27DirectoryAtFinalPathRefuses: a directory at the digest-named
// FINAL path is not an immutable copy either — same refusal class,
// naming the shape (r27 F5/F3).
func TestR27DirectoryAtFinalPathRefuses(t *testing.T) {
	c, root := mcCamp(t, "r27-f5-final")
	rep := apWrite(t, r26F2Body)
	_, final, tmp := r26F2Paths(t, c, r26F2Body)
	if err := os.MkdirAll(final, 0o755); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(final, "keep")
	if err := os.WriteFile(keep, []byte("not a copy"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errS := apVerify(t, root, c, "--property", "p1",
		"--report", rep)
	if code != 2 {
		t.Fatalf("a directory at the final path must refuse: exit %d "+
			"err %q", code, errS)
	}
	if !strings.Contains(errS, final) || !strings.Contains(errS, "directory") {
		t.Fatalf("the refusal must name the path %s and the shape "+
			"directory: %q", final, errS)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("a refused directory is not scratch and must survive: %v",
			err)
	}
	if _, err := os.Lstat(tmp); !os.IsNotExist(err) {
		t.Fatalf("a refused store must leave no scratch at %s (lstat "+
			"err %v)", tmp, err)
	}
}

// TestR27LegacyScratchIsStillSweptAndRecovered: the kept r26 rails. A
// leftover LEGACY fixed-name tmp (report-<digest>.json.tmp) whose bytes
// already hash to the digest is the crash-after-write case and is
// RECOVERED by rename; one holding foreign bytes is scratch and is
// SWEPT. Both must still bind exit 0 under the per-call scratch regime,
// leaving exactly one digest-named copy.
func TestR27LegacyScratchIsStillSweptAndRecovered(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"honest-bytes", r26F2Body},
		{"foreign-bytes", `{"stale": "scratch"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, root := mcCamp(t, "r27-legacy-"+tc.name)
			rep := apWrite(t, r26F2Body)
			digest, final, tmp := r26F2Paths(t, c, r26F2Body)
			if err := os.WriteFile(tmp, []byte(tc.body), 0o444); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(tmp, 0o444); err != nil {
				t.Fatal(err)
			}
			code, _, errS := apVerify(t, root, c, "--property", "p1",
				"--report", rep)
			if code != 0 {
				t.Fatalf("a leftover 0444 legacy tmp must not wedge "+
					"the digest: exit %d err %q", code, errS)
			}
			r26F2WantFinal(t, final, digest)
			dir := filepath.Dir(final)
			r27NoScratchLeft(t, dir)
			r27OnlyCopy(t, dir, final)
		})
	}
}

// TestR27UnopenableReportsDirIsSurfaced: the audited r27 F6. The old
// arm inspected only d.Sync(), so an os.Open failure (reports dir mode
// 0333 -> EACCES) silently skipped the whole durability step while the
// comment claimed best-effort. An Open failure must now name the path
// and the error; only Sync failures meaning the filesystem cannot are
// tolerated.
func TestR27UnopenableReportsDirIsSurfaced(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses the 0333 directory mode")
	}
	c, root := mcCamp(t, "r27-f6")
	rep := apWrite(t, r26F2Body)
	_, final, _ := r26F2Paths(t, c, r26F2Body)
	dir := filepath.Dir(final)
	if err := os.Chmod(dir, 0o333); err != nil {
		t.Fatal(err)
	}
	restore := func() {
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatalf("cannot restore the reports dir mode: %v", err)
		}
	}
	t.Cleanup(restore)
	code, _, errS := apVerify(t, root, c, "--property", "p1",
		"--report", rep)
	if code != 2 {
		t.Fatalf("an unopenable report store must refuse: exit %d err "+
			"%q", code, errS)
	}
	if !strings.Contains(errS, dir) ||
		!strings.Contains(errS, "cannot open the report store") {
		t.Fatalf("the refusal must name the store %s and the Open "+
			"failure: %q", dir, errS)
	}
	if _, err := os.Lstat(final); err != nil {
		t.Fatalf("the copy must exist before the failed durability step: "+
			"%v", err)
	}
	restore()
	r27NoScratchLeft(t, dir)
}

// TestR27ConcurrentBindsOfOneDigestBothSucceed: the audited r27 F4.
// Two writers of one digest shared the fixed tmp name, so the loser's
// os.Rename returned ENOENT and the bind exited 2 with a raw "no such
// file or directory" on the very path the docs call idempotent
// (reproduced 4/8 and 2/10 rounds). The scratch name is now per-call
// unique and a lost rename is tolerated by re-verifying the published
// bytes: EVERY concurrent store must succeed, exactly one final file
// must stand, it must hash to the digest, and it must be 0444.
func TestR27ConcurrentBindsOfOneDigestBothSucceed(t *testing.T) {
	c, _ := mcCamp(t, "r27-f4")
	_, final, _ := r26F2Paths(t, c, r26F2Body)
	digest := validation.Sha256Hex([]byte(r26F2Body))
	const n = 8
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = storeReportCopy(c, digest, []byte(r26F2Body))
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent store %d of %d must succeed, got %v "+
				"(one digest, one immutable copy, both exit 0)", i+1, n, err)
		}
	}
	r26F2WantFinal(t, final, digest)
	dir := filepath.Dir(final)
	r27NoScratchLeft(t, dir)
	r27OnlyCopy(t, dir, final)
}

// TestR27HonestCopyReuseBindsTwice: idempotent reuse of an honest copy
// is kept intact — binding the same bytes twice exits 0 both times and
// leaves exactly one 0444 file, never a second copy and never scratch.
func TestR27HonestCopyReuseBindsTwice(t *testing.T) {
	c, root := mcCamp(t, "r27-reuse")
	rep := apWrite(t, r26F2Body)
	digest, final, _ := r26F2Paths(t, c, r26F2Body)
	dir := filepath.Dir(final)
	for i := 1; i <= 2; i++ {
		code, _, errS := apVerify(t, root, c, "--property", "p1",
			"--report", rep)
		if code != 0 {
			t.Fatalf("bind %d must reuse the honest copy (exit 0, one "+
				"file): exit %d err %q", i, code, errS)
		}
		r26F2WantFinal(t, final, digest)
		r27NoScratchLeft(t, dir)
		r27OnlyCopy(t, dir, final)
	}
}

// TestR27AdoptPublishedVerifiesBytesAndShape pins the lost-rename
// fallback itself (r27 F4b): it succeeds ONLY against a regular final
// copy whose bytes hash to the digest — a symlink there is the F3
// refusal (victim untouched) and foreign bytes are the tamper refusal.
func TestR27AdoptPublishedVerifiesBytesAndShape(t *testing.T) {
	c, _ := mcCamp(t, "r27-f4b")
	digest, final, _ := r26F2Paths(t, c, r26F2Body)
	dir := filepath.Dir(final)
	if err := os.WriteFile(final, []byte(r26F2Body), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := storeAdoptPublished(dir, final, digest)
	if err != nil || got != final {
		t.Fatalf("an honest published copy must be adopted: %q %v",
			got, err)
	}
	r26F2WantFinal(t, final, digest)
	if err := os.Remove(final); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(final, []byte(`{"published": false}`), 0o444); err != nil {
		t.Fatal(err)
	}
	if _, err := storeAdoptPublished(dir, final, digest); err == nil ||
		!strings.Contains(err.Error(), "foreign bytes") {
		t.Fatalf("foreign bytes at the final path must refuse as tamper: "+
			"%v", err)
	}
	if err := os.Remove(final); err != nil {
		t.Fatal(err)
	}
	victim := r27Victim(t, r26F2Body)
	if err := os.Symlink(victim, final); err != nil {
		t.Fatal(err)
	}
	if _, err := storeAdoptPublished(dir, final, digest); err == nil ||
		!strings.Contains(err.Error(), "symlink") {
		t.Fatalf("a symlink at the final path must refuse by shape: %v",
			err)
	}
	r27WantVictim(t, victim)
}

// TestR27bHardlinkAtFinalPathRefuses pins the hardlink arm: lstat sees a
// regular file, but the inode is shared with a name outside the store —
// so the store's read-only chmod would rewrite a foreign name's mode.
func TestR27bHardlinkAtFinalPathRefuses(t *testing.T) {
	c, root := mcCamp(t, "r27b-hardlink")
	body := `{"schema_version": "1.0", "published": true,
		"publish_problems": [], "review_independent": true,
		"capabilities_missing": [], "flags": {"loop_bound": 4},
		"property_outcomes": {"p1": {"outcome": "PROVEN",
			"per_rule": {"inv_1": "PROVEN"}}},
		"review_findings": []}`
	rep := apWrite(t, body)
	digest := validation.Sha256Hex([]byte(body))
	dir := filepath.Join(c.ArtifactsDir, "reports")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim.json")
	if err := os.WriteFile(victim, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(victim, filepath.Join(dir, "report-"+digest+".json")); err != nil {
		t.Skipf("hardlinks unsupported here: %v", err)
	}
	code, _, errS := apVerify(t, root, c, "--property", "p1", "--report", rep)
	if code != 2 || !strings.Contains(errS, "hard link") {
		t.Fatalf("a hardlinked store path must refuse: exit %d err %q",
			code, errS)
	}
	fi, err := os.Stat(victim)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("the foreign name's mode changed: %v", fi.Mode())
	}
}

// TestR28SymlinkedReportsDirRefusesAndLeavesVictimAlone pins r28 F4. The
// auditor's repro: symlink <campaign>/artifacts/reports to a directory
// OUTSIDE the campaign, then bind. os.MkdirAll follows the link, so the
// store wrote (and chmod 0444'd) report-<sha>.json in that outside
// directory — a write outside the campaign with no audit-visible trace,
// because only the two NAMES inside the store were lstat-checked. The bind
// must now exit 2 naming the path and its shape, and the outside directory
// must still hold nothing at all.
func TestR28SymlinkedReportsDirRefusesAndLeavesVictimAlone(t *testing.T) {
	c, root := mcCamp(t, "r28-f4")
	rep := apWrite(t, r26F2Body)
	digest := validation.Sha256Hex([]byte(r26F2Body))
	dir := filepath.Join(c.ArtifactsDir, "reports")
	victimDir := t.TempDir()
	if err := os.Symlink(victimDir, dir); err != nil {
		t.Fatal(err)
	}
	code, out, errS := apVerify(t, root, c, "--property", "p1",
		"--report", rep)
	if code != 2 {
		t.Fatalf("a symlinked store directory must refuse: exit %d "+
			"stdout %q stderr %q", code, out, errS)
	}
	for _, want := range []string{dir, "symlink", "inside the campaign"} {
		if !strings.Contains(errS, want) {
			t.Fatalf("the refusal must name %q: %q", want, errS)
		}
	}
	// Nothing was created through the link: not the copy, not scratch.
	ents, err := os.ReadDir(victimDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 0 {
		names := []string{}
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Fatalf("the store wrote outside the campaign through the link: %v",
			names)
	}
	if _, err := os.Lstat(filepath.Join(victimDir,
		"report-"+digest+".json")); !os.IsNotExist(err) {
		t.Fatalf("the copy landed outside the campaign (lstat err %v)", err)
	}
	// The REFUSED bind left no registered-but-unlogged row either.
	if rows := t28RegistryRows(t, c); strings.Contains(rows, digest) {
		t.Fatalf("a refused bind must not register the report: %s", rows)
	}
}

// TestR28SymlinkedArtifactsDirRefuses is the same rail one level up: the
// artifacts directory ITSELF being a link is the identical escape (it is
// the parent the reports dir is derived from), so it refuses the same way.
func TestR28SymlinkedArtifactsDirRefuses(t *testing.T) {
	c, root := mcCamp(t, "r28-f4b")
	rep := apWrite(t, r26F2Body)
	real := c.ArtifactsDir
	moved := real + ".real"
	if err := os.Rename(real, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, real); err != nil {
		t.Fatal(err)
	}
	code, _, errS := apVerify(t, root, c, "--property", "p1",
		"--report", rep)
	if code != 2 {
		t.Fatalf("a symlinked artifacts directory must refuse: exit %d "+
			"stderr %q", code, errS)
	}
	for _, want := range []string{real, "symlink", "inside the campaign"} {
		if !strings.Contains(errS, want) {
			t.Fatalf("the refusal must name %q: %q", want, errS)
		}
	}
}

// TestR28FileAtReportsPathRefuses: the same directory rail names the other
// shape — a plain file where the store directory belongs. os.MkdirAll used
// to surface a raw ENOTDIR; the refusal must say what is there.
func TestR28FileAtReportsPathRefuses(t *testing.T) {
	c, root := mcCamp(t, "r28-f4c")
	rep := apWrite(t, r26F2Body)
	dir := filepath.Join(c.ArtifactsDir, "reports")
	if err := os.WriteFile(dir, []byte("not a directory\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errS := apVerify(t, root, c, "--property", "p1",
		"--report", rep)
	if code != 2 {
		t.Fatalf("a file where the store directory belongs must refuse: "+
			"exit %d stderr %q", code, errS)
	}
	for _, want := range []string{dir, "regular file",
		"inside the campaign"} {
		if !strings.Contains(errS, want) {
			t.Fatalf("the refusal must name %q: %q", want, errS)
		}
	}
}

// t28RegistryRows renders the live registry rows (id + sha256) so a test
// can assert what a refused/committed bind registered.
func t28RegistryRows(t *testing.T, c *state.Campaign) string {
	t.Helper()
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	out := ""
	for _, row := range validation.ObjAt(st, "artifacts").A {
		out += validation.ObjStr(row, "artifact_id") + " " +
			validation.ObjStr(row, "sha256") + "\n"
	}
	return out
}

// TestR28AdoptedCopyIsSealedReadOnly pins the r28 adoption-sealing half.
// The auditor planted a matching-bytes file at the digest-named final path
// with mode 0646 and bound: the bytes were adopted, the row said
// "immutable copy", the docs promised the copy is written read-only — and
// the planted 0646 survived. Adoption must seal 0444 (and fsync it) the
// way the write path does.
func TestR28AdoptedCopyIsSealedReadOnly(t *testing.T) {
	c, root := mcCamp(t, "r28-adopt")
	rep := apWrite(t, r26F2Body)
	digest, final, _ := r26F2Paths(t, c, r26F2Body)
	// The planted copy: the exact bytes the bind will map, with a mode
	// nothing promises.
	if err := os.WriteFile(final, []byte(r26F2Body), 0o646); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(final, 0o646); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(final); err != nil ||
		fi.Mode().Perm() != 0o646 {
		t.Fatalf("the fixture must start 0646: %v %v", fi, err)
	}
	code, _, errS := apVerify(t, root, c, "--property", "p1",
		"--report", rep)
	if code != 0 {
		t.Fatalf("an honest pre-existing copy must bind: exit %d err %q",
			code, errS)
	}
	r26F2WantFinal(t, final, digest)
	// The bind's own row names the copy it just sealed.
	if rows := t28RegistryRows(t, c); !strings.Contains(rows, digest) {
		t.Fatalf("the adopted copy must be registered: %s", rows)
	}
}

// TestR28AdoptSealFailureRefuses: when the copy cannot be sealed, the bind
// refuses rather than hand back a path it could not put in the read-only
// state the row and the docs claim. (The seal failure here is a reports
// directory the process cannot open for the directory fsync — the same
// EACCES the r27 F6 rail surfaces.)
func TestR28AdoptSealFailureRefuses(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses the 0333 directory mode")
	}
	c, root := mcCamp(t, "r28-adopt-fail")
	rep := apWrite(t, r26F2Body)
	_, final, _ := r26F2Paths(t, c, r26F2Body)
	dir := filepath.Dir(final)
	if err := os.WriteFile(final, []byte(r26F2Body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o333); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	code, _, errS := apVerify(t, root, c, "--property", "p1",
		"--report", rep)
	if code != 2 {
		t.Fatalf("an unsealable adopted copy must refuse: exit %d err %q",
			code, errS)
	}
	if !strings.Contains(errS, "cannot open the report store") {
		t.Fatalf("the refusal must name the seal step: %q", errS)
	}
}
