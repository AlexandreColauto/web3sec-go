package cli

import (
	"fmt"
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
