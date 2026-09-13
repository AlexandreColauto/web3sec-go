package cli

// cmd_rank_test.go: the CLI half of A3 — `webv2 rank <campaign>` prints
// the acceptance-ranked table (which findings matter): qualified rows by
// score (or band, when the policy's submission_budget says so),
// disqualified rows named below, the budget in the header. Read-only.

import (
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// rankCliFinding ingests a bare hypothesis and, when given, records a
// validated risk band and/or a critic verdict on top of it.
func rankCliFinding(t *testing.T, c *state.Campaign, title, band,
	verdict string) string {
	t.Helper()
	f, err := findings.IngestHypothesis(c, validation.VObj(
		kvT("title", validation.VStr(title)),
		kvT("root_cause", validation.VObj(
			kvT("class", validation.VStr("unclassified")),
			kvT("description", validation.VStr("rank cli fixture mechanism")))),
		kvT("affected", validation.VArr(validation.VObj(
			kvT("path", validation.VStr("src/V.sol"))))),
		kvT("attacker", validation.VObj(
			kvT("profile", validation.VStr("arbitrary EOA")),
			kvT("capabilities", validation.VArr()))),
	), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	if band == "" && verdict == "" {
		return fid
	}
	vf, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if band != "" {
		riskObj := asDictCLI(objAt(vf, "risk"))
		riskObj = setObjFieldCLI(riskObj, "validated", validation.VObj(
			kvT("score", validation.VFloat(7.5)),
			kvT("band", validation.VStr(band)),
			kvT("rationale", validation.VStr("rank fixture"))))
		vf = setObjFieldCLI(vf, "risk", riskObj)
	}
	if err := findings.SaveFinding(c, &vf); err != nil {
		t.Fatal(err)
	}
	if verdict != "" {
		if _, err := findings.SetCriticVerdict(c, fid, verdict,
			"rank fixture"); err != nil {
			t.Fatal(err)
		}
	}
	return fid
}

func TestRankTable(t *testing.T) {
	root := t.TempDir()
	cid := initOne(t, root)
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	// f1: high band + confirmed = 2.0 + 1.5 = 3.50 (top row)
	// f2: bare = 0.00
	// f3: disproved = disqualified (0.00, out of the table)
	f1 := rankCliFinding(t, c, "High-band confirmed flow", "high", "confirmed")
	f2 := rankCliFinding(t, c, "Bare hypothesis", "", "")
	f3 := rankCliFinding(t, c, "Disproved flow", "", "disproved")
	code, out, errS := run(t, "--root", root, "rank", c.CampaignID)
	if code != 0 {
		t.Fatalf("exit %d, want 0: %q\n%s", code, errS, out)
	}
	// An unscoped campaign says so: the ranking must not read as advice.
	want := "acceptance ranking — 3 live finding(s) (key: acceptance)\n" +
		rankUnscopedNote +
		"  #  id  score  band  evidence  critic  title\n" +
		"  1  " + f1 + "  3.50  high  E0  confirmed  High-band confirmed flow\n" +
		"  2  " + f2 + "  0.00  —  E0  —  Bare hypothesis\n" +
		"disqualified (critic disproved): " + f3 + "\n"
	if out != want {
		t.Fatalf("output =\n%q\nwant\n%q", out, want)
	}
}

func TestRankNoFindings(t *testing.T) {
	root := t.TempDir()
	cid := initOne(t, root)
	code, out, errS := run(t, "--root", root, "rank", cid)
	if code != 0 {
		t.Fatalf("exit %d, want 0: %q\n%s", code, errS, out)
	}
	if out != "no live findings to rank\n" {
		t.Fatalf("output = %q", out)
	}
}

func TestRankBudgetHeader(t *testing.T) {
	root := t.TempDir()
	cid := initOne(t, root)
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	rankCliFinding(t, c, "A scoped high-band finding", "high", "confirmed")
	// scope the campaign with a policy carrying the submission budget
	policy := validation.VObj(
		kvT("program", validation.VStr("rank fixture program")),
		kvT("program_url", validation.VStr("https://example.invalid/rank")),
		kvT("chains", validation.VArr(validation.VStr("ethereum"))),
		kvT("scope", validation.VArr(validation.VObj(
			kvT("target", validation.VStr("src/")),
			kvT("kind", validation.VStr("path"))))),
		kvT("severity_rules", validation.VArr(validation.VObj(
			kvT("severity", validation.VStr("critical")),
			kvT("match", validation.VObj(
				kvT("bug_classes",
					validation.VArr(validation.VStr("access-control")))))))),
		kvT("poc_requirements", validation.VObj(
			kvT("min_evidence_level", validation.VStr("E4")),
			kvT("require_fork_repro", validation.VBool(false)))),
		kvT("submission_budget", validation.VObj(
			kvT("max_findings", validation.VInt(5)),
			kvT("rank_by", validation.VStr("severity")))))
	policyPath := filepath.Join(root, "policy.json")
	if err := validation.WriteJson(policyPath, policy, ""); err != nil {
		t.Fatal(err)
	}
	doc, err := validation.ReadJson(c.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	doc.O = validation.SetOrAppend(doc.O, "policy_path", validation.VStr(policyPath))
	if err := validation.WriteJson(c.StatePath, doc, "campaign_state"); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "rank", c.CampaignID)
	if code != 0 {
		t.Fatalf("exit %d, want 0: %q\n%s", code, errS, out)
	}
	want := "acceptance ranking — 1 live finding(s) (key: severity, " +
		"submission budget 5)\n"
	if !strings.HasPrefix(out, want) {
		t.Fatalf("header =\n%q\nwant prefix\n%q", out, want)
	}
}

func TestRankPolicyOffHasNoPriorKeys(t *testing.T) {
	// The (f) CLI half: a campaign scoped with the DEFAULT policy (no
	// acceptance_priors) ranks today's numbers with no prior marker
	// anywhere in the output — the byte check on the rendered surface.
	root := t.TempDir()
	cid := initOne(t, root)
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	f1 := rankCliFinding(t, c, "A scoped high-band finding", "high", "confirmed")
	policy := validation.VObj(
		kvT("program", validation.VStr("rank fixture program")),
		kvT("program_url", validation.VStr("https://example.invalid/rank")),
		kvT("chains", validation.VArr(validation.VStr("ethereum"))),
		kvT("scope", validation.VArr(validation.VObj(
			kvT("target", validation.VStr("src/")),
			kvT("kind", validation.VStr("path"))))),
		kvT("severity_rules", validation.VArr(validation.VObj(
			kvT("severity", validation.VStr("critical")),
			kvT("match", validation.VObj(
				kvT("bug_classes",
					validation.VArr(validation.VStr("access-control")))))))),
		kvT("poc_requirements", validation.VObj(
			kvT("min_evidence_level", validation.VStr("E4")),
			kvT("require_fork_repro", validation.VBool(false)))))
	policyPath := filepath.Join(root, "policy.json")
	if err := validation.WriteJson(policyPath, policy, ""); err != nil {
		t.Fatal(err)
	}
	doc, err := validation.ReadJson(c.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	doc.O = validation.SetOrAppend(doc.O, "policy_path", validation.VStr(policyPath))
	if err := validation.WriteJson(c.StatePath, doc, "campaign_state"); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "rank", c.CampaignID)
	if code != 0 {
		t.Fatalf("exit %d, want 0: %q\n%s", code, errS, out)
	}
	// scoped (no unscoped note), today's number, no prior marker.
	want := "acceptance ranking — 1 live finding(s) (key: acceptance)\n" +
		"  #  id  score  band  evidence  critic  title\n" +
		"  1  " + f1 + "  3.50  high  E0  confirmed  A scoped high-band finding\n"
	if out != want {
		t.Fatalf("output =\n%q\nwant\n%q", out, want)
	}
	if strings.Contains(out, "prior") {
		t.Fatalf("policy-off rank output must not mention priors:\n%q", out)
	}
}

func TestRankArgparse(t *testing.T) {
	root := t.TempDir()
	initOne(t, root)

	code, out, errS := run(t, "--root", root, "rank")
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q\n%s", code, errS, out)
	}
	if !strings.Contains(errS,
		"the following arguments are required: campaign") {
		t.Fatalf("stderr %q", errS)
	}
	if !strings.Contains(errS, "usage: webv2 rank") {
		t.Fatalf("usage block missing:\n%s", errS)
	}

	code, out, errS = run(t, "--root", root, "rank", "C-1", "extra")
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q\n%s", code, errS, out)
	}
	if !strings.Contains(errS, "unrecognized arguments: extra") {
		t.Fatalf("stderr %q", errS)
	}

	code, out, errS = run(t, "--root", root, "rank", "C-1", "--bogus")
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q\n%s", code, errS, out)
	}
	if !strings.Contains(errS, "unrecognized arguments: --bogus") {
		t.Fatalf("stderr %q", errS)
	}
}

// TestRankHoldsBackOutcomes pins r5 issue 2: a DISPROVED row is a ledger
// OUTCOME (the scorecard and calibration still count it — the twin's
// fabrication law) but not a rank CANDIDATE. The one-row disproved campaign
// must not read as "1 finding matters".
func TestRankHoldsBackOutcomes(t *testing.T) {
	root := t.TempDir()
	cid := initOne(t, root)
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	fid := rankCliFinding(t, c, "vault drains on reentry", "", "")
	if code, _, errS := run(t, "--root", root, "move", cid, fid,
		"DISPROVED", "--adjacent", "the oracle staleness window was never "+
			"checked against the TWAP fallback", "--reason",
		"controlled repro shows the guard rejects the payload"); code != 0 {
		t.Fatalf("move DISPROVED: exit %d %q", code, errS)
	}
	code, out, errS := run(t, "--root", root, "rank", cid)
	if code != 0 {
		t.Fatalf("rank exit %d %q", code, errS)
	}
	if strings.Contains(out, "1 live finding(s)") ||
		!strings.Contains(out, "no candidate findings to rank") {
		t.Fatalf("a lone disproof must not present as a candidate: %q",
			out)
	}
	if !strings.Contains(out, "scorecard still counts them") {
		t.Fatalf("the outcome's continuing home must be named: %q", out)
	}
	// The scorecard keeps the row visible as a live OUTCOME (unchanged
	// law: calibration counts disproofs):
	code, out, errS = run(t, "--root", root, "scorecard", cid)
	if code != 0 || !strings.Contains(out, "DISPROVED") {
		t.Fatalf("scorecard keeps disproof accounting: exit %d %q %q",
			code, out, errS)
	}
}
