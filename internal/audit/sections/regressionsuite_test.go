package sections

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/regression"
	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

func regressSectionCampaign(t *testing.T, id string) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "Acme", state.InitOpts{CampaignID: id})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// acmeTarget records the one scabench target the section tests read.
func acmeTarget(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	target, err := regression.AddTarget(c, regression.TargetSpec{
		Kind: "scabench", Program: "Acme", Shape: "vault-erc4626",
		CommitHint: "main",
	})
	if err != nil {
		t.Fatal(err)
	}
	return target
}

// TestRegressionSuiteIsPresenceGated is the test that protects the pinned
// section lists in scripts/verify-full.sh and scripts/check-golden.py: a
// campaign that is not a regression target must render NOTHING, so those two
// gates do not need editing when this section lands.
func TestRegressionSuiteIsPresenceGated(t *testing.T) {
	c := regressSectionCampaign(t, "C-regsectgate01")
	if _, err := RegressionSuite(c); !errors.Is(err, ErrSkip) {
		t.Fatalf("a campaign with no regression target must ErrSkip, got %v", err)
	}
}

func TestRegressionSuiteReportsAnUnpinnedTarget(t *testing.T) {
	c := regressSectionCampaign(t, "C-regsectread01")
	acmeTarget(t, c)
	sec, err := RegressionSuite(c)
	if err != nil {
		t.Fatal(err)
	}
	problems := validation.ObjAt(sec, "problems")
	if len(problems.A) != 1 {
		t.Fatalf("%d problem(s), want exactly the unpinned-target one", len(problems.A))
	}
	if !strings.Contains(problems.A[0].S, "resolved_sha") {
		t.Fatalf("problem = %q, want it to name resolved_sha", problems.A[0].S)
	}
	assertSectionBool(t, sec, false) // still unpinned
}

// TestRegressionSuiteCatchesARunWithNoTargetRecord is the drift the section
// exists to catch: a run whose target has no target record cannot be reached
// through the writer (RecordRun refuses an unknown target), so the record is
// written by hand here.
func TestRegressionSuiteCatchesARunWithNoTargetRecord(t *testing.T) {
	c := regressSectionCampaign(t, "C-regsectrun01")
	acmeTarget(t, c)
	writeOrphanRun(t, c)
	sec, err := RegressionSuite(c)
	if err != nil {
		t.Fatal(err)
	}
	problems := validation.ObjAt(sec, "problems")
	found := false
	for _, p := range problems.A {
		if strings.Contains(p.S, "T-000000000000") &&
			strings.Contains(p.S, "no target record") {
			found = true
		}
	}
	if !found {
		t.Fatalf("problems = %v, want one naming the orphan run's target",
			problems.A)
	}
}

// assertSectionInt / assertSectionBool pin one leaf of a section document.
func assertSectionInt(t *testing.T, v validation.Value, key string, want int64) {
	t.Helper()
	if got := validation.ObjAt(v, key); got.Kind != validation.Int || got.I != want {
		t.Fatalf("%s = %v, want %d", key, got, want)
	}
}

// assertSectionBool pins the section's own "ok" leaf. It takes no key because
// every call site asks the same question — the section's verdict — and an
// always-constant parameter is a parameter that lies about being one.
func assertSectionBool(t *testing.T, v validation.Value, want bool) {
	t.Helper()
	if got := validation.ObjAt(v, "ok"); got.Kind != validation.Bool || got.B != want {
		t.Fatalf("ok = %v, want %v", got, want)
	}
}

func TestRegressionSuiteGoesGreenAfterThePin(t *testing.T) {
	c := regressSectionCampaign(t, "C-regsectgreen01")
	target := acmeTarget(t, c)
	if err := writeRunFor(t, c, target); err != nil {
		t.Fatal(err)
	}
	sha, sid := pinRealTree(t, c, target)
	sec, err := RegressionSuite(c)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjAt(sec, "problems"); len(got.A) != 0 {
		t.Fatalf("problems = %v, want none after the pin", got.A)
	}
	assertSectionBool(t, sec, true)
	assertSectionInt(t, sec, "checked", 2) // one target + one run
	row := validation.ObjAt(sec, "targets").A[0]
	if got := validation.ObjStr(row, "resolved_sha"); got != sha {
		t.Fatalf("target row resolved_sha = %q, want %q", got, sha)
	}
	if got := validation.ObjStr(row, "snapshot_id"); got != sid {
		t.Fatalf("target row snapshot_id = %q, want %q", got, sid)
	}
	assertSectionInt(t, row, "runs", 1)
}

// gitTreeWithCommit writes a one-file tree, commits it, and returns the
// directory plus its HEAD commit.
func gitTreeWithCommit(t *testing.T) (string, string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Vault.sol"),
		[]byte("contract Vault {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	for _, args := range [][]string{
		{"-c", "init.defaultBranch=main", "init", "-q"},
		{"add", "-A"}, {"commit", "-q", "-m", "init"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir, cmd.Env = dir, env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	rev, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	return dir, strings.TrimSpace(string(rev))
}

// pinRealTree snapshots a real git tree into the campaign and pins the target
// to it, through the real producers (snapshot.PinSourceSnapshot +
// regression.PinTarget) — never a hand-written record.
func pinRealTree(t *testing.T, c *state.Campaign, target validation.Value) (string, string) {
	t.Helper()
	dir, sha := gitTreeWithCommit(t)
	snap, err := snapshot.PinSourceSnapshot(c, dir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	sid := validation.ObjStr(snap, "snapshot_id")
	if _, err := regression.PinTarget(c, regression.PinSpec{
		TargetID: validation.ObjStr(target, "target_id"), ResolvedSHA: sha,
		SnapshotID: sid, ResolvedBy: "operator",
	}); err != nil {
		t.Fatal(err)
	}
	return sha, sid
}

// writeRunFor records one run through the REAL writer (the realism law): the
// score file is the real scorer's own output shape — found/missed are arrays
// of gold ids.
func writeRunFor(t *testing.T, c *state.Campaign, target validation.Value) error {
	t.Helper()
	score := filepath.Join(t.TempDir(), "score.json")
	if err := os.WriteFile(score, []byte(`{"found": [], "missed": ["G-99"],
		"false_positives": 0, "pass": false, "bonus": false, "verdict": "FAIL",
		"verdict_note": "", "operator_confirmed": {}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := regression.RecordRun(c, regression.RunSpec{
		TargetID: validation.ObjStr(target, "target_id"),
		Scorer:   "eval-gold", ScoreFile: score,
	})
	return err
}

// writeOrphanRun writes a schema-valid run record naming a target that has no
// target record — the one state the writer cannot produce, so the section's
// drift check needs it by hand.
func writeOrphanRun(t *testing.T, c *state.Campaign) {
	t.Helper()
	if err := os.MkdirAll(regression.RunsDir(c), 0o755); err != nil {
		t.Fatal(err)
	}
	doc := validation.VObj(
		validation.KV{K: "run_id", V: validation.VStr("RUN-000000000001")},
		validation.KV{K: "campaign_id", V: validation.VStr(c.CampaignID)},
		validation.KV{K: "target_id", V: validation.VStr("T-000000000000")},
		validation.KV{K: "scorer", V: validation.VStr("eval-gold")},
		validation.KV{K: "score", V: validation.VObj(
			validation.KV{K: "found", V: validation.VInt(0)},
			validation.KV{K: "missed", V: validation.VInt(0)},
			validation.KV{K: "false_positives", V: validation.VInt(0)},
			validation.KV{K: "verdict", V: validation.VStr("FAIL")},
		)},
		validation.KV{K: "measurement", V: validation.VStr("rediscovery")},
		validation.KV{K: "is_detection_rate", V: validation.VBool(false)},
		validation.KV{K: "created_at", V: validation.VStr("2026-09-21T00:00:00Z")},
		validation.KV{K: "schema_version", V: validation.VInt(1)},
	)
	path := filepath.Join(regression.RunsDir(c), "RUN-000000000001.json")
	if err := validation.WriteJson(path, doc, "regression_run"); err != nil {
		t.Fatal(err)
	}
}

// The two SHAs a control-target section test pins: distinct, 40-hex, and never
// a real commit — the section reads the record, it does not verify the commit.
const (
	controlPreSHA  = "1111111111111111111111111111111111111111"
	controlPostSHA = "2222222222222222222222222222222222222222"
)

// controlSectionTarget records a control target (kind=control,
// shape=already-exploited) and pins it to a REAL git tree through the real
// producers, so the only problems the section can report are the control
// target's own: no control block, no P1 handoff.
func controlSectionTarget(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	target, err := regression.AddTarget(c, regression.TargetSpec{
		Kind: "control", Program: "Exploited Protocol",
		RecordID: "exploited-protocol", Repo: "org/exploited-protocol",
		Shape: "already-exploited", CommitHint: controlPreSHA,
	})
	if err != nil {
		t.Fatal(err)
	}
	sha, sid := pinRealTree(t, c, target)
	if sha == "" || sid == "" {
		t.Fatalf("pin produced no sha/snapshot id (%q, %q)", sha, sid)
	}
	return target
}

// confirmedSectionFinding ingests one finding and stamps CONFIRMED through the
// store's own writer — findings.Transition needs E5 evidence and a sandbox,
// which is the operator step's job, not this test's.
func confirmedSectionFinding(t *testing.T, c *state.Campaign) string {
	t.Helper()
	payload := validation.VObj(
		validation.KV{K: "title", V: validation.VStr("Reentrancy drains the vault")},
		validation.KV{K: "root_cause", V: validation.VObj(
			validation.KV{K: "class", V: validation.VStr("reentrancy")},
			validation.KV{K: "description", V: validation.VStr("the mechanism described in detail here")},
		)},
		validation.KV{K: "affected", V: validation.VArr(validation.VObj(
			validation.KV{K: "path", V: validation.VStr("src/V.sol")},
			validation.KV{K: "function", V: validation.VStr("withdraw")},
		))},
		validation.KV{K: "attacker", V: validation.VObj(
			validation.KV{K: "profile", V: validation.VStr("arbitrary EOA")},
			validation.KV{K: "capabilities", V: validation.VArr()},
		)},
	)
	finding, err := findings.IngestHypothesis(c, payload, "code", "control", "")
	if err != nil {
		t.Fatal(err)
	}
	finding.O = validation.SetOrAppend(finding.O, "status", validation.VStr("CONFIRMED"))
	if err := findings.SaveFinding(c, &finding); err != nil {
		t.Fatal(err)
	}
	return validation.ObjStr(finding, "finding_id")
}

// TestRegressionSuiteKeepsAHalfFinishedControlTargetRed is §3a's control
// target as the section sees it: a control row with no control block and no
// P1 handoff is TWO problems, not a blank — the Phase 2 spike's extraction
// half stays blocked and the audit says so. The row must also render the
// absent handoff figure as EMPTY, never as a 0 that reads as a measurement.
func TestRegressionSuiteKeepsAHalfFinishedControlTargetRed(t *testing.T) {
	c := regressSectionCampaign(t, "C-regsectctl001")
	controlSectionTarget(t, c)
	sec, err := RegressionSuite(c)
	if err != nil {
		t.Fatal(err)
	}
	problems := validation.ObjAt(sec, "problems")
	var joined strings.Builder
	for _, p := range problems.A {
		joined.WriteString(p.S)
		joined.WriteString("\n")
	}
	for _, want := range []string{
		"carries no control block", "carries no P1 handoff",
		// The message names BOTH honest forms: a handoff that must carry a
		// figure would be the fabrication the schema's unpriceable escape
		// exists to remove (c5ba1048).
		"unpriceable decision",
	} {
		if !strings.Contains(joined.String(), want) {
			t.Fatalf("problems = %q, want one naming %q", joined.String(), want)
		}
	}
	assertSectionBool(t, sec, false)
	row := validation.ObjAt(sec, "targets").A[0]
	if got := validation.ObjStr(row, "handoff_extractable_usd"); got != "" {
		t.Fatalf("absent handoff figure renders %q, want the empty string", got)
	}
}

// TestRegressionSuiteGoesGreenForAFinishedControlTarget is the other half: the
// same row, with the incident + pre-patch pin + harness recorded and a
// CONFIRMED finding's handoff on top, has NO problems and carries the three
// control fields the audit and `status` read. Without this test the two
// problem lines above could refuse every control target and still pass.
func TestRegressionSuiteGoesGreenForAFinishedControlTarget(t *testing.T) {
	c := regressSectionCampaign(t, "C-regsectctl002")
	target := controlSectionTarget(t, c)
	tid := validation.ObjStr(target, "target_id")
	recordSectionControl(t, c, tid)
	fid := confirmedSectionFinding(t, c)
	if _, err := regression.RecordHandoff(c, regression.HandoffSpec{
		TargetID: tid, FindingID: fid, ExtractableUSD: 900000,
		Source: "reproduction on the pre-patch commit", RecordedBy: "operator",
	}); err != nil {
		t.Fatal(err)
	}
	sec, err := RegressionSuite(c)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjAt(sec, "problems"); len(got.A) != 0 {
		t.Fatalf("problems = %v, want none for a finished control target", got.A)
	}
	assertSectionBool(t, sec, true)
	assertFinishedControlRow(t, sec, fid)
}

// assertFinishedControlRow pins the three leaves a finished control target must
// carry: the pre-patch pin, and the handoff's finding and figure.
func assertFinishedControlRow(t *testing.T, sec validation.Value, fid string) {
	t.Helper()
	row := validation.ObjAt(sec, "targets").A[0]
	if got := validation.ObjStr(row, "control_pre_patch_sha"); got != controlPreSHA {
		t.Fatalf("control_pre_patch_sha = %q, want %q", got, controlPreSHA)
	}
	if got := validation.ObjStr(row, "handoff_finding_id"); got != fid {
		t.Fatalf("handoff_finding_id = %q, want %q", got, fid)
	}
	if got := validation.ObjStr(row, "handoff_extractable_usd"); got != "900000" {
		t.Fatalf("handoff_extractable_usd = %q, want 900000", got)
	}
}

// recordSectionControl writes the control block the finished-control tests
// share, through the real writer.
func recordSectionControl(t *testing.T, c *state.Campaign, tid string) {
	t.Helper()
	if _, err := regression.RecordControl(c, regression.ControlSpec{
		TargetID: tid, IncidentURL: "https://example.test/incident",
		IncidentDate: "2025-09-01", LossUSD: 12500000,
		LossSource:  "post-mortem §2 (recovered funds excluded)",
		PrePatchSHA: controlPreSHA, PatchSHA: controlPostSHA,
		HarnessRunner: "foundry", HarnessCommand: "forge test",
	}); err != nil {
		t.Fatal(err)
	}
}

// TestRegressionSuiteAcceptsAnUnpriceableHandoff: a control target whose
// CONFIRMED finding has no honest figure is FINISHED, not half-finished. The
// handoff exists, it names the confirmed finding, and it records WHY there is
// no number — the 10b fork spike REFUSED the figure (c5ba1048,
// docs/gates/v16-P1-10b-fork-spike.md) — so it is a complete, honest handoff
// and the section goes green. The absent figure still renders as EMPTY, never
// as a 0 that would read as a measurement.
func TestRegressionSuiteAcceptsAnUnpriceableHandoff(t *testing.T) {
	c := regressSectionCampaign(t, "C-regsectctl003")
	target := controlSectionTarget(t, c)
	tid := validation.ObjStr(target, "target_id")
	recordSectionControl(t, c, tid)
	fid := confirmedSectionFinding(t, c)
	if _, err := regression.RecordHandoff(c, regression.HandoffSpec{
		TargetID: tid, FindingID: fid, Source: "10b fork spike (refusal)",
		Unpriceable: true, Ceiling: "capacity basis: no attack was run",
		Reason:     "the 10b spike refused the figure: no attack was run",
		RecordedBy: "operator",
	}); err != nil {
		t.Fatal(err)
	}
	sec, err := RegressionSuite(c)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjAt(sec, "problems"); len(got.A) != 0 {
		t.Fatalf("problems = %v, want none: an unpriceable handoff is a handoff", got.A)
	}
	assertSectionBool(t, sec, true)
	row := validation.ObjAt(sec, "targets").A[0]
	if got := validation.ObjStr(row, "handoff_finding_id"); got != fid {
		t.Fatalf("handoff_finding_id = %q, want %q", got, fid)
	}
	if got := validation.ObjStr(row, "handoff_extractable_usd"); got != "" {
		t.Fatalf("unpriceable handoff renders figure %q, want the empty string", got)
	}
}

// TestRegressionSuiteRejectsAHandoffWithNeitherForm: the handoff check reads
// the two honest forms, not the key. A hand-edited record carrying neither a
// figure nor the unpriceable decision is not a handoff — the write path and
// the schema refuse that shape, so this is the section catching what can only
// have arrived by hand (the same discipline the unpriceable section applies to
// a hand-edited priceable: false). It is caught TWICE, deliberately: the
// schema refuses the bytes, and the handoff check refuses to call the record a
// handoff — neither check may depend on the other having run.
func TestRegressionSuiteRejectsAHandoffWithNeitherForm(t *testing.T) {
	c := regressSectionCampaign(t, "C-regsectctl004")
	target := controlSectionTarget(t, c)
	tid := validation.ObjStr(target, "target_id")
	recordSectionControl(t, c, tid)
	doc, ok, err := regression.Target(c, tid)
	if err != nil || !ok {
		t.Fatalf("reload target: ok=%v err=%v", ok, err)
	}
	doc.O = validation.SetOrAppend(doc.O, "handoff", validation.VObj(
		KV("finding_id", validation.VStr("F-cfff3ebc0250")),
		KV("source", validation.VStr("hand-edited")),
		KV("recorded_at", validation.VStr("2026-01-01T00:00:00Z"))))
	path := filepath.Join(regression.TargetsDir(c), tid+".json")
	if err := validation.WriteJson(path, doc, ""); err != nil {
		t.Fatal(err)
	}
	sec, err := RegressionSuite(c)
	if err != nil {
		t.Fatal(err)
	}
	problems := validation.ObjAt(sec, "problems").A
	if !problemMentions(problems, "validation failed") ||
		!problemMentions(problems, "carries no P1 handoff") {
		t.Fatalf("problems = %v, want the schema refusal AND the "+
			"no-P1-handoff problem", problems)
	}
}
