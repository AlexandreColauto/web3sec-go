package findings

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

// ---- fixtures (port of tests/test_findings.py + conftest.py helpers) ----

// ingestCamp is the `camp` fixture: a fresh campaign with a pinned target.
func ingestCamp(t *testing.T) *state.Campaign {
	t.Helper()
	root := t.TempDir()
	c, err := state.Init(root, "Acme Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "V.sol"),
		[]byte("contract V {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, target, nil, nil); err != nil {
		t.Fatal(err)
	}
	return c
}

// hypoPayload is the `hypo()` helper.
func hypoPayload(over ...validation.KV) validation.Value {
	base := validation.VObj(
		kv("title", validation.VStr(
			"User can withdraw more than deposited via rounding")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("precision-rounding")),
			kv("description", validation.VStr(
				"share calculation rounds in the attacker's favor")),
		)),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/Vault.sol")),
			kv("function", validation.VStr("withdraw")),
		))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()),
		)),
	)
	for _, o := range over {
		base.O = validation.SetOrAppend(base.O, o.K, o.V)
	}
	return base
}

// hypoE4Payload is hypoPayload under an E4-floor class. Wave N, T6 gave every
// KNOWN class whose CONFIRMED floor is stricter than the loosest known-class
// floor a class-floor advisory of its own, so a test that counts intake
// warnings for the fixture's default class (precision-rounding — known, but
// with no floor-table entry, so the gate charges the conservative E5) would be
// measuring the T6 advisory rather than its own warning. The advisory has
// dedicated tests in internal/taxonomy and internal/cli.
func hypoE4Payload(over ...validation.KV) validation.Value {
	return hypoPayload(append([]validation.KV{kv("root_cause",
		validation.VObj(
			kv("class", validation.VStr("logic-error")),
			kv("description", validation.VStr(
				"share calculation rounds in the attacker's favor"))))},
		over...)...)
}

var execSeq int

// testExec is the conftest `sandboxed_exec` equivalent: it writes the EXEC
// ledger record directly (sandbox.register_exec lands with P2).
func testExec(t *testing.T, c *state.Campaign, profile, findingID string,
	exitStatus int64, stdout string) validation.Value {
	t.Helper()
	execSeq++
	execID := fmt.Sprintf("EXEC-%010x", execSeq)
	dir := filepath.Join(c.ExecsDir, execID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	stdoutPath := filepath.Join(dir, "stdout.log")
	stderrPath := filepath.Join(dir, "stderr.log")
	if err := os.WriteFile(stdoutPath, []byte(stdout), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stderrPath, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	fidV := validation.VNull()
	if findingID != "" {
		fidV = validation.VStr(findingID)
	}
	rec := validation.VObj(
		kv("exec_id", validation.VStr(execID)),
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("profile", validation.VStr(profile)),
		kv("finding_id", fidV),
		kv("artifact_id", validation.VNull()),
		kv("command", validation.VStr("forge test --match-test test_exploit")),
		kv("exit_status", validation.VInt(exitStatus)),
		kv("stdout_path", validation.VStr(stdoutPath)),
		kv("stderr_path", validation.VStr(stderrPath)),
	)
	if err := validation.WriteJson(filepath.Join(dir, "exec_record.json"),
		rec, ""); err != nil {
		t.Fatal(err)
	}
	return rec
}

// execEvidenceItem is the conftest `evidence_item` helper.
func execEvidenceItem(rec validation.Value, level, typ, desc, eid string) validation.Value {
	return validation.VObj(
		kv("evidence_id", validation.VStr(eid)),
		kv("level", validation.VStr(level)),
		kv("type", validation.VStr(typ)),
		kv("description", validation.VStr(desc)),
		kv("sandbox_profile", objAt(rec, "profile")),
		kv("artifact_id", objAt(rec, "exec_id")),
	)
}

func wantErr(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q does not contain %q", err.Error(), want)
	}
}

// ---- ported tests (tests/test_findings.py core slice, part 2) ----

func TestIngestStampsProvenanceAndSignature(t *testing.T) {
	c := ingestCamp(t)
	f, err := IngestHypothesis(c, hypoPayload(), "code", "05", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := objStr(f, "status"); got != "HYPOTHESIS" {
		t.Fatalf("status = %q, want HYPOTHESIS", got)
	}
	snap, err := c.ActiveSnapshotIDOrNone()
	if err != nil || snap == nil {
		t.Fatalf("campaign snapshot: %v %v", snap, err)
	}
	if got := objStr(objAt(f, "snapshot_ids"), "source"); got != *snap {
		t.Fatalf("snapshot_ids.source = %q, want %q", got, *snap)
	}
	if objStr(objAt(f, "dedup"), "technical_signature") == "" {
		t.Fatal("dedup.technical_signature empty")
	}
	hist := objAt(f, "history")
	if hist.Kind != validation.Arr || len(hist.A) != 1 {
		t.Fatalf("history = %v", hist)
	}
	if got := objStr(hist.A[0], "to"); got != "HYPOTHESIS" {
		t.Fatalf("history[0].to = %q", got)
	}
	// A bare hypothesis costs no discovery slot: the budget meters RISES
	// above E0, not suspicion (the reform). The rise path below charges one.
	assertSlotCount(t, c, 0)
	if objBool(f, "discovery_slot_consumed") {
		t.Fatal("a bare hypothesis must not carry the slot flag")
	}
	risen := addEvidenceOfLevel(t, c, f, "E1")
	assertSlotCount(t, c, 1)
	if !objBool(risen, "discovery_slot_consumed") {
		t.Fatal("the first above-E0 evidence must set the slot flag")
	}
}

// TestDiscoveryBudgetEnforced: the ceiling no longer gates hypothesis
// INGEST (suspicion is free); it gates the first RISE above E0.
func TestDiscoveryBudgetEnforced(t *testing.T) {
	root := t.TempDir()
	c, err := state.Init(root, "Acme Program", state.InitOpts{
		Budget: &validation.Value{Kind: validation.Obj, O: []validation.KV{
			kv("max_discovery_findings", validation.VInt(1)),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	a := ingestBare(t, c)
	b := ingestBare(t, c) // both hypotheses land at E0, ceiling untouched
	assertSlotCount(t, c, 0)
	addEvidenceOfLevel(t, c, a, "E1") // the one affordable rise
	_, err = AddEvidence(c, objStr(b, "finding_id"), validation.VObj(
		kv("evidence_id", validation.VStr("EV-b")),
		kv("level", validation.VStr("E1")),
		kv("type", validation.VStr("manual")),
		kv("description", validation.VStr("the second rise cannot be paid"))))
	wantErr(t, err, "budget")
}

func TestIngestRejectsPreloadedExecutionEvidence(t *testing.T) {
	c := ingestCamp(t)
	item := validation.VObj(
		kv("evidence_id", validation.VStr("EV-x")),
		kv("level", validation.VStr("E4")),
		kv("type", validation.VStr("foundry-test")),
		kv("description", validation.VStr("smuggled execution evidence")),
		kv("sandbox_profile", validation.VStr("docker-networkless")),
	)
	_, err := IngestHypothesis(c,
		hypoPayload(kv("evidence", validation.VArr(item))),
		"code", "", "")
	wantErr(t, err, "ingest rejected: pre-loaded evidence EV-x at E4")
}

func TestIngestE7NeedsArtifact(t *testing.T) {
	c := ingestCamp(t)
	item := validation.VObj(
		kv("evidence_id", validation.VStr("EV-e")),
		kv("level", validation.VStr("E7")),
		kv("type", validation.VStr("balance-delta")),
		kv("description", validation.VStr("impact quantified by hand")),
	)
	_, err := IngestHypothesis(c,
		hypoPayload(kv("evidence", validation.VArr(item))),
		"code", "", "")
	wantErr(t, err, "E7 (economic impact quantified) must reference the artifact")
}

func TestProducedAtDefaultsBeforeValidation(t *testing.T) {
	c := ingestCamp(t)
	f, err := IngestHypothesis(c, hypoPayload(), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	out, err := AddEvidence(c, fid, validation.VObj(
		kv("evidence_id", validation.VStr("EV-p")),
		kv("level", validation.VStr("E1")),
		kv("type", validation.VStr("manual")),
		kv("description", validation.VStr("code reading, no timestamp given")),
	))
	if err != nil {
		t.Fatal(err)
	}
	ev := objAt(out, "evidence")
	if len(ev.A) != 1 {
		t.Fatalf("evidence len = %d, want 1", len(ev.A))
	}
	if got := objStr(ev.A[0], "produced_at"); got == "" {
		t.Fatal("produced_at not defaulted before validation")
	}
}

func TestE5WithoutProfileIsRejected(t *testing.T) {
	c := ingestCamp(t)
	f, _ := IngestHypothesis(c, hypoPayload(), "code", "", "")
	fid := objStr(f, "finding_id")
	_, err := AddEvidence(c, fid, validation.VObj(
		kv("evidence_id", validation.VStr("EV-1")),
		kv("level", validation.VStr("E5")),
		kv("type", validation.VStr("fork-test")),
		kv("description", validation.VStr("no sandbox")),
	))
	wantErr(t, err, "must name the sandbox_profile")
	// A merely CLAIMED container profile is also rejected: the EXEC ledger
	// is the source of truth, not the caller's string.
	_, err = AddEvidence(c, fid, validation.VObj(
		kv("evidence_id", validation.VStr("EV-1b")),
		kv("level", validation.VStr("E5")),
		kv("type", validation.VStr("fork-test")),
		kv("description", validation.VStr("fabricated")),
		kv("sandbox_profile", validation.VStr("docker-networkless")),
	))
	wantErr(t, err, "EXEC record")
}

func TestHostReadonlyProfileCannotBackE4(t *testing.T) {
	c := ingestCamp(t)
	f, _ := IngestHypothesis(c, hypoPayload(), "code", "", "")
	fid := objStr(f, "finding_id")
	rec := testExec(t, c, "host-readonly", fid, 0, "")
	_, err := AddEvidence(c, fid,
		execEvidenceItem(rec, "E4", "foundry-test", "unsandboxed run", "EV-h"))
	wantErr(t, err, "not an E4-capable profile")
}

func TestExecProfileMismatchIsRejected(t *testing.T) {
	c := ingestCamp(t)
	f, _ := IngestHypothesis(c, hypoPayload(), "code", "", "")
	fid := objStr(f, "finding_id")
	rec := testExec(t, c, "docker-networkless", fid, 0, "PASS: test_exploit\n")
	bad := execEvidenceItem(rec, "E4", "foundry-test", "misclaimed profile", "EV-m")
	bad.O = validation.SetOrAppend(bad.O, "sandbox_profile", validation.VStr("docker-gvisor"))
	_, err := AddEvidence(c, fid, bad)
	wantErr(t, err, "ran under")
}

func TestMissingExecReferenceIsRejected(t *testing.T) {
	c := ingestCamp(t)
	f, _ := IngestHypothesis(c, hypoPayload(), "code", "", "")
	fid := objStr(f, "finding_id")
	testExec(t, c, "docker-networkless", fid, 0, "PASS: test_exploit\n")
	item := validation.VObj(
		kv("evidence_id", validation.VStr("EV-x")),
		kv("level", validation.VStr("E4")),
		kv("type", validation.VStr("foundry-test")),
		kv("description", validation.VStr("cites an exec that never happened")),
		kv("sandbox_profile", validation.VStr("docker-networkless")),
		kv("artifact_id", validation.VStr("EXEC-nope0000")),
	)
	_, err := AddEvidence(c, fid, item)
	wantErr(t, err, "no such EXEC record")
}

func TestUncitedExecIsRejectedWhenOneExists(t *testing.T) {
	c := ingestCamp(t)
	f, _ := IngestHypothesis(c, hypoPayload(), "code", "", "")
	fid := objStr(f, "finding_id")
	testExec(t, c, "docker-networkless", fid, 0, "PASS: test_exploit\n")
	// artifact_id ABSENT (not null — null is a schema error): the item
	// claims a profile but cites no run, so it must be rejected even
	// though a matching exec exists.
	item := validation.VObj(
		kv("evidence_id", validation.VStr("EV-u")),
		kv("level", validation.VStr("E4")),
		kv("type", validation.VStr("foundry-test")),
		kv("description", validation.VStr("uncited run")),
		kv("sandbox_profile", validation.VStr("docker-networkless")),
	)
	_, err := AddEvidence(c, fid, item)
	wantErr(t, err, "must cite its EXEC record")
}

func TestE7IsAnalysisEvidenceNotExecution(t *testing.T) {
	c := ingestCamp(t)
	f, _ := IngestHypothesis(c, hypoPayload(), "code", "", "")
	fid := objStr(f, "finding_id")
	_, err := AddEvidence(c, fid, validation.VObj(
		kv("evidence_id", validation.VStr("EV-e")),
		kv("level", validation.VStr("E7")),
		kv("type", validation.VStr("balance-delta")),
		kv("description", validation.VStr("impact quantified by hand")),
	))
	wantErr(t, err, "artifact")
	// With a registered artifact the E7 item lands.
	art := filepath.Join(c.ArtifactsDir, "impact.json")
	if err := os.WriteFile(art,
		[]byte(`{"extractable_usd": 2100000}`), 0o644); err != nil {
		t.Fatal(err)
	}
	aid, err := c.RegisterArtifact("economic-impact", art, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := AddEvidence(c, fid, validation.VObj(
		kv("evidence_id", validation.VStr("EV-e")),
		kv("level", validation.VStr("E7")),
		kv("type", validation.VStr("balance-delta")),
		kv("description", validation.VStr("impact quantified from fork state")),
		kv("artifact_id", validation.VStr(aid)),
	))
	if err != nil {
		t.Fatal(err)
	}
	ev := objAt(out, "evidence")
	last := ev.A[len(ev.A)-1]
	if got := objStr(last, "level"); got != "E7" {
		t.Fatalf("evidence[-1].level = %q, want E7", got)
	}
}

// ---- ported tests (tests/test_review_fixes.py S4) ----

func TestClaimDriftAcceptsAnyMatchingFigure(t *testing.T) {
	ok, err := ClaimDriftProblems(validation.VObj(
		kv("title", validation.VStr("a 2% fee gate enables a 100% drain")),
		kv("economic_impact", validation.VObj(
			kv("extraction_ratio", validation.VFloat(1.0)))),
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(ok) != 0 {
		t.Fatalf("any-matching-figure: %v", ok)
	}
	bad, err := ClaimDriftProblems(validation.VObj(
		kv("title", validation.VStr("a 2% fee gate enables a 50% drain")),
		kv("economic_impact", validation.VObj(
			kv("extraction_ratio", validation.VFloat(1.0)))),
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(bad) != 1 || !strings.Contains(bad[0], "closest figure") {
		t.Fatalf("all-disagreeing title: %v", bad)
	}
	half, err := ClaimDriftProblems(validation.VObj(
		kv("title", validation.VStr("drains half the pool")),
		kv("economic_impact", validation.VObj(
			kv("extraction_ratio", validation.VFloat(0.5)))),
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(half) != 0 {
		t.Fatalf("half: %v", half)
	}
}

// ---- intake checkpoint (warnings, not rejections) ----

func TestIntakeCheckpointEconomicWithoutImpact(t *testing.T) {
	w := IntakeCheckpoint(hypoE4Payload(), "economic", "")
	if len(w) != 1 || !strings.Contains(w[0], "trajectory 'economic'") {
		t.Fatalf("warnings = %v", w)
	}
	// The campaign in hand is named in the repair hint, not the metavariable.
	named := IntakeCheckpoint(hypoE4Payload(), "economic", "C-deadbeef")
	if len(named) != 1 ||
		!strings.Contains(named[0], "webv2 impact C-deadbeef <finding>") {
		t.Fatalf("named warnings = %v", named)
	}
	with := hypoE4Payload(kv("risk", validation.VObj(
		kv("economic", validation.VObj(
			kv("extractable_usd", validation.VInt(2100000)))))))
	if got := IntakeCheckpoint(with, "economic", ""); len(got) != 0 {
		t.Fatalf("warnings = %v", got)
	}
}

// ---- discovery-slot reform: suspicion is free, confirmation is metered ----

// ingestBare files a schema-valid HYPOTHESIS with no evidence (E0).
func ingestBare(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	f, err := IngestHypothesis(c, hypoPayload(), "code", "05", "")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// addEvidenceOfLevel appends one code-reading evidence item at [level].
func addEvidenceOfLevel(t *testing.T, c *state.Campaign, f validation.Value,
	level string) validation.Value {
	t.Helper()
	out, err := AddEvidence(c, objStr(f, "finding_id"), validation.VObj(
		kv("evidence_id", validation.VStr("EV-"+strings.ToLower(level))),
		kv("level", validation.VStr(level)),
		kv("type", validation.VStr("manual")),
		kv("description", validation.VStr("code reading at "+level)),
	))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// ingestWithEvidence is ingestBare with the payload already carrying one
// above-E0 item — the pre-loaded rise.
func ingestWithEvidence(t *testing.T, c *state.Campaign,
	level string) validation.Value {
	t.Helper()
	item := validation.VObj(
		kv("evidence_id", validation.VStr("EV-pre")),
		kv("level", validation.VStr(level)),
		kv("type", validation.VStr("manual")),
		kv("description", validation.VStr("pre-loaded code reading")),
	)
	f, err := IngestHypothesis(c,
		hypoPayload(kv("evidence", validation.VArr(item))), "code", "05", "")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// assertSlotCount reads budget.discovery_findings_so_far off the campaign.
func assertSlotCount(t *testing.T, c *state.Campaign, want int64) {
	t.Helper()
	b, err := c.Budget()
	if err != nil {
		t.Fatal(err)
	}
	if got := objAt(b, "discovery_findings_so_far").I; got != want {
		t.Fatalf("discovery_findings_so_far = %d, want %d", got, want)
	}
}

// TestDiscoverySlotConsumedOnRiseNotIngest: a bare hypothesis costs no slot;
// the first above-E0 evidence consumes exactly one; a second item consumes
// no more; a finding that ingests WITH pre-loaded above-E0 evidence pays at
// ingest.
func TestDiscoverySlotConsumedOnRiseNotIngest(t *testing.T) {
	c := ingestCamp(t)
	f := ingestBare(t, c)
	assertSlotCount(t, c, 0)
	if objBool(f, "discovery_slot_consumed") {
		t.Fatal("bare hypothesis must not carry the slot flag")
	}

	f = addEvidenceOfLevel(t, c, f, "E1")
	assertSlotCount(t, c, 1)
	if !objBool(f, "discovery_slot_consumed") {
		t.Fatal("first above-E0 evidence must set the slot flag")
	}
	f = addEvidenceOfLevel(t, c, f, "E2")
	assertSlotCount(t, c, 1) // idempotent
	if objAt(f, "evidence").Kind != validation.Arr ||
		len(objAt(f, "evidence").A) != 2 {
		t.Fatalf("evidence = %v", objAt(f, "evidence"))
	}

	c2 := ingestCamp(t)
	pre := ingestWithEvidence(t, c2, "E1") // pre-loaded rise
	assertSlotCount(t, c2, 1)
	if !objBool(pre, "discovery_slot_consumed") {
		t.Fatal("a pre-loaded above-E0 payload must set the slot flag")
	}
}

// TestDiscoverySlotRefusalKeepsTheIngestText: the ceiling still gates rises,
// not hypotheses, and its refusal is byte-identical to the ingest-era text.
func TestDiscoverySlotRefusalKeepsTheIngestText(t *testing.T) {
	c := slotCappedCampaign(t, 1)
	a := ingestBare(t, c)
	addEvidenceOfLevel(t, c, a, "E1")
	assertSlotCount(t, c, 1)

	// Bare suspicion is still free at the ceiling.
	b := ingestBare(t, c)
	assertSlotCount(t, c, 1)
	if _, err := AddEvidence(c, objStr(b, "finding_id"), validation.VObj(
		kv("evidence_id", validation.VStr("EV-b1")),
		kv("level", validation.VStr("E1")),
		kv("type", validation.VStr("manual")),
		kv("description", validation.VStr("the second rise cannot be paid")),
	)); err == nil || err.Error() != slotExhaustedText(c) {
		t.Fatalf("rise refusal = %v, want %q", err, slotExhaustedText(c))
	}
	if _, err := ingestWithEvidenceRaw(c, "E1"); err == nil ||
		err.Error() != slotExhaustedText(c) {
		t.Fatalf("pre-loaded rise refusal = %v, want %q", err,
			slotExhaustedText(c))
	}
}

// TestDiscoverySlotChargedOnPromotionAboveE0: the transition seam charges on
// the first promotion above E0 and only once per finding.
func TestDiscoverySlotChargedOnPromotionAboveE0(t *testing.T) {
	c := ingestCamp(t)
	f := ingestBare(t, c)
	fid := objStr(f, "finding_id")
	assertSlotCount(t, c, 0)
	if _, err := Transition(c, fid, "PROVISIONALLY_VALID",
		"static read supports it", "", "", false); err != nil {
		t.Fatal(err)
	}
	assertSlotCount(t, c, 1)
	got, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if !objBool(got, "discovery_slot_consumed") {
		t.Fatal("a promotion above E0 must set the slot flag")
	}
	// A second promotion above E0 (E1 -> E2) is already paid for.
	if _, err := Transition(c, fid, "POSSIBLE", "reachability shown",
		"", "", false); err != nil {
		t.Fatal(err)
	}
	assertSlotCount(t, c, 1)
	// A fall back to the E0 baseline charges nothing.
	if _, err := Transition(c, fid, "NEEDS_RESEARCH", "back to research",
		"", "", false); err != nil {
		t.Fatal(err)
	}
	assertSlotCount(t, c, 1)
}

// TestDiscoverySlotRefusesPromotionAtCeiling is the negative control for the
// transition seam: the refusal is the same text, and the hypothesis itself
// stays free.
func TestDiscoverySlotRefusesPromotionAtCeiling(t *testing.T) {
	c := slotCappedCampaign(t, 1)
	a := ingestBare(t, c)
	if _, err := Transition(c, objStr(a, "finding_id"), "POSSIBLE",
		"reachability shown", "", "", false); err != nil {
		t.Fatal(err)
	}
	b := ingestBare(t, c) // free at the ceiling
	_, err := Transition(c, objStr(b, "finding_id"), "POSSIBLE",
		"reachability shown", "", "", false)
	if err == nil || err.Error() != slotExhaustedText(c) {
		t.Fatalf("promotion refusal = %v, want %q", err, slotExhaustedText(c))
	}
	// The refused promotion left B at E0 — no partial move, no charge.
	got, err := LoadFinding(c, objStr(b, "finding_id"))
	if err != nil {
		t.Fatal(err)
	}
	if s := objStr(got, "status"); s != "HYPOTHESIS" {
		t.Fatalf("refused promotion changed status to %q", s)
	}
	if objBool(got, "discovery_slot_consumed") {
		t.Fatal("a refused promotion must not set the slot flag")
	}
	assertSlotCount(t, c, 1)
}

// slotCappedCampaign is a fresh campaign whose only spendable slot is the
// one ceiling in [max].
func slotCappedCampaign(t *testing.T, max int64) *state.Campaign {
	t.Helper()
	root := t.TempDir()
	c, err := state.Init(root, "Acme Program", state.InitOpts{
		Budget: &validation.Value{Kind: validation.Obj, O: []validation.KV{
			kv("max_discovery_findings", validation.VInt(max)),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// slotExhaustedText is the ceiling refusal — byte-identical to the text the
// ingest path raised before the slot moved to the rise.
func slotExhaustedText(c *state.Campaign) string {
	return "discovery budget exhausted — raise the ceiling (webv2 budget " +
		c.CampaignID + " --set-discovery N --actor NAME) or plan a new pass"
}

// ingestWithEvidenceRaw is ingestWithEvidence with the error returned rather
// than fataled, for refusal assertions.
func ingestWithEvidenceRaw(c *state.Campaign,
	level string) (validation.Value, error) {
	item := validation.VObj(
		kv("evidence_id", validation.VStr("EV-raw")),
		kv("level", validation.VStr(level)),
		kv("type", validation.VStr("manual")),
		kv("description", validation.VStr("pre-loaded code reading")),
	)
	return IngestHypothesis(c,
		hypoPayload(kv("evidence", validation.VArr(item))), "code", "05", "")
}

func TestIntakeCheckpointSeamAdvisory(t *testing.T) {
	prev := classAdvisoryFunc
	classAdvisoryFunc = func(bugClass *string) string {
		return "unknown class (test)"
	}
	defer func() { classAdvisoryFunc = prev }()
	w := IntakeCheckpoint(hypoPayload(), "code", "")
	if len(w) != 1 || w[0] != "unknown class (test)" {
		t.Fatalf("warnings = %v", w)
	}
	// The advisory rides into the ingest event log.
	c := ingestCamp(t)
	f, err := IngestHypothesis(c, hypoPayload(), "code", "05", "")
	if err != nil {
		t.Fatal(err)
	}
	if objStr(f, "status") != "HYPOTHESIS" {
		t.Fatalf("status = %q", objStr(f, "status"))
	}
}
