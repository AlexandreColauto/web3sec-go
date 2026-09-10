package findings

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

// ---- helpers ----

// pos finds a finding and moves it to POSSIBLE (the triage step every gate
// test starts from).
func pos(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	f, err := IngestHypothesis(c, hypoPayload(), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	if _, err := Transition(c, fid, "POSSIBLE", "triage", "", "", false); err != nil {
		t.Fatal(err)
	}
	got, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// ---- ported tests ----

// Port of test_illegal_jump_hypothesis_to_confirmed.
func TestIllegalJumpHypothesisToConfirmed(t *testing.T) {
	c := ingestCamp(t)
	f, err := IngestHypothesis(c, hypoPayload(), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = Transition(c, objStr(f, "finding_id"), "CONFIRMED",
		"I believe it", "", "", false)
	var it *IllegalTransition
	if !errors.As(err, &it) {
		t.Fatalf("want IllegalTransition, got %v", err)
	}
	want := "HYPOTHESIS -> CONFIRMED is not a legal transition (legal: " +
		"['DISPROVED', 'DUPLICATE', 'INFORMATIONAL', 'NEEDS_RESEARCH', " +
		"'OUT_OF_SCOPE', 'POSSIBLE', 'PROVISIONALLY_VALID'])"
	if err.Error() != want {
		t.Fatalf("message = %q, want %q", err.Error(), want)
	}
	// the finding is untouched
	got, err := LoadFinding(c, objStr(f, "finding_id"))
	if err != nil {
		t.Fatal(err)
	}
	if st := objStr(got, "status"); st != "HYPOTHESIS" {
		t.Fatalf("status = %q, want HYPOTHESIS", st)
	}
}

// Port of test_confirmation_gate_failures_are_enumerated.
func TestConfirmationGateFailuresAreEnumerated(t *testing.T) {
	c := ingestCamp(t)
	got := pos(t, c)
	failures, err := ConfirmationGates(c, got)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Join(failures, "; ")
	for _, want := range []string{"critic", "recall", "reproduction",
		"evidence level"} {
		if !strings.Contains(text, want) {
			t.Errorf("failure text %q misses %q", text, want)
		}
	}
	if len(failures) != 6 {
		t.Fatalf("failures = %d, want 6", len(failures))
	}
	detail, err := ConfirmationGateDetail(c, got)
	if err != nil {
		t.Fatal(err)
	}
	wantIDs := []string{"critic-verdict", "memory-check",
		"reproduction-reproduced", "evidence-floor",
		"evidence-floor-unreachable", "reproduction-tier"}
	for i, id := range wantIDs {
		if detail[i].CheckID != id {
			t.Errorf("failure %d id = %q, want %q", i, detail[i].CheckID, id)
		}
	}
	if detail[0].Message != "hostile critic verdict is None, need 'confirmed'" {
		t.Errorf("critic message = %q", detail[0].Message)
	}
	if detail[0].Remediation !=
		"webv2 verdict <fid> confirmed '<reasoning>' --actor <you>" {
		t.Errorf("critic remediation = %q", detail[0].Remediation)
	}
	if detail[3].Message != "evidence level E0 < required E5 for CONFIRMED" {
		t.Errorf("evidence-floor message = %q", detail[3].Message)
	}
}

// Port of test_confirmed_requires_full_gate_bundle: every gate clause is
// closed in turn, then the move succeeds.
func TestConfirmedRequiresFullGateBundle(t *testing.T) {
	c := ingestCamp(t)
	got := pos(t, c)
	fid := objStr(got, "finding_id")
	// E5 evidence without a sandbox profile is inadmissible
	_, err := AddEvidence(c, fid, validation.VObj(
		kv("evidence_id", validation.VStr("EV-1")),
		kv("level", validation.VStr("E5")),
		kv("type", validation.VStr("fork-test")),
		kv("description", validation.VStr("no sandbox")),
	))
	if err == nil {
		t.Fatal("E5 evidence without a sandbox profile must be rejected")
	}
	// ... and so is one that merely CLAIMS a container profile: the EXEC
	// ledger is the source of truth, not the caller's string.
	_, err = AddEvidence(c, fid, validation.VObj(
		kv("evidence_id", validation.VStr("EV-1b")),
		kv("level", validation.VStr("E5")),
		kv("type", validation.VStr("fork-test")),
		kv("description", validation.VStr("fabricated")),
		kv("sandbox_profile", validation.VStr("docker-networkless")),
	))
	wantErr(t, err, "EXEC record")
	rec := testExec(t, c, "docker-networkless", fid, 0, "PASS: test_exploit\n")
	if _, err := AddEvidence(c, fid, execEvidenceItem(rec, "E5", "fork-test",
		"fork repro extracts value", "EV-2")); err != nil {
		t.Fatal(err)
	}
	if _, err := SetCriticVerdict(c, fid, "confirmed", "checked"); err != nil {
		t.Fatal(err)
	}
	installMemoryStore(t, globalMemoryRow())
	if _, err := RecordMemoryCheck(c, fid, []validation.Value{validation.VObj(
		kv("memory_ids", validation.VArr(validation.VStr("MEM-global01"))),
		kv("mode", validation.VStr("negative")))}); err != nil {
		t.Fatal(err)
	}
	vf, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	ver := asDict(objAt(vf, "verification"))
	ver.O = validation.SetOrAppend(ver.O, "reproduction", validation.VObj(
		kv("tier_reached", validation.VStr("T3")),
		kv("status", validation.VStr("reproduced")),
		kv("attempts", validation.VArr()),
	))
	vf.O = validation.SetOrAppend(vf.O, "verification", ver)
	if err := SaveFinding(c, &vf); err != nil {
		t.Fatal(err)
	}
	// missing nothing now — the bundle closes and the move lands
	confirmed, err := Transition(c, fid, "CONFIRMED", "gates satisfied", "",
		"", false)
	if err != nil {
		t.Fatalf("CONFIRMED gate rejected a full bundle: %v", err)
	}
	if st := objStr(confirmed, "status"); st != "CONFIRMED" {
		t.Fatalf("status = %q, want CONFIRMED", st)
	}
	reloaded, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if st := objStr(reloaded, "status"); st != "CONFIRMED" {
		t.Fatalf("persisted status = %q, want CONFIRMED", st)
	}
	// the move is in the finding's own history AND the campaign log
	// (NEW -> HYPOTHESIS -> POSSIBLE -> CONFIRMED)
	hist := objAt(reloaded, "history")
	if len(hist.A) != 3 || objStr(hist.A[2], "to") != "CONFIRMED" {
		t.Fatalf("history = %v", hist)
	}
}

// Port of test_evidence_rejected_on_terminal_finding.
func TestEvidenceRejectedOnTerminalFinding(t *testing.T) {
	c := ingestCamp(t)
	f, err := IngestHypothesis(c, hypoPayload(), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	if _, err := Transition(c, fid, "DISPROVED", "the path is guarded", "", "",
		false); err != nil {
		t.Fatal(err)
	}
	_, err = AddEvidence(c, fid, validation.VObj(
		kv("evidence_id", validation.VStr("EV-9")),
		kv("level", validation.VStr("E2")),
		kv("type", validation.VStr("static-analysis")),
		kv("description", validation.VStr("post-mortem note")),
	))
	wantErr(t, err, "terminal")
	// a second transition out of DISPROVED is illegal (absorbing)
	_, err = Transition(c, fid, "POSSIBLE", "back", "", "", false)
	var it *IllegalTransition
	if !errors.As(err, &it) {
		t.Fatalf("want IllegalTransition, got %v", err)
	}
}

// Port of test_terminal_states_are_absorbing.
func TestTerminalStatesAreAbsorbing(t *testing.T) {
	for _, terminal := range []string{"DISPROVED", "OUT_OF_SCOPE",
		"INFORMATIONAL", "DUPLICATE"} {
		c := ingestCamp(t)
		f, err := IngestHypothesis(c, hypoPayload(), "code", "", "")
		if err != nil {
			t.Fatal(err)
		}
		fid := objStr(f, "finding_id")
		if _, err := Transition(c, fid, terminal, "closed by triage", "", "",
			false); err != nil {
			t.Fatalf("%s: %v", terminal, err)
		}
		for _, to := range []string{"HYPOTHESIS", "POSSIBLE", "CONFIRMED",
			"CHAIN"} {
			_, err := Transition(c, fid, to, "back", "", "", false)
			var it *IllegalTransition
			if !errors.As(err, &it) {
				t.Errorf("%s -> %s: want IllegalTransition, got %v", terminal,
					to, err)
			}
		}
		got, err := LoadFinding(c, fid)
		if err != nil {
			t.Fatal(err)
		}
		if st := objStr(got, "status"); st != terminal {
			t.Errorf("status = %q, want %q", st, terminal)
		}
	}
}

// Port of test_terminal_duplicate_freezes.
func TestTerminalDuplicateFreezes(t *testing.T) {
	c := ingestCamp(t)
	f, err := IngestHypothesis(c, hypoPayload(), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	dup, err := MarkDuplicate(c, fid, "F-abcdef012345")
	if err != nil {
		t.Fatal(err)
	}
	if st := objStr(dup, "status"); st != "DUPLICATE" {
		t.Fatalf("status = %q, want DUPLICATE", st)
	}
	if of := objStr(objAt(dup, "dedup"), "duplicate_of"); of != "F-abcdef012345" {
		t.Fatalf("duplicate_of = %q", of)
	}
	if reason := objStr(objAt(dup, "history").A[1], "reason"); reason !=
		"technical/root-cause duplicate of F-abcdef012345" {
		t.Fatalf("history reason = %q", reason)
	}
	_, err = Transition(c, fid, "POSSIBLE", "un-merge", "", "", false)
	var it *IllegalTransition
	if !errors.As(err, &it) {
		t.Fatalf("want IllegalTransition, got %v", err)
	}
}

// Port of test_tier3_flag_never_auto_merges — the FINDING-FACING half.
// PORT-NOTE: tests/test_findings.py drives this through dedup.run_dedup,
// which is unported; flag_possible_duplicate is the exact function run_dedup
// calls for a tier-3 match, and the contract under test is that it records
// the flag without touching the status.
func TestTier3FlagNeverAutoMerges(t *testing.T) {
	c := ingestCamp(t)
	f, err := IngestHypothesis(c, hypoPayload(), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	flagged, err := FlagPossibleDuplicate(c, fid, "F-abcdef012345")
	if err != nil {
		t.Fatal(err)
	}
	if st := objStr(flagged, "status"); st != "HYPOTHESIS" {
		t.Fatalf("tier-3 flag must not merge: status = %q", st)
	}
	dedup := objAt(flagged, "dedup")
	if of := objAt(dedup, "possible_duplicate_of"); len(of.A) != 1 ||
		of.A[0].S != "F-abcdef012345" {
		t.Fatalf("possible_duplicate_of = %v", of)
	}
	if _, ok := fieldAt(dedup, "duplicate_of"); ok {
		t.Error("a possible duplicate must not be recorded as a duplicate")
	}
	// idempotent: flagging twice keeps one entry
	again, err := FlagPossibleDuplicate(c, fid, "F-abcdef012345")
	if err != nil {
		t.Fatal(err)
	}
	if of := objAt(objAt(again, "dedup"), "possible_duplicate_of"); len(of.A) != 1 {
		t.Fatalf("flag not idempotent: %v", of)
	}
	// the flag is on the campaign log
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if objStr(e, "type") == "finding.possible_duplicate" &&
			objStr(objAt(e, "data"), "of") == "F-abcdef012345" {
			found = true
		}
	}
	if !found {
		t.Error("finding.possible_duplicate event missing")
	}
}

// Port of test_tier1_auto_merge — the FINDING-FACING half. PORT-NOTE:
// dedup.run_dedup (the report's tier1_merges count) is unported;
// mark_duplicate is the exact merge primitive it calls for a tier-1 match.
func TestTier1AutoMerge(t *testing.T) {
	c := ingestCamp(t)
	f, err := IngestHypothesis(c, hypoPayload(), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	merged, err := MarkDuplicate(c, fid, "F-abcdef012345")
	if err != nil {
		t.Fatal(err)
	}
	if st := objStr(merged, "status"); st != "DUPLICATE" {
		t.Fatalf("status = %q, want DUPLICATE", st)
	}
	if of := objStr(objAt(merged, "dedup"), "duplicate_of"); of !=
		"F-abcdef012345" {
		t.Fatalf("duplicate_of = %q", of)
	}
	// a merged finding leaves the live set
	live, err := LoadLiveFindings(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range live {
		if objStr(l, "finding_id") == fid {
			t.Error("a DUPLICATE must not stay live")
		}
	}
}

// Port of test_incompatible_classes_never_tier3 — the FINDING-FACING half.
// PORT-NOTE: the tier-3 classifier (dedup.set_economic_signature /
// run_dedup) is unported; what the finding layer guarantees is that a
// different-class finding is never MERGED — flag_possible_duplicate is the
// only writer of possible_duplicate_of and it leaves the status alone.
func TestIncompatibleClassesNeverTier3(t *testing.T) {
	c := ingestCamp(t)
	a, err := IngestHypothesis(c, hypoPayload(), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := IngestHypothesis(c, hypoPayload(
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("reentrancy")),
			kv("description", validation.VStr(
				"reentrancy drains the vault balance"))))), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	aid, bid := objStr(a, "finding_id"), objStr(b, "finding_id")
	flagged, err := FlagPossibleDuplicate(c, aid, bid)
	if err != nil {
		t.Fatal(err)
	}
	if st := objStr(flagged, "status"); st != "HYPOTHESIS" {
		t.Fatalf("status = %q, want HYPOTHESIS (never merged)", st)
	}
	other, err := LoadFinding(c, bid)
	if err != nil {
		t.Fatal(err)
	}
	if st := objStr(other, "status"); st != "HYPOTHESIS" {
		t.Fatalf("the other finding was touched: status = %q", st)
	}
}

// ---- transition plumbing: byte-exact event/audit strings ----

func TestTransitionEventStrings(t *testing.T) {
	c := ingestCamp(t)
	f, err := IngestHypothesis(c, hypoPayload(), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	if _, err := Transition(c, fid, "POSSIBLE", "triage", "critic", "", false); err != nil {
		t.Fatal(err)
	}
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	var ev validation.Value
	found := false
	for _, e := range events {
		if objStr(e, "type") == "finding.status" {
			ev, found = e, true
		}
	}
	if !found {
		t.Fatal("no finding.status event")
	}
	data := objAt(ev, "data")
	if objStr(data, "from") != "HYPOTHESIS" || objStr(data, "to") != "POSSIBLE" {
		t.Errorf("event from/to = %q -> %q", objStr(data, "from"),
			objStr(data, "to"))
	}
	if objStr(data, "reason") != "triage" || objStr(data, "actor") != "critic" {
		t.Errorf("event reason/actor = %q / %q", objStr(data, "reason"),
			objStr(data, "actor"))
	}
	if ref := objAt(ev, "ref"); ref.Kind != validation.Str || ref.S != fid {
		t.Errorf("event ref = %v, want %q", ref, fid)
	}
	// same-status move is a no-op (no new history row, no event)
	before := len(events)
	got, err := Transition(c, fid, "POSSIBLE", "again", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if hist := objAt(got, "history"); len(hist.A) != 2 {
		t.Fatalf("no-op move appended history: %v", hist)
	}
	events, err = c.Events()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != before {
		t.Fatalf("no-op move logged an event: %d -> %d", before, len(events))
	}
}

// The DISPROVED adjacent-property guard reads the protocol model; with a
// lifecycle family in play a bare DISPROVED is refused with the planner's
// exact message.
func TestDisprovedRequiresAdjacentProperty(t *testing.T) {
	c := ingestCamp(t)
	f, err := IngestHypothesis(c, hypoPayload(), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	prev := plannerFamiliesForFindingFunc
	plannerFamiliesForFindingFunc = func(validation.Value,
		validation.Value) map[string]struct{} {
		return map[string]struct{}{"withdraw": {}}
	}
	defer func() { plannerFamiliesForFindingFunc = prev }()
	_, err = Transition(c, fid, "DISPROVED", "not exploitable", "", "", false)
	wantErr(t, err, adjacentRequiredMsg)
	// an adjacent attestation clears the guard
	if _, err := Transition(c, fid, "DISPROVED", "not exploitable", "",
		"checked the sibling refund path", false); err != nil {
		t.Fatalf("adjacent attestation rejected: %v", err)
	}
	// ... and so does an explicit clear
	c2 := ingestCamp(t)
	f2, err := IngestHypothesis(c2, hypoPayload(), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Transition(c2, objStr(f2, "finding_id"), "DISPROVED",
		"no lifecycle family applies", "", "", true); err != nil {
		t.Fatalf("adjacent-clear rejected: %v", err)
	}
}

// set_critic_verdict validates the verdict vocabulary.
func TestSetCriticVerdictValidation(t *testing.T) {
	c := ingestCamp(t)
	f, err := IngestHypothesis(c, hypoPayload(), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	_, err = SetCriticVerdict(c, fid, "vibes", "no")
	wantErr(t, err, "invalid critic verdict 'vibes'")
	got, err := SetCriticVerdict(c, fid, "possible", "needs a fork run")
	if err != nil {
		t.Fatal(err)
	}
	ver := asDict(objAt(got, "verification"))
	if v := objStr(ver, "critic_verdict"); v != "possible" {
		t.Fatalf("critic_verdict = %q", v)
	}
	if r := objStr(objAt(got, "dedup_meta"), "critic_reasoning"); r !=
		"needs a fork run" {
		t.Fatalf("critic_reasoning = %q", r)
	}
}

// set_triager_outlook records the critic's payment-likelihood call.
func TestSetTriagerOutlook(t *testing.T) {
	c := ingestCamp(t)
	f, err := IngestHypothesis(c, hypoPayload(), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	got, err := SetTriagerOutlook(c, fid, "likely",
		"on-chain fork PoC with drain terminal; policy pays critical")
	if err != nil {
		t.Fatal(err)
	}
	o := objAt(objAt(got, "verification"), "triager_outlook")
	if objStr(o, "outcome") != "likely" {
		t.Fatal("outcome not recorded")
	}
	if _, err := SetTriagerOutlook(c, fid, "maybe", "short"); err == nil {
		t.Fatal("invalid enum must be rejected")
	}
	if _, err := SetTriagerOutlook(c, fid, "likely", "too short"); err == nil {
		t.Fatal("reason under 15 runes must be rejected")
	}
	// idempotent replace, not append:
	f2, err := SetTriagerOutlook(c, fid, "uncertain",
		"policy excludes the token's chain; acceptance unclear")
	if err != nil {
		t.Fatal(err)
	}
	if objStr(objAt(objAt(f2, "verification"), "triager_outlook"), "outcome") != "uncertain" {
		t.Fatal("second call must replace the first")
	}
}

// set_shield_adjudication records the extraction decision with its actor.
func TestSetShieldAdjudication(t *testing.T) {
	c := ingestCamp(t)
	f, err := IngestHypothesis(c, hypoPayload(), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	_, err = SetShieldAdjudication(c, fid, true, "it extracts", "operator")
	wantErr(t, err, "must be substantive (>= 15 chars)")
	got, err := SetShieldAdjudication(c, fid, true,
		"the economic effect is extraction despite the documented intent",
		"operator")
	if err != nil {
		t.Fatal(err)
	}
	adj := objAt(asDict(objAt(got, "verification")), "shield_adjudication")
	if !objAt(adj, "extraction_despite_intent").B {
		t.Error("extraction_despite_intent must be true")
	}
	if objStr(adj, "actor") != "operator" || objStr(adj, "at") == "" {
		t.Errorf("adjudication attribution = %v", adj)
	}
	if objStr(adj, "reasoning") !=
		"the economic effect is extraction despite the documented intent" {
		t.Errorf("reasoning = %q", objStr(adj, "reasoning"))
	}
}

// mark_precondition audits one precondition, exact or substring match.
func TestMarkPrecondition(t *testing.T) {
	c := ingestCamp(t)
	f, err := IngestHypothesis(c, hypoPayload(), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	_, err = MarkPrecondition(c, fid, "attacker holds a flash loan", true)
	want := "\"" + fid + ": no precondition matching 'attacker holds a flash loan'\""
	if err == nil || err.Error() != want {
		t.Fatalf("KeyError text = %v, want %s", err, want)
	}
	// install a precondition, then audit it (case-insensitive substring)
	vf, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	vf.O = validation.SetOrAppend(vf.O, "preconditions", validation.VArr(validation.VObj(
		kv("description", validation.VStr("the victim must stake before withdraw")),
		kv("kind", validation.VStr("state")),
	)))
	if err := SaveFinding(c, &vf); err != nil {
		t.Fatal(err)
	}
	got, err := MarkPrecondition(c, fid, "VICTIM MUST STAKE", true)
	if err != nil {
		t.Fatal(err)
	}
	pre := objAt(got, "preconditions").A[0]
	if v := objStr(pre, "enforced_by_poc"); v != "true" {
		t.Fatalf("enforced_by_poc = %q, want true", v)
	}
	if _, err := MarkPrecondition(c, fid, "victim must stake", false); err != nil {
		t.Fatal(err)
	}
	got, err = LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if v := objStr(objAt(got, "preconditions").A[0], "enforced_by_poc"); v != "false" {
		t.Fatalf("enforced_by_poc = %q, want false", v)
	}
}

// fold_into_lineage pins the lineage id without touching the status.
func TestFoldIntoLineage(t *testing.T) {
	c := ingestCamp(t)
	f, err := IngestHypothesis(c, hypoPayload(), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	got, err := FoldIntoLineage(c, fid, "LIN-abcdef01")
	if err != nil {
		t.Fatal(err)
	}
	if id := objStr(objAt(got, "dedup"), "lineage_id"); id != "LIN-abcdef01" {
		t.Fatalf("lineage_id = %q", id)
	}
	if st := objStr(got, "status"); st != "HYPOTHESIS" {
		t.Fatalf("status = %q, want HYPOTHESIS", st)
	}
}

// Port of tests/test_cli_e2e_confirm.py::test_cli_confirm_flow_with_shield —
// the STATE-EFFECT half. PORT-NOTE: the CLI wiring (`webv2 init/snap/model/
// plan/ingest/mint/verdict/recall/move/shield`) is a later task; every
// operator decision below is the same call the CLI makes, so the run-2 gap
// (the shield gate fires before the adjudication exists, and the sanctioned
// writer then succeeds) is pinned at the finding layer.
func TestConfirmedFlowStateEffectsWithShield(t *testing.T) {
	c := ingestCamp(t)
	payload := hypoPayload(
		kv("title", validation.VStr(
			"Out-of-band transfer inflates per-share price")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("logic-error")),
			kv("cwe", validation.VStr("CWE-682")),
			kv("description", validation.VStr(
				"a direct transfer to the vault inflates totalAssets' "+
					"denominator without minting shares")))),
		kv("invariant", validation.VObj(
			kv("id", validation.VStr("INV-5")),
			kv("statement", validation.VStr(
				"the exchange rate must not move in favor of existing shares")))))
	f, err := IngestHypothesis(c, payload, "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	rec := testExec(t, c, "docker-networkless", fid, 0, "PASS: test_exploit\n")
	if _, err := AddEvidence(c, fid, execEvidenceItem(rec, "E4", "foundry-test",
		"PoC transfers then deposits; per-share price rises", "EV-1")); err != nil {
		t.Fatal(err)
	}
	if _, err := SetCriticVerdict(c, fid, "confirmed",
		"no compensating control at the entry"); err != nil {
		t.Fatal(err)
	}
	installMemoryStore(t, globalMemoryRow())
	if _, err := RecordMemoryCheck(c, fid, []validation.Value{validation.VObj(
		kv("memory_ids", validation.VArr(validation.VStr("MEM-global01"))),
		kv("mode", validation.VStr("negative")))}); err != nil {
		t.Fatal(err)
	}
	vf, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	ver := asDict(objAt(vf, "verification"))
	ver.O = validation.SetOrAppend(ver.O, "reproduction", validation.VObj(
		kv("tier_reached", validation.VStr("T2")),
		kv("status", validation.VStr("reproduced")),
		kv("attempts", validation.VArr()),
	))
	vf.O = validation.SetOrAppend(vf.O, "verification", ver)
	if err := SaveFinding(c, &vf); err != nil {
		t.Fatal(err)
	}
	if _, err := Transition(c, fid, "POSSIBLE",
		"E4 sandboxed repro + critic confirmed", "", "", false); err != nil {
		t.Fatal(err)
	}
	// INV-5 is documented about the target itself, so the registry check is
	// exempt; the intent language makes the shield gate fire.
	prevDoc, prevIntent := documentedInvariantsFunc, intentClaimsFunc
	prevLinks := loadInvariantLinksFunc
	// `webv2 model` seeds the registry from the protocol model
	loadInvariantLinksFunc = func(*state.Campaign) (validation.Value, error) {
		return validation.VObj(kv("invariants", validation.VObj(
			kv("INV-5", validation.VObj(
				kv("status", validation.VStr("UNVERIFIED")),
				kv("source", validation.VStr("documented"))))))), nil
	}
	documentedInvariantsFunc = func(*state.Campaign) (map[string]validation.Value, error) {
		return map[string]validation.Value{"INV-5": validation.VObj()}, nil
	}
	intentClaimsFunc = func(*state.Campaign) (map[string]validation.Value, error) {
		return map[string]validation.Value{"INV-5": validation.VObj(
			kv("intent_line", validation.VStr("INV-5: excess value transferred "+
				"to the vault is intended to accrue to existing stakers"))),
		}, nil
	}
	defer func() {
		documentedInvariantsFunc, intentClaimsFunc = prevDoc, prevIntent
		loadInvariantLinksFunc = prevLinks
	}()
	_, err = Transition(c, fid, "CONFIRMED", "gates passed", "", "", false)
	if err == nil {
		t.Fatal("CONFIRMED must fail while the shield is unadjudicated")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "shield") {
		t.Fatalf("gate error must name the shield: %v", err)
	}
	if _, err := SetShieldAdjudication(c, fid, true, "the economic effect is "+
		"extraction despite the documented intent", "operator"); err != nil {
		t.Fatal(err)
	}
	if _, err := Transition(c, fid, "CONFIRMED",
		"shield adjudicated; gates passed", "", "", false); err != nil {
		t.Fatalf("the sanctioned shield writer failed: %v", err)
	}
	final, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if st := objStr(final, "status"); st != "CONFIRMED" {
		t.Fatalf("status = %q, want CONFIRMED", st)
	}
	adj := objAt(asDict(objAt(final, "verification")), "shield_adjudication")
	if !objAt(adj, "extraction_despite_intent").B {
		t.Error("extraction_despite_intent must be true")
	}
	if objStr(adj, "actor") == "" {
		t.Error("the adjudication must be attributed")
	}
}

// A re-pinned source snapshot makes the gate's snapshot-compatible check
// fail (Python calls assert_snapshot_compatible with its strict default).
func TestGateSnapshotMismatchFailsClosed(t *testing.T) {
	c := ingestCamp(t)
	got := pos(t, c)
	// a second, different source pin moves the active snapshot
	target2 := filepath.Join(t.TempDir(), "target2")
	if err := os.MkdirAll(target2, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target2, "V.sol"),
		[]byte("contract V { uint256 x; }"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, target2, nil, nil); err != nil {
		t.Fatal(err)
	}
	detail, err := ConfirmationGateDetail(c, got)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range detail {
		if f.CheckID == "snapshot-compatible" {
			found = true
			if !strings.Contains(f.Message, "re-verify instead of trusting") {
				t.Errorf("snapshot message = %q", f.Message)
			}
		}
	}
	if !found {
		t.Fatalf("snapshot-compatible failure missing: %v", detail)
	}
}

// Smoke test for _anchor_rescan (a transition dependency; its own tests live
// in tests/test_plan_lenses.py task 6, a different slice). The planner seams
// are wired here to prove the contract: one idempotent ANCHOR priority for a
// CONFIRMED high/critical finding, canonical bug_class only, and the
// exhausted-lens re-open pass runs first.
func TestAnchorRescanSmoke(t *testing.T) {
	c := ingestCamp(t)
	payload := hypoPayload(
		kv("reported_severity", validation.VStr("high")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("logic-error")),
			kv("description", validation.VStr("vault accounting drift")))))
	payload.O = validation.SetOrAppend(payload.O, "affected", validation.VArr(
		validation.VObj(kv("path", validation.VStr("src/V.sol")),
			kv("contract", validation.VStr("Rollup")))))
	f, err := IngestHypothesis(c, payload, "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	planPath := filepath.Join(c.ArtifactsDir, "campaign_plan.json")
	plan := validation.VObj(
		kv("priorities", validation.VArr()),
		kv("lenses", validation.VArr(validation.VObj(
			kv("id", validation.VStr("L-1")),
			kv("lens", validation.VStr("accounting")),
			kv("status", validation.VStr("answered")),
			kv("families", validation.VArr(validation.VStr("withdraw"))),
			kv("closed_reason", validation.VStr("nothing found")),
			kv("closed_at", validation.VStr("2026-01-01T00:00:00+00:00")),
		))),
	)
	writePlan := func(v validation.Value) error {
		if err := validation.WriteJson(planPath, v, ""); err != nil {
			return err
		}
		plan = v
		return nil
	}
	if err := writePlan(plan); err != nil {
		t.Fatal(err)
	}
	prevLoad, prevSave := plannerLoadPlanReadonlyFunc, plannerSavePlanFunc
	prevFam, prevClasses := plannerFamiliesForFindingFunc, taxonomyKnownClassesFunc
	plannerLoadPlanReadonlyFunc = func(*state.Campaign) (validation.Value, error) {
		return plan, nil
	}
	plannerSavePlanFunc = func(_ *state.Campaign, v validation.Value) error {
		return writePlan(v)
	}
	plannerFamiliesForFindingFunc = func(validation.Value,
		validation.Value) map[string]struct{} {
		return map[string]struct{}{"withdraw": {}}
	}
	taxonomyKnownClassesFunc = func() map[string]struct{} {
		return map[string]struct{}{"logic-error": {}}
	}
	defer func() {
		plannerLoadPlanReadonlyFunc, plannerSavePlanFunc = prevLoad, prevSave
		plannerFamiliesForFindingFunc, taxonomyKnownClassesFunc = prevFam,
			prevClasses
	}()
	if err := anchorRescan(c, f); err != nil {
		t.Fatal(err)
	}
	// the exhausted lens was re-opened first, with the closed_* keys dropped
	lens := objAt(plan, "lenses").A[0]
	if st := objStr(lens, "status"); st != "open" {
		t.Fatalf("lens status = %q, want open", st)
	}
	if !strings.Contains(objStr(lens, "reopen_reason"), "was closed") {
		t.Errorf("reopen_reason = %q", objStr(lens, "reopen_reason"))
	}
	if _, ok := fieldAt(lens, "closed_reason"); ok {
		t.Error("closed_reason must be dropped on re-open")
	}
	prio := objAt(plan, "priorities").A[0]
	if id := objStr(prio, "id"); id != "Q-001" {
		t.Fatalf("priority id = %q, want Q-001", id)
	}
	if objStr(prio, "anchor_of") != objStr(f, "finding_id") {
		t.Errorf("anchor_of = %q", objStr(prio, "anchor_of"))
	}
	if cls := objStr(prio, "bug_class"); cls != "logic-error" {
		t.Errorf("bug_class = %q", cls)
	}
	if comps := objAt(prio, "components"); len(comps.A) != 1 ||
		comps.A[0].S != "Rollup" {
		t.Errorf("components = %v", comps)
	}
	// idempotent
	if err := anchorRescan(c, f); err != nil {
		t.Fatal(err)
	}
	if n := len(objAt(plan, "priorities").A); n != 1 {
		t.Fatalf("priorities = %d, want 1 (idempotent)", n)
	}
	// severity-gated: a low finding never anchors
	low, err := IngestHypothesis(c, hypoPayload(
		kv("reported_severity", validation.VStr("low"))), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := anchorRescan(c, low); err != nil {
		t.Fatal(err)
	}
	if n := len(objAt(plan, "priorities").A); n != 1 {
		t.Fatalf("low severity added an anchor: %d priorities", n)
	}
}
