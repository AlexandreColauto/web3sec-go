package sft

// Port of tests/test_sft_backfill.py (Task D): trajectory backfill +
// TODO-guard. A pinned campaign with a model-proposed hypothesis exercises the
// hash-verified / reconstructed / hand-written provenance ladder, the
// structured pre-fill (SUPPORTED -> CONFIRMED, invariant head + list dedup),
// the TODO placeholders that block curation, and the CLI draft writer.

import (
	"strconv"
	"strings"
	"testing"

	"websec/internal/boundary"
	"websec/internal/findings"
	"websec/internal/roles"
	"websec/internal/state"
	"websec/internal/trajectory"
	"websec/internal/validation"
)

const backfillSnap = "SNAP-BF01"

func backfillCamp(t *testing.T) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "sft-backfill-test", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.PinSnapshot(validation.VObj(
		kv("snapshot_id", validation.VStr(backfillSnap)),
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("created_at", validation.VStr("2026-01-01T00:00:00Z")),
		kv("source", validation.VObj(
			kv("ladder", validation.VStr("artifact")),
			kv("content_hash", validation.VStr(strings.Repeat("a", 64)))))))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// backfillHypothesis is tests/test_trajectory.py::valid_hypothesis.
func backfillHypothesis() validation.Value {
	return validation.VObj(
		kv("bug_class", validation.VStr("oracle-manipulation")),
		kv("claim", validation.VStr("The vault prices redemptions against a "+
			"manipulable TWAP, allowing a flash loan to push the price and "+
			"redeem shares above NAV.")),
		kv("target", validation.VObj(
			kv("path", validation.VStr("src/Vault.sol")),
			kv("function", validation.VStr("redeem")))),
		kv("assumptions", validation.VArr(validation.VObj(
			kv("id", validation.VStr("A1")),
			kv("type", validation.VStr("reachability")),
			kv("claim", validation.VStr("the TWAP window is longer than the "+
				"flash-loan manipulation horizon, so the price push holds")),
			kv("status", validation.VStr("UNKNOWN")),
			kv("model_belief", validation.VFloat(0.9)),
			kv("blocking", validation.VBool(true))))),
		kv("initial_plan", validation.VArr(validation.VObj(
			kv("step", validation.VInt(1)),
			kv("tool_id", validation.VStr("callgraph")),
			kv("target_assumptions", validation.VArr(validation.VStr("A1"))),
			kv("expected_observation", validation.VStr(
				"redeem() has no modifier and reads TWAP"))))),
		kv("uncertainty", validation.VObj(
			kv("open_questions", validation.VArr(
				validation.VStr("current pool TVL"))))))
}

func backfillRequest(ch string) validation.Value {
	return validation.VObj(
		kv("role", validation.VStr("proposer")),
		kv("model_id", validation.VStr("test-model")),
		kv("prompt_version", validation.VStr(strings.Repeat("0", 16))),
		kv("response_schema", validation.VStr("hypothesis")),
		kv("context_hash", validation.VStr(ch)))
}

func backfillResponse(fid string) validation.Value {
	return validation.VObj(
		kv("role", validation.VStr("proposer")),
		kv("response_schema", validation.VStr("hypothesis")),
		kv("payload_sha256", validation.VStr(strings.Repeat("b", 64))),
		kv("applied_ref", validation.VStr(fid)),
		kv("finding_id", validation.VStr(fid)))
}

func criticVerdict(fid string) validation.Value {
	return validation.VObj(
		kv("finding_id", validation.VStr(fid)),
		kv("claim_version", validation.VInt(1)),
		kv("per_assumption", validation.VArr(validation.VObj(
			kv("assumption_id", validation.VStr("A1")),
			kv("status", validation.VStr("SUPPORTED")),
			kv("evidence_cited", validation.VArr(validation.VStr("EV-1"))),
			kv("note", validation.VStr(
				"callgraph confirms redeem() reads the TWAP"))))),
		kv("verdict", validation.VStr("confirmed")),
		kv("missing_proof", validation.VArr()))
}

func ingestHyp(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	f, err := boundary.IngestModelHypothesis(c, backfillHypothesis(),
		boundary.HypothesisOpts{})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestSFTBackfillHashVerified(t *testing.T) {
	camp := backfillCamp(t)
	// Positive control: a pre-existing finding must survive in the user turn
	// while the backfilled one is excluded (selective exclusion, not wipe).
	fPre := ingestHyp(t, camp)
	bundle0, err := roles.BuildProposerContext(camp, nil)
	if err != nil {
		t.Fatal(err)
	}
	ch0 := boundary.ContextHash(bundle0)
	if _, err := trajectory.RecordModelEvent(camp, "model.request",
		backfillRequest(ch0), nil); err != nil {
		t.Fatal(err)
	}
	f := ingestHyp(t, camp)
	fid := objStr(f, "finding_id")
	if _, err := trajectory.RecordModelEvent(camp, "model.response",
		backfillResponse(fid), &fid); err != nil {
		t.Fatal(err)
	}
	draft, err := BackfillFinding(camp, fid)
	if err != nil {
		t.Fatal(err)
	}
	if objStr(draft, "status") != "draft" {
		t.Fatalf("status = %q", objStr(draft, "status"))
	}
	if objAt(draft, "taxonomy").Kind != validation.Null {
		t.Fatalf("taxonomy = %v", objAt(draft, "taxonomy"))
	}
	if got := validation.CanonCompact(objAt(draft, "source")); got !=
		`{"cluster":"`+fid+`","kind":"backfill","ref":"`+fid+`"}` {
		t.Fatalf("source = %s", got)
	}
	prov := objAt(draft, "provenance")
	if got := objStr(prov, "bundle_provenance"); got != "hash-verified" {
		t.Fatalf("bundle_provenance = %q", got)
	}
	if got := objStr(prov, "context_hash"); got != ch0 {
		t.Fatalf("context_hash = %q want %q", got, ch0)
	}
	refs := objAt(prov, "trajectory_refs").A
	if len(refs) != 2 {
		t.Fatalf("trajectory_refs = %v", refs)
	}
	// Order is [response_seq, request_seq] (reverse-chronological).
	first, err := strconv.Atoi(refs[0].S)
	if err != nil {
		t.Fatal(err)
	}
	second, err := strconv.Atoi(refs[1].S)
	if err != nil {
		t.Fatal(err)
	}
	if first <= second {
		t.Fatalf("refs = %v", refs)
	}
	msgs := objAt(draft, "messages").A
	if got := objStr(msgs[0], "content"); got != promptText(t) {
		t.Fatal("system turn is not byte-identical to production")
	}
	user, err := validation.ParseOrdered([]byte(objStr(msgs[1], "content")))
	if err != nil {
		t.Fatal(err)
	}
	seenPre := false
	for _, s := range objAt(user, "existing_findings").A {
		if objStr(s, "finding_id") == fid {
			t.Fatal("backfilled finding leaked into the user turn")
		}
		if objStr(s, "finding_id") == objStr(fPre, "finding_id") {
			seenPre = true
		}
	}
	if !seenPre {
		t.Fatal("pre-existing finding missing from the user turn")
	}
}

func TestSFTBackfillReconstructedOnDrift(t *testing.T) {
	camp := backfillCamp(t)
	if _, err := trajectory.RecordModelEvent(camp, "model.request",
		backfillRequest(strings.Repeat("f", 64)), nil); err != nil {
		t.Fatal(err)
	}
	f := ingestHyp(t, camp)
	fid := objStr(f, "finding_id")
	if _, err := trajectory.RecordModelEvent(camp, "model.response",
		backfillResponse(fid), &fid); err != nil {
		t.Fatal(err)
	}
	draft, err := BackfillFinding(camp, fid)
	if err != nil {
		t.Fatal(err)
	}
	prov := objAt(draft, "provenance")
	if got := objStr(prov, "bundle_provenance"); got != "reconstructed" {
		t.Fatalf("bundle_provenance = %q", got)
	}
	if objAt(prov, "context_hash").Kind != validation.Null {
		t.Fatalf("context_hash = %v", objAt(prov, "context_hash"))
	}
}

func TestSFTBackfillNoEventsHandWritten(t *testing.T) {
	camp := backfillCamp(t)
	f := ingestHyp(t, camp)
	draft, err := BackfillFinding(camp, objStr(f, "finding_id"))
	if err != nil {
		t.Fatal(err)
	}
	prov := objAt(draft, "provenance")
	if got := objStr(prov, "bundle_provenance"); got != "hand-written" {
		t.Fatalf("bundle_provenance = %q", got)
	}
	if got := objAt(prov, "trajectory_refs"); got.Kind != validation.Arr ||
		len(got.A) != 0 {
		t.Fatalf("trajectory_refs = %v", got)
	}
	if objAt(prov, "context_hash").Kind != validation.Null {
		t.Fatalf("context_hash = %v", objAt(prov, "context_hash"))
	}
}

func TestSFTBackfillStructuredPrefillAndTranslation(t *testing.T) {
	camp := backfillCamp(t)
	f := ingestHyp(t, camp)
	fid := objStr(f, "finding_id")
	// Plant head + list invariants (with a duplicate statement) so the
	// head/security_invariants prefill + dedup path is exercised.
	head := "shares priced at or above net asset value at redemption time always"
	second := "total supply of vault shares always equals sum of individual " +
		"balances held"
	rec, err := findings.LoadFinding(camp, fid)
	if err != nil {
		t.Fatal(err)
	}
	rec = setKey(rec, "invariant", validation.VObj(
		kv("statement", validation.VStr(head))))
	rec = setKey(rec, "security_invariants", validation.VArr(
		validation.VObj(kv("statement", validation.VStr(head))),
		validation.VObj(kv("statement", validation.VStr(second)))))
	if err := findings.SaveFinding(camp, &rec); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.AddEvidence(camp, fid, validation.VObj(
		kv("evidence_id", validation.VStr("EV-1")),
		kv("level", validation.VStr("E1")),
		kv("type", validation.VStr("static-analysis")),
		kv("description", validation.VStr(
			"callgraph: redeem() reads TWAP")))); err != nil {
		t.Fatal(err)
	}
	if _, err := boundary.ApplyCriticVerdict(camp, fid, criticVerdict(fid),
		""); err != nil {
		t.Fatal(err)
	}
	draft, err := BackfillFinding(camp, fid)
	if err != nil {
		t.Fatal(err)
	}
	st := objAt(draft, "structured")
	if got := objStr(st, "bug_class"); got != "oracle-manipulation" {
		t.Fatalf("bug_class = %q", got)
	}
	var a1 validation.Value
	for _, a := range objAt(st, "assumptions").A {
		if objStr(a, "id") == "A1" {
			a1 = a
		}
	}
	if got := objStr(a1, "status"); got != "CONFIRMED" {
		t.Fatalf("A1 status = %q", got)
	}
	if !strings.Contains(objStr(a1, "reason"), "EV-1") {
		t.Fatalf("A1 reason = %q", objStr(a1, "reason"))
	}
	invs := objAt(st, "invariants").A
	if len(invs) != 2 || objStr(invs[0], "statement") != head ||
		objStr(invs[1], "statement") != second {
		t.Fatalf("invariants = %v", invs)
	}
	for _, i := range invs {
		if objStr(i, "status") != "UNCHECKED" {
			t.Fatalf("invariant status = %q", objStr(i, "status"))
		}
	}
}

func TestSFTBackfillDraftFailsLintUntilCompleted(t *testing.T) {
	camp := backfillCamp(t)
	f := ingestHyp(t, camp)
	draft, err := BackfillFinding(camp, objStr(f, "finding_id"))
	if err != nil {
		t.Fatal(err)
	}
	// Lint operates on store-shaped records (schema requires id/version); the
	// store assigns the real id at add, so the test pins a fixture id.
	draft = setKey(draft, "id", validation.VStr("SFT-9001"))
	draft = setKey(draft, "version", validation.VInt(1))
	hard := hardReasons(LintExample(draft, nil, "draft"))
	if !hasPrefixReason(hard, "todo:") {
		t.Fatalf("hard = %v", hard)
	}
	if !hasPrefixReason(hard, "name-anchoring:") {
		t.Fatalf("hard = %v", hard)
	}
}

func TestSFTTodoPlaceholdersCoverBugClassAndCase(t *testing.T) {
	// The backfill skeleton emits bug_class "TODO-bug-class"; the guard must
	// catch it even when every other field is clean, case-insensitively.
	clean := validation.VObj(
		kv("bug_class", validation.VStr("oracle-manipulation")),
		kv("claim", validation.VStr("real claim")),
		kv("assumptions", validation.VArr(validation.VObj(
			kv("id", validation.VStr("A1")),
			kv("reason", validation.VStr("evidence: EV-1"))))),
		kv("expected_impact", validation.VStr("1000 USDC loss")),
		kv("next_test", validation.VStr("run fork")))
	if got := todoPlaceholders(clean); len(got) != 0 {
		t.Fatalf("clean = %v", got)
	}
	cases := []struct {
		field string
		value string
		want  string
	}{
		{"bug_class", "TODO-bug-class", "bug_class"},
		{"claim", "todo: finish claim", "claim"},
		{"expected_impact", "todo: quantify", "expected_impact"},
	}
	for _, tc := range cases {
		got := todoPlaceholders(setKey(clean, tc.field, validation.VStr(tc.value)))
		if !inList(got, tc.want) {
			t.Fatalf("%s: got %v", tc.field, got)
		}
	}
}

func TestSFTTodoGuardBlocksCuration(t *testing.T) {
	useStore(t)
	camp := backfillCamp(t)
	f := ingestHyp(t, camp)
	draft, err := BackfillFinding(camp, objStr(f, "finding_id"))
	if err != nil {
		t.Fatal(err)
	}
	// taxonomy null + status curated is rejected by the schema (allOf)...
	_, err = AddExample(draft, "curated")
	if err == nil || !strings.Contains(err.Error(), "schema violation") {
		t.Fatalf("err = %v", err)
	}
	// ...and once taxonomy is set, the TODO guard rejects it via lint.
	draft = setKey(draft, "taxonomy", validation.VStr("confirmed-critical"))
	_, err = AddExample(draft, "curated")
	if err == nil || !strings.Contains(err.Error(), "lint failed") {
		t.Fatalf("err = %v", err)
	}
}
