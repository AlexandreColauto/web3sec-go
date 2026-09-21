package boundary

// Port of tests/test_model_boundary.py: a malformed model output is rejected
// at the boundary, logged as a rejected generation, and NEVER reaches
// findings.transition() — no coerced, coerced-then-partial, or belief-backed
// state change. Also covered: the role/kind matrix, tool-registry
// hallucination checks, evidence-citation checks, claim-version staleness,
// and the cheap memory.utility signal (re-raised / override-declared /
// not-matched).

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/learning"
	"websec/internal/roles"
	"websec/internal/sandbox"
	"websec/internal/sequencepoc"
	"websec/internal/state"
	"websec/internal/validation"
)

const snapID = "SNAP-0001"

func pin(t *testing.T, c *state.Campaign) {
	t.Helper()
	_, err := c.PinSnapshot(validation.VObj(
		kv("snapshot_id", validation.VStr(snapID)),
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("created_at", validation.VStr("2026-01-01T00:00:00Z")),
		kv("source", validation.VObj(
			kv("ladder", validation.VStr("artifact")),
			kv("content_hash", validation.VStr(strings.Repeat("a", 64)))))))
	if err != nil {
		t.Fatal(err)
	}
}

func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

func setKV(v validation.Value, k string, val validation.Value) validation.Value {
	out := validation.VObj()
	done := false
	for _, pair := range v.O {
		if pair.K == k {
			out.O = append(out.O, kv(k, val))
			done = true
			continue
		}
		out.O = append(out.O, pair)
	}
	if !done {
		out.O = append(out.O, kv(k, val))
	}
	return out
}

func delKV(v validation.Value, k string) validation.Value {
	out := validation.VObj()
	for _, pair := range v.O {
		if pair.K != k {
			out.O = append(out.O, pair)
		}
	}
	return out
}

// setPath sets obj[path0][idx][path1] = val (test-only nested edit).
func setPath(v validation.Value, path0 string, idx int, path1 string,
	val validation.Value) validation.Value {
	arr := validation.ObjAt(v, path0)
	items := append([]validation.Value(nil), arr.A...)
	items[idx] = setKV(items[idx], path1, val)
	return setKV(v, path0, validation.VArr(items...))
}

func validHypothesis() validation.Value {
	return validation.VObj(
		kv("bug_class", validation.VStr("oracle-manipulation")),
		kv("claim", validation.VStr("The vault prices redemptions against a "+
			"manipulable TWAP, allowing a flash loan to push the price and "+
			"redeem shares above NAV.")),
		kv("target", validation.VObj(
			kv("path", validation.VStr("src/Vault.sol")),
			kv("function", validation.VStr("redeem")))),
		kv("assumptions", validation.VArr(
			validation.VObj(
				kv("id", validation.VStr("A1")),
				kv("type", validation.VStr("reachability")),
				kv("claim", validation.VStr("the TWAP window is longer than "+
					"the flash-loan manipulation horizon, so the price push "+
					"holds")),
				kv("status", validation.VStr("UNKNOWN")),
				kv("model_belief", validation.VFloat(0.9)),
				kv("blocking", validation.VBool(true)),
				kv("verification_options", validation.VArr(
					validation.VStr("callgraph")))),
			validation.VObj(
				kv("id", validation.VStr("A2")),
				kv("type", validation.VStr("economic")),
				kv("claim", validation.VStr("the flash-loan round trip is "+
					"profitable at current TVL")),
				kv("status", validation.VStr("UNKNOWN")),
				kv("model_belief", validation.VFloat(0.6)),
				kv("blocking", validation.VBool(true)),
				kv("dependencies", validation.VArr(validation.VStr("A1"))),
				kv("verification_options", validation.VArr(
					validation.VStr("balance-delta")))))),
		kv("initial_plan", validation.VArr(
			validation.VObj(
				kv("step", validation.VInt(1)),
				kv("tool_id", validation.VStr("callgraph")),
				kv("target_assumptions", validation.VArr(
					validation.VStr("A1"))),
				kv("expected_observation", validation.VStr(
					"redeem() has no modifier and reads TWAP"))),
			validation.VObj(
				kv("step", validation.VInt(2)),
				kv("tool_id", validation.VStr("balance-delta")),
				kv("target_assumptions", validation.VArr(
					validation.VStr("A2"))),
				kv("expected_observation", validation.VStr(
					"delta exceeds the flash-loan premium"))))),
		kv("uncertainty", validation.VObj(
			kv("open_questions", validation.VArr(
				validation.VStr("current pool TVL"))))))
}

func validCriticVerdict(fid string) validation.Value {
	return validation.VObj(
		kv("finding_id", validation.VStr(fid)),
		kv("claim_version", validation.VInt(1)),
		kv("per_assumption", validation.VArr(
			validation.VObj(
				kv("assumption_id", validation.VStr("A1")),
				kv("status", validation.VStr("SUPPORTED")),
				kv("evidence_cited", validation.VArr(validation.VStr("EV-1"))),
				kv("note", validation.VStr(
					"callgraph confirms no modifier on redeem()"))),
			validation.VObj(
				kv("assumption_id", validation.VStr("A2")),
				kv("status", validation.VStr("REFUTED")),
				kv("evidence_cited", validation.VArr(validation.VStr("EV-1"))),
				kv("note", validation.VStr(
					"balance delta below the premium at current TVL"))))),
		kv("verdict", validation.VStr("disproved")),
		kv("missing_proof", validation.VArr()),
		kv("recommended_checks", validation.VArr(validation.VObj(
			kv("tool_id", validation.VStr("balance-delta")),
			kv("target_assumptions", validation.VArr(
				validation.VStr("A2")))))))
}

func validReproducerRequest(fid string) validation.Value {
	return validation.VObj(
		kv("finding_id", validation.VStr(fid)),
		kv("snapshot_id", validation.VStr(snapID)),
		kv("execution_profile", validation.VStr("fork-runner")),
		kv("success_criteria", validation.VObj(
			kv("exit_status", validation.VInt(0)),
			kv("min_evidence_level", validation.VStr("E5")),
			kv("requires_captured_output", validation.VBool(true)))),
		kv("program", validation.VStr("forge test --fork-url "+
			"http://127.0.0.1:8545 --fork-block-number 20000000 "+
			"--match-test test_exploit")),
		kv("notes", validation.VNull()))
}

// boundaryFloorSeq mints unique ids for the manual floor items the fixtures
// attach before a status whose evidence floor is above E0.
var boundaryFloorSeq int

// floorEvidence attaches a manual (non-exec) item at *level* — the evidence a
// status floor demands before the status stamp. It is the finding's first rise
// above E0, so it pays the discovery slot once; any later item at or below that
// level rides the same rise for free, keeping the campaign's slot spend
// unchanged.
func floorEvidence(t *testing.T, c *state.Campaign, fid, level string) {
	t.Helper()
	boundaryFloorSeq++
	if _, err := findings.AddEvidence(c, fid, validation.VObj(
		kv("evidence_id", validation.VStr(
			fmt.Sprintf("EV-boundary-floor-%04d", boundaryFloorSeq))),
		kv("level", validation.VStr(level)),
		kv("type", validation.VStr("manual")),
		kv("description", validation.VStr(
			"manual code reading at triage: the path to the sink is reachable")))); err != nil {
		t.Fatalf("add floor evidence %s: %v", level, err)
	}
}

func ev1(t *testing.T, c *state.Campaign, fid string) {
	t.Helper()
	if _, err := findings.AddEvidence(c, fid, validation.VObj(
		kv("evidence_id", validation.VStr("EV-1")),
		kv("level", validation.VStr("E1")),
		kv("type", validation.VStr("static-analysis")),
		kv("description", validation.VStr(
			"callgraph: redeem() has no access modifier")))); err != nil {
		t.Fatal(err)
	}
}

func rejectedEvents(t *testing.T, c *state.Campaign) []validation.Value {
	t.Helper()
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	out := []validation.Value{}
	for _, e := range events {
		if validation.ObjStr(e, "type") == "model.rejected" {
			out = append(out, e)
		}
	}
	return out
}

func eventTypes(t *testing.T, c *state.Campaign) []string {
	t.Helper()
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	out := []string{}
	for _, e := range events {
		out = append(out, validation.ObjStr(e, "type"))
	}
	return out
}

func newCamp(t *testing.T) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "Acme Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func mustIngest(t *testing.T, c *state.Campaign, raw validation.Value) validation.Value {
	t.Helper()
	f, err := IngestModelHypothesis(c, raw, HypothesisOpts{})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func assumptionStatus(t *testing.T, c *state.Campaign, fid, aid string) string {
	t.Helper()
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range validation.ObjAt(f, "assumptions").A {
		if validation.ObjStr(a, "id") == aid {
			return validation.ObjStr(a, "status")
		}
	}
	t.Fatalf("assumption %s not found", aid)
	return ""
}

// ---------------------------------------------------------------------------
// hypothesis ingest
// ---------------------------------------------------------------------------

func TestValidHypothesisIngests(t *testing.T) {
	c := newCamp(t)
	pin(t, c)
	f, err := IngestModelHypothesis(c, validHypothesis(), HypothesisOpts{
		Stage: strPtr("discovery-specialist"), Model: "qwen3-14b"})
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(f, "status"); got != "HYPOTHESIS" {
		t.Errorf("status = %s", got)
	}
	if got := validation.ObjStr(validation.ObjAt(f, "root_cause"), "class"); got != "oracle-manipulation" {
		t.Errorf("root_cause.class = %s", got)
	}
	ids := []string{}
	for _, a := range validation.ObjAt(f, "assumptions").A {
		ids = append(ids, validation.ObjStr(a, "id"))
		if got := validation.ObjStr(a, "status"); got != "UNKNOWN" {
			t.Errorf("assumption status = %s, want UNKNOWN", got)
		}
	}
	if len(ids) != 2 || ids[0] != "A1" || ids[1] != "A2" {
		t.Errorf("assumption ids = %v", ids)
	}
	if got := objInt(f, "claim_version"); got != 1 {
		t.Errorf("claim_version = %d", got)
	}
	types := eventTypes(t, c)
	if !slices.Contains(types, "finding.ingested") {
		t.Error("finding.ingested missing")
	}
	if !slices.Contains(types, "model.plan_received") {
		t.Error("model.plan_received missing")
	}
}

func TestMalformedHypothesisRejectedAndStateUntouched(t *testing.T) {
	c := newCamp(t)
	pin(t, c)
	bad := setKV(validHypothesis(), "bug_class", validation.VStr("Not-A-Class"))
	_, err := IngestModelHypothesis(c, bad, HypothesisOpts{})
	if err == nil || !strings.Contains(err.Error(), "contract failure") {
		t.Fatalf("err = %v, want contract failure", err)
	}
	all, err := findings.LoadAllFindings(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 0 {
		t.Errorf("findings = %d, want 0", len(all))
	}
	rej := rejectedEvents(t, c)
	if len(rej) != 1 {
		t.Fatalf("rejected events = %d, want 1", len(rej))
	}
	data := validation.ObjAt(rej[0], "data")
	if got := validation.ObjStr(data, "role"); got != "proposer" {
		t.Errorf("role = %s", got)
	}
	if got := validation.ObjStr(data, "kind"); got != "hypothesis" {
		t.Errorf("kind = %s", got)
	}
	if validation.ObjAt(data, "payload_sha256").Kind != validation.Str {
		t.Error("payload_sha256 missing")
	}
	if v, err := c.VerifyLog(); err != nil || !v.OK {
		t.Errorf("chain not ok: %v %v", v, err)
	}
}

func TestHypothesisWithUnknownToolRejected(t *testing.T) {
	c := newCamp(t)
	pin(t, c)
	h := setPath(validHypothesis(), "initial_plan", 0, "tool_id",
		validation.VStr("warp-speed"))
	_, err := IngestModelHypothesis(c, h, HypothesisOpts{})
	if err == nil || !strings.Contains(err.Error(), "registry") {
		t.Fatalf("err = %v, want registry", err)
	}
	all, _ := findings.LoadAllFindings(c)
	if len(all) != 0 {
		t.Errorf("findings = %d, want 0", len(all))
	}
}

func TestHypothesisWithNonUnknownAssumptionRejected(t *testing.T) {
	c := newCamp(t)
	pin(t, c)
	h := setPath(validHypothesis(), "assumptions", 0, "status",
		validation.VStr("SUPPORTED"))
	_, err := IngestModelHypothesis(c, h, HypothesisOpts{})
	if err == nil || !strings.Contains(err.Error(), "contract failure") {
		t.Fatalf("err = %v, want contract failure", err)
	}
	all, _ := findings.LoadAllFindings(c)
	if len(all) != 0 {
		t.Errorf("findings = %d, want 0", len(all))
	}
}

func TestHypothesisOverrideMustNameRealMemory(t *testing.T) {
	c := newCamp(t)
	pin(t, c)
	h := setKV(validHypothesis(), "differs_from_memory", validation.VArr(
		validation.VObj(
			kv("memory_id", validation.VStr("MEM-nonexistent")),
			kv("assumption_id", validation.VStr("A1")),
			kv("how_it_differs", validation.VStr(
				"this variant differs in the oracle window")))))
	_, err := IngestModelHypothesis(c, h, HypothesisOpts{})
	if err == nil || !strings.Contains(err.Error(), "unknown memory row") {
		t.Fatalf("err = %v, want unknown memory row", err)
	}
	all, _ := findings.LoadAllFindings(c)
	if len(all) != 0 {
		t.Errorf("findings = %d, want 0", len(all))
	}
}

func TestHypothesisWithExploitSequenceCarriesIntoFinding(t *testing.T) {
	c := newCamp(t)
	pin(t, c)
	seq := validation.VArr(
		validation.VObj(
			kv("step", validation.VInt(1)),
			kv("actor", validation.VStr("attacker")),
			kv("action", validation.VStr(
				"flash-borrow 1,000,000 USDC from the lending market")),
			kv("state_effect", validation.VStr(
				"attacker controls 1M USDC for one tx")),
			kv("calls", validation.VArr(validation.VStr("lender.flashLoan")))),
		validation.VObj(
			kv("step", validation.VInt(2)),
			kv("actor", validation.VStr("keeper")),
			kv("action", validation.VStr(
				"keeper-triggered redeem settles at the pushed TWAP price")),
			kv("state_effect", validation.VStr("shares redeemed above NAV")),
			kv("calls", validation.VArr(validation.VStr("vault.redeem")))))
	h := setKV(validHypothesis(), "exploit_sequence", seq)
	if err := ValidateResponse("proposer", "hypothesis", h, c); err != nil {
		t.Fatal(err)
	}
	f := mustIngest(t, c, h)
	if got := validation.CanonCompact(validation.ObjAt(f, "exploit_sequence")); got !=
		validation.CanonCompact(seq) {
		t.Errorf("exploit_sequence = %s", got)
	}
	if !sequencepoc.IsSequenceRequired(f) {
		t.Error("is_sequence_required = false, want true")
	}
}

func TestHypothesisWithoutExploitSequenceHasNoKey(t *testing.T) {
	c := newCamp(t)
	pin(t, c)
	f := mustIngest(t, c, validHypothesis())
	if validation.ObjAt(f, "exploit_sequence").Kind != validation.Null {
		t.Error("exploit_sequence present")
	}
}

// ---------------------------------------------------------------------------
// critic verdict
// ---------------------------------------------------------------------------

func criticSetup(t *testing.T, c *state.Campaign) string {
	t.Helper()
	pin(t, c)
	f := mustIngest(t, c, validHypothesis())
	fid := validation.ObjStr(f, "finding_id")
	ev1(t, c, fid)
	return fid
}

func TestCriticVerdictWithoutEvidenceRejected(t *testing.T) {
	c := newCamp(t)
	fid := criticSetup(t, c)
	v := setPath(validCriticVerdict(fid), "per_assumption", 0,
		"evidence_cited", validation.VArr())
	_, err := ApplyCriticVerdict(c, fid, v, "")
	if err == nil || !strings.Contains(err.Error(), "does not trust belief") {
		t.Fatalf("err = %v", err)
	}
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range validation.ObjAt(f, "assumptions").A {
		if validation.ObjStr(a, "status") != "UNKNOWN" {
			t.Errorf("assumption moved: %s", validation.ObjStr(a, "status"))
		}
	}
	if validation.ObjAt(validation.ObjAt(f, "verification"), "critic_verdict").Kind != validation.Null {
		t.Error("critic_verdict present")
	}
	if len(rejectedEvents(t, c)) != 1 {
		t.Errorf("rejected events = %d, want 1", len(rejectedEvents(t, c)))
	}
}

func TestCriticVerdictWithHallucinatedEvidenceRejected(t *testing.T) {
	c := newCamp(t)
	fid := criticSetup(t, c)
	v := setPath(validCriticVerdict(fid), "per_assumption", 0,
		"evidence_cited", validation.VArr(validation.VStr("EV-fabricated")))
	if _, err := ApplyCriticVerdict(c, fid, v, ""); err == nil {
		t.Fatal("want rejection")
	}
	if got := assumptionStatus(t, c, fid, "A1"); got != "UNKNOWN" {
		t.Errorf("A1 = %s", got)
	}
}

func TestCriticVerdictUnknownAssumptionRejected(t *testing.T) {
	c := newCamp(t)
	fid := criticSetup(t, c)
	v := setPath(validCriticVerdict(fid), "per_assumption", 1,
		"assumption_id", validation.VStr("A99"))
	_, err := ApplyCriticVerdict(c, fid, v, "")
	if err == nil || !strings.Contains(err.Error(), "A99") {
		t.Fatalf("err = %v", err)
	}
	if got := assumptionStatus(t, c, fid, "A2"); got != "UNKNOWN" {
		t.Errorf("A2 = %s", got)
	}
}

func TestCriticVerdictIllegalMoveRejected(t *testing.T) {
	c := newCamp(t)
	fid := criticSetup(t, c)
	legal := validation.VObj(
		kv("finding_id", validation.VStr(fid)),
		kv("claim_version", validation.VInt(1)),
		kv("per_assumption", validation.VArr(validation.VObj(
			kv("assumption_id", validation.VStr("A2")),
			kv("status", validation.VStr("REFUTED")),
			kv("evidence_cited", validation.VArr(validation.VStr("EV-1"))),
			kv("note", validation.VStr("not profitable here"))))),
		kv("verdict", validation.VStr("possible")),
		kv("missing_proof", validation.VArr(
			validation.VStr("A1: reachability"))))
	if _, err := ApplyCriticVerdict(c, fid, legal, ""); err != nil {
		t.Fatal(err)
	}
	if got := assumptionStatus(t, c, fid, "A2"); got != "REFUTED" {
		t.Fatalf("A2 = %s, want REFUTED", got)
	}
	illegal := validation.VObj(
		kv("finding_id", validation.VStr(fid)),
		kv("claim_version", validation.VInt(1)),
		kv("per_assumption", validation.VArr(validation.VObj(
			kv("assumption_id", validation.VStr("A2")),
			kv("status", validation.VStr("UNKNOWN")),
			kv("evidence_cited", validation.VArr()),
			kv("note", validation.VStr("unknown again"))))),
		kv("verdict", validation.VStr("possible")),
		kv("missing_proof", validation.VArr()))
	_, err := ApplyCriticVerdict(c, fid, illegal, "")
	if err == nil || !strings.Contains(err.Error(), "not a legal assumption move") {
		t.Fatalf("err = %v", err)
	}
	if got := assumptionStatus(t, c, fid, "A2"); got != "REFUTED" {
		t.Errorf("A2 = %s, want REFUTED", got)
	}
}

func TestCriticVerdictStaleClaimVersionRejected(t *testing.T) {
	c := newCamp(t)
	fid := criticSetup(t, c)
	v := setKV(validCriticVerdict(fid), "claim_version", validation.VInt(2))
	_, err := ApplyCriticVerdict(c, fid, v, "")
	if err == nil || !strings.Contains(err.Error(), "stale critic verdict") {
		t.Fatalf("err = %v", err)
	}
	if len(rejectedEvents(t, c)) != 1 {
		t.Errorf("rejected = %d", len(rejectedEvents(t, c)))
	}
}

func TestValidCriticVerdictApplies(t *testing.T) {
	c := newCamp(t)
	fid := criticSetup(t, c)
	f, err := ApplyCriticVerdict(c, fid, validCriticVerdict(fid), "")
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]validation.Value{}
	for _, a := range validation.ObjAt(f, "assumptions").A {
		byID[validation.ObjStr(a, "id")] = a
	}
	if got := validation.ObjStr(byID["A1"], "status"); got != "SUPPORTED" {
		t.Errorf("A1 = %s", got)
	}
	if got := validation.ObjStr(byID["A2"], "status"); got != "REFUTED" {
		t.Errorf("A2 = %s", got)
	}
	if got := validation.CanonCompact(validation.ObjAt(byID["A1"], "support")); got !=
		`["EV-1"]` {
		t.Errorf("A1 support = %s", got)
	}
	if got := validation.CanonCompact(validation.ObjAt(byID["A2"], "contradictions")); got !=
		`["EV-1"]` {
		t.Errorf("A2 contradictions = %s", got)
	}
	if got := validation.ObjStr(validation.ObjAt(f, "verification"), "critic_verdict"); got != "disproved" {
		t.Errorf("critic_verdict = %s", got)
	}
	if len(rejectedEvents(t, c)) != 0 {
		t.Error("unexpected rejection events")
	}
}

// ---------------------------------------------------------------------------
// plan / reproducer / role matrix
// ---------------------------------------------------------------------------

func TestPlanUnknownFindingRejected(t *testing.T) {
	c := newCamp(t)
	pin(t, c)
	plan := validation.VObj(
		kv("finding_id", validation.VStr("F-000000000000")),
		kv("steps", validation.VArr(validation.VObj(
			kv("step", validation.VInt(1)),
			kv("tool_id", validation.VStr("callgraph")),
			kv("expected_observation", validation.VStr(
				"the call graph is empty"))))))
	err := ValidateResponse("proposer", "plan", plan, c)
	if err == nil || !strings.Contains(err.Error(), "unknown finding") {
		t.Fatalf("err = %v", err)
	}
}

func TestRoleKindMatrixEnforced(t *testing.T) {
	c := newCamp(t)
	pin(t, c)
	err := ValidateResponse("critic", "hypothesis", validHypothesis(), nil)
	if err == nil || !strings.Contains(err.Error(), "may not emit") {
		t.Errorf("critic/hypothesis err = %v", err)
	}
	err = ValidateResponse("proposer", "critic_verdict",
		validCriticVerdict("F-000000000000"), nil)
	if err == nil || !strings.Contains(err.Error(), "may not emit") {
		t.Errorf("proposer/critic_verdict err = %v", err)
	}
	err = ValidateResponse("oracle", "plan", validation.VObj(), nil)
	if err == nil || !strings.Contains(err.Error(), "unknown role") {
		t.Errorf("oracle err = %v", err)
	}
}

func reproSetup(t *testing.T, c *state.Campaign) string {
	t.Helper()
	pin(t, c)
	f := mustIngest(t, c, validHypothesis())
	fid := validation.ObjStr(f, "finding_id")
	// R3-3: POSSIBLE carries an E2 floor, so the shared advance helper earns
	// it BEFORE the status stamp (evidence floors gate every status).
	floorEvidence(t, c, fid, "E2")
	if _, err := findings.Transition(c, fid, "POSSIBLE", "triage", "", "", false); err != nil {
		t.Fatal(err)
	}
	return fid
}

func TestReproducerRequestPinDriftRejected(t *testing.T) {
	c := newCamp(t)
	fid := reproSetup(t, c)
	r := setKV(validReproducerRequest(fid), "snapshot_id",
		validation.VStr("SNAP-9999"))
	_, err := SubmitReproducerRequest(c, r)
	if err == nil || !strings.Contains(err.Error(), "drift") {
		t.Fatalf("err = %v", err)
	}
	rej := rejectedEvents(t, c)
	if len(rej) == 0 {
		t.Fatal("no rejection event")
	}
	last := validation.ObjAt(rej[len(rej)-1], "data")
	if got := validation.ObjStr(last, "kind"); got != "reproducer_request" {
		t.Errorf("kind = %s", got)
	}
	if got := validation.ObjStr(last, "role"); got != "reproducer" {
		t.Errorf("role = %s", got)
	}
}

func TestReproducerRequestValidAccepted(t *testing.T) {
	c := newCamp(t)
	fid := reproSetup(t, c)
	out, err := SubmitReproducerRequest(c, validReproducerRequest(fid))
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(out, "execution_profile"); got != "fork-runner" {
		t.Errorf("execution_profile = %s", got)
	}
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(events[len(events)-1], "type"); got != "model.reproducer_request" {
		t.Errorf("last event = %s", got)
	}
}

func TestReproducerRequestUnknownProfileRejected(t *testing.T) {
	c := newCamp(t)
	fid := reproSetup(t, c)
	r := setKV(validReproducerRequest(fid), "execution_profile",
		validation.VStr("bare-metal"))
	if _, err := SubmitReproducerRequest(c, r); err == nil {
		t.Fatal("want rejection")
	}
	rej := rejectedEvents(t, c)
	last := validation.ObjAt(rej[len(rej)-1], "data")
	if got := validation.ObjStr(last, "kind"); got != "reproducer_request" {
		t.Errorf("kind = %s", got)
	}
}

// TestReproducerRequestProfileRegistryParity pins boundary-layer acceptance
// against sandbox.Profiles itself — the single source of truth. The L3 advice
// wave grew the registry from five names to eight (the host toolchains
// halmos, forge-fuzz and minicertora), so a fixture pinned to one profile
// (TestReproducerRequestValidAccepted) no longer proves the others are
// admissible. Acceptance rows mirror that test; the final row mirrors
// TestReproducerRequestUnknownProfileRejected with the literal name 'bogus'.
func TestReproducerRequestProfileRegistryParity(t *testing.T) {
	for _, profile := range sandbox.Profiles {
		profile := profile
		t.Run(profile, func(t *testing.T) {
			c := newCamp(t)
			fid := reproSetup(t, c)
			out, err := SubmitReproducerRequest(c, setKV(
				validReproducerRequest(fid), "execution_profile",
				validation.VStr(profile)))
			if err != nil {
				t.Fatalf("execution_profile %s rejected: %v", profile, err)
			}
			if got := validation.ObjStr(out, "execution_profile"); got != profile {
				t.Errorf("execution_profile = %s, want %s", got, profile)
			}
		})
	}
	t.Run("bogus", func(t *testing.T) {
		c := newCamp(t)
		fid := reproSetup(t, c)
		r := setKV(validReproducerRequest(fid), "execution_profile",
			validation.VStr("bogus"))
		if _, err := SubmitReproducerRequest(c, r); err == nil {
			t.Fatal("want rejection for execution_profile bogus")
		}
		if slices.Contains(sandbox.Profiles, "bogus") {
			t.Fatal("sandbox.Profiles must not contain bogus")
		}
	})
}

// ---------------------------------------------------------------------------
// request records
// ---------------------------------------------------------------------------

func TestRequestRecordValidation(t *testing.T) {
	c := newCamp(t)
	pin(t, c)
	dir := t.TempDir()
	src := filepath.Join(dir, "init.py")
	if err := os.WriteFile(src, []byte("x = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pv, err := PromptVersion(src)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(pv) {
		t.Errorf("prompt_version = %s", pv)
	}
	req := validation.VObj(
		kv("role", validation.VStr("proposer")),
		kv("model_id", validation.VStr("qwen3-14b")),
		kv("prompt_version", validation.VStr(pv)),
		kv("context_hash", validation.VStr(strings.Repeat("0", 64))),
		kv("response_schema", validation.VStr("hypothesis")),
		// v1.6 Part 1: the record must carry its declared input artifact set.
		kv("input_artifacts", declaration("ART-aaaa1111")))
	if err := ValidateRequest(req); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	bad := setKV(req, "context_hash", validation.VStr("not-a-hash"))
	if err := ValidateRequest(bad); err == nil {
		t.Fatal("bad request accepted")
	}
}

// ---------------------------------------------------------------------------
// the negative-memory utility signal
// ---------------------------------------------------------------------------

func utilityFixture(t *testing.T, c *state.Campaign) string {
	t.Helper()
	pin(t, c)
	bc := "oracle-manipulation"
	mem, err := learning.QueueMemory(c, learning.QueueOpts{
		Kind:   "disproved",
		Status: "DISPROVED",
		Pattern: "TWAP oracle manipulation via flash loan on the " +
			"redemption path",
		BugClass: &bc,
		DecidingPropositions: []validation.Value{validation.VObj(
			kv("type", validation.VStr("temporal")),
			kv("statement", validation.VStr("the TWAP window is shorter than "+
				"the flash-loan manipulation horizon, so the pushed price "+
				"reverts before redemption settles")))}})
	if err != nil {
		t.Fatal(err)
	}
	return validation.ObjStr(mem, "memory_id")
}

func utilityEvent(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	for i := len(events) - 1; i >= 0; i-- {
		if validation.ObjStr(events[i], "type") == "memory.utility" {
			return validation.ObjAt(events[i], "data")
		}
	}
	t.Fatal("no memory.utility event")
	return validation.VNull()
}

func strList(v validation.Value) []string {
	out := []string{}
	if v.Kind == validation.Arr {
		for _, x := range v.A {
			out = append(out, scalarText(x))
		}
	}
	return out
}

func TestUtilityReRaisedWhenHypothesisMatchesPrior(t *testing.T) {
	c := newCamp(t)
	mid := utilityFixture(t, c)
	bc := "oracle-manipulation"
	bundle, err := roles.BuildProposerContext(c, &bc)
	if err != nil {
		t.Fatal(err)
	}
	priors := validation.ObjAt(validation.ObjAt(bundle, "negative_memory"), "known_non_issues")
	if len(priors.A) == 0 {
		t.Fatal("no prior surfaced")
	}
	prior := priors.A[0]
	if got := validation.ObjStr(prior, "memory_id"); got != mid {
		t.Errorf("memory_id = %s, want %s", got, mid)
	}
	if got := validation.ObjStr(prior, "rejection_class"); got != "invalid-hypothesis" {
		t.Errorf("rejection_class = %s", got)
	}
	if got := validation.ObjStr(validation.ObjAt(prior, "deciding_propositions").A[0], "type"); got != "temporal" {
		t.Errorf("proposition type = %s", got)
	}
	if got := validation.ObjAt(prior, "pin_diverged"); got.Kind != validation.Bool || got.B {
		t.Errorf("pin_diverged = %v", got)
	}
	mustIngest(t, c, validHypothesis())
	data := utilityEvent(t, c)
	if got := strList(validation.ObjAt(data, "re_raised")); len(got) != 1 || got[0] != mid {
		t.Errorf("re_raised = %v", got)
	}
	if got := strList(validation.ObjAt(data, "override_declared")); len(got) != 0 {
		t.Errorf("override_declared = %v", got)
	}
}

func TestUtilityOverrideDeclared(t *testing.T) {
	c := newCamp(t)
	mid := utilityFixture(t, c)
	h := setKV(validHypothesis(), "differs_from_memory", validation.VArr(
		validation.VObj(
			kv("memory_id", validation.VStr(mid)),
			kv("assumption_id", validation.VStr("A1")),
			kv("how_it_differs", validation.VStr("here the TWAP window is a "+
				"rolling 30 minutes and the redemption settles within it, "+
				"unlike the prior's sub-block window")))))
	mustIngest(t, c, h)
	data := utilityEvent(t, c)
	if got := strList(validation.ObjAt(data, "override_declared")); len(got) != 1 || got[0] != mid {
		t.Errorf("override_declared = %v", got)
	}
	if got := strList(validation.ObjAt(data, "re_raised")); len(got) != 0 {
		t.Errorf("re_raised = %v", got)
	}
}

func TestUtilityNotMatchedForDifferentHypothesis(t *testing.T) {
	c := newCamp(t)
	mid := utilityFixture(t, c)
	h := setKV(validHypothesis(), "bug_class", validation.VStr("access-control"))
	h = setKV(h, "assumptions", validation.VArr(validation.VObj(
		kv("id", validation.VStr("A1")),
		kv("type", validation.VStr("authority")),
		kv("claim", validation.VStr("the admin key can mint tokens with no "+
			"timelock delay")),
		kv("status", validation.VStr("UNKNOWN")),
		kv("model_belief", validation.VFloat(0.5)),
		kv("blocking", validation.VBool(true)),
		kv("verification_options", validation.VArr(
			validation.VStr("callgraph"))))))
	h = setKV(h, "initial_plan", validation.VArr(validation.VObj(
		kv("step", validation.VInt(1)),
		kv("tool_id", validation.VStr("callgraph")),
		kv("target_assumptions", validation.VArr(validation.VStr("A1"))),
		kv("expected_observation", validation.VStr(
			"mint() has only an admin modifier")))))
	mustIngest(t, c, h)
	data := utilityEvent(t, c)
	if got := strList(validation.ObjAt(data, "not_matched")); len(got) != 1 || got[0] != mid {
		t.Errorf("not_matched = %v", got)
	}
	if got := strList(validation.ObjAt(data, "re_raised")); len(got) != 0 {
		t.Errorf("re_raised = %v", got)
	}
}

func TestUtilityV1RowFallsBackToClassMatch(t *testing.T) {
	c := newCamp(t)
	pin(t, c)
	bc := "oracle-manipulation"
	v1, err := learning.QueueMemory(c, learning.QueueOpts{
		Kind:     "disproved",
		Status:   "DISPROVED",
		Pattern:  "TWAP oracle manipulation via flash loan",
		BugClass: &bc})
	if err != nil {
		t.Fatal(err)
	}
	mid := validation.ObjStr(v1, "memory_id")
	p := filepath.Join(c.MemoryDir, mid+".json")
	raw, err := validation.ReadJson(p)
	if err != nil {
		t.Fatal(err)
	}
	raw = delKV(delKV(raw, "schema_version"), "rejection_class")
	text := validation.CanonCompact(raw)
	if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	mustIngest(t, c, validHypothesis())
	data := utilityEvent(t, c)
	if got := strList(validation.ObjAt(data, "re_raised")); !slices.Contains(got, mid) {
		t.Errorf("re_raised = %v, want %s", got, mid)
	}
	bundle, err := roles.BuildProposerContext(c, &bc)
	if err != nil {
		t.Fatal(err)
	}
	prior := validation.ObjAt(validation.ObjAt(bundle, "negative_memory"), "known_non_issues").A[0]
	if got := objInt(prior, "schema_version"); got != 1 {
		t.Errorf("schema_version = %d, want 1", got)
	}
	if got := validation.ObjAt(prior, "deciding_propositions"); got.Kind != validation.Arr ||
		len(got.A) != 0 {
		t.Errorf("deciding_propositions = %v", got)
	}
}

// objInt is a test-local int accessor (the package's objStr covers strings).
func objInt(v validation.Value, key string) int64 {
	if x := validation.ObjAt(v, key); x.Kind == validation.Int {
		return x.I
	}
	return 0
}
