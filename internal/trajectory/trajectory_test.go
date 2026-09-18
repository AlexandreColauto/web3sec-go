package trajectory

// Port of tests/test_trajectory.py and the trajectory-owned half of
// tests/test_outcome_events.py: the model trajectory is a typed, checkable
// family. record_model_event refuses non-conforming payloads BEFORE logging;
// verify_trajectory flags hand-written or drifted model.* events (missing
// version stamps, dangling finding refs) even though the hash chain itself
// still verifies — and it reports, never raises.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"websec/internal/boundary"
	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

const snapID = "SNAP-0001"
const caseID = "CASE-0123456789abcdef"

func pin(t *testing.T, c *state.Campaign) {
	t.Helper()
	if _, err := c.PinSnapshot(validation.VObj(
		kv("snapshot_id", validation.VStr(snapID)),
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("created_at", validation.VStr("2026-01-01T00:00:00Z")),
		kv("source", validation.VObj(
			kv("ladder", validation.VStr("artifact")),
			kv("content_hash", validation.VStr(strings.Repeat("a", 64))))))); err != nil {
		t.Fatal(err)
	}
}

func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

func newCamp(t *testing.T) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "Acme Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	return c
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

func validRequest() validation.Value {
	return validation.VObj(
		kv("role", validation.VStr("proposer")),
		kv("model_id", validation.VStr("qwen3-14b")),
		kv("prompt_version", validation.VStr("0123456789abcdef")),
		kv("response_schema", validation.VStr("hypothesis")),
		kv("context_hash", validation.VStr(strings.Repeat("0", 64))))
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
		kv("missing_proof", validation.VArr()))
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

// fullRoundtrip is request record + hypothesis ingest + evidence + critic
// verdict + reproducer request — the fixture the brief's verify test names.
func fullRoundtrip(t *testing.T, c *state.Campaign) string {
	t.Helper()
	pin(t, c)
	f, err := boundary.IngestModelHypothesis(c, validHypothesis(),
		boundary.HypothesisOpts{Request: validRequest()})
	if err != nil {
		t.Fatal(err)
	}
	fid := validation.ObjStr(f, "finding_id")
	ev1(t, c, fid)
	if _, err := boundary.ApplyCriticVerdict(c, fid, validCriticVerdict(fid),
		""); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.Transition(c, fid, "POSSIBLE", "triage", "", "", false); err != nil {
		t.Fatal(err)
	}
	if _, err := boundary.SubmitReproducerRequest(c,
		validReproducerRequest(fid)); err != nil {
		t.Fatal(err)
	}
	return fid
}

func trajTypes(t *testing.T, c *state.Campaign) []string {
	t.Helper()
	traj, err := ModelTrajectory(c)
	if err != nil {
		t.Fatal(err)
	}
	out := []string{}
	for _, e := range traj {
		out = append(out, validation.ObjStr(e, "type"))
	}
	return out
}

// ---------------------------------------------------------------------------
// record_model_event: round trip + rejections
// ---------------------------------------------------------------------------

func TestRecordModelEventRoundtrip(t *testing.T) {
	c := newCamp(t)
	pin(t, c)
	f, err := boundary.IngestModelHypothesis(c, validHypothesis(),
		boundary.HypothesisOpts{Request: validRequest()})
	if err != nil {
		t.Fatal(err)
	}
	fid := validation.ObjStr(f, "finding_id")
	resp := validation.VObj(
		kv("role", validation.VStr("proposer")),
		kv("response_schema", validation.VStr("hypothesis")),
		kv("payload_sha256", validation.VStr(strings.Repeat("b", 64))),
		kv("applied_ref", validation.VStr(fid)),
		kv("finding_id", validation.VStr(fid)))
	ev, err := RecordModelEvent(c, "model.response", resp, &fid)
	if err != nil {
		t.Fatal(err)
	}
	traj, err := ModelTrajectory(c)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"model.request", "model.plan_received", "model.response"}
	if got := trajTypes(t, c); !eqStrings(got, want) {
		t.Fatalf("types = %v, want %v", got, want)
	}
	req, plan, rsp := traj[0], traj[1], traj[2]
	if validation.ObjStr(req, "role") != "proposer" || validation.ObjAt(req, "ref").Kind != validation.Null {
		t.Errorf("req role/ref = %v", req)
	}
	rd := validation.ObjAt(req, "data")
	if got := validation.ObjStr(rd, "prompt_version"); got != "0123456789abcdef" {
		t.Errorf("prompt_version = %s", got)
	}
	if got := validation.ObjStr(rd, "context_hash"); got != strings.Repeat("0", 64) {
		t.Errorf("context_hash = %s", got)
	}
	if validation.ObjAt(plan, "role").Kind != validation.Null {
		t.Error("plan role should be null")
	}
	if got := validation.ObjStr(plan, "ref"); got != fid {
		t.Errorf("plan ref = %s", got)
	}
	if got := validation.ObjAt(plan, "data"); !objEq(got, jsonV(`{"steps":2,"tools":["balance-delta","callgraph"]}`)) {
		t.Errorf("plan data = %s", validation.CanonCompact(got))
	}
	if validation.ObjStr(rsp, "role") != "proposer" || validation.ObjStr(rsp, "ref") != fid {
		t.Error("response role/ref wrong")
	}
	if got := validation.ObjStr(validation.ObjAt(rsp, "data"), "applied_ref"); got != fid {
		t.Errorf("applied_ref = %s", got)
	}
	if validation.ObjStr(rsp, "event_hash") != validation.ObjStr(ev, "event_hash") {
		t.Error("event_hash mismatch")
	}
	seqs := []int64{}
	for _, e := range traj {
		seqs = append(seqs, objInt(e, "seq"))
	}
	for i := 1; i < len(seqs); i++ {
		if seqs[i] < seqs[i-1] {
			t.Errorf("seq out of order: %v", seqs)
		}
	}
	if v, err := c.VerifyLog(); err != nil || !v.OK {
		t.Errorf("chain not ok: %v %v", v, err)
	}
}

func TestRecordModelEventMissingContextHashLogsNothing(t *testing.T) {
	c := newCamp(t)
	pin(t, c)
	bad := delKV(validRequest(), "context_hash")
	before, err := c.NextSeq()
	if err != nil {
		t.Fatal(err)
	}
	_, err = RecordModelEvent(c, "model.request", bad, nil)
	if err == nil || !strings.Contains(err.Error(), "contract failure") {
		t.Fatalf("err = %v", err)
	}
	after, _ := c.NextSeq()
	if after != before {
		t.Errorf("next_seq moved: %d -> %d", before, after)
	}
	traj, _ := ModelTrajectory(c)
	if len(traj) != 0 {
		t.Errorf("trajectory = %v", traj)
	}
}

func TestRecordModelEventUnknownTypeRaises(t *testing.T) {
	c := newCamp(t)
	if _, err := RecordModelEvent(c, "model.requestx", validation.VObj(
		kv("role", validation.VStr("proposer"))), nil); err == nil ||
		!strings.Contains(err.Error(), "unknown model event type") {
		t.Errorf("err = %v", err)
	}
	if _, err := RecordModelEvent(c, "finding.ingested", validation.VObj(),
		nil); err == nil || !strings.Contains(err.Error(), "unknown model event type") {
		t.Errorf("err = %v", err)
	}
}

func TestRecordModelEventRejectsNonObjectData(t *testing.T) {
	c := newCamp(t)
	_, err := RecordModelEvent(c, "model.request", validation.VArr(
		validation.VStr("not"), validation.VStr("an"),
		validation.VStr("object")), nil)
	if err == nil || !strings.Contains(err.Error(), "JSON object") {
		t.Fatalf("err = %v", err)
	}
}

func TestRecordModelEventRequestSuccessPath(t *testing.T) {
	c := newCamp(t)
	pin(t, c)
	data := validRequest()
	ev, err := RecordModelEvent(c, "model.request", data, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(ev, "type"); got != "model.request" {
		t.Errorf("type = %s", got)
	}
	if got := validation.ObjAt(ev, "data"); !objEq(got, data) {
		t.Errorf("data = %s", validation.CanonCompact(got))
	}
	traj, _ := ModelTrajectory(c)
	if len(traj) != 1 || validation.ObjStr(traj[0], "type") != "model.request" {
		t.Fatalf("trajectory = %v", traj)
	}
	if got := validation.ObjStr(traj[0], "role"); got != "proposer" {
		t.Errorf("role = %s", got)
	}
	if got := validation.ObjAt(traj[0], "data"); !objEq(got, data) {
		t.Errorf("data = %s", validation.CanonCompact(got))
	}
}

// ---------------------------------------------------------------------------
// verify_trajectory: clean fixture, drift, dangling refs, torn log
// ---------------------------------------------------------------------------

func TestVerifyTrajectoryOkOnBoundaryRoundtrip(t *testing.T) {
	c := newCamp(t)
	fid := fullRoundtrip(t, c)
	report, err := VerifyTrajectory(c)
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjAt(report, "ok").Kind != validation.Bool || !validation.ObjAt(report, "ok").B {
		t.Errorf("ok = %v", validation.ObjAt(report, "ok"))
	}
	if problems := validation.ObjAt(report, "problems"); problems.Kind != validation.Arr ||
		len(problems.A) != 0 {
		t.Errorf("problems = %v", problems)
	}
	if got := objInt(report, "events"); got != 3 {
		t.Errorf("events = %d, want 3", got)
	}
	want := []string{"model.request", "model.plan_received",
		"model.reproducer_request"}
	if got := trajTypes(t, c); !eqStrings(got, want) {
		t.Errorf("types = %v, want %v", got, want)
	}
	traj, _ := ModelTrajectory(c)
	last := traj[len(traj)-1]
	if got := validation.ObjStr(last, "ref"); got != fid {
		t.Errorf("last ref = %s", got)
	}
	if got := validation.ObjStr(validation.ObjAt(last, "data"), "request_sha256"); !regexp.MustCompile(
		`^[0-9a-f]{64}$`).MatchString(got) {
		t.Errorf("request_sha256 = %s", got)
	}
}

func TestHandWrittenMalformedEventFlagged(t *testing.T) {
	c := newCamp(t)
	pin(t, c)
	if _, err := boundary.IngestModelHypothesis(c, validHypothesis(),
		boundary.HypothesisOpts{}); err != nil {
		t.Fatal(err)
	}
	// hand-written: chains fine, but skipped the context_hash stamp
	hand := validation.VObj(
		kv("role", validation.VStr("proposer")),
		kv("model_id", validation.VStr("qwen3-14b")),
		kv("prompt_version", validation.VStr("0123456789abcdef")),
		kv("response_schema", validation.VStr("hypothesis")))
	if _, err := c.Log("model.request", nil, &hand); err != nil {
		t.Fatal(err)
	}
	if v, _ := c.VerifyLog(); !v.OK {
		t.Fatal("chain should verify")
	}
	report, err := VerifyTrajectory(c)
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjAt(report, "ok").B {
		t.Error("ok = true, want false")
	}
	problems := validation.ObjAt(report, "problems")
	if len(problems.A) == 0 {
		t.Error("no problems reported")
	}
	found := false
	for _, p := range problems.A {
		if strings.Contains(scalarText(p), "context_hash") {
			found = true
		}
	}
	if !found {
		t.Errorf("no context_hash problem in %v", problems)
	}
}

func TestDanglingRefFlagged(t *testing.T) {
	c := newCamp(t)
	pin(t, c)
	bad := "F-000000000000"
	if _, err := RecordModelEvent(c, "model.rejected", validation.VObj(
		kv("role", validation.VStr("proposer")),
		kv("kind", validation.VStr("hypothesis")),
		kv("error", validation.VStr("hypothesis contract failure at <root>: "+
			"assumptions missing")),
		kv("payload_sha256", validation.VStr(strings.Repeat("c", 64)))),
		&bad); err != nil {
		t.Fatal(err)
	}
	report, err := VerifyTrajectory(c)
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjAt(report, "ok").B {
		t.Error("ok = true, want false")
	}
	found := false
	for _, p := range validation.ObjAt(report, "problems").A {
		if strings.Contains(scalarText(p), "F-000000000000") {
			found = true
		}
	}
	if !found {
		t.Errorf("no dangling-ref problem in %v", validation.ObjAt(report, "problems"))
	}
}

func TestDanglingDataFindingIDFlagged(t *testing.T) {
	c := newCamp(t)
	pin(t, c)
	bad := "F-000000000000"
	if _, err := RecordModelEvent(c, "model.response", validation.VObj(
		kv("role", validation.VStr("proposer")),
		kv("response_schema", validation.VStr("hypothesis")),
		kv("payload_sha256", validation.VStr(strings.Repeat("b", 64))),
		kv("applied_ref", validation.VStr(bad)),
		kv("finding_id", validation.VStr(bad))), nil); err != nil {
		t.Fatal(err)
	}
	report, err := VerifyTrajectory(c)
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjAt(report, "ok").B {
		t.Error("ok = true, want false")
	}
	found := false
	for _, p := range validation.ObjAt(report, "problems").A {
		s := scalarText(p)
		if strings.Contains(s, "data.finding_id") && strings.Contains(s, bad) {
			found = true
		}
	}
	if !found {
		t.Errorf("no data.finding_id problem in %v", validation.ObjAt(report, "problems"))
	}
}

func TestVerifyTrajectorySurvivesTornLog(t *testing.T) {
	c := newCamp(t)
	pin(t, c)
	if _, err := boundary.IngestModelHypothesis(c, validHypothesis(),
		boundary.HypothesisOpts{}); err != nil {
		t.Fatal(err)
	}
	fh, err := os.OpenFile(c.EventsPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fh.WriteString("{torn line\n"); err != nil {
		t.Fatal(err)
	}
	fh.Close()
	report, err := VerifyTrajectory(c)
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjAt(report, "ok").B {
		t.Error("ok = true, want false")
	}
	if len(validation.ObjAt(report, "problems").A) == 0 {
		t.Error("no problems")
	}
	if got := objInt(report, "events"); got != 0 {
		t.Errorf("events = %d, want 0", got)
	}
}

func TestVerifyTrajectoryReportsCorruptFindingJSON(t *testing.T) {
	c := newCamp(t)
	pin(t, c)
	f, err := boundary.IngestModelHypothesis(c, validHypothesis(),
		boundary.HypothesisOpts{Request: validRequest()})
	if err != nil {
		t.Fatal(err)
	}
	fid := validation.ObjStr(f, "finding_id")
	ev1(t, c, fid)
	if _, err := RecordModelEvent(c, "model.response", validation.VObj(
		kv("role", validation.VStr("proposer")),
		kv("response_schema", validation.VStr("hypothesis")),
		kv("payload_sha256", validation.VStr(strings.Repeat("b", 64))),
		kv("applied_ref", validation.VStr(fid)),
		kv("finding_id", validation.VStr(fid))), &fid); err != nil {
		t.Fatal(err)
	}
	// Corrupt the finding file on disk AFTER every event is logged.
	p := filepath.Join(c.FindingsDir, fid+".json")
	if err := os.WriteFile(p, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if v, _ := c.VerifyLog(); !v.OK {
		t.Fatal("chain should verify")
	}
	report, err := VerifyTrajectory(c)
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjAt(report, "ok").B {
		t.Error("ok = true, want false")
	}
	found := false
	for _, p := range validation.ObjAt(report, "problems").A {
		s := scalarText(p)
		if strings.Contains(s, fid) && strings.Contains(s, "not readable JSON") {
			found = true
		}
	}
	if !found {
		t.Errorf("no corrupt-finding problem in %v", validation.ObjAt(report, "problems"))
	}
}

// ---------------------------------------------------------------------------
// model_trajectory projection
// ---------------------------------------------------------------------------

func TestModelTrajectoryExcludesNonModelEvents(t *testing.T) {
	c := newCamp(t)
	fullRoundtrip(t, c)
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	allTypes := []string{}
	for _, e := range events {
		allTypes = append(allTypes, validation.ObjStr(e, "type"))
	}
	if !containsStr(allTypes, "finding.ingested") ||
		!containsStr(allTypes, "snapshot.pinned") {
		t.Fatalf("fixture events = %v", allTypes)
	}
	trajTypes := trajTypes(t, c)
	if containsStr(trajTypes, "finding.ingested") ||
		containsStr(trajTypes, "snapshot.pinned") {
		t.Errorf("trajectory leaked non-model events: %v", trajTypes)
	}
	for _, ty := range trajTypes {
		if !containsStr(ModelEventTypeNames(), ty) {
			t.Errorf("unknown trajectory type %s", ty)
		}
	}
}

func TestModelTrajectoryOnEmptyCampaign(t *testing.T) {
	c := newCamp(t)
	traj, err := ModelTrajectory(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(traj) != 0 {
		t.Errorf("trajectory = %v", traj)
	}
	report, err := VerifyTrajectory(c)
	if err != nil {
		t.Fatal(err)
	}
	if !validation.ObjAt(report, "ok").B {
		t.Error("ok = false")
	}
	if got := objInt(report, "events"); got != 0 {
		t.Errorf("events = %d", got)
	}
}

// ---------------------------------------------------------------------------
// schema sync: the trajectory family vs the boundary's own schemas
// ---------------------------------------------------------------------------

func TestModelRequestDefinitionMatchesBoundarySchema(t *testing.T) {
	trajRaw, err := os.ReadFile(filepath.Join(schemaDir(), "trajectory.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	boundaryRaw, err := os.ReadFile(filepath.Join(schemaDir(),
		"model_request.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var traj, bound map[string]any
	if err := json.Unmarshal(trajRaw, &traj); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(boundaryRaw, &bound); err != nil {
		t.Fatal(err)
	}
	trajDef := traj["definitions"].(map[string]any)["model_request"].(map[string]any)
	wantReq := stringSet(bound["required"].([]any))
	gotReq := stringSet(trajDef["required"].([]any))
	if !eqSets(gotReq, wantReq) {
		t.Errorf("required = %v, want %v", gotReq, wantReq)
	}
	if !objEq(jsonValue(trajDef["properties"]),
		jsonValue(bound["properties"])) {
		t.Error("properties differ")
	}
}

// TestOutcomeSchemaAndWriterVocabularyCannotDrift is
// test_outcome_schema_and_writer_vocabulary_cannot_drift: the schema's enums
// and the writer's module constants must agree — the constants exist for
// precise pre-write errors, the schema is the contract; neither may move
// without the other.
func TestOutcomeSchemaAndWriterVocabularyCannotDrift(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(schemaDir(), "trajectory.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	outcomeDef := schema["definitions"].(map[string]any)["outcome"].(map[string]any)
	props := outcomeDef["properties"].(map[string]any)
	if got, want := jsonList(props["outcome"].(map[string]any)["enum"]),
		OutcomeValues; !eqStrs(got, want) {
		t.Errorf("outcome enum = %v, want %v", got, want)
	}
	if got, want := jsonList(props["final_evidence_tier"].(map[string]any)["enum"]),
		findings.EVIDENCE_ORDER; !eqStrs(got, want) {
		t.Errorf("final_evidence_tier enum = %v, want %v", got, want)
	}
	if got, want := stringSet(outcomeDef["required"].([]any)), stringSet([]any{
		"campaign_id", "outcome", "final_status", "final_evidence_tier"}); !eqSets(got, want) {
		t.Errorf("required = %v, want %v", got, want)
	}
	training := props["training"].(map[string]any)
	if got, want := stringSet(training["required"].([]any)), stringSet([]any{
		"visibility", "excluded"}); !eqSets(got, want) {
		t.Errorf("training.required = %v, want %v", got, want)
	}
	trainProps := training["properties"].(map[string]any)
	if got, want := jsonList(trainProps["visibility"].(map[string]any)["enum"]),
		[]string{"visible", "hidden"}; !eqStrs(got, want) {
		t.Errorf("training.visibility enum = %v, want %v", got, want)
	}
	// required-when-excluded via if/then
	if got := training["if"].(map[string]any)["properties"].(map[string]any)["excluded"]; !objEq(jsonValue(got), validation.VObj(validation.KV{K: "const",
		V: validation.VBool(true)})) {
		t.Errorf("training.if excluded = %v, want {const: true}", got)
	}
	if got, want := jsonList(training["then"].(map[string]any)["required"]),
		[]string{"exclude_reason"}; !eqStrs(got, want) {
		t.Errorf("training.then.required = %v, want %v", got, want)
	}
}

func jsonList(v any) []string {
	xs, _ := v.([]any)
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

func eqStrs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func schemaDir() string {
	// internal/trajectory -> repo root -> assets/schema (the embedded pack's
	// on-disk mirror; the test reads the same bytes validation serves).
	wd, _ := os.Getwd()
	return filepath.Join(wd, "..", "..", "assets", "schema")
}

func jsonValue(v any) validation.Value {
	raw, _ := json.Marshal(v)
	out, _ := validation.ParseOrdered(raw)
	return out
}

func stringSet(xs []any) map[string]bool {
	out := map[string]bool{}
	for _, x := range xs {
		if s, ok := x.(string); ok {
			out[s] = true
		}
	}
	return out
}

func eqSets(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// record_outcome (tests/test_outcome_events.py, trajectory half)
// ---------------------------------------------------------------------------

type stubStore struct{ cases map[string]validation.Value }

func (s stubStore) LoadCase(id string) (validation.Value, error) {
	c, ok := s.cases[id]
	if !ok {
		return validation.VNull(), errNoCase
	}
	return c, nil
}

type brokenStore struct{}

func (brokenStore) LoadCase(string) (validation.Value, error) {
	panic("store on fire")
}

var errNoCase = &caseError{}

type caseError struct{}

func (*caseError) Error() string { return "no such case" }

func hypo() validation.Value {
	return validation.VObj(
		kv("title", validation.VStr("User can withdraw more than deposited "+
			"via rounding")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("precision-rounding")),
			kv("description", validation.VStr("share calculation rounds in "+
				"the attacker's favor")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/Vault.sol")),
			kv("function", validation.VStr("withdraw"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()))))
}

func disprovedFinding(t *testing.T, c *state.Campaign) string {
	t.Helper()
	f, err := findings.IngestHypothesis(c, hypo(), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := validation.ObjStr(f, "finding_id")
	if _, err := findings.Transition(c, fid, "NEEDS_RESEARCH", "triage", "",
		"", false); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.Transition(c, fid, "DISPROVED",
		"negative-mode memory check hit", "", "", false); err != nil {
		t.Fatal(err)
	}
	return fid
}

func trainingOf(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	traj, err := ModelTrajectory(c)
	if err != nil {
		t.Fatal(err)
	}
	return validation.ObjAt(validation.ObjAt(traj[len(traj)-1], "data"), "training")
}

func TestOutcomeEventRoundtrip(t *testing.T) {
	c := newCamp(t)
	fid := disprovedFinding(t, c)
	ev, err := RecordOutcome(c, fid, "disproved", OutcomeOpts{
		FinalStatus: "DISPROVED", FinalEvidenceTier: "E2"})
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(ev, "type"); got != "outcome" {
		t.Errorf("type = %s", got)
	}
	if got := validation.ObjStr(ev, "ref"); got != fid {
		t.Errorf("ref = %s", got)
	}
	data := validation.ObjAt(ev, "data")
	if got := validation.ObjStr(data, "campaign_id"); got != c.CampaignID {
		t.Errorf("campaign_id = %s", got)
	}
	if got := validation.ObjStr(data, "outcome"); got != "disproved" {
		t.Errorf("outcome = %s", got)
	}
	if got := validation.ObjStr(data, "final_status"); got != "DISPROVED" {
		t.Errorf("final_status = %s", got)
	}
	if got := validation.ObjStr(data, "final_evidence_tier"); got != "E2" {
		t.Errorf("final_evidence_tier = %s", got)
	}
	if got := validation.ObjStr(data, "finding_id"); got != fid {
		t.Errorf("finding_id = %s", got)
	}
	if validation.ObjAt(data, "case_id").Kind != validation.Null {
		t.Error("case_id should be null")
	}
	if got := validation.ObjAt(data, "training"); !objEq(got, jsonV(`{"visibility":"visible","excluded":false,"exclude_reason":null}`)) {
		t.Errorf("training = %s", validation.CanonCompact(got))
	}
	if validation.ObjStr(data, "at") == "" {
		t.Error("at missing")
	}
	traj, _ := ModelTrajectory(c)
	last := traj[len(traj)-1]
	if validation.ObjStr(last, "type") != "outcome" {
		t.Errorf("last type = %s", validation.ObjStr(last, "type"))
	}
	if validation.ObjAt(last, "role").Kind != validation.Null {
		t.Error("role should be null")
	}
	if got := validation.ObjStr(last, "ref"); got != fid {
		t.Errorf("ref = %s", got)
	}
	if !objEq(validation.ObjAt(last, "data"), data) {
		t.Error("projection data differs")
	}
	if v, _ := c.VerifyLog(); !v.OK {
		t.Error("chain not ok")
	}
	report, err := VerifyTrajectory(c)
	if err != nil {
		t.Fatal(err)
	}
	if !validation.ObjAt(report, "ok").B || len(validation.ObjAt(report, "problems").A) != 0 ||
		objInt(report, "events") != 1 {
		t.Errorf("report = %v", report)
	}
}

func TestOutcomeEventConfirmedExploitableViaCaseIDVisible(t *testing.T) {
	c := newCamp(t)
	fid := disprovedFinding(t, c)
	if _, err := RecordOutcome(c, fid, "confirmed-exploitable",
		OutcomeOpts{FinalStatus: "CONFIRMED", FinalEvidenceTier: "E5",
			CaseID: strPtr(caseID)}); err != nil {
		t.Fatal(err)
	}
	traj, _ := ModelTrajectory(c)
	data := validation.ObjAt(traj[len(traj)-1], "data")
	if got := validation.ObjStr(data, "outcome"); got != "confirmed-exploitable" {
		t.Errorf("outcome = %s", got)
	}
	if got := validation.ObjStr(data, "case_id"); got != caseID {
		t.Errorf("case_id = %s", got)
	}
}

func withStore(t *testing.T, s EvalStore) {
	t.Helper()
	SetEvalStore(s)
	t.Cleanup(func() { SetEvalStore(nil) })
}

func TestHeldOutCaseDerivesHiddenAndExcluded(t *testing.T) {
	c := newCamp(t)
	fid := disprovedFinding(t, c)
	withStore(t, stubStore{map[string]validation.Value{caseID: validation.VObj(
		kv("case_id", validation.VStr(caseID)),
		kv("partition", validation.VStr("held-out")))}})
	if _, err := RecordOutcome(c, fid, "confirmed-exploitable",
		OutcomeOpts{FinalStatus: "CONFIRMED", FinalEvidenceTier: "E4",
			CaseID: strPtr(caseID)}); err != nil {
		t.Fatal(err)
	}
	if got := trainingOf(t, c); !objEq(got, jsonV(`{"visibility":"hidden","excluded":true,"exclude_reason":"case partition 'held-out' — leakage guard"}`)) {
		t.Errorf("training = %s", validation.CanonCompact(got))
	}
}

func TestTrainingCaseDerivesHiddenAndExcluded(t *testing.T) {
	c := newCamp(t)
	fid := disprovedFinding(t, c)
	withStore(t, stubStore{map[string]validation.Value{caseID: validation.VObj(
		kv("case_id", validation.VStr(caseID)),
		kv("partition", validation.VStr("training")))}})
	if _, err := RecordOutcome(c, fid, "disproved", OutcomeOpts{
		FinalStatus: "DISPROVED", FinalEvidenceTier: "E1",
		CaseID: strPtr(caseID)}); err != nil {
		t.Fatal(err)
	}
	if got := trainingOf(t, c); !objEq(got, jsonV(`{"visibility":"hidden","excluded":true,"exclude_reason":"case partition 'training' — leakage guard"}`)) {
		t.Errorf("training = %s", validation.CanonCompact(got))
	}
}

func TestDevCaseDerivesVisible(t *testing.T) {
	c := newCamp(t)
	fid := disprovedFinding(t, c)
	withStore(t, stubStore{map[string]validation.Value{caseID: validation.VObj(
		kv("case_id", validation.VStr(caseID)),
		kv("partition", validation.VStr("dev")))}})
	if _, err := RecordOutcome(c, fid, "disproved", OutcomeOpts{
		FinalStatus: "DISPROVED", FinalEvidenceTier: "E1",
		CaseID: strPtr(caseID)}); err != nil {
		t.Fatal(err)
	}
	if got := trainingOf(t, c); !objEq(got, jsonV(`{"visibility":"visible","excluded":false,"exclude_reason":null}`)) {
		t.Errorf("training = %s", validation.CanonCompact(got))
	}
}

func TestUnreadableCaseStoreFailsClosed(t *testing.T) {
	c := newCamp(t)
	fid := disprovedFinding(t, c)
	withStore(t, nil)
	if _, err := RecordOutcome(c, fid, "disproved", OutcomeOpts{
		FinalStatus: "DISPROVED", FinalEvidenceTier: "E1",
		CaseID: strPtr(caseID)}); err != nil {
		t.Fatal(err)
	}
	if got := trainingOf(t, c); !objEq(got, jsonV(`{"visibility":"hidden","excluded":true,"exclude_reason":"case partition unreadable (fail closed)"}`)) {
		t.Errorf("training = %s", validation.CanonCompact(got))
	}
}

func TestCaseAbsentFromStoreFailsClosed(t *testing.T) {
	c := newCamp(t)
	fid := disprovedFinding(t, c)
	withStore(t, stubStore{map[string]validation.Value{}})
	if _, err := RecordOutcome(c, fid, "disproved", OutcomeOpts{
		FinalStatus: "DISPROVED", FinalEvidenceTier: "E1",
		CaseID: strPtr(caseID)}); err != nil {
		t.Fatal(err)
	}
	tr := trainingOf(t, c)
	if validation.ObjStr(tr, "visibility") != "hidden" ||
		validation.ObjAt(tr, "excluded").Kind != validation.Bool || !validation.ObjAt(tr, "excluded").B ||
		validation.ObjStr(tr, "exclude_reason") != "case partition unreadable (fail closed)" {
		t.Errorf("training = %v", tr)
	}
}

func TestBrokenStoreLoaderFailsClosed(t *testing.T) {
	c := newCamp(t)
	fid := disprovedFinding(t, c)
	withStore(t, brokenStore{})
	if _, err := RecordOutcome(c, fid, "disproved", OutcomeOpts{
		FinalStatus: "DISPROVED", FinalEvidenceTier: "E1",
		CaseID: strPtr(caseID)}); err != nil {
		t.Fatal(err)
	}
	if got := trainingOf(t, c); !objEq(got, jsonV(`{"visibility":"hidden","excluded":true,"exclude_reason":"case partition unreadable (fail closed)"}`)) {
		t.Errorf("training = %s", validation.CanonCompact(got))
	}
}

func TestUnrecognizedPartitionFailsClosed(t *testing.T) {
	c := newCamp(t)
	fid := disprovedFinding(t, c)
	withStore(t, stubStore{map[string]validation.Value{caseID: validation.VObj(
		kv("case_id", validation.VStr(caseID)),
		kv("partition", validation.VStr("mystery")))}})
	if _, err := RecordOutcome(c, fid, "disproved", OutcomeOpts{
		FinalStatus: "DISPROVED", FinalEvidenceTier: "E1",
		CaseID: strPtr(caseID)}); err != nil {
		t.Fatal(err)
	}
	tr := trainingOf(t, c)
	if validation.ObjStr(tr, "visibility") != "hidden" ||
		validation.ObjAt(tr, "excluded").Kind != validation.Bool || !validation.ObjAt(tr, "excluded").B ||
		!strings.Contains(validation.ObjStr(tr, "exclude_reason"), "unrecognized") {
		t.Errorf("training = %v", tr)
	}
}

func TestCallerExclusionOverridesDerivation(t *testing.T) {
	c := newCamp(t)
	fid := disprovedFinding(t, c)
	if _, err := RecordOutcome(c, fid, "disproved", OutcomeOpts{
		FinalStatus: "DISPROVED", FinalEvidenceTier: "E1", Excluded: true,
		ExcludeReason: strPtr("operator: closed outside a case run")}); err != nil {
		t.Fatal(err)
	}
	if got := trainingOf(t, c); !objEq(got, jsonV(`{"visibility":"hidden","excluded":true,"exclude_reason":"operator: closed outside a case run"}`)) {
		t.Errorf("training = %s", validation.CanonCompact(got))
	}
}

func assertNothingWritten(t *testing.T, c *state.Campaign, before int) {
	t.Helper()
	after, err := c.NextSeq()
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Errorf("next_seq = %d, want %d", after, before)
	}
	traj, err := ModelTrajectory(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(traj) != 0 {
		t.Errorf("trajectory = %v", traj)
	}
	if v, _ := c.VerifyLog(); !v.OK {
		t.Error("chain not ok")
	}
}

func TestInvalidOutcomeRejectedBeforeWrite(t *testing.T) {
	c := newCamp(t)
	if _, err := findings.IngestHypothesis(c, hypo(), "code", "", ""); err != nil {
		t.Fatal(err)
	}
	before, _ := c.NextSeq()
	_, err := RecordOutcome(c, "F-000000000000", "totally-won", OutcomeOpts{
		FinalStatus: "DISPROVED", FinalEvidenceTier: "E2"})
	if err == nil || !strings.Contains(err.Error(), "unknown outcome") {
		t.Fatalf("err = %v", err)
	}
	assertNothingWritten(t, c, before)
}

func TestInvalidEvidenceTierRejectedBeforeWrite(t *testing.T) {
	c := newCamp(t)
	fid := disprovedFinding(t, c)
	before, _ := c.NextSeq()
	_, err := RecordOutcome(c, fid, "disproved", OutcomeOpts{
		FinalStatus: "DISPROVED", FinalEvidenceTier: "E9"})
	if err == nil || !strings.Contains(err.Error(), "unknown evidence tier") {
		t.Fatalf("err = %v", err)
	}
	assertNothingWritten(t, c, before)
}

func TestInvalidFinalStatusRejectedBeforeWrite(t *testing.T) {
	c := newCamp(t)
	fid := disprovedFinding(t, c)
	before, _ := c.NextSeq()
	_, err := RecordOutcome(c, fid, "disproved", OutcomeOpts{
		FinalStatus: "CONFIRMEDD", FinalEvidenceTier: "E2"})
	if err == nil || !strings.Contains(err.Error(), "unknown final_status") {
		t.Fatalf("err = %v", err)
	}
	assertNothingWritten(t, c, before)
}

func TestUnknownFindingRejectedBeforeWrite(t *testing.T) {
	c := newCamp(t)
	before, _ := c.NextSeq()
	_, err := RecordOutcome(c, "F-000000000000", "disproved", OutcomeOpts{
		FinalStatus: "DISPROVED", FinalEvidenceTier: "E2"})
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("err = %v", err)
	}
	assertNothingWritten(t, c, before)
}

func TestExclusionWithoutReasonRejectedBeforeWrite(t *testing.T) {
	c := newCamp(t)
	fid := disprovedFinding(t, c)
	before, _ := c.NextSeq()
	_, err := RecordOutcome(c, fid, "disproved", OutcomeOpts{
		FinalStatus: "DISPROVED", FinalEvidenceTier: "E2", Excluded: true})
	if err == nil || !strings.Contains(err.Error(), "exclude_reason") {
		t.Fatalf("err = %v", err)
	}
	assertNothingWritten(t, c, before)
}

func TestHandWrittenOutcomeEventFlaggedByVerify(t *testing.T) {
	c := newCamp(t)
	fid := disprovedFinding(t, c)
	if _, err := RecordOutcome(c, fid, "disproved", OutcomeOpts{
		FinalStatus: "DISPROVED", FinalEvidenceTier: "E2"}); err != nil {
		t.Fatal(err)
	}
	hand := validation.VObj(kv("outcome", validation.VStr("disproved")))
	if _, err := c.Log("outcome", &fid, &hand); err != nil {
		t.Fatal(err)
	}
	if v, _ := c.VerifyLog(); !v.OK {
		t.Fatal("chain should verify")
	}
	report, err := VerifyTrajectory(c)
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjAt(report, "ok").B {
		t.Error("ok = true, want false")
	}
	if got := objInt(report, "events"); got != 2 {
		t.Errorf("events = %d, want 2", got)
	}
}

// ---- test-local helpers ---------------------------------------------------

func objInt(v validation.Value, key string) int64 {
	if x := validation.ObjAt(v, key); x.Kind == validation.Int {
		return x.I
	}
	return 0
}

func delKV(v validation.Value, key string) validation.Value {
	out := validation.VObj()
	for _, pair := range v.O {
		if pair.K != key {
			out.O = append(out.O, pair)
		}
	}
	return out
}

func strPtr(s string) *string { return &s }

func eqStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func containsStr(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// jsonV parses a JSON literal for order-insensitive comparison.
func jsonV(s string) validation.Value {
	v, err := validation.ParseOrdered([]byte(s))
	if err != nil {
		panic(err)
	}
	return v
}

// objEq is Python dict/list equality: object key ORDER is irrelevant.
func objEq(a, b validation.Value) bool {
	if a.Kind != b.Kind {
		return false
	}
	switch a.Kind {
	case validation.Obj:
		if len(a.O) != len(b.O) {
			return false
		}
		for _, pair := range a.O {
			other := validation.ObjAt(b, pair.K)
			if other.Kind == validation.Null && pair.V.Kind != validation.Null {
				return false
			}
			if !objEq(pair.V, other) {
				return false
			}
		}
		return true
	case validation.Arr:
		if len(a.A) != len(b.A) {
			return false
		}
		for i := range a.A {
			if !objEq(a.A[i], b.A[i]) {
				return false
			}
		}
		return true
	case validation.Str:
		return a.S == b.S
	case validation.Int:
		return a.I == b.I
	case validation.Flt:
		return a.F == b.F
	case validation.Bool:
		return a.B == b.B
	case validation.Null:
		return true
	}
	return false
}
