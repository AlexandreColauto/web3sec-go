package findings

import (
	"errors"
	"strings"
	"testing"

	"websec/assets"
	"websec/internal/state"
	"websec/internal/validation"
)

// ---- fixtures (port of tests/test_assumptions.py) ----

// assumptionHypo is the assumptions module's hypo() payload.
func assumptionHypo() validation.Value {
	return validation.VObj(
		kv("title", validation.VStr(
			"User can drain the vault via oracle price manipulation")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("oracle-manipulation")),
			kv("description", validation.VStr(
				"withdrawal pricing trusts a spot price an attacker can "+
					"move in one transaction")),
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
}

// assumptionPayload is the Python assumption() helper.
func assumptionPayload(over ...validation.KV) validation.Value {
	base := validation.VObj(
		kv("id", validation.VStr("A1")),
		kv("type", validation.VStr("reachability")),
		kv("claim", validation.VStr("checkable proposition A1: the vulnerable "+
			"path is reachable and exploitable as described")),
		kv("status", validation.VStr("UNKNOWN")),
		kv("model_belief", validation.VFloat(0.5)),
		kv("blocking", validation.VBool(true)),
	)
	for _, o := range over {
		base.O = validation.SetOrAppend(base.O, o.K, o.V)
	}
	return base
}

// evidenced is _evidenced: a real, store-backed evidence item (E1 — no EXEC).
func evidenced(t *testing.T, c *state.Campaign, fid string) validation.Value {
	t.Helper()
	out, err := AddEvidence(c, fid, validation.VObj(
		kv("evidence_id", validation.VStr("EV-A1")),
		kv("level", validation.VStr("E1")),
		kv("type", validation.VStr("static-analysis")),
		kv("description", validation.VStr(
			"call graph shows the path is externally reachable")),
	))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// lookupKey is a presence-checked object lookup for the schema-drift diff.
func lookupKey(v validation.Value, k string) (validation.Value, bool) {
	for _, kv := range v.O {
		if kv.K == k {
			return kv.V, true
		}
	}
	return validation.VNull(), false
}

// valueEqual is Python == on two JSON values (object order insensitive).
func valueEqual(a, b validation.Value) bool {
	if a.Kind != b.Kind {
		return false
	}
	switch a.Kind {
	case validation.Null:
		return true
	case validation.Bool:
		return a.B == b.B
	case validation.Int:
		return validation.IntText(a) == validation.IntText(b)
	case validation.Flt:
		return a.F == b.F
	case validation.Str:
		return a.S == b.S
	case validation.Arr:
		if len(a.A) != len(b.A) {
			return false
		}
		for i := range a.A {
			if !valueEqual(a.A[i], b.A[i]) {
				return false
			}
		}
		return true
	case validation.Obj:
		if len(a.O) != len(b.O) {
			return false
		}
		for _, kv := range a.O {
			bv, ok := lookupKey(b, kv.K)
			if !ok || !valueEqual(kv.V, bv) {
				return false
			}
		}
		return true
	}
	return false
}

// ---- schema level ----

// Port of test_standalone_and_inlined_assumption_schemas_cannot_drift.
func TestStandaloneAndInlinedAssumptionSchemasCannotDrift(t *testing.T) {
	rawStandalone, err := assets.FS.ReadFile("schema/assumption.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	rawFinding, err := assets.FS.ReadFile("schema/finding.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	standalone, err := validation.ParseOrdered(rawStandalone)
	if err != nil {
		t.Fatal(err)
	}
	finding, err := validation.ParseOrdered(rawFinding)
	if err != nil {
		t.Fatal(err)
	}
	assumptionDef, ok := lookupKey(validation.ObjAt(finding, "definitions"), "assumption")
	if !ok {
		t.Fatal("finding.schema.json has no definitions.assumption")
	}
	for _, key := range []string{"type", "additionalProperties", "required",
		"properties"} {
		want, ok1 := lookupKey(standalone, key)
		got, ok2 := lookupKey(assumptionDef, key)
		if !ok1 || !ok2 {
			t.Fatalf("key %q missing (standalone=%v inlined=%v)", key, ok1, ok2)
		}
		if !valueEqual(got, want) {
			t.Errorf("finding.schema.json definitions.assumption drifted "+
				"from assumption.schema.json at %q", key)
		}
	}
}

// Port of test_assumption_schema_rejects_unknown_type_and_bad_belief.
func TestAssumptionSchemaRejectsUnknownTypeAndBadBelief(t *testing.T) {
	bad := assumptionPayload(kv("type", validation.VStr("vibes")))
	if err := validation.Validate(bad, "assumption", 1); err == nil {
		t.Error("unknown assumption type must fail schema validation")
	}
	belief := assumptionPayload(kv("model_belief", validation.VFloat(1.7)))
	if err := validation.Validate(belief, "assumption", 1); err == nil {
		t.Error("model_belief 1.7 must fail schema validation")
	}
	short := assumptionPayload(kv("claim", validation.VStr("short")))
	if err := validation.Validate(short, "assumption", 1); err == nil {
		t.Error("a 5-char claim must fail schema validation")
	}
	if err := validation.Validate(assumptionPayload(), "assumption", 1); err != nil {
		t.Fatalf("the canonical assumption must validate: %v", err)
	}
}

// Port of test_existing_findings_load_without_migration_errors.
func TestExistingFindingsLoadWithoutMigrationErrors(t *testing.T) {
	c := ingestCamp(t)
	f, err := IngestHypothesis(c, assumptionHypo(), "code", "05", "")
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadFinding(c, validation.ObjStr(f, "finding_id"))
	if err != nil {
		t.Fatal(err)
	}
	if err := validation.Validate(reloaded, "finding", 1); err != nil {
		t.Fatalf("legacy finding must round-trip: %v", err)
	}
	if _, ok := fieldAt(reloaded, "assumptions"); ok {
		t.Error("a fresh finding must not carry assumptions")
	}
	if _, ok := fieldAt(reloaded, "claim_version"); ok {
		t.Error("a fresh finding must not carry claim_version")
	}
	all, err := LoadAllFindings(c)
	if err != nil || len(all) == 0 {
		t.Fatalf("load_all_findings = %d rows, err=%v", len(all), err)
	}
}

// ---- install ----

// Port of test_set_assumptions_installs_and_validates.
func TestSetAssumptionsInstallsAndValidates(t *testing.T) {
	c := ingestCamp(t)
	f, err := IngestHypothesis(c, assumptionHypo(), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := validation.ObjStr(f, "finding_id")
	cv := int64(1)
	got, err := SetAssumptions(c, fid, []validation.Value{
		assumptionPayload(),
		assumptionPayload(kv("id", validation.VStr("A2")),
			kv("type", validation.VStr("economic")),
			kv("dependencies", validation.VArr(validation.VStr("A1"))),
			kv("verification_options", validation.VArr(
				validation.VStr("fork-sim")))),
	}, &cv, "")
	if err != nil {
		t.Fatal(err)
	}
	assumptions := validation.ObjAt(got, "assumptions")
	if len(assumptions.A) != 2 {
		t.Fatalf("assumptions = %d, want 2", len(assumptions.A))
	}
	if id := validation.ObjStr(assumptions.A[0], "id"); id != "A1" {
		t.Errorf("assumptions[0].id = %q", id)
	}
	for _, a := range assumptions.A {
		if st := validation.ObjStr(a, "status"); st != "UNKNOWN" {
			t.Errorf("installed status = %q, want UNKNOWN", st)
		}
	}
	if deps := validation.ObjAt(assumptions.A[1], "dependencies"); len(deps.A) != 1 ||
		deps.A[0].S != "A1" {
		t.Errorf("A2.dependencies = %v", deps)
	}
	if got := validation.ObjAt(got, "claim_version").I; got != 1 {
		t.Errorf("claim_version = %d, want 1", got)
	}
	if err := validation.Validate(got, "finding", 1); err != nil {
		t.Fatalf("installed finding must validate: %v", err)
	}
}

// Port of test_set_assumptions_rejects_pre_evidenced_status.
func TestSetAssumptionsRejectsPreEvidencedStatus(t *testing.T) {
	c := ingestCamp(t)
	f, _ := IngestHypothesis(c, assumptionHypo(), "code", "", "")
	fid := validation.ObjStr(f, "finding_id")
	_, err := SetAssumptions(c, fid, []validation.Value{
		assumptionPayload(kv("status", validation.VStr("SUPPORTED")))}, nil, "")
	wantErr(t, err, "start UNKNOWN")
	_, err = SetAssumptions(c, fid, []validation.Value{
		assumptionPayload(kv("support", validation.VArr(validation.VStr("ART-1"))))},
		nil, "")
	wantErr(t, err, "support/contradictions")
	_, err = SetAssumptions(c, fid, []validation.Value{
		assumptionPayload(), assumptionPayload()}, nil, "")
	wantErr(t, err, "duplicate")
	_, err = SetAssumptions(c, fid, []validation.Value{
		assumptionPayload(kv("dependencies",
			validation.VArr(validation.VStr("A9"))))}, nil, "")
	wantErr(t, err, "unknown id")
}

// ---- transitions: the provenance hard-stop ----

// Port of test_flip_with_only_model_belief_is_rejected.
func TestFlipWithOnlyModelBeliefIsRejected(t *testing.T) {
	c := ingestCamp(t)
	f, _ := IngestHypothesis(c, assumptionHypo(), "code", "", "")
	fid := validation.ObjStr(f, "finding_id")
	cv := int64(1)
	if _, err := SetAssumptions(c, fid, []validation.Value{
		assumptionPayload(kv("model_belief", validation.VFloat(0.99)))},
		&cv, ""); err != nil {
		t.Fatal(err)
	}
	// the model is 99% sure — that must not be enough
	_, err := AssumptionTransition(c, fid, "A1", "SUPPORTED", []string{}, "")
	if !strings.Contains(err.Error(), "model_belief") &&
		!strings.Contains(err.Error(), "evidence") {
		t.Fatalf("empty evidence_ids: %v", err)
	}
	var it *IllegalTransition
	if !errors.As(err, &it) {
		t.Fatalf("want IllegalTransition, got %T", err)
	}
	_, err = AssumptionTransition(c, fid, "A1", "SUPPORTED", nil, "")
	if !errors.As(err, &it) {
		t.Fatalf("omitted evidence_ids: %v", err)
	}
	got, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if st := validation.ObjStr(validation.ObjAt(got, "assumptions").A[0], "status"); st != "UNKNOWN" {
		t.Fatalf("status = %q, want UNKNOWN", st)
	}
}

// Port of test_flip_with_hallucinated_artifact_is_rejected.
func TestFlipWithHallucinatedArtifactIsRejected(t *testing.T) {
	c := ingestCamp(t)
	f, _ := IngestHypothesis(c, assumptionHypo(), "code", "", "")
	fid := validation.ObjStr(f, "finding_id")
	if _, err := SetAssumptions(c, fid, []validation.Value{
		assumptionPayload()}, nil, ""); err != nil {
		t.Fatal(err)
	}
	_, err := AssumptionTransition(c, fid, "A1", "SUPPORTED",
		[]string{"ART-00000000"}, "")
	wantErr(t, err, "does not exist in the campaign")
	_, err = AssumptionTransition(c, fid, "A1", "REFUTED",
		[]string{"EXEC-0000000000000000"}, "")
	wantErr(t, err, "does not exist in the campaign")
}

// Port of test_flip_with_real_evidence_succeeds_and_records_provenance.
func TestFlipWithRealEvidenceSucceedsAndRecordsProvenance(t *testing.T) {
	c := ingestCamp(t)
	f, _ := IngestHypothesis(c, assumptionHypo(), "code", "", "")
	fid := validation.ObjStr(f, "finding_id")
	cv := int64(1)
	if _, err := SetAssumptions(c, fid, []validation.Value{
		assumptionPayload()}, &cv, ""); err != nil {
		t.Fatal(err)
	}
	evidenced(t, c, fid)
	if _, err := AssumptionTransition(c, fid, "A1", "SUPPORTED",
		[]string{"EV-A1"}, "proposer"); err != nil {
		t.Fatal(err)
	}
	got, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	a := validation.ObjAt(got, "assumptions").A[0]
	if st := validation.ObjStr(a, "status"); st != "SUPPORTED" {
		t.Errorf("status = %q, want SUPPORTED", st)
	}
	if sup := validation.ObjAt(a, "support"); len(sup.A) != 1 || sup.A[0].S != "EV-A1" {
		t.Errorf("support = %v", sup)
	}
	// the transition is in the hash-chained log
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if validation.ObjStr(e, "type") == "finding.assumption_transition" {
			found = true
		}
	}
	if !found {
		t.Error("finding.assumption_transition missing from the event log")
	}
}

// Port of test_exec_record_always_satisfies_provenance.
func TestExecRecordAlwaysSatisfiesProvenance(t *testing.T) {
	c := ingestCamp(t)
	f, _ := IngestHypothesis(c, assumptionHypo(), "code", "", "")
	fid := validation.ObjStr(f, "finding_id")
	if _, err := SetAssumptions(c, fid, []validation.Value{
		assumptionPayload(kv("type", validation.VStr("reachability")))},
		nil, ""); err != nil {
		t.Fatal(err)
	}
	rec := testExec(t, c, "docker-networkless", fid, 0, "PASS: test_exploit\n")
	if _, err := AssumptionTransition(c, fid, "A1", "SUPPORTED",
		[]string{validation.ObjStr(rec, "exec_id")}, ""); err != nil {
		t.Fatal(err)
	}
	got, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if st := validation.ObjStr(validation.ObjAt(got, "assumptions").A[0], "status"); st != "SUPPORTED" {
		t.Fatalf("status = %q, want SUPPORTED", st)
	}
}

// Port of test_supported_to_refuted_requires_contradiction.
func TestSupportedToRefutedRequiresContradiction(t *testing.T) {
	c := ingestCamp(t)
	f, _ := IngestHypothesis(c, assumptionHypo(), "code", "", "")
	fid := validation.ObjStr(f, "finding_id")
	if _, err := SetAssumptions(c, fid, []validation.Value{
		assumptionPayload()}, nil, ""); err != nil {
		t.Fatal(err)
	}
	evidenced(t, c, fid)
	if _, err := AssumptionTransition(c, fid, "A1", "SUPPORTED",
		[]string{"EV-A1"}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := AddEvidence(c, fid, validation.VObj(
		kv("evidence_id", validation.VStr("EV-X1")),
		kv("level", validation.VStr("E2")),
		kv("type", validation.VStr("reachability")),
		kv("description", validation.VStr("trace shows the modifier reverts "+
			"for unprivileged callers; the path is not reachable")),
	)); err != nil {
		t.Fatal(err)
	}
	if _, err := AssumptionTransition(c, fid, "A1", "REFUTED",
		[]string{"EV-X1"}, ""); err != nil {
		t.Fatal(err)
	}
	got, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	a := validation.ObjAt(got, "assumptions").A[0]
	if st := validation.ObjStr(a, "status"); st != "REFUTED" {
		t.Errorf("status = %q, want REFUTED", st)
	}
	if cs := validation.ObjAt(a, "contradictions"); len(cs.A) != 1 ||
		cs.A[0].S != "EV-X1" {
		t.Errorf("contradictions = %v", cs)
	}
	// both sides remain on record
	if sup := validation.ObjAt(a, "support"); len(sup.A) != 1 || sup.A[0].S != "EV-A1" {
		t.Errorf("support = %v", sup)
	}
}

// Port of test_refuted_to_supported_is_legal_with_new_provenance.
func TestRefutedToSupportedIsLegalWithNewProvenance(t *testing.T) {
	c := ingestCamp(t)
	f, _ := IngestHypothesis(c, assumptionHypo(), "code", "", "")
	fid := validation.ObjStr(f, "finding_id")
	if _, err := SetAssumptions(c, fid, []validation.Value{
		assumptionPayload()}, nil, ""); err != nil {
		t.Fatal(err)
	}
	evidenced(t, c, fid)
	for _, to := range []string{"SUPPORTED", "REFUTED", "SUPPORTED"} {
		if _, err := AssumptionTransition(c, fid, "A1", to,
			[]string{"EV-A1"}, ""); err != nil {
			t.Fatalf("%s: %v", to, err)
		}
	}
	got, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if st := validation.ObjStr(validation.ObjAt(got, "assumptions").A[0], "status"); st != "SUPPORTED" {
		t.Fatalf("status = %q, want SUPPORTED", st)
	}
}

// Port of test_illegal_moves_and_unknown_ids_rejected.
func TestIllegalMovesAndUnknownIDsRejected(t *testing.T) {
	c := ingestCamp(t)
	f, _ := IngestHypothesis(c, assumptionHypo(), "code", "", "")
	fid := validation.ObjStr(f, "finding_id")
	if _, err := SetAssumptions(c, fid, []validation.Value{
		assumptionPayload()}, nil, ""); err != nil {
		t.Fatal(err)
	}
	evidenced(t, c, fid)
	_, err := AssumptionTransition(c, fid, "A1", "MAYBE",
		[]string{"EV-A1"}, "")
	var it *IllegalTransition
	if !errors.As(err, &it) {
		t.Fatalf("MAYBE: %v", err)
	}
	_, err = AssumptionTransition(c, fid, "A1", "UNKNOWN",
		[]string{"EV-A1"}, "") // UNKNOWN -> UNKNOWN
	wantErr(t, err, "not a legal move")
	if !errors.As(err, &it) {
		t.Fatalf("UNKNOWN->UNKNOWN: %v", err)
	}
	_, err = AssumptionTransition(c, fid, "A7", "SUPPORTED",
		[]string{"EV-A1"}, "")
	wantErr(t, err, "not an assumption")
}

// Port of test_transition_event_carries_versions_and_kinds.
func TestTransitionEventCarriesVersionsAndKinds(t *testing.T) {
	c := ingestCamp(t)
	f, _ := IngestHypothesis(c, assumptionHypo(), "code", "", "")
	fid := validation.ObjStr(f, "finding_id")
	cv := int64(3)
	if _, err := SetAssumptions(c, fid, []validation.Value{
		assumptionPayload()}, &cv, ""); err != nil {
		t.Fatal(err)
	}
	evidenced(t, c, fid)
	if _, err := AssumptionTransition(c, fid, "A1", "SUPPORTED",
		[]string{"EV-A1"}, ""); err != nil {
		t.Fatal(err)
	}
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	var ev validation.Value
	found := false
	for _, e := range events {
		if validation.ObjStr(e, "type") == "finding.assumption_transition" {
			ev, found = e, true
			break
		}
	}
	if !found {
		t.Fatal("no finding.assumption_transition event")
	}
	data := validation.ObjAt(ev, "data")
	if got := validation.ObjAt(data, "claim_version").I; got != 3 {
		t.Errorf("claim_version = %d, want 3", got)
	}
	if kinds := validation.ObjAt(data, "kinds"); len(kinds.A) != 1 ||
		kinds.A[0].S != "evidence" {
		t.Errorf("kinds = %v", kinds)
	}
	if ids := validation.ObjAt(data, "evidence_ids"); len(ids.A) != 1 ||
		ids.A[0].S != "EV-A1" {
		t.Errorf("evidence_ids = %v", ids)
	}
}
