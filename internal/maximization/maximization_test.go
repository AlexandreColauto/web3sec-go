// Port tests for internal/maximization (webv2/maximization.py).
//
// DEVIATION (declared): the Python repo carries no test_maximization.py (it
// was deleted with test_cli_ladder.py in commit 300fd74), so these are
// behavior tests written against the module's own contract, cross-checked
// against the live Python module with a parity driver (.scratch/).
package maximization

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/sandbox"
	"websec/internal/state"
	"websec/internal/validation"
)

func kv(k string, v validation.Value) validation.KV { return validation.KV{K: k, V: v} }

func newCampaign(t *testing.T, name string) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), name, state.InitOpts{})
	if err != nil {
		t.Fatalf("init campaign: %v", err)
	}
	return c
}

func seedGlobalMemory(t *testing.T) {
	t.Helper()
	row := validation.VObj(
		kv("memory_id", validation.VStr("MEM-shared01")),
		kv("campaign_id", validation.VStr("ingest:test:case")),
		kv("finding_id", validation.VNull()),
		kv("snapshot_id", validation.VNull()),
		kv("created_at", validation.VStr("2026-09-06T00:00:00+00:00")),
		kv("kind", validation.VStr("confirmed")),
		kv("status", validation.VStr("CONFIRMED")),
		kv("pattern", validation.VStr("Shared memory pattern")),
		kv("bug_class", validation.VStr("logic-error")),
		kv("cwe", validation.VNull()),
		kv("evidence_summary", validation.VStr("Seeded incident.")),
		kv("partition", validation.VStr("dev")),
		kv("schema_version", validation.VInt(2)),
		kv("rejection_class", validation.VNull()),
		kv("deciding_propositions", validation.VArr()),
		kv("promotion_status", validation.VStr("promoted")),
		kv("approved_by", validation.VStr("operator")),
		kv("approved_at", validation.VStr("2026-09-06T00:00:00+00:00")),
	)
	wrapper := validation.VArr(validation.VObj(
		kv("program_key", validation.VStr("test|other|-")),
		kv("published_at", validation.VStr("2026-09-06T00:00:00+00:00")),
		kv("row", row),
		kv("scope", validation.VStr("global"))))
	findings.SetSharedMemoryRows(func(string) ([]validation.Value, error) {
		return wrapper.A, nil
	})
	t.Cleanup(func() {
		findings.SetSharedMemoryRows(
			func(string) ([]validation.Value, error) { return nil, nil })
	})
}

// floorEvidenceSeq mints unique evidence ids for the manual floor items the
// fixtures attach before a status whose evidence floor is above E0.
var floorEvidenceSeq int

// addFloorEvidence attaches a manual (non-exec) evidence item at *level*: the
// reachability evidence a status floor demands before the status stamp. It is
// the finding's first rise above E0, so it pays the discovery slot once — the
// exec-backed evidence the fixtures attach afterwards rides that same rise for
// free, keeping the campaign's slot spend unchanged.
func addFloorEvidence(t *testing.T, c *state.Campaign, fid, level string) {
	t.Helper()
	floorEvidenceSeq++
	if _, err := findings.AddEvidence(c, fid, validation.VObj(
		kv("evidence_id", validation.VStr(
			fmt.Sprintf("EV-manual-%04d", floorEvidenceSeq))),
		kv("level", validation.VStr(level)),
		kv("type", validation.VStr("manual")),
		kv("description", validation.VStr(
			"manual reachability note: the path to the sink is reachable")))); err != nil {
		t.Fatalf("add floor evidence %s: %v", level, err)
	}
}

// confirmedFinding ingests and confirms one logic-error finding with a real
// sandboxed exec, so reproduce_rung has something to mint against.
func confirmedFinding(t *testing.T, c *state.Campaign, title string) validation.Value {
	t.Helper()
	f, err := findings.IngestHypothesis(c, validation.VObj(
		kv("title", validation.VStr(title)),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("logic-error")),
			kv("description", validation.VStr(
				"test fixture: rounding loss on deposit")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/V.sol")),
			kv("function", validation.VStr("deposit"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()))),
		kv("capabilities", validation.VObj(
			kv("granted", validation.VArr(validation.VStr("drain_treasury"))),
			kv("required", validation.VArr()))),
	), "attacker", "06", "")
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	fid := validation.ObjStr(f, "finding_id")
	// R3-3: the POSSIBLE floor is E2, so the fixture earns the reachability
	// evidence BEFORE the status stamp (evidence floors gate every status).
	addFloorEvidence(t, c, fid, "E2")
	if _, err := findings.Transition(c, fid, "POSSIBLE", "triage", "triage",
		"", false); err != nil {
		t.Fatal(err)
	}
	rec := registerExec(t, c, fid)
	if _, err := findings.AddEvidence(c, fid, validation.VObj(
		kv("evidence_id", validation.VStr("EV-unit")),
		kv("level", validation.VStr("E4")),
		kv("type", validation.VStr("foundry-test")),
		kv("description", validation.VStr("sandboxed unit PoC")),
		kv("sandbox_profile", validation.ObjAt(rec, "profile")),
		kv("artifact_id", validation.ObjAt(rec, "exec_id")))); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.SetCriticVerdict(c, fid, "confirmed", "checked"); err != nil {
		t.Fatal(err)
	}
	seedGlobalMemory(t)
	if _, err := findings.RecordMemoryCheck(c, fid, []validation.Value{
		validation.VObj(
			kv("memory_ids", validation.VArr(validation.VStr("MEM-shared01"))),
			kv("mode", validation.VStr("negative")))}); err != nil {
		t.Fatal(err)
	}
	vf, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	ver := validation.AsObj(validation.ObjAt(vf, "verification"))
	ver.O = validation.SetOrAppend(ver.O, "reproduction", validation.VObj(
		kv("tier_reached", validation.VStr("T2")),
		kv("status", validation.VStr("reproduced")),
		kv("attempts", validation.VArr())))
	vf.O = validation.SetOrAppend(vf.O, "verification", ver)
	if err := findings.SaveFinding(c, &vf); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.Transition(c, fid, "CONFIRMED", "gates passed", "",
		"", false); err != nil {
		t.Fatalf("transition CONFIRMED: %v", err)
	}
	out, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func registerExec(t *testing.T, c *state.Campaign, fid string) validation.Value {
	t.Helper()
	rec, err := sandbox.RegisterExec(c, sandbox.RegisterOpts{
		Profile: "docker-networkless", Command: "forge test --match-test test_x",
		ReportedBy: "test-harness", FindingID: &fid,
		StdoutText: "PASS: test_x\n"})
	if err != nil {
		t.Fatalf("register exec: %v", err)
	}
	return rec
}

func keysOf(v validation.Value) []string {
	out := []string{}
	for _, kv := range v.O {
		out = append(out, kv.K)
	}
	return out
}

// --- start_ladder ----------------------------------------------------------

func TestStartLadderBaseRungAndIdempotence(t *testing.T) {
	c := newCampaign(t, "Acme")
	f := confirmedFinding(t, c, "Rounding loss")
	fid := validation.ObjStr(f, "finding_id")
	lad, err := StartLadder(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	wantKeys := []string{"ladder_id", "finding_id", "campaign_id", "created_at",
		"updated_at", "axes_explored", "axis_notes", "variants",
		"maximal_rung_id", "disposition", "history"}
	if strings.Join(keysOf(lad), ",") != strings.Join(wantKeys, ",") {
		t.Fatalf("ladder keys = %v", keysOf(lad))
	}
	if !strings.HasPrefix(validation.ObjStr(lad, "ladder_id"), "LAD-") {
		t.Fatalf("ladder_id = %s", validation.ObjStr(lad, "ladder_id"))
	}
	base := listOf(lad, "variants").A[0]
	wantRungKeys := []string{"rung_id", "name", "description", "axes",
		"capital_usd", "extraction_ratio", "removed_preconditions",
		"added_preconditions", "status", "exec_id", "evidence_id", "reason",
		"created_at", "reproduced_at"}
	if strings.Join(keysOf(base), ",") != strings.Join(wantRungKeys, ",") {
		t.Fatalf("rung keys = %v", keysOf(base))
	}
	if validation.ObjStr(base, "name") != "base" || validation.ObjStr(base, "status") != "reproduced" {
		t.Fatalf("base = %s", validation.CanonCompact(base))
	}
	if validation.ObjStr(base, "description") != "as claimed at reproduction: Rounding loss" {
		t.Fatalf("description = %s", validation.ObjStr(base, "description"))
	}
	if !strings.HasPrefix(validation.ObjStr(base, "exec_id"), "EXEC-") {
		t.Fatalf("base exec_id = %s", validation.ObjStr(base, "exec_id"))
	}
	if validation.ObjStr(validation.AsObj(validation.ObjAt(lad, "disposition")), "state") != "open" {
		t.Fatalf("disposition = %v", validation.ObjAt(lad, "disposition"))
	}
	f2, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	mx := validation.AsObj(validation.ObjAt(f2, "maximization"))
	if validation.ObjStr(mx, "ladder_id") != validation.ObjStr(lad, "ladder_id") ||
		validation.ObjStr(mx, "disposition") != "open" {
		t.Fatalf("finding.maximization = %v", mx)
	}
	// idempotent
	again, err := StartLadder(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(again, "ladder_id") != validation.ObjStr(lad, "ladder_id") {
		t.Fatal("start_ladder is not idempotent")
	}
	// the ladder persisted on disk
	raw, err := os.ReadFile(filepath.Join(c.Dir, "ladders", fid+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), validation.ObjStr(lad, "ladder_id")) {
		t.Fatal("ladder artifact missing")
	}
}

func TestStartLadderAssumedBaseWithoutReproduction(t *testing.T) {
	c := newCampaign(t, "Acme")
	f, err := findings.IngestHypothesis(c, validation.VObj(
		kv("title", validation.VStr("Unproven claim")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("logic-error")),
			kv("description", validation.VStr("mechanism described in detail here")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/V.sol")),
			kv("function", validation.VStr("f"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()),
			kv("required_capital_usd", validation.VFloat(250000)))),
	), "code", "test", "")
	if err != nil {
		t.Fatal(err)
	}
	lad, err := StartLadder(c, validation.ObjStr(f, "finding_id"))
	if err != nil {
		t.Fatal(err)
	}
	base := listOf(lad, "variants").A[0]
	if validation.ObjStr(base, "status") != "assumed" {
		t.Fatalf("status = %s", validation.ObjStr(base, "status"))
	}
	if validation.ObjStr(base, "exec_id") != "" {
		t.Fatalf("exec_id = %v", validation.ObjAt(base, "exec_id"))
	}
	if got := validation.ObjAt(base, "capital_usd"); got.Kind != validation.Flt || got.F != 250000 {
		t.Fatalf("capital = %v", got)
	}
}

// --- add_variant / explore_axis -------------------------------------------

func TestAddVariantValidationsAndAxisBookkeeping(t *testing.T) {
	c := newCampaign(t, "Acme")
	fid := validation.ObjStr(confirmedFinding(t, c, "Rounding loss"), "finding_id")
	if _, err := AddVariant(c, fid, "dust", "dust the pool with one wei",
		nil, nil, nil, nil, nil); err == nil ||
		!strings.Contains(err.Error(), "must name the axis") {
		t.Fatalf("empty axes err = %v", err)
	}
	if _, err := AddVariant(c, fid, "dust", "dust the pool with one wei",
		[]string{"bogus"}, nil, nil, nil, nil); err == nil ||
		!strings.Contains(err.Error(), "unknown axis 'bogus'; the axes are "+
			"('capital-minimization', 'precondition-removal', "+
			"'role-conflation', 'ordering-permutation', 'cap-saturation')") {
		t.Fatalf("unknown axis err = %v", err)
	}
	if _, err := AddVariant(c, fid, "dust", "dust the pool with one wei",
		[]string{"capital-minimization"}, nil, nil, nil, nil); err == nil ||
		!strings.Contains(err.Error(), "no ladder for "+fid) {
		t.Fatalf("missing ladder err = %v", err)
	}
	if _, err := StartLadder(c, fid); err != nil {
		t.Fatal(err)
	}
	cap1, ratio := 1.0, 0.99
	rung, err := AddVariant(c, fid, "dust", "dust the pool with one wei",
		[]string{"capital-minimization", "cap-saturation"}, &cap1, &ratio,
		[]string{"victim stakes"}, []string{"hold until oracle"})
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(rung, "status") != "assumed" || validation.ObjStr(rung, "reason") != "" {
		t.Fatalf("rung = %s", validation.CanonCompact(rung))
	}
	if got := listStrings(listOf(rung, "axes")); len(got) != 2 {
		t.Fatalf("axes = %v", got)
	}
	lad, err := LoadLadder(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if len(listOf(*lad, "variants").A) != 2 {
		t.Fatalf("variants = %v", listOf(*lad, "variants"))
	}
	if got := strings.Join(listStrings(listOf(*lad, "axes_explored")), ","); got !=
		"capital-minimization,cap-saturation" {
		t.Fatalf("axes_explored = %s", got)
	}
}

func TestAddVariantRefusedOnCompleteLadder(t *testing.T) {
	c := newCampaign(t, "Acme")
	fid := validation.ObjStr(confirmedFinding(t, c, "Rounding loss"), "finding_id")
	lad, err := StartLadder(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	lad.O = validation.SetOrAppend(lad.O, "disposition", validation.VObj(
		kv("state", validation.VStr("complete")),
		kv("reason", validation.VNull()),
		kv("actor", validation.VStr("op")),
		kv("at", validation.VStr("2026-09-06T00:00:00+00:00"))))
	if _, err := SaveLadder(c, &lad); err != nil {
		t.Fatal(err)
	}
	_, err = AddVariant(c, fid, "late", "a late variant attempt",
		[]string{"cap-saturation"}, nil, nil, nil, nil)
	want := "ladder disposition is complete; reopen it with an explicit " +
		"reason before adding work (webv2 ladder reopen)"
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v, want %q", err, want)
	}
	// a waived ladder is re-openable
	lad.O = validation.SetOrAppend(lad.O, "disposition", validation.VObj(
		kv("state", validation.VStr("waived")),
		kv("reason", validation.VStr("budget exhausted, accepted risk")),
		kv("actor", validation.VStr("op")),
		kv("at", validation.VStr("2026-09-06T00:00:00+00:00"))))
	if _, err := SaveLadder(c, &lad); err != nil {
		t.Fatal(err)
	}
	if _, err := AddVariant(c, fid, "late", "a late variant attempt",
		[]string{"cap-saturation"}, nil, nil, nil, nil); err != nil {
		t.Fatalf("waived ladder must accept work: %v", err)
	}
}

func TestExploreAxisRequiresWrittenNote(t *testing.T) {
	c := newCampaign(t, "Acme")
	fid := validation.ObjStr(confirmedFinding(t, c, "Rounding loss"), "finding_id")
	if _, err := StartLadder(c, fid); err != nil {
		t.Fatal(err)
	}
	if _, err := ExploreAxis(c, fid, "bogus", "long enough note"); err == nil ||
		!strings.Contains(err.Error(), "unknown axis") {
		t.Fatalf("err = %v", err)
	}
	if _, err := ExploreAxis(c, fid, "cap-saturation", "nope"); err == nil ||
		!strings.Contains(err.Error(), "needs a written reason") {
		t.Fatalf("err = %v", err)
	}
	lad, err := ExploreAxis(c, fid, "cap-saturation",
		"  no payout cap in this code path  ")
	if err != nil {
		t.Fatal(err)
	}
	notes := validation.AsObj(validation.ObjAt(lad, "axis_notes"))
	if validation.ObjStr(notes, "cap-saturation") != "no payout cap in this code path" {
		t.Fatalf("note = %v", notes)
	}
	if got := strings.Join(listStrings(listOf(lad, "axes_explored")), ","); got !=
		"cap-saturation" {
		t.Fatalf("axes_explored = %s", got)
	}
}

// --- reproduce / disprove --------------------------------------------------

func TestReproduceRungBindsExecAndEvidence(t *testing.T) {
	c := newCampaign(t, "Acme")
	fid := validation.ObjStr(confirmedFinding(t, c, "Rounding loss"), "finding_id")
	if _, err := StartLadder(c, fid); err != nil {
		t.Fatal(err)
	}
	rung, err := AddVariant(c, fid, "dust", "dust the pool with one wei",
		[]string{"capital-minimization"}, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := registerExec(t, c, fid)
	execID := validation.ObjStr(rec, "exec_id")
	got, err := ReproduceRung(c, fid, validation.ObjStr(rung, "rung_id"), execID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(got, "status") != "reproduced" || validation.ObjStr(got, "exec_id") != execID {
		t.Fatalf("rung = %s", validation.CanonCompact(got))
	}
	if !strings.HasPrefix(validation.ObjStr(got, "evidence_id"), "EV-") {
		t.Fatalf("evidence_id = %v", validation.ObjAt(got, "evidence_id"))
	}
	if validation.ObjStr(got, "reproduced_at") == "" {
		t.Fatal("reproduced_at missing")
	}
	lad2, err := LoadLadder(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	hist := listOf(*lad2, "history").A
	if len(hist) != 1 || validation.ObjStr(hist[0], "event") != "reproduced" ||
		validation.ObjStr(hist[0], "exec_id") != execID {
		t.Fatalf("history = %v", hist)
	}
	// unknown rung: Python's KeyError text (str(e) is repr(message))
	_, err = ReproduceRung(c, fid, "R-nope", execID, nil)
	if err == nil || err.Error() != `"unknown rung 'R-nope'; rungs: [`+
		validation.PyReprStr(validation.ObjStr(listOf(*lad2, "variants").A[0], "rung_id"))+
		`, `+validation.PyReprStr(validation.ObjStr(rung, "rung_id"))+`]"` {
		t.Fatalf("unknown rung err = %v", err)
	}
}

func TestDisproveRungRecordsNegativeMemory(t *testing.T) {
	c := newCampaign(t, "Acme")
	fid := validation.ObjStr(confirmedFinding(t, c, "Rounding loss"), "finding_id")
	if _, err := StartLadder(c, fid); err != nil {
		t.Fatal(err)
	}
	rung, err := AddVariant(c, fid, "dust", "dust the pool with one wei",
		[]string{"capital-minimization"}, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	rungID := validation.ObjStr(rung, "rung_id")
	if _, err := DisproveRung(c, fid, rungID, "short"); err == nil ||
		!strings.Contains(err.Error(), "a disproof needs a written reason") {
		t.Fatalf("err = %v", err)
	}
	var got MemoryRequest
	SetQueueMemory(func(_ *state.Campaign, req MemoryRequest) (validation.Value, error) {
		got = req
		return validation.VObj(kv("memory_id", validation.VStr("MEM-neg"))), nil
	})
	t.Cleanup(func() { SetQueueMemory(nil) })
	out, err := DisproveRung(c, fid, rungID,
		"  the pool rejects 1 wei deposits (MIN_DEPOSIT)  ")
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(out, "status") != "disproved" ||
		validation.ObjStr(out, "reason") != "the pool rejects 1 wei deposits (MIN_DEPOSIT)" {
		t.Fatalf("rung = %s", validation.CanonCompact(out))
	}
	if got.Kind != "disproved" || got.Status != "DISPROVED" ||
		got.FindingID == nil || *got.FindingID != fid {
		t.Fatalf("memory request = %+v", got)
	}
	if got.Pattern != "maximal-exploitation dead end: dust — dust the pool with one wei" {
		t.Fatalf("pattern = %s", got.Pattern)
	}
	if got.EvidenceSummary != "the pool rejects 1 wei deposits (MIN_DEPOSIT)" {
		t.Fatalf("evidence_summary = %s", got.EvidenceSummary)
	}
	if got.Negative == nil || validation.ObjStr(*got.Negative, "why_safe") !=
		"the pool rejects 1 wei deposits (MIN_DEPOSIT)" {
		t.Fatalf("negative = %v", got.Negative)
	}
	// a reproduced rung cannot be disproved
	rec := registerExec(t, c, fid)
	if _, err := ReproduceRung(c, fid, rungID, validation.ObjStr(rec, "exec_id"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := DisproveRung(c, fid, rungID, "it actually works fine"); err == nil ||
		!strings.Contains(err.Error(), "cannot be disproved") {
		t.Fatalf("err = %v", err)
	}
}

// --- set_maximal / complete / waive ---------------------------------------

func TestSetMaximalPinsOnlyReproducedRungs(t *testing.T) {
	c := newCampaign(t, "Acme")
	fid := validation.ObjStr(confirmedFinding(t, c, "Rounding loss"), "finding_id")
	if _, err := StartLadder(c, fid); err != nil {
		t.Fatal(err)
	}
	capUSD, ratio := 1.0, 1.0
	rung, err := AddVariant(c, fid, "dust", "dust the pool with one wei",
		[]string{"capital-minimization"}, &capUSD, &ratio, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	rungID := validation.ObjStr(rung, "rung_id")
	_, err = SetMaximal(c, fid, rungID)
	if err == nil || !strings.Contains(err.Error(), "is 'assumed'; the claim "+
		"may only pin to a REPRODUCED rung") {
		t.Fatalf("err = %v", err)
	}
	rec := registerExec(t, c, fid)
	if _, err := ReproduceRung(c, fid, rungID, validation.ObjStr(rec, "exec_id"), nil); err != nil {
		t.Fatal(err)
	}
	f2, err := SetMaximal(c, fid, rungID)
	if err != nil {
		t.Fatal(err)
	}
	mx := validation.AsObj(validation.ObjAt(f2, "maximization"))
	if validation.ObjStr(mx, "maximal_rung_id") != rungID ||
		validation.ObjStr(mx, "claim_from") != rungID {
		t.Fatalf("maximization = %v", mx)
	}
	if got := validation.ObjAt(validation.AsObj(validation.ObjAt(f2, "attacker")), "required_capital_usd"); got.Kind !=
		validation.Flt || got.F != 1 {
		t.Fatalf("capital = %v", got)
	}
	if got := validation.ObjAt(validation.AsObj(validation.ObjAt(f2, "economic_impact")), "extraction_ratio"); got.Kind !=
		validation.Flt || got.F != 1 {
		t.Fatalf("ratio = %v", got)
	}
	lad2, err := LoadLadder(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(*lad2, "maximal_rung_id") != rungID {
		t.Fatalf("ladder maximal = %v", validation.ObjAt(*lad2, "maximal_rung_id"))
	}
}

func TestCompleteLadderGatesAndSuccess(t *testing.T) {
	c := newCampaign(t, "Acme")
	fid := validation.ObjStr(confirmedFinding(t, c, "Rounding loss"), "finding_id")
	if _, err := StartLadder(c, fid); err != nil {
		t.Fatal(err)
	}
	_, err := CompleteLadder(c, fid, "operator")
	if err == nil || !strings.Contains(err.Error(), "ladder not complete: "+
		"unexplored axes ['capital-minimization', 'precondition-removal', "+
		"'role-conflation', 'ordering-permutation', 'cap-saturation']") {
		t.Fatalf("unexplored err = %v", err)
	}
	for _, a := range Axes {
		if _, err := ExploreAxis(c, fid, a, "considered and not applicable"); err != nil {
			t.Fatal(err)
		}
	}
	_, err = CompleteLadder(c, fid, "operator")
	if err == nil || !strings.Contains(err.Error(), "no maximal rung pinned") {
		t.Fatalf("no-maximal err = %v", err)
	}
	rung, err := AddVariant(c, fid, "dust", "dust the pool with one wei",
		[]string{"capital-minimization"}, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := registerExec(t, c, fid)
	if _, err := ReproduceRung(c, fid, validation.ObjStr(rung, "rung_id"),
		validation.ObjStr(rec, "exec_id"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := SetMaximal(c, fid, validation.ObjStr(rung, "rung_id")); err != nil {
		t.Fatal(err)
	}
	lad, err := CompleteLadder(c, fid, "operator")
	if err != nil {
		t.Fatal(err)
	}
	disp := validation.AsObj(validation.ObjAt(lad, "disposition"))
	if validation.ObjStr(disp, "state") != "complete" || validation.ObjStr(disp, "actor") != "operator" {
		t.Fatalf("disposition = %v", disp)
	}
	f2, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(validation.AsObj(validation.ObjAt(f2, "maximization")), "disposition") != "complete" {
		t.Fatalf("finding disposition = %v", validation.ObjAt(f2, "maximization"))
	}
}

func TestWaiveLadderIsAttributedAndRecordsWaiver(t *testing.T) {
	c := newCampaign(t, "Acme")
	fid := validation.ObjStr(confirmedFinding(t, c, "Rounding loss"), "finding_id")
	if _, err := StartLadder(c, fid); err != nil {
		t.Fatal(err)
	}
	lad, err := WaiveLadder(c, fid, "budget exhausted before the ladder closed",
		"operator")
	if err != nil {
		t.Fatal(err)
	}
	disp := validation.AsObj(validation.ObjAt(lad, "disposition"))
	if validation.ObjStr(disp, "state") != "waived" ||
		validation.ObjStr(disp, "reason") != "budget exhausted before the ladder closed" ||
		validation.ObjStr(disp, "actor") != "operator" {
		t.Fatalf("disposition = %v", disp)
	}
	f2, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(validation.AsObj(validation.ObjAt(f2, "maximization")), "disposition") != "waived" {
		t.Fatalf("finding disposition = %v", validation.ObjAt(f2, "maximization"))
	}
	if _, err := os.Stat(filepath.Join(c.Dir, "waivers.jsonl")); err != nil {
		t.Fatalf("waiver not recorded: %v", err)
	}
}

// TestReopenLadder (B2): the escape hatch requireOpen's error message always
// advertised. An open ladder is refused, a closed (complete) ladder refuses
// mutation until reopened with a written reason, and the reopened ladder
// accepts work again.
func TestReopenLadder(t *testing.T) {
	c := newCampaign(t, "Acme")
	fid := validation.ObjStr(confirmedFinding(t, c, "Rounding loss"), "finding_id")
	if _, err := StartLadder(c, fid); err != nil {
		t.Fatal(err)
	}
	// (a) an already-open ladder needs no reopening
	if _, err := ReopenLadder(c, fid, "any reason here", "op"); err == nil ||
		!strings.Contains(err.Error(), "already open") {
		t.Fatalf("open-ladder reopen err = %v", err)
	}
	// close the ladder for real (the requireOpen-refusing state)
	for _, a := range Axes {
		if _, err := ExploreAxis(c, fid, a, "considered and not applicable"); err != nil {
			t.Fatal(err)
		}
	}
	rung, err := AddVariant(c, fid, "dust", "dust the pool with one wei",
		[]string{"capital-minimization"}, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := registerExec(t, c, fid)
	if _, err := ReproduceRung(c, fid, validation.ObjStr(rung, "rung_id"),
		validation.ObjStr(rec, "exec_id"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := SetMaximal(c, fid, validation.ObjStr(rung, "rung_id")); err != nil {
		t.Fatal(err)
	}
	if _, err := CompleteLadder(c, fid, "operator"); err != nil {
		t.Fatal(err)
	}
	// a complete ladder refuses mutation and points at reopen (a valid axis
	// is passed so the check reaches requireOpen, past the axis validation)
	if _, err := AddVariant(c, fid, "more", "more work",
		[]string{"cap-saturation"}, nil, nil, nil, nil); err == nil ||
		!strings.Contains(err.Error(), "reopen") {
		t.Fatalf("complete-ladder AddVariant err = %v (want reopen hint)", err)
	}
	// (b) reopening with no written reason is refused
	if _, err := ReopenLadder(c, fid, "", "op"); err == nil ||
		!strings.Contains(err.Error(), "needs a written reason") {
		t.Fatalf("no-reason reopen err = %v", err)
	}
	// (c) reopen with a reason: open again, attributed, finding kept in sync
	lad, err := ReopenLadder(c, fid, "a cheaper rung appeared after closure", "op2")
	if err != nil {
		t.Fatal(err)
	}
	disp := validation.AsObj(validation.ObjAt(lad, "disposition"))
	if validation.ObjStr(disp, "state") != "open" || validation.ObjStr(disp, "actor") != "op2" {
		t.Fatalf("disposition = %v", disp)
	}
	if !strings.Contains(validation.ObjStr(disp, "reason"), "cheaper rung") {
		t.Fatalf("reason = %q", validation.ObjStr(disp, "reason"))
	}
	f2, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(validation.AsObj(validation.ObjAt(f2, "maximization")), "disposition") != "open" {
		t.Fatalf("finding disposition = %v", validation.ObjAt(f2, "maximization"))
	}
	// the reopened ladder accepts work again (requireOpen no longer refuses)
	if _, err := AddVariant(c, fid, "dust2", "dust again",
		[]string{"cap-saturation"}, nil, nil, nil, nil); err != nil {
		t.Fatalf("AddVariant after reopen = %v (want allowed)", err)
	}
}

// --- ladder_report ---------------------------------------------------------

func TestLadderReportDeltasAndUnexplored(t *testing.T) {
	c := newCampaign(t, "Acme")
	fid := validation.ObjStr(confirmedFinding(t, c, "Rounding loss"), "finding_id")
	lad, err := StartLadder(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	base := listOf(lad, "variants").A[0]
	base.O = validation.SetOrAppend(base.O, "capital_usd", validation.VFloat(100000))
	base.O = validation.SetOrAppend(base.O, "extraction_ratio", validation.VFloat(0.5))
	if err := replaceRung(&lad, base); err != nil {
		t.Fatal(err)
	}
	if _, err := SaveLadder(c, &lad); err != nil {
		t.Fatal(err)
	}
	capUSD, ratio := 1.0, 1.0
	if _, err := AddVariant(c, fid, "dust", "dust the pool with one wei",
		[]string{"capital-minimization"}, &capUSD, &ratio, nil, nil); err != nil {
		t.Fatal(err)
	}
	rep, err := LadderReport(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	rungs := listOf(rep, "rungs").A
	if len(rungs) != 2 {
		t.Fatalf("rungs = %v", rungs)
	}
	if got := validation.ObjAt(rungs[1], "capital_delta_usd"); got.Kind != validation.Flt ||
		got.F != -99999 {
		t.Fatalf("capital delta = %v", got)
	}
	if got := validation.ObjAt(rungs[1], "extraction_delta"); got.Kind != validation.Flt ||
		got.F != 0.5 {
		t.Fatalf("extraction delta = %v", got)
	}
	if got := validation.ObjAt(rungs[0], "capital_delta_usd"); got.Kind != validation.Flt ||
		got.F != 0 {
		t.Fatalf("base delta = %v", got)
	}
	if validation.ObjAt(rep, "maximal").Kind != validation.Null {
		t.Fatalf("maximal = %v", validation.ObjAt(rep, "maximal"))
	}
	if got := strings.Join(listStrings(listOf(rep, "unexplored_axes")), ","); got !=
		"precondition-removal,role-conflation,ordering-permutation,cap-saturation" {
		t.Fatalf("unexplored = %s", got)
	}
	// absent ladder: {"finding_id": ..., "ladder": None}
	other, err := LadderReport(c, "F-missing12345")
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjAt(other, "ladder").Kind != validation.Null ||
		validation.ObjStr(other, "finding_id") != "F-missing12345" {
		t.Fatalf("absent report = %s", validation.CanonCompact(other))
	}
}

func TestLoadLadderValidatesStoredArtifact(t *testing.T) {
	c := newCampaign(t, "Acme")
	fid := validation.ObjStr(confirmedFinding(t, c, "Rounding loss"), "finding_id")
	if _, err := StartLadder(c, fid); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(c.Dir, "ladders", fid+".json")
	var doc map[string]any
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	delete(doc, "variants")
	bad, _ := json.Marshal(doc)
	if err := os.WriteFile(p, bad, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadLadder(c, fid); err == nil ||
		!strings.Contains(err.Error(), "variants") {
		t.Fatalf("err = %v, want schema failure naming variants", err)
	}
}

func TestTailOfAndNewIDShapes(t *testing.T) {
	id := state.NewID("x", 6)
	if !strings.HasPrefix(id, "x-") || len(id) != 8 {
		t.Fatalf("new_id = %s", id)
	}
	if tailOf("LAD-abcdefgh") != "abcdefgh" {
		t.Fatalf("tail = %s", tailOf("LAD-abcdefgh"))
	}
	if !slices.Contains(SortAxes([]string{"b", "a"}), "a") {
		t.Fatal("SortAxes broken")
	}
}
