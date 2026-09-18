package findings

// T35 testmap re-triage: test_budget_discovery.py::test_exhaustion_message_names_the_command.
// TestDiscoveryBudgetEnforced pins the refusal; this pins the actionable text:
// the operator is told which command raises the ceiling.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

func TestExhaustionMessageNamesTheCommand(t *testing.T) {
	root := t.TempDir()
	c, err := state.Init(root, "bud7", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetDiscoveryBudget(1, "op"); err != nil {
		t.Fatal(err)
	}
	// Suspicion is free: both hypotheses land at E0. The slot is spent on the
	// first RISE above E0, so the second rise is what hits the ceiling.
	a, err := IngestHypothesis(c, hypoPayload(), "code", "t", "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := IngestHypothesis(c, hypoPayload(), "code", "t", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AddEvidence(c, validation.ObjStr(a, "finding_id"), validation.VObj(
		kv("evidence_id", validation.VStr("EV-a")),
		kv("level", validation.VStr("E1")),
		kv("type", validation.VStr("manual")),
		kv("description", validation.VStr("the first rise spends the slot")),
	)); err != nil {
		t.Fatal(err)
	}
	_, err = AddEvidence(c, validation.ObjStr(b, "finding_id"), validation.VObj(
		kv("evidence_id", validation.VStr("EV-b")),
		kv("level", validation.VStr("E1")),
		kv("type", validation.VStr("manual")),
		kv("description", validation.VStr("the second rise must fail"))))
	if err == nil {
		t.Fatal("second rise must fail on the exhausted budget")
	}
	msg := err.Error()
	if !strings.Contains(msg, "--set-discovery") {
		t.Errorf("message does not name --set-discovery: %q", msg)
	}
	if !strings.Contains(msg, "webv2 budget") {
		t.Errorf("message does not name the webv2 budget command: %q", msg)
	}
	if !strings.Contains(msg, "discovery budget exhausted") {
		t.Errorf("message does not name the exhausted state: %q", msg)
	}
}

// --- tests/test_design_upgrades.py section 2: evidence as a partial order ---

// oracleFindingWith is the Python file's _oracle_finding_with: an
// oracle-manipulation hypothesis confirmed to POSSIBLE, one sandboxed exec,
// then the given (level, type) evidence specs. E4+ items cite the EXEC ledger;
// the E7 item cites a registered economic-impact artifact.
func oracleFindingWith(t *testing.T, c *state.Campaign,
	specs [][2]string) validation.Value {
	t.Helper()
	payload := hypoPayload(
		kv("title", validation.VStr(
			"Attacker withdraws unbacked funds via price skew")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("oracle-manipulation")),
			kv("description", validation.VStr(
				"spot price read lets attacker trade against own price")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/V.sol")),
			kv("function", validation.VStr("borrow"))))),
		kv("economic_impact", validation.VObj(
			kv("extractable_usd", validation.VInt(1000000)))))
	f, err := IngestHypothesis(c, payload, "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := validation.ObjStr(f, "finding_id")
	if _, err := Transition(c, fid, "POSSIBLE", "triage", "", "", false); err != nil {
		t.Fatal(err)
	}
	rec := testExec(t, c, "docker-networkless", fid, 0, "PASS: poc\n")
	art := filepath.Join(c.ArtifactsDir, "impact-dump.json")
	if err := os.WriteFile(art, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	aid, err := c.RegisterArtifact("economic-impact", art, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, spec := range specs {
		level, typ := spec[0], spec[1]
		idx, err := LevelIndex(level)
		if err != nil {
			t.Fatal(err)
		}
		floor, _ := LevelIndex("E4")
		item := validation.VObj(
			kv("evidence_id", validation.VStr(fmt.Sprintf("EV-g%d", i))),
			kv("level", validation.VStr(level)),
			kv("type", validation.VStr(typ)),
			kv("description", validation.VStr("evidence for gate clause test")))
		if idx >= floor {
			item.O = validation.SetOrAppend(item.O, "sandbox_profile",
				validation.ObjAt(rec, "profile"))
			item.O = validation.SetOrAppend(item.O, "artifact_id", validation.ObjAt(rec, "exec_id"))
		}
		if level == "E7" {
			item.O = validation.SetOrAppend(item.O, "artifact_id", validation.VStr(aid))
		}
		if _, err := AddEvidence(c, fid, item); err != nil {
			t.Fatal(err)
		}
	}
	got, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestEconomicGateForkOnlyIsInsufficient(t *testing.T) {
	c := ingestCamp(t)
	f := oracleFindingWith(t, c, [][2]string{{"E5", "fork-test"}})
	deficit := EvidenceDeficit(f, "CONFIRMED", nil)
	if deficit == nil {
		t.Fatal("fork-only evidence must leave a deficit")
	}
	for _, want := range []string{"foundry-test", "E4", "E7"} {
		if !strings.Contains(*deficit, want) {
			t.Errorf("deficit %q does not name %q", *deficit, want)
		}
	}
}

func TestEconomicGateAcceptsIndependentReproAsAlternative(t *testing.T) {
	c := ingestCamp(t)
	f := oracleFindingWith(t, c, [][2]string{
		{"E4", "foundry-test"}, {"E5", "differential"}, {"E7", "balance-delta"}})
	if d := EvidenceDeficit(f, "CONFIRMED", nil); d != nil {
		t.Fatalf("differential repro must satisfy the independent clause: %q", *d)
	}
}

func TestEconomicGateSymbolicDoesNotSatisfyLocalPOC(t *testing.T) {
	c := ingestCamp(t)
	f := oracleFindingWith(t, c, [][2]string{
		{"E4", "symbolic-witness"}, {"E5", "fork-test"},
		{"E7", "balance-delta"}})
	deficit := EvidenceDeficit(f, "CONFIRMED", nil)
	if deficit == nil {
		t.Fatal("symbolic witness is not a local PoC")
	}
	if !strings.Contains(*deficit, "unit-test") {
		t.Errorf("deficit %q does not demand unit-test", *deficit)
	}
}

func TestEvidenceCannotSubstituteForMissingClause(t *testing.T) {
	c := ingestCamp(t)
	f := oracleFindingWith(t, c, [][2]string{
		{"E5", "fork-test"}, {"E5", "differential"}, {"E7", "balance-delta"},
		{"E7", "manual"}})
	deficit := EvidenceDeficit(f, "CONFIRMED", nil)
	if deficit == nil {
		t.Fatal("a missing local-PoC clause must leave a deficit")
	}
	if !strings.Contains(*deficit, "unit-test") {
		t.Errorf("deficit %q does not demand the unit-test clause", *deficit)
	}
	if strings.Contains(*deficit, "fork-test") {
		t.Errorf("deficit %q wrongly re-demands the satisfied fork clause",
			*deficit)
	}
	if strings.Contains(*deficit, "E7") {
		t.Errorf("deficit %q wrongly re-demands the satisfied E7 clause",
			*deficit)
	}
	if got := len(validation.ObjAt(f, "evidence").A); got != 4 {
		t.Errorf("evidence items = %d, want 4", got)
	}
}

func TestEconomicGateIsThreeClauses(t *testing.T) {
	clauses := GateRequirements("CONFIRMED", "oracle-manipulation", nil)
	if len(clauses) != 3 {
		t.Fatalf("clauses = %d, want 3", len(clauses))
	}
	want := []struct {
		types    []string
		minLevel string
	}{
		{[]string{"unit-test", "foundry-test", "fuzz"}, "E4"},
		{[]string{"fork-test", "trace", "balance-delta", "differential",
			"historical-analog", "manual"}, "E5"},
		{[]string{"balance-delta", "manual"}, "E7"},
	}
	for i, w := range want {
		if clauses[i].MinLevel != w.minLevel {
			t.Errorf("clause %d min = %s, want %s", i, clauses[i].MinLevel,
				w.minLevel)
		}
		if len(clauses[i].Types) != len(w.types) {
			t.Errorf("clause %d types = %v, want %v", i, clauses[i].Types, w.types)
			continue
		}
		for _, typ := range w.types {
			if _, ok := clauses[i].Types[typ]; !ok {
				t.Errorf("clause %d lacks type %s: %v", i, typ, clauses[i].Types)
			}
		}
	}
}

func TestFullConfirmationOfEconomicClassWithThreeClauses(t *testing.T) {
	c := ingestCamp(t)
	f := oracleFindingWith(t, c, [][2]string{
		{"E4", "foundry-test"}, {"E5", "fork-test"}, {"E7", "balance-delta"}})
	fid := validation.ObjStr(f, "finding_id")
	if _, err := SetCriticVerdict(c, fid, "confirmed", "ok"); err != nil {
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
	ver := asDict(validation.ObjAt(vf, "verification"))
	ver.O = validation.SetOrAppend(ver.O, "reproduction", validation.VObj(
		kv("tier_reached", validation.VStr("T3")),
		kv("status", validation.VStr("reproduced")),
		kv("attempts", validation.VArr())))
	vf.O = validation.SetOrAppend(vf.O, "verification", ver)
	if err := SaveFinding(c, &vf); err != nil {
		t.Fatal(err)
	}
	if _, err := Transition(c, fid, "CONFIRMED", "three-clause gate satisfied",
		"", "", false); err != nil {
		t.Fatal(err)
	}
	got, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(got, "status") != "CONFIRMED" {
		t.Fatalf("status = %q, want CONFIRMED", validation.ObjStr(got, "status"))
	}
}

func TestDefaultClassDeficitKeepsLadderWording(t *testing.T) {
	deficit := EvidenceDeficit(classFinding("logic-error"), "CONFIRMED", nil)
	if deficit == nil {
		t.Fatal("an evidence-less finding must have a deficit")
	}
	if *deficit != "evidence level E0 < required E4 for CONFIRMED" {
		t.Fatalf("deficit = %q", *deficit)
	}
}
