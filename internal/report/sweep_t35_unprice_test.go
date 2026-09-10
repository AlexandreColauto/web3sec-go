package report

// Port of tests/test_unpriceable_impact.py's report half: the UNPRICEABLE
// decision prints exactly where the invented figure used to.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/risk"
	"websec/internal/sandbox"
	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

const (
	t35Ceiling = "capacity basis: the sink is an address[255] test constant — " +
		"no live liquidity bounds it"
	t35Reason = "the sink is a test fixture, so any USD figure would be " +
		"invented precision, not a measurement"
	t35Actor = "operator"
)

// t35GateReadyEconomic is _gate_ready_economic: every CONFIRMED clause but
// the economic E7 one.
func t35GateReadyEconomic(t *testing.T) (*state.Campaign, string) {
	t.Helper()
	root := t.TempDir()
	t.Setenv("WEBV2_GLOBAL_MEMORY_DIR", filepath.Join(root, "global-memory"))
	installMemorySeams(t)
	if err := t35SeedGlobalRow(root); err != nil {
		t.Fatal(err)
	}
	c, err := state.Init(root, "unpriceable", state.InitOpts{})
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
	f, err := findings.IngestHypothesis(c, validation.VObj(
		kv("title", validation.VStr(
			"Attacker skews the oracle and borrows unbacked funds")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("oracle-manipulation")),
			kv("description", validation.VStr("the spot price read lets the "+
				"attacker trade against its own quote")))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr())))), "economic", "t", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	rec, err := sandbox.RegisterExec(c, sandbox.RegisterOpts{
		Profile: "docker-networkless",
		Command: "forge test --match-test test_exploit", FindingID: &fid,
		ReportedBy: "pytest-harness", StdoutText: "PASS: test_exploit\n"})
	if err != nil {
		t.Fatal(err)
	}
	for i, lv := range []string{"E4", "E5"} {
		etype := "foundry-test"
		if lv == "E5" {
			etype = "fork-test"
		}
		if _, err := findings.AddEvidence(c, fid, validation.VObj(
			kv("evidence_id", validation.VStr("EV-u"+string(rune('0'+i)))),
			kv("level", validation.VStr(lv)),
			kv("type", validation.VStr(etype)),
			kv("description", validation.VStr("gate fixture")),
			kv("sandbox_profile", objAt(rec, "profile")),
			kv("artifact_id", objAt(rec, "exec_id")))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := findings.SetCriticVerdict(c, fid, "confirmed",
		"mechanism sound"); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.RecordMemoryCheck(c, fid, []validation.Value{
		validation.VObj(
			kv("memory_ids", validation.VArr(validation.VStr("MEM-shared01"))),
			kv("mode", validation.VStr("negative")))}); err != nil {
		t.Fatal(err)
	}
	f, err = findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	ver := objAt(f, "verification")
	if ver.Kind != validation.Obj {
		ver = validation.VObj()
	}
	ver.O = validation.SetOrAppend(ver.O, "reproduction", validation.VObj(
		kv("tier_reached", validation.VStr("T3")),
		kv("status", validation.VStr("reproduced")),
		kv("attempts", validation.VArr())))
	f.O = validation.SetOrAppend(f.O, "verification", ver)
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
	return c, fid
}

// Port of tests/test_unpriceable_impact.py::test_report_prints_unpriceable_where_the_number_used_to_go.
func TestReportPrintsUnpriceableWhereTheNumberUsedToGo(t *testing.T) {
	c, fid := t35GateReadyEconomic(t)
	if _, err := risk.RecordEconomicImpact(c, fid,
		validation.VInt(630450), validation.VNull(),
		validation.VNull()); err != nil {
		t.Fatal(err)
	}
	if _, err := risk.RecordUnpriceable(c, fid, t35Ceiling, t35Reason,
		t35Actor); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.Transition(c, fid, "POSSIBLE", "triage", "", "",
		false); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.Transition(c, fid, "CONFIRMED",
		"unpriceable decision recorded", "", "", false); err != nil {
		t.Fatal(err)
	}
	text := t35Generate(t, c)
	if !strings.Contains(text, "UNPRICEABLE (ceiling: "+t35Ceiling+")") {
		t.Errorf("report lacks the unpriceable ceiling line:\n%s",
			tailLines(text, 60))
	}
	if strings.Contains(text, "630,450") {
		t.Error("report still prints the withdrawn invented figure")
	}
	if strings.Contains(text, "$None") {
		t.Error("report prints $None")
	}
	if !strings.Contains(text, "economically extractable: UNPRICEABLE") {
		t.Error("report lacks the economically-extractable UNPRICEABLE line")
	}
}

// t35SeedGlobalRow writes the MEM-shared01 row the gate fixture consults.
func t35SeedGlobalRow(root string) error {
	gdir := filepath.Join(root, "global-memory")
	if err := os.MkdirAll(gdir, 0o755); err != nil {
		return err
	}
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
		kv("approved_at", validation.VStr("2026-09-06T00:00:00+00:00")))
	return validation.WriteJson(filepath.Join(gdir, "memory.json"),
		validation.VArr(validation.VObj(
			kv("program_key", validation.VStr("test|other|-")),
			kv("published_at", validation.VStr("2026-09-06T00:00:00+00:00")),
			kv("row", row),
			kv("scope", validation.VStr("global")))), "")
}
