package findings

import (
	"regexp"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

func genFinding(evidence ...validation.Value) validation.Value {
	return validation.VObj(kv("evidence", validation.VArr(evidence...)))
}

// ev is one evidence item, the shape the gate clauses read.
func ev(level, typ string) validation.Value {
	return validation.VObj(kv("level", validation.VStr(level)), kv("type", validation.VStr(typ)))
}

// classFinding is a finding whose root_cause carries the bug class (the
// field evidence_deficit resolves the gate floor from).
func classFinding(class string, evidence ...validation.Value) validation.Value {
	return validation.VObj(
		kv("root_cause", validation.VObj(kv("class", validation.VStr(class)))),
		kv("evidence", validation.VArr(evidence...)),
	)
}

// ---- signature vectors (byte-exact from the Python twin) ----
func TestTechnicalSignatureVectors(t *testing.T) {
	cases := []struct {
		bugClass, path, function, invariant string
		want                                string
	}{
		// tests/test_dedup_determinism.py corpus (stage A1)
		{"oracle-manipulation", "src/Oracle.sol", "getPrice", "INV-0001", "816bb555b137976a"},
		{"access-control", "  src/Vault.sol  ", "withdraw", "", "fce15ca74e0c37ab"},
		{"  UPPER  ", "Path/Base.sol", "  GetPrice  ", "", "f56dcbd5b9aa119a"},
		{"logic-error", "", "", "", "747886fd0a6a9d26"},
		{"", "", "", "", "be5be69f55e91af2"},
		{"slash/escape\t path", "Caf\u00e9.sol", "fn\twith\tspaces", "INV-\u00e9", "dac25c768d0b8583"},
		{"unicode", "syst\u00e9me/V\u00e4ult.sol", "fonc\u00e7ion", "", "00cac11e8512219f"},
		{"dot.", "./relative/../up.sol", "f().x", "", "87b1dd01fdddafbc"},
		// stage A2 vectors (measured against webv3sec-final)
		{"access-control", "contracts/Vault.sol", "withdraw", "attacker can drain",
			"34d7e9f5cb76ba4c"},
		{"logic-error", "src/Tokens/Share.sol", "", "", "d31c33ae8f83ae14"},
		{"reentrancy", "contracts/x/\u6865.sol", "foo bar",
			"\u00fcn\u00efcod\u00e9 desc \u2192 test", "131a6df0ddc8b30a"},
		// full-case-mapping vectors: Python str.lower() maps U+0130 to
		// "i"+U+0307 and applies the Greek Final_Sigma rule; these pin
		// cases.Lower (pyLower) against that (measured 2026-09-09).
		{"access-control", "\u0130stanbul/Vault.sol", "withdraw", "", "e767f612c2a534d2"},
		{"access-control", "contracts/\u039f\u0394\u039f\u03a3.sol",
			"\u03a3\u03a3", "", "f2f5d58a7e7f39eb"},
	}
	for _, c := range cases {
		got := TechnicalSignature(c.bugClass, c.path, c.function, c.invariant)
		if got != c.want {
			t.Errorf("TechnicalSignature(%q,%q,%q,%q) = %q, want %q",
				c.bugClass, c.path, c.function, c.invariant, got, c.want)
		}
	}
}

func TestTextSignatureVectors(t *testing.T) {
	cases := []struct {
		text, want string
	}{
		{"Hello World", "b94d27b9934d3e08"},
		{"  HELLO   WORLD  ", "b94d27b9934d3e08"},
		{"", "e3b0c44298fc1c14"},
		{"  ", "e3b0c44298fc1c14"},
		{"Caf\u00e9 \u00e0 r\u00e9sum\u00e9 \u00e9crits multiple   spaces", "dbbbc6c16116f725"},
		{"line1\nline2\ttab  trailing  ", "3992955815f47826"},
		// stage A2 vectors (measured against webv3sec-final)
		{"attacker can drain", "5ca6e3c9e3fa2e3b"},
		{"\u00fcn\u00efcod\u00e9 desc \u2192 test", "9f6c3eda330cb35f"},
		{"  leading/trailing  ", "c8934274fe66c133"},
		{"line1\nline2\ttab", "6c56e3ad6d0f6fc6"},
		// full-case-mapping vectors (see TestTechnicalSignatureVectors)
		{"\u0130stanbul", "4a4df120f7d1f3c2"},
		{"\u0391\u03a3  \u03a3\u03a3", "457222885f70f07d"},
		{"\u039f\u0394\u039f\u03a3 Vault", "00576a0dd6274b00"},
	}
	for _, c := range cases {
		if got := TextSignature(c.text); got != c.want {
			t.Errorf("TextSignature(%q) = %q, want %q", c.text, got, c.want)
		}
	}
}

// ---- levels, floors, execution -------------------------------------------
func TestRequiredLevelForStatusAndClassFloors(t *testing.T) {
	checks := []struct {
		status, class, want string
	}{
		{"CONFIRMED", "access-control", "E4"},
		{"CONFIRMED", "authorization", "E4"},
		{"CONFIRMED", "oracle-manipulation", "E5"},
		{"CONFIRMED", "share-price-inflation", "E6"},
		{"CONFIRMED", "liquidation-logic", "E5"},
		{"CONFIRMED", "unknown-class", "E5"},
		{"CONFIRMED", "", "E5"},
		{"HYPOTHESIS", "access-control", "E0"},
		{"NEEDS_RESEARCH", "", "E0"},
		{"PROVISIONALLY_VALID", "", "E1"},
		{"POSSIBLE", "", "E2"},
		{"CHAIN", "", "E4"},
		{"NOT_A_STATUS", "", "E0"},
	}
	for _, c := range checks {
		if got := RequiredLevelFor(c.status, c.class); got != c.want {
			t.Errorf("RequiredLevelFor(%q,%q) = %q, want %q", c.status, c.class, got, c.want)
		}
	}
	if got := RequiredLevelFor("CONFIRMED", "bridge-message"); got != "E6" {
		t.Errorf("bridge-message floor = %q, want E6", got)
	}
	if got := RequiredLevelFor("CONFIRMED", "reentrancy"); got != "E4" {
		t.Errorf("reentrancy floor = %q, want E4", got)
	}
}

// TestEffectiveFloorSeam: required_level_for_campaign routes a non-nil
// campaign through the floors.effective_floor seam (floors.go, Task 3);
// nil keeps the built-in default, and a nil resolver restores it.
func TestEffectiveFloorSeam(t *testing.T) {
	if got := RequiredLevelForCampaign(nil, "CONFIRMED", "oracle-manipulation"); got != "E5" {
		t.Errorf("nil campaign floor = %q, want E5", got)
	}
	c := &state.Campaign{CampaignID: "C-abcdef1234"}
	SetEffectiveFloor(func(c *state.Campaign, status, bugClass string) string {
		if status == "CONFIRMED" {
			return "E4"
		}
		return RequiredLevelFor(status, bugClass)
	})
	defer SetEffectiveFloor(nil)
	if got := RequiredLevelForCampaign(c, "CONFIRMED", "oracle-manipulation"); got != "E4" {
		t.Errorf("seam floor = %q, want E4", got)
	}
	clauses := GateRequirements("CONFIRMED", "oracle-manipulation", c)
	if len(clauses) != 3 || clauses[1].MinLevel != "E4" {
		t.Errorf("seam must relax the live-state clause: %+v", clauses)
	}
	SetEffectiveFloor(nil)
	if got := RequiredLevelForCampaign(c, "CONFIRMED", "oracle-manipulation"); got != "E5" {
		t.Errorf("floor after reset = %q, want E5", got)
	}
}

func TestLevelIndexAndIsExecutionLevel(t *testing.T) {
	if i, err := LevelIndex("E0"); err != nil || i != 0 {
		t.Errorf("LevelIndex(E0) = %d,%v", i, err)
	}
	if i, err := LevelIndex("E7"); err != nil || i != 7 {
		t.Errorf("LevelIndex(E7) = %d,%v", i, err)
	}
	if _, err := LevelIndex("E9"); err == nil ||
		!strings.Contains(err.Error(), "unknown evidence level") {
		t.Errorf("LevelIndex(E9) want unknown-level error, got %v", err)
	}
	exec := []struct {
		level string
		want  bool
	}{
		{"E4", true}, {"E5", true}, {"E6", true},
		{"E7", false}, {"E3", false}, {"E0", false},
	}
	for _, c := range exec {
		if got, _ := IsExecutionLevel(c.level); got != c.want {
			t.Errorf("IsExecutionLevel(%q) = %v, want %v", c.level, got, c.want)
		}
	}
}

func TestGateRequirements(t *testing.T) {
	cls := GateRequirements("POSSIBLE", "", nil)
	if len(cls) != 1 || cls[0].MinLevel != "E2" || cls[0].Types != nil {
		t.Fatalf("POSSIBLE gate = %+v", cls)
	}
	cls = GateRequirements("CONFIRMED", "access-control", nil)
	if len(cls) != 1 || cls[0].MinLevel != "E4" {
		t.Fatalf("authz CONFIRMED gate = %+v", cls)
	}
	cls = GateRequirements("CONFIRMED", "oracle-manipulation", nil)
	if len(cls) != 3 {
		t.Fatalf("economic gate wants 3 clauses, got %d", len(cls))
	}
	if cls[0].MinLevel != "E4" {
		t.Errorf("local-poc clause min = %s, want E4", cls[0].MinLevel)
	}
	if cls[1].MinLevel != "E5" {
		t.Errorf("fork/independent clause min = %s, want E5", cls[1].MinLevel)
	}
	if cls[2].MinLevel != "E7" {
		t.Errorf("economic clause min = %s, want E7", cls[2].MinLevel)
	}
	if _, ok := cls[0].Types["unit-test"]; !ok {
		t.Errorf("local-poc clause must cite unit-test type")
	}
	if _, ok := cls[2].Types["manual"]; !ok {
		t.Errorf("economic clause must cite manual type")
	}
}

// Port of tests/test_findings.py::test_class_specific_evidence_floor at the
// gate level: an access-control bug is fully provable locally, so E4 (a
// foundry-test unit repro) satisfies the single any-type CONFIRMED clause.
func TestClassSpecificEvidenceFloor(t *testing.T) {
	clauses := GateRequirements("CONFIRMED", "access-control", nil)
	if len(clauses) != 1 || clauses[0].Types != nil || clauses[0].MinLevel != "E4" {
		t.Fatalf("access-control CONFIRMED gate = %+v", clauses)
	}
	if !ClauseMet(classFinding("access-control", ev("E4", "foundry-test")), clauses[0]) {
		t.Error("E4 foundry-test must satisfy the access-control floor")
	}
	if ClauseMet(classFinding("access-control", ev("E3", "foundry-test")), clauses[0]) {
		t.Error("E3 must not satisfy the access-control floor")
	}
	finding := classFinding("access-control", ev("E4", "foundry-test"))
	if d := EvidenceDeficit(finding, "CONFIRMED", nil); d != nil {
		t.Errorf("E4 access-control deficit = %q, want nil", *d)
	}
}

// Port of tests/test_findings.py::test_economic_class_demands_fork_evidence
// at the gate level: an E4 unit harness is not enough for an oracle class —
// the live-state clause demands the E5 floor, and the deficit says so.
func TestEconomicClassDemandsForkEvidence(t *testing.T) {
	clauses := GateRequirements("CONFIRMED", "oracle-manipulation", nil)
	if len(clauses) != 3 {
		t.Fatalf("oracle gate wants 3 clauses, got %d", len(clauses))
	}
	local := classFinding("oracle-manipulation", ev("E4", "foundry-test"))
	if !ClauseMet(local, clauses[0]) {
		t.Error("E4 unit harness must satisfy the local-poc clause")
	}
	if ClauseMet(local, clauses[1]) {
		t.Error("E4 unit harness must NOT satisfy the fork/independent clause")
	}
	deficit := EvidenceDeficit(local, "CONFIRMED", nil)
	if deficit == nil || !strings.Contains(*deficit, "E5") {
		t.Fatalf("deficit = %v, want it to demand E5", deficit)
	}
	if !strings.Contains(*deficit, "E7") {
		t.Errorf("deficit = %q, want it to demand E7", *deficit)
	}
	full := classFinding("oracle-manipulation", ev("E4", "foundry-test"),
		ev("E5", "fork-test"), ev("E7", "manual"))
	for i, cl := range clauses {
		if !ClauseMet(full, cl) {
			t.Errorf("clause %d unmet by the full bundle (%+v)", i, cl)
		}
	}
	if d := EvidenceDeficit(full, "CONFIRMED", nil); d != nil {
		t.Errorf("full bundle deficit = %q, want nil", *d)
	}
}

func TestClauseMet(t *testing.T) {
	low := genFinding(ev("E1", "manual"))
	if ClauseMet(low, GateRequirement{Types: nil, MinLevel: "E2"}) {
		t.Error("E1 should not satisfy an E2 any-type clause")
	}
	high := genFinding(ev("E3", "manual"))
	if !ClauseMet(high, GateRequirement{Types: nil, MinLevel: "E2"}) {
		t.Error("E3 should satisfy an E2 any-type clause")
	}
	restricted := GateRequirement{Types: setOf("foundry-test", "fuzz"), MinLevel: "E4"}
	ok := genFinding(ev("E5", "fuzz"))
	if !ClauseMet(ok, restricted) {
		t.Error("E5 fuzz should satisfy the foundry/fuzz E4 clause")
	}
	strong := genFinding(ev("E7", "manual"))
	if ClauseMet(strong, restricted) {
		t.Error("E7 manual must NOT satisfy the foundry/fuzz clause")
	}
	weak := genFinding(ev("E2", "fuzz"))
	if ClauseMet(weak, restricted) {
		t.Error("E2 fuzz must NOT satisfy an E4 clause")
	}
	junk := genFinding(validation.VObj(kv("description", validation.VStr("no level"))))
	if ClauseMet(junk, GateRequirement{Types: nil, MinLevel: "E0"}) {
		t.Error("level-less item must not satisfy any clause")
	}
}

func TestFindingLevel(t *testing.T) {
	if got, _ := FindingLevel(genFinding()); got != "E0" {
		t.Errorf("no evidence = %q, want E0", got)
	}
	got, _ := FindingLevel(genFinding(ev("E3", "manual"), ev("E5", "fuzz"), ev("E1", "manual")))
	if got != "E5" {
		t.Errorf("evidence E3,E5,E1 = %q, want E5", got)
	}
}

// ---- storage --------------------------------------------------------------

// Port of tests/test_findings.py::
// test_load_all_findings_orders_by_created_at_then_id — deterministic
// regardless of the random uuid4 filenames: order is (created_at,
// finding_id), NOT the filename glob order.
func TestLoadAllFindingsOrdersByCreatedAtThenID(t *testing.T) {
	c := newCampaign(t)
	rows := []struct{ id, ts string }{
		{"F-aaaa", "2026-01-03T00:00:00+00:00"}, // newest
		{"F-bbbb", "2026-01-01T00:00:00+00:00"}, // oldest
		{"F-cccc", "2026-01-02T00:00:00+00:00"}, // middle
		{"F-dddd", "2026-01-01T00:00:00+00:00"}, // created_at tie with F-bbbb
	}
	for _, r := range rows {
		v := validation.VObj(
			kv("finding_id", validation.VStr(r.id)),
			kv("created_at", validation.VStr(r.ts)),
			kv("updated_at", validation.VStr(r.ts)),
		)
		if err := validation.WriteJson(FindingPath(c, r.id), v, ""); err != nil {
			t.Fatal(err)
		}
	}
	got, err := LoadAllFindings(c)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"F-bbbb", "F-dddd", "F-cccc", "F-aaaa"}
	if len(got) != len(want) {
		t.Fatalf("load_all_findings = %d rows, want %d", len(got), len(want))
	}
	for i, w := range want {
		if id := objStr(got[i], "finding_id"); id != w {
			t.Errorf("row %d = %s, want %s", i, id, w)
		}
	}
}

func TestFindingPathAndNewFindingID(t *testing.T) {
	c := &state.Campaign{FindingsDir: "findings"}
	if got, want := FindingPath(c, "F-abcdef123456"), "findings/F-abcdef123456.json"; got != want {
		t.Errorf("FindingPath = %q, want %q", got, want)
	}
	re := regexp.MustCompile(`^F-[0-9a-f]{12}$`)
	a, b := NewFindingID(), NewFindingID()
	if !re.MatchString(a) {
		t.Errorf("NewFindingID = %q, want ^F-[0-9a-f]{12}$", a)
	}
	if a == b {
		t.Errorf("two fresh ids collided: %q", a)
	}
}

func TestSaveLoadFindingRoundTrip(t *testing.T) {
	c := newCampaign(t)
	const at = "2026-01-01T00:00:00+00:00"
	f := validFinding("F-abcdef123456", c.CampaignID, at)
	if err := SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
	if objStr(f, "updated_at") == at {
		t.Error("save_finding must re-stamp updated_at")
	}
	got, err := LoadFinding(c, "F-abcdef123456")
	if err != nil {
		t.Fatal(err)
	}
	if id := objStr(got, "finding_id"); id != "F-abcdef123456" {
		t.Errorf("round-trip finding_id = %q", id)
	}
	if _, err := LoadFinding(c, "F-000000000000"); err == nil ||
		!strings.Contains(err.Error(), "no finding 'F-000000000000' in "+c.CampaignID) {
		t.Errorf("missing-finding error = %v", err)
	}
	// an invalid finding is rejected by the schema (and the in-place
	// updated_at stamp still happens first, as in Python)
	bad := validFinding("F-abcdef123457", c.CampaignID, at)
	bad.O = bad.O[:1]
	if err := SaveFinding(c, &bad); err == nil {
		t.Error("invalid finding must fail schema validation")
	}
}

func TestLoadLiveFindingsFiltersTerminalJunk(t *testing.T) {
	c := newCampaign(t)
	const at = "2026-01-01T00:00:00+00:00"
	for _, s := range []struct{ id, status string }{
		{"F-000000000001", "HYPOTHESIS"},
		{"F-000000000002", "DUPLICATE"},
		{"F-000000000003", "OUT_OF_SCOPE"},
		{"F-000000000004", "CONFIRMED"},
	} {
		v := validation.VObj(
			kv("finding_id", validation.VStr(s.id)),
			kv("status", validation.VStr(s.status)),
			kv("created_at", validation.VStr(at)),
		)
		if err := validation.WriteJson(FindingPath(c, s.id), v, ""); err != nil {
			t.Fatal(err)
		}
	}
	live, err := LoadLiveFindings(c)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"F-000000000001", "F-000000000004"}
	if len(live) != len(want) {
		t.Fatalf("load_live_findings = %d rows, want %d", len(live), len(want))
	}
	for i, w := range want {
		if id := objStr(live[i], "finding_id"); id != w {
			t.Errorf("live row %d = %s, want %s", i, id, w)
		}
	}
}

// newCampaign is a temp campaign root (mirrors the Python `camp` fixture).
func newCampaign(t *testing.T) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "Acme Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// validFinding is a schema-valid HYPOTHESIS (the minimum the finding schema
// accepts), used by the storage tests.
func validFinding(id, campaignID, at string) validation.Value {
	return validation.VObj(
		kv("finding_id", validation.VStr(id)),
		kv("campaign_id", validation.VStr(campaignID)),
		kv("snapshot_ids", validation.VObj(kv("source", validation.VStr("SNAP-abcdef12")))),
		kv("title", validation.VStr("round-trip hypothesis for storage")),
		kv("status", validation.VStr("HYPOTHESIS")),
		kv("trajectory", validation.VStr("code")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("reentrancy")),
			kv("description", validation.VStr("reentrancy drains the vault balance")),
		)),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()),
		)),
		kv("evidence", validation.VArr()),
		kv("risk", validation.VObj()),
		kv("dedup", validation.VObj()),
		kv("history", validation.VArr()),
		kv("created_at", validation.VStr(at)),
		kv("updated_at", validation.VStr(at)),
	)
}
