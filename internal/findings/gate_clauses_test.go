package findings

// gate_clauses_test.go: the library-level half of tests/test_gate_checklist.py
// — confirmation_gate_clauses is the single source of the CONFIRMED-gate
// clause set, confirmation_gate_detail is its failing-only view, and the
// transition contract (the failure list's bytes) has not moved. GOLDEN_A and
// GOLDEN_B are the pre-change-tree captures, re-extracted from the live
// Python twin (tests/test_gate_checklist.py) rather than hand-edited.

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

const goldenA = "[{\"check_id\": \"critic-verdict\", \"message\": \"hostile critic verdict is None, need 'confirmed'\", \"remediation\": \"webv2 verdict <fid> confirmed '<reasoning>' --actor <you>\"}, {\"check_id\": \"memory-check\", \"message\": \"no verified graph-memory recall recorded — none recorded, or every recorded check is stale (a referenced row changed or left the store) — run `webv2 recall <CAMPAIGN> --finding <FINDING>`\", \"remediation\": \"webv2 recall <campaign> --finding <fid>   (records a graph-memory consultation)\"}, {\"check_id\": \"reproduction-reproduced\", \"message\": \"reproduction status is None, need 'reproduced'\", \"remediation\": \"webv2 mint <fid> --exec <EXEC-ID>   (a reproduced attempt, sandboxed)\"}, {\"check_id\": \"evidence-floor\", \"message\": \"evidence level E0 < required E5 for CONFIRMED\", \"remediation\": \"webv2 mint <fid> --exec <EXEC-ID>   (or, for a NAMED decision: webv2 floors set — an override, logged, never a silent edit). Economic-class E7: when no USD figure is defensible, record the decision instead — webv2 impact <campaign> <fid> --unpriceable --ceiling '<capacity basis>' --reason '<why>' --actor <you>\"}, {\"check_id\": \"evidence-floor-unreachable\", \"message\": \"structurally unreachable in this campaign: no deployment/chain pin on the active snapshot — fork evidence (E5+) has no fork target, for single-call PoCs and multi-tx sequence PoCs (`webv2 sequence run`) alike; pin one (`webv2 snap`) or record a floor override (`webv2 floors set`); FORK_RPC_URL is not set — the fork-runner profile cannot reach a chain — if the target truly cannot produce that evidence, record the decision with `webv2 floors set` instead of editing the framework's floor table\", \"remediation\": \"webv2 snap / export FORK_RPC_URL   (make the evidence reachable) — or webv2 floors set to record the override as a decision\"}, {\"check_id\": \"reproduction-tier\", \"message\": \"evidence floor E5 demands a fork-level reproduction (T3+), but tier_reached is 'none' — record the fork-tier attempt (record_attempt / attempt_and_mint) before confirming\", \"remediation\": \"webv2 mint <campaign> <fid> --exec <fork exec> --description '...' --tier T3   (record the fork-tier attempt the evidence is based on)\"}]"

const goldenB = "[{\"check_id\": \"memory-check\", \"message\": \"no verified graph-memory recall recorded — none recorded, or every recorded check is stale (a referenced row changed or left the store) — run `webv2 recall <CAMPAIGN> --finding <FINDING>`\", \"remediation\": \"webv2 recall <campaign> --finding <fid>   (records a graph-memory consultation)\"}, {\"check_id\": \"evidence-floor\", \"message\": \"no evidence of type ['balance-delta', 'manual'] at level >= E7 and no unpriceable decision recorded (`webv2 impact <CAMPAIGN> <finding> --unpriceable --ceiling '<capacity basis>' --reason <why no figure is defensible> --actor <you>`)\", \"remediation\": \"webv2 mint <fid> --exec <EXEC-ID>   (or, for a NAMED decision: webv2 floors set — an override, logged, never a silent edit). Economic-class E7: when no USD figure is defensible, record the decision instead — webv2 impact <campaign> <fid> --unpriceable --ceiling '<capacity basis>' --reason '<why>' --actor <you>\"}, {\"check_id\": \"evidence-floor-unreachable\", \"message\": \"structurally unreachable in this campaign: no deployment/chain pin on the active snapshot — fork evidence (E5+) has no fork target, for single-call PoCs and multi-tx sequence PoCs (`webv2 sequence run`) alike; pin one (`webv2 snap`) or record a floor override (`webv2 floors set`); FORK_RPC_URL is not set — the fork-runner profile cannot reach a chain — if the target truly cannot produce that evidence, record the decision with `webv2 floors set` instead of editing the framework's floor table\", \"remediation\": \"webv2 snap / export FORK_RPC_URL   (make the evidence reachable) — or webv2 floors set to record the override as a decision\"}]"

// goldenFailure is the parsed shape of one GOLDEN_* entry.
type goldenFailure struct {
	CheckID     string `json:"check_id"`
	Message     string `json:"message"`
	Remediation string `json:"remediation"`
}

func parseGolden(t *testing.T, s string) []goldenFailure {
	t.Helper()
	var out []goldenFailure
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatal("empty golden")
	}
	return out
}

// maskedFailures renders the detail the way Python's _norm does: the finding
// id and campaign id are masked, then the JSON is parsed back.
func maskedFailures(t *testing.T, c *state.Campaign,
	detail []GateFailure, fid string) []goldenFailure {
	t.Helper()
	vals := make([]validation.Value, 0, len(detail))
	for _, d := range detail {
		vals = append(vals, d.Value())
	}
	s := validation.CanonCompact(validation.VArr(vals...))
	s = strings.ReplaceAll(s, fid, "<FINDING>")
	s = strings.ReplaceAll(s, c.CampaignID, "<CAMPAIGN>")
	var out []goldenFailure
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		t.Fatalf("unmarshal %s: %v", s, err)
	}
	return out
}

func assertFailuresEqual(t *testing.T, got, want []goldenFailure) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("failures = %d, want %d\n got %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("failure %d = %+v\nwant %+v", i, got[i], want[i])
		}
	}
}

// minimalFinding is the MINIMAL fixture of tests/test_gate_checklist.py.
func minimalFinding(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	payload := validation.VObj(
		kv("title", validation.VStr("a test hypothesis")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("first-depositor-inflation")),
			kv("description", validation.VStr("the first depositor sets the "+
				"share price with a single wei, inflating later depositors' "+
				"price")),
		)),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr(validation.VStr("deposit"))),
		)),
	)
	f, err := IngestHypothesis(c, payload, "code", "t", "")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// gateReadyEconomic is _gate_ready_economic(camp, memory_check=False): the
// economic-class finding whose only open clause is the E7 quantification.
func gateReadyEconomic(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	payload := hypoPayload(
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("oracle-manipulation")),
			kv("description", validation.VStr("the oracle is manipulable")),
		)),
	)
	f, err := IngestHypothesis(c, payload, "economic", "t", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	rec := testExec(t, c, "docker-networkless", fid, 0, "PASS: test_exploit\n")
	pairs := []struct{ level, typ string }{
		{"E4", "foundry-test"}, {"E5", "fork-test"}}
	for i, p := range pairs {
		if _, err := AddEvidence(c, fid, execEvidenceItem(rec, p.level,
			p.typ, "gate fixture", fmt.Sprintf("EV-u%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := SetCriticVerdict(c, fid, "confirmed", "mechanism sound"); err != nil {
		t.Fatal(err)
	}
	f, err = LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	ver := asDict(objAt(f, "verification"))
	ver.O = validation.SetOrAppend(ver.O, "reproduction", validation.VObj(
		kv("tier_reached", validation.VStr("T3")),
		kv("status", validation.VStr("reproduced")),
		kv("attempts", validation.VArr()),
	))
	f.O = validation.SetOrAppend(f.O, "verification", ver)
	if err := SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
	out, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Port of test_gate_detail_byte_identical_to_pre_change_tree.
func TestGateDetailByteIdenticalToPreChangeTree(t *testing.T) {
	c := ingestCamp(t)
	f := minimalFinding(t, c)
	detail, err := ConfirmationGateDetail(c, f)
	if err != nil {
		t.Fatal(err)
	}
	want := parseGolden(t, goldenA)
	assertFailuresEqual(t, maskedFailures(t, c, detail, objStr(f, "finding_id")),
		want)
	// _confirmation_gates renders the same list as "<check_id>: <message>"
	gates, err := ConfirmationGates(c, f)
	if err != nil {
		t.Fatal(err)
	}
	if len(gates) != len(want) {
		t.Fatalf("gates = %d, want %d", len(gates), len(want))
	}
	for i, w := range want {
		masked := strings.ReplaceAll(gates[i], objStr(f, "finding_id"),
			"<FINDING>")
		masked = strings.ReplaceAll(masked, c.CampaignID, "<CAMPAIGN>")
		if masked != w.CheckID+": "+w.Message {
			t.Errorf("gate %d = %q", i, masked)
		}
	}
}

// Port of test_gate_detail_identical_with_satisfied_clauses_present.
func TestGateDetailIdenticalWithSatisfiedClausesPresent(t *testing.T) {
	c := ingestCamp(t)
	f := gateReadyEconomic(t, c)
	detail, err := ConfirmationGateDetail(c, f)
	if err != nil {
		t.Fatal(err)
	}
	want := parseGolden(t, goldenB)
	assertFailuresEqual(t, maskedFailures(t, c, detail, objStr(f, "finding_id")),
		want)
}

// Port of test_clause_collector_is_the_only_source: detail is exactly the
// failing subset of the clause collector.
func TestClauseCollectorIsTheOnlySource(t *testing.T) {
	c := ingestCamp(t)
	f := minimalFinding(t, c)
	clauses, err := ConfirmationGateClauses(c, f)
	if err != nil {
		t.Fatal(err)
	}
	detail, err := ConfirmationGateDetail(c, f)
	if err != nil {
		t.Fatal(err)
	}
	failing := []GateFailure{}
	for _, cl := range clauses {
		if !cl.OK {
			failing = append(failing, GateFailure{CheckID: cl.CheckID,
				Message: cl.Message, Remediation: cl.Remediation})
		}
	}
	if len(failing) != len(detail) {
		t.Fatalf("subset = %d, detail = %d", len(failing), len(detail))
	}
	for i := range detail {
		if failing[i] != detail[i] {
			t.Errorf("clause %d = %+v, detail = %+v", i, failing[i], detail[i])
		}
	}
	// every clause carries its remediation from GATE_REMEDIATION
	for _, cl := range clauses {
		if cl.Remediation != GATE_REMEDIATION[cl.CheckID] {
			t.Errorf("clause %s remediation = %q", cl.CheckID, cl.Remediation)
		}
	}
}

// Port of test_named_decision_line_needs_an_economic_clause (library half):
// a non-economic class has no economic clause for the decision to satisfy.
func TestNamedDecisionLineNeedsAnEconomicClause(t *testing.T) {
	c := ingestCamp(t)
	f := minimalFinding(t, c)
	fid := objStr(f, "finding_id")
	imp := validation.VObj(
		kv("priceable", validation.VBool(false)),
		kv("ceiling", validation.VStr(ceilingBasis)),
	)
	f.O = validation.SetOrAppend(f.O, "economic_impact", imp)
	if err := SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if UnpriceableDecision(loaded) == nil {
		t.Fatal("fixture must record an unpriceable decision")
	}
	if EconomicClausePresent(c, loaded) {
		t.Error("first-depositor-inflation has no economic clause")
	}
	// the economic class DOES have one
	ec := ingestCamp(t)
	ef := gateReadyEconomic(t, ec)
	if !EconomicClausePresent(ec, ef) {
		t.Error("oracle-manipulation must carry an economic clause")
	}
}

// ceilingBasis is the CEILING fixture string.
const ceilingBasis = "capacity basis: the sink is an address[255] test " +
	"constant — no live liquidity bounds it"
