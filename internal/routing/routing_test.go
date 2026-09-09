package routing

// Port of tests/test_routing.py: assumption-driven next-action routing
// (task 7, §4.3). These tests pin the ranking, the policy-as-data layering,
// and the loop hook.

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

func assumption(aid string, blocking bool, status string, options, deps []string,
	aType string) validation.Value {
	opts := []validation.Value{}
	for _, o := range options {
		opts = append(opts, validation.VStr(o))
	}
	depVals := []validation.Value{}
	for _, d := range deps {
		depVals = append(depVals, validation.VStr(d))
	}
	return validation.VObj(
		kv("id", validation.VStr(aid)),
		kv("type", validation.VStr(aType)),
		kv("claim", validation.VStr("checkable proposition "+aid+": the path "+
			"is reachable and exploitable as described")),
		kv("status", validation.VStr(status)),
		kv("model_belief", validation.VFloat(0.5)),
		kv("blocking", validation.VBool(blocking)),
		kv("dependencies", validation.VArr(depVals...)),
		kv("verification_options", validation.VArr(opts...)),
		kv("support", validation.VArr()),
		kv("contradictions", validation.VArr()))
}

// plainAssumption is assumption(aid, options=[...]) with the defaults.
func plainAssumption(aid string, options ...string) validation.Value {
	return assumption(aid, true, "UNKNOWN", options, nil, "reachability")
}

func synthFinding(bugClass string, evidence []validation.Value,
	assumptions ...validation.Value) validation.Value {
	ev := evidence
	if ev == nil {
		ev = []validation.Value{}
	}
	return validation.VObj(
		kv("finding_id", validation.VStr("F-synth")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr(bugClass)))),
		kv("evidence", validation.VArr(ev...)),
		kv("assumptions", validation.VArr(assumptions...)))
}

func hypo() validation.Value {
	return validation.VObj(
		kv("title", validation.VStr("Attacker drains the vault through the "+
			"unsettled window")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("reentrancy")),
			kv("description", validation.VStr(
				"external call before state finality")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/Vault.sol")),
			kv("function", validation.VStr("withdraw"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()))))
}

func newCamp(t *testing.T) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "routing-program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// liveFinding is the fixture: a real campaign finding with two assumptions.
func liveFinding(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	f, err := findings.IngestHypothesis(c, hypo(), "code", "test", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	one := int64(1)
	if _, err := findings.SetAssumptions(c, fid, []validation.Value{
		plainAssumption("A1", "static-analysis"),
		plainAssumption("A2", "callgraph"),
	}, &one, "proposer"); err != nil {
		t.Fatal(err)
	}
	finding, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	return finding
}

func rankedIDs(t *testing.T, actions []validation.Value) []string {
	t.Helper()
	out := []string{}
	for _, a := range actions {
		out = append(out, objStr(a, "assumption_id"))
	}
	return out
}

func pairs(t *testing.T, actions []validation.Value) []string {
	t.Helper()
	out := []string{}
	for _, a := range actions {
		out = append(out, objStr(a, "assumption_id")+"/"+objStr(a, "tool_id"))
	}
	return out
}

// ---------------------------------------------------------------------------
// dependency_impact
// ---------------------------------------------------------------------------

func TestDependencyChainRanksHighestImpactResolverFirst(t *testing.T) {
	finding := synthFinding("unclassified", nil,
		plainAssumption("A1", "callgraph"),
		assumption("A2", true, "UNKNOWN", []string{"source-slice"},
			[]string{"A1"}, "reachability"),
		assumption("A3", true, "UNKNOWN", []string{"resemble"},
			[]string{"A2"}, "reachability"))
	for _, tc := range []struct {
		aid  string
		want int
	}{{"A1", 2}, {"A2", 1}, {"A3", 0}} {
		got, err := DependencyImpact(finding, tc.aid)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Errorf("dependency_impact(%s) = %d, want %d", tc.aid, got, tc.want)
		}
	}
	ranked, err := NextActions(finding, nil, validation.VNull())
	if err != nil {
		t.Fatal(err)
	}
	if got := rankedIDs(t, ranked); !eqStrings(got, []string{"A1", "A2", "A3"}) {
		t.Errorf("ranked = %v", got)
	}
}

func TestDependencyImpactCountsOnlyUnresolvedAndIsCycleSafe(t *testing.T) {
	finding := synthFinding("unclassified", nil,
		plainAssumption("A1", "callgraph"),
		assumption("A2", true, "SUPPORTED", []string{"callgraph"},
			[]string{"A1"}, "reachability"),
		assumption("A3", true, "UNKNOWN", []string{"callgraph"},
			[]string{"A1", "A2"}, "reachability"))
	got, err := DependencyImpact(finding, "A1")
	if err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Errorf("dependency_impact(A1) = %d, want 1", got)
	}
	cyclic := synthFinding("unclassified", nil,
		assumption("A4", true, "UNKNOWN", []string{"callgraph"},
			[]string{"A5"}, "reachability"),
		assumption("A5", true, "UNKNOWN", []string{"callgraph"},
			[]string{"A4"}, "reachability"))
	got, err = DependencyImpact(cyclic, "A4")
	if err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Errorf("cyclic dependency_impact(A4) = %d, want 1", got)
	}
	if _, err := DependencyImpact(finding, "A9"); err == nil ||
		!strings.Contains(err.Error(), "A9") {
		t.Errorf("err = %v", err)
	}
}

// ---------------------------------------------------------------------------
// gate_value
// ---------------------------------------------------------------------------

func TestResolvedFloorZeroesGateValue(t *testing.T) {
	policy, err := LoadPolicy(nil)
	if err != nil {
		t.Fatal(err)
	}
	bare := synthFinding("reentrancy", nil, plainAssumption("A1", "callgraph"))
	g, err := GateValue(bare, "A1", policy)
	if err != nil {
		t.Fatal(err)
	}
	if !(g > 0.0) {
		t.Errorf("gate = %v, want > 0", g)
	}
	met := synthFinding("reentrancy",
		[]validation.Value{validation.VObj(
			kv("level", validation.VStr("E4")),
			kv("type", validation.VStr("foundry-test")))},
		plainAssumption("A1", "callgraph"))
	g, err = GateValue(met, "A1", policy)
	if err != nil {
		t.Fatal(err)
	}
	if g != 0.0 {
		t.Errorf("gate = %v, want 0", g)
	}
}

func TestGateValueGapScalesWithOptionTier(t *testing.T) {
	policy, err := LoadPolicy(nil)
	if err != nil {
		t.Fatal(err)
	}
	weak := synthFinding("unclassified", nil, plainAssumption("A1", "callgraph"))
	strong := synthFinding("unclassified", nil, plainAssumption("A1", "fork"))
	g, _ := GateValue(weak, "A1", policy)
	if math.Abs(g-0.25) > 1e-9 {
		t.Errorf("weak gate = %v, want 0.25", g)
	}
	g, _ = GateValue(strong, "A1", policy)
	if g != 0.0 {
		t.Errorf("strong gate = %v, want 0", g)
	}
}

func TestEffectiveFloorIsMaxOfPlaybookAndClassConfirmFloor(t *testing.T) {
	if got := findings.RequiredLevelFor("CONFIRMED", "bridge-message"); got != "E6" {
		t.Errorf("CLASS_CONFIRM_FLOOR[bridge-message] = %s", got)
	}
	if got := findings.RequiredLevelFor("CONFIRMED", "upgrade-initializer"); got != "E4" {
		t.Errorf("CLASS_CONFIRM_FLOOR[upgrade-initializer] = %s", got)
	}
	if got := floorNumber(synthFinding("bridge-message", nil)); got != 6 {
		t.Errorf("floor(bridge-message) = %d, want 6", got)
	}
	if got := floorNumber(synthFinding("upgrade-initializer", nil)); got != 4 {
		t.Errorf("floor(upgrade-initializer) = %d, want 4", got)
	}
}

func TestBridgeMessageGateUsesTrueE6Floor(t *testing.T) {
	policy, err := LoadPolicy(nil)
	if err != nil {
		t.Fatal(err)
	}
	finding := synthFinding("bridge-message", nil,
		plainAssumption("A1", "callgraph"))
	g, err := GateValue(finding, "A1", policy)
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(g-1.0) > 1e-9 {
		t.Errorf("gate = %v, want 1.0", g)
	}
}

func TestUpgradeInitializerGateUsesTrueE4Floor(t *testing.T) {
	policy, err := LoadPolicy(nil)
	if err != nil {
		t.Fatal(err)
	}
	finding := synthFinding("upgrade-initializer", nil,
		plainAssumption("A1", "callgraph"))
	g, err := GateValue(finding, "A1", policy)
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(g-0.75) > 1e-9 {
		t.Errorf("gate = %v, want 0.75", g)
	}
}

func TestTrueFloorFlipsRankingViaCeilingCompression(t *testing.T) {
	finding := synthFinding("bridge-message", nil,
		plainAssumption("A1", "invariant-check", "fork"),
		plainAssumption("A2", "callgraph", "fork"))
	ranked, err := NextActions(finding, nil, validation.VNull())
	if err != nil {
		t.Fatal(err)
	}
	got := pairs(t, ranked)
	want := []string{"A1/fork", "A2/fork"}
	if len(got) < 2 || !eqStrings(got[:2], want) {
		t.Errorf("ranked = %v, want first two %v", got, want)
	}
}

// ---------------------------------------------------------------------------
// policy layering + validation
// ---------------------------------------------------------------------------

func TestPolicyOverrideWithZeroCostWeightChangesOrder(t *testing.T) {
	c := newCamp(t)
	finding := synthFinding("unclassified", nil,
		plainAssumption("A1", "static-analysis"),
		plainAssumption("A2", "callgraph"))
	def, err := NextActions(finding, nil, validation.VNull())
	if err != nil {
		t.Fatal(err)
	}
	if got := rankedIDs(t, def); !eqStrings(got, []string{"A2", "A1"}) {
		t.Errorf("default ranked = %v", got)
	}
	override := `{"weights":{"dependency_impact":1.0,"evidence_value":1.0,` +
		`"cost":0.0,"gate_value":1.5}}`
	if err := os.WriteFile(filepath.Join(c.Dir, "assumption_routing.json"),
		[]byte(override), 0o644); err != nil {
		t.Fatal(err)
	}
	reranked, err := NextActions(finding, c, validation.VNull())
	if err != nil {
		t.Fatal(err)
	}
	if got := rankedIDs(t, reranked); !eqStrings(got, []string{"A1", "A2"}) {
		t.Errorf("reranked = %v", got)
	}
}

func TestLoadPolicyTwoTierLayering(t *testing.T) {
	c := newCamp(t)
	pol, err := LoadPolicy(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := floatAt(objAt(pol, "weights"), "cost"); math.Abs(got-0.5) > 1e-9 {
		t.Errorf("default cost weight = %v", got)
	}
	if err := os.WriteFile(filepath.Join(c.Dir, "assumption_routing.json"),
		[]byte(`{"weights":{"cost":0.0}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	pol, err = LoadPolicy(c)
	if err != nil {
		t.Fatal(err)
	}
	if got := floatAt(objAt(pol, "weights"), "cost"); got != 0.0 {
		t.Errorf("campaign cost weight = %v", got)
	}
	if got := floatAt(objAt(pol, "weights"), "gate_value"); math.Abs(got-1.5) > 1e-9 {
		t.Errorf("campaign gate weight = %v", got)
	}
}

func TestBadPolicyMissingToolIDFailsLoudNamingIt(t *testing.T) {
	bad := delKey(DefaultPolicy(), "tool_cost", "fork")
	finding := synthFinding("unclassified", nil,
		plainAssumption("A1", "callgraph"))
	_, err := NextActions(finding, nil, bad)
	if err == nil || !strings.Contains(err.Error(), "fork") {
		t.Fatalf("err = %v", err)
	}
}

func TestBadCampaignLocalPolicyFailsLoudNamingIt(t *testing.T) {
	c := newCamp(t)
	bad := delKey(DefaultPolicy(), "tool_evidence_tier", "trace")
	if err := os.WriteFile(filepath.Join(c.Dir, "assumption_routing.json"),
		[]byte(validation.CanonCompact(bad)), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadPolicy(c)
	if err == nil || !strings.Contains(err.Error(), "trace") {
		t.Fatalf("err = %v", err)
	}
}

func TestPolicyRejectsBadWeightsTiersCosts(t *testing.T) {
	finding := synthFinding("unclassified", nil,
		plainAssumption("A1", "callgraph"))
	badWeights := setKey(DefaultPolicy(), "weights", validation.VObj(
		kv("dependency_impact", validation.VFloat(1.0))))
	if _, err := NextActions(finding, nil, badWeights); err == nil ||
		!strings.Contains(err.Error(), "weights") {
		t.Errorf("weights err = %v", err)
	}
	badTier := setKey(DefaultPolicy(), "tool_evidence_tier",
		setKey(objAt(DefaultPolicy(), "tool_evidence_tier"), "fork",
			validation.VInt(9)))
	if _, err := NextActions(finding, nil, badTier); err == nil ||
		!strings.Contains(err.Error(), "fork") {
		t.Errorf("tier err = %v", err)
	}
	badCost := setKey(DefaultPolicy(), "tool_cost",
		setKey(objAt(DefaultPolicy(), "tool_cost"), "fork",
			validation.VStr("interstellar")))
	if _, err := NextActions(finding, nil, badCost); err == nil ||
		!strings.Contains(err.Error(), "fork") {
		t.Errorf("cost err = %v", err)
	}
}

func TestExamplePolicyCoversEveryRegistryTool(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(wd, "..", "..", "config",
		"assumption_routing.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	example, err := validation.ParseOrdered(raw)
	if err != nil {
		t.Fatal(err)
	}
	reg := registrySet()
	for _, key := range []string{"tool_evidence_tier", "tool_cost"} {
		m := objAt(example, key)
		if len(m.O) != len(reg) {
			t.Errorf("%s covers %d tools, registry has %d", key, len(m.O),
				len(reg))
		}
		for _, pair := range m.O {
			if !reg[pair.K] {
				t.Errorf("%s names unknown tool %s", key, pair.K)
			}
		}
	}
	// and the example itself validates as a policy
	if err := ValidatePolicy(delKeysPrefixed(example, "_"), "example"); err != nil {
		t.Errorf("example policy invalid: %v", err)
	}
}

// ---------------------------------------------------------------------------
// next_actions semantics
// ---------------------------------------------------------------------------

func TestUnknownToolInVerificationOptionsIsSkipped(t *testing.T) {
	finding := synthFinding("unclassified", nil,
		plainAssumption("A1", "not-a-real-tool", "callgraph"))
	ranked, err := NextActions(finding, nil, validation.VNull())
	if err != nil {
		t.Fatal(err)
	}
	if got := pairs(t, ranked); !eqStrings(got, []string{"A1/callgraph"}) {
		t.Errorf("ranked = %v", got)
	}
	stranded := synthFinding("unclassified", nil,
		plainAssumption("A1", "not-a-real-tool"))
	ranked, err = NextActions(stranded, nil, validation.VNull())
	if err != nil {
		t.Fatal(err)
	}
	if len(ranked) != 0 {
		t.Errorf("stranded = %v", ranked)
	}
}

func TestHuntOrderFallbackWhenNoUsableOptions(t *testing.T) {
	c := newCamp(t)
	finding := synthFinding("reentrancy", nil, plainAssumption("A1"))
	ranked, err := NextActions(finding, c, validation.VNull())
	if err != nil {
		t.Fatal(err)
	}
	if len(ranked) == 0 {
		t.Fatal("no candidates")
	}
	if got := objStr(ranked[0], "assumption_id"); got != "A1" {
		t.Errorf("assumption_id = %s", got)
	}
	if got := objStr(ranked[0], "tool_id"); got != "callgraph" {
		t.Errorf("tool_id = %s", got)
	}
}

func TestEmptyWhenAllBlockingAssumptionsResolved(t *testing.T) {
	finding := synthFinding("unclassified", nil,
		assumption("A1", true, "SUPPORTED", nil, nil, "reachability"),
		assumption("A2", true, "REFUTED", nil, nil, "reachability"),
		assumption("A3", false, "UNKNOWN", nil, nil, "reachability"))
	ranked, err := NextActions(finding, nil, validation.VNull())
	if err != nil {
		t.Fatal(err)
	}
	if len(ranked) != 0 {
		t.Errorf("ranked = %v", ranked)
	}
}

func TestNonBlockingAndLegacyUnverifiedStatuses(t *testing.T) {
	finding := synthFinding("unclassified", nil,
		assumption("A1", false, "UNKNOWN", nil, nil, "reachability"),
		assumption("A2", true, "UNVERIFIED", []string{"callgraph"}, nil,
			"reachability"))
	ranked, err := NextActions(finding, nil, validation.VNull())
	if err != nil {
		t.Fatal(err)
	}
	if got := rankedIDs(t, ranked); !eqStrings(got, []string{"A2"}) {
		t.Errorf("ranked = %v", got)
	}
}

func TestScoreCandidateShapeAndWeights(t *testing.T) {
	policy, err := LoadPolicy(nil)
	if err != nil {
		t.Fatal(err)
	}
	finding := synthFinding("unclassified", nil,
		plainAssumption("A1", "symbolic"),
		assumption("A2", true, "UNKNOWN", []string{"symbolic"},
			[]string{"A1"}, "reachability"))
	impact, err := DependencyImpact(finding, "A1")
	if err != nil {
		t.Fatal(err)
	}
	gate, err := GateValue(finding, "A1", policy)
	if err != nil {
		t.Fatal(err)
	}
	score, err := ScoreCandidate("A1", "symbolic", finding, policy, impact, gate)
	if err != nil {
		t.Fatal(err)
	}
	// impact 1 * 1.0, tier 3 * 1.0, -2 * 0.5, gate 0 (tier 3 past floor 2)
	want := [4]float64{1.0, 3.0, -1.0, 0.0}
	for i := range want {
		if score[i] != want[i] {
			t.Errorf("score[%d] = %v, want %v", i, score[i], want[i])
		}
	}
}

func TestRankingIsDeterministicWithAssumptionIDTiebreak(t *testing.T) {
	finding := synthFinding("unclassified", nil,
		plainAssumption("A2", "callgraph"),
		plainAssumption("A1", "callgraph"))
	first, err := NextActions(finding, nil, validation.VNull())
	if err != nil {
		t.Fatal(err)
	}
	second, err := NextActions(finding, nil, validation.VNull())
	if err != nil {
		t.Fatal(err)
	}
	if validation.CanonCompact(validation.VArr(first...)) !=
		validation.CanonCompact(validation.VArr(second...)) {
		t.Error("ranking not deterministic")
	}
	if got := rankedIDs(t, first); !eqStrings(got, []string{"A1", "A2"}) {
		t.Errorf("ranked = %v", got)
	}
	for _, a := range first {
		if len(a.O) != 4 {
			t.Errorf("keys = %d, want 4", len(a.O))
		}
		if got := objAt(a, "score"); got.Kind != validation.Arr ||
			len(got.A) != 4 {
			t.Errorf("score = %v", got)
		}
		if !strings.Contains(objStr(a, "reason"), "dependency impact") {
			t.Errorf("reason = %s", objStr(a, "reason"))
		}
	}
}

func TestNextActionsIsPure(t *testing.T) {
	c := newCamp(t)
	finding := liveFinding(t, c)
	beforeEvents, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	beforeFiles := readFindings(t, c)
	for i := 0; i < 2; i++ {
		if _, err := NextActions(finding, c, validation.VNull()); err != nil {
			t.Fatal(err)
		}
	}
	afterEvents, _ := c.Events()
	if len(afterEvents) != len(beforeEvents) {
		t.Errorf("events changed: %d -> %d", len(beforeEvents), len(afterEvents))
	}
	afterFiles := readFindings(t, c)
	if len(afterFiles) != len(beforeFiles) {
		t.Errorf("finding files changed")
	}
	for k, v := range beforeFiles {
		if afterFiles[k] != v {
			t.Errorf("finding %s changed", k)
		}
	}
}

// ---------------------------------------------------------------------------
// decide_next loop hook
// ---------------------------------------------------------------------------

func TestDecideNextLogsRoutingDecidedAndLogStaysGreen(t *testing.T) {
	c := newCamp(t)
	finding := liveFinding(t, c)
	fid := objStr(finding, "finding_id")
	before, _ := c.Events()
	decision, err := DecideNext(c, fid, validation.VNull())
	if err != nil {
		t.Fatal(err)
	}
	if got := objStr(decision, "finding_id"); got != fid {
		t.Errorf("finding_id = %s", got)
	}
	actions := objAt(decision, "actions")
	selected := objAt(decision, "selected")
	if !objEq(selected, actions.A[0]) {
		t.Error("selected != actions[0]")
	}
	if got := objStr(selected, "assumption_id"); got != "A2" {
		t.Errorf("selected = %s, want A2", got)
	}
	after, _ := c.Events()
	newTypes := []string{}
	for _, e := range after[len(before):] {
		newTypes = append(newTypes, objStr(e, "type"))
	}
	if !containsStr(newTypes, "routing.decided") {
		t.Errorf("new types = %v", newTypes)
	}
	for _, ty := range newTypes {
		if strings.HasPrefix(ty, "model.") {
			t.Errorf("model event logged: %s", ty)
		}
	}
	if v, _ := c.VerifyLog(); !v.OK {
		t.Error("chain not ok")
	}
}

func TestDecideNextWithNothingUnresolvedSelectsNone(t *testing.T) {
	c := newCamp(t)
	f, err := findings.IngestHypothesis(c, hypo(), "code", "test", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	one := int64(1)
	if _, err := findings.SetAssumptions(c, fid, []validation.Value{
		assumption("A1", false, "UNKNOWN", []string{"callgraph"}, nil,
			"reachability"),
	}, &one, "proposer"); err != nil {
		t.Fatal(err)
	}
	decision, err := DecideNext(c, fid, validation.VNull())
	if err != nil {
		t.Fatal(err)
	}
	if got := objAt(decision, "actions"); got.Kind != validation.Arr ||
		len(got.A) != 0 {
		t.Errorf("actions = %v", got)
	}
	if objAt(decision, "selected").Kind != validation.Null {
		t.Error("selected should be null")
	}
	if v, _ := c.VerifyLog(); !v.OK {
		t.Error("chain not ok")
	}
}

// ---- test-local helpers ---------------------------------------------------

func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

func floatAt(v validation.Value, key string) float64 {
	x := objAt(v, key)
	switch x.Kind {
	case validation.Flt:
		return x.F
	case validation.Int:
		return float64(x.I)
	}
	return 0
}

// delKey removes a key from a nested object map (policy fixtures).
func delKey(policy validation.Value, mapKey, key string) validation.Value {
	inner := objAt(policy, mapKey)
	out := validation.VObj()
	for _, pair := range inner.O {
		if pair.K != key {
			out.O = append(out.O, pair)
		}
	}
	return setKey(policy, mapKey, out)
}

// delKeysPrefixed drops the `_comment`-style keys a policy layer ignores.
func delKeysPrefixed(v validation.Value, prefix string) validation.Value {
	out := validation.VObj()
	for _, pair := range v.O {
		if strings.HasPrefix(pair.K, prefix) {
			continue
		}
		out.O = append(out.O, pair)
	}
	return out
}

func readFindings(t *testing.T, c *state.Campaign) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(c.FindingsDir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "F-") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(c.FindingsDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = string(raw)
	}
	return out
}

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
			other := objAt(b, pair.K)
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
