package anchorlink

import (
	"testing"

	"websec/internal/validation"
)

// kv is a jval object entry (the tests build artifact values by hand).
func kv(k string, v validation.Value) validation.KV { return validation.KV{K: k, V: v} }

// contract is one protocol_model.contracts[] entry.
func contract(name, path string) validation.Value {
	return validation.VObj(kv("name", validation.VStr(name)),
		kv("path", validation.VStr(path)))
}

// miniModel is the synthesized model: two same-NAME contracts in different
// dirs (the basename collision), Rollup with its entry points, and a second
// contract sharing Rollup's directory (so the lifecycle-id rule has more than
// one candidate path).
func miniModel() validation.Value {
	return validation.VObj(
		kv("contracts", validation.VArr(
			contract("Rollup", "l1/rollup/Rollup.sol"),
			contract("L1MessageQueueWithGasPriceOracle",
				"l1/rollup/L1MessageQueueWithGasPriceOracle.sol"),
			contract("L1ERC20Gateway", "l1/gateways/L1ERC20Gateway.sol"),
			contract("L1ERC20Gateway", "l2/gateways/L1ERC20Gateway.sol"),
		)),
		kv("state_machines", validation.VArr(
			validation.VObj(kv("name", validation.VStr("rollup/BatchLifecycle"))),
		)),
	)
}

func mustOpen(t *testing.T, model validation.Value) *Store {
	t.Helper()
	s, err := Open(model)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

// surfaceRow builds a probe_surface.rows[] entry in the real field shape.
func surfaceRow(rowID, contractName, consumer string, consumerLine int,
	asserter string, asserterLine int, tier int, siblings ...validation.Value) validation.Value {
	return validation.VObj(
		kv("row_id", validation.VStr(rowID)),
		kv("probe", validation.VStr("assertion-strength")),
		kv("axis", validation.VStr("enforcement-timing")),
		kv("lens", validation.VStr("L-03")),
		kv("tier", validation.VInt(int64(tier))),
		kv("rank", validation.VInt(1)),
		kv("assertion_gap", validation.VInt(4)),
		kv("siblings", validation.VArr(siblings...)),
		kv("contract", validation.VStr(contractName)),
		kv("consumer", validation.VStr(consumer)),
		kv("consumer_line", validation.VInt(int64(consumerLine))),
		kv("asserter", validation.VStr(asserter)),
		kv("asserter_line", validation.VInt(int64(asserterLine))),
	)
}

// sibling is one row sibling site.
func sibling(contractName string, line int) validation.Value {
	return validation.VObj(kv("contract", validation.VStr(contractName)),
		kv("line", validation.VInt(int64(line))),
		kv("test_double", validation.VBool(false)))
}

// priority builds a campaign_plan.priorities[] entry in the real field shape.
func priority(id string, components ...string) validation.Value {
	comps := make([]validation.Value, len(components))
	for i, c := range components {
		comps[i] = validation.VStr(c)
	}
	return validation.VObj(
		kv("id", validation.VStr(id)),
		kv("question", validation.VStr("q")),
		kv("risk", validation.VFloat(0.7)),
		kv("components", validation.VArr(comps...)),
		kv("invariant_ids", validation.VArr()),
		kv("status", validation.VStr("open")),
	)
}

// finding builds a findings/*.json entry with one affected file.
func finding(id, file, function string, lines ...int) validation.Value {
	ls := make([]validation.Value, len(lines))
	for i, l := range lines {
		ls[i] = validation.VInt(int64(l))
	}
	return validation.VObj(
		kv("finding_id", validation.VStr(id)),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr(file)),
			kv("function", validation.VStr(function)),
			kv("lines", validation.VArr(ls...))))),
	)
}

func TestOpenRejectsMalformedModel(t *testing.T) {
	if _, err := Open(validation.VNull()); err == nil {
		t.Fatal("Open(null) accepted a non-object model")
	}
	bad := validation.VObj(kv("contracts", validation.VStr("nope")))
	if _, err := Open(bad); err == nil {
		t.Fatal("Open accepted a non-array contracts field")
	}
}

func TestRowTargetsResolvesContractAndRidesFunctions(t *testing.T) {
	s := mustOpen(t, miniModel())
	row := surfaceRow("34589e8588", "Rollup", "commitBatch", 204,
		"finalizeBatch", 496, 0, sibling("Rollup", 204))
	paths, funcs := s.RowTargets(row)
	if len(paths) != 1 || paths[0] != "l1/rollup/Rollup.sol" {
		t.Fatalf("paths = %v", paths)
	}
	if len(funcs) != 2 || funcs[0] != "commitBatch" || funcs[1] != "finalizeBatch" {
		t.Fatalf("funcs = %v", funcs)
	}
}

func TestRowTargetsAmbiguousNameFansOut(t *testing.T) {
	s := mustOpen(t, miniModel())
	row := surfaceRow("a047e6509f", "L1ERC20Gateway", "onDropMessage", 74,
		"finalizeWithdrawERC20", 108, 0, sibling("L1ERC20Gateway", 122))
	paths, funcs := s.RowTargets(row)
	want := []string{"l1/gateways/L1ERC20Gateway.sol", "l2/gateways/L1ERC20Gateway.sol"}
	if len(paths) != len(want) || paths[0] != want[0] || paths[1] != want[1] {
		t.Fatalf("paths = %v, want every candidate of the basename citation", paths)
	}
	if len(funcs) != 2 || funcs[0] != "onDropMessage" || funcs[1] != "finalizeWithdrawERC20" {
		t.Fatalf("funcs = %v", funcs)
	}
}

func TestRowTargetsIncludesSiblings(t *testing.T) {
	s := mustOpen(t, miniModel())
	row := surfaceRow("r1", "Rollup", "commitBatch", 204, "", 0, 0,
		sibling("L1MessageQueueWithGasPriceOracle", 12),
		sibling("L1ERC20Gateway", 9)) // a basename citation: both copies
	paths, _ := s.RowTargets(row)
	want := []string{"l1/rollup/Rollup.sol",
		"l1/rollup/L1MessageQueueWithGasPriceOracle.sol",
		"l1/gateways/L1ERC20Gateway.sol", "l2/gateways/L1ERC20Gateway.sol"}
	if len(paths) != len(want) {
		t.Fatalf("paths = %v, want %v", paths, want)
	}
	for i, p := range want {
		if paths[i] != p {
			t.Fatalf("paths = %v, want %v", paths, want)
		}
	}
}

func TestPriorityTargetsNameLifecycleAndUnknown(t *testing.T) {
	s := mustOpen(t, miniModel())
	if got := s.PriorityTargets(priority("Q-008", "Rollup")); len(got) != 1 ||
		got[0] != "l1/rollup/Rollup.sol" {
		t.Fatalf("name component: %v", got)
	}
	// A lifecycle id is matched by its directory, so it reaches every path
	// under */rollup (the model's state machine name is the licence to do so).
	got := s.PriorityTargets(priority("LC-008", "rollup/BatchLifecycle"))
	want := []string{"l1/rollup/L1MessageQueueWithGasPriceOracle.sol", "l1/rollup/Rollup.sol"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("lifecycle component: %v want %v", got, want)
	}
	for _, c := range []string{"rollup/NopeLifecycle", "l2gw/StandardERC20BridgeLifecycle",
		"RollupX", "l1gw/L1Staking staker lifecycle"} {
		if got := s.PriorityTargets(priority("Q-x", c)); len(got) != 0 {
			t.Errorf("component %q resolved to %v; unknown must resolve to nothing", c, got)
		}
	}
	if got := s.PriorityTargets(priority("Q-x", "L1ERC20Gateway")); len(got) != 2 ||
		got[0] != "l1/gateways/L1ERC20Gateway.sol" ||
		got[1] != "l2/gateways/L1ERC20Gateway.sol" {
		t.Errorf("basename citation component resolved to %v", got)
	}
	if got := s.PriorityTargets(validation.VObj()); len(got) != 0 {
		t.Errorf("components-less priority resolved to %v", got)
	}
}

func TestFindingTargetsSuffixRule(t *testing.T) {
	s := mustOpen(t, miniModel())
	cases := []struct{ file, want string }{
		{"l1/rollup/Rollup.sol", "l1/rollup/Rollup.sol"},
		{"contracts/l1/rollup/Rollup.sol", "l1/rollup/Rollup.sol"},
		{"contracts/contracts/l1/rollup/Rollup.sol", "l1/rollup/Rollup.sol"},
		{"./l1/rollup/Rollup.sol", "l1/rollup/Rollup.sol"},
		{"contracts\\l1\\rollup\\Rollup.sol", "l1/rollup/Rollup.sol"},
		// basename-only does NOT resolve: the rule is directional.
		{"Rollup.sol", ""},
		{"l1/other/Rollup.sol", ""},
		{"l1/gateways/L1ERC20Gateway.sol", "l1/gateways/L1ERC20Gateway.sol"},
		// the same basename in the other dir stays the other contract
		{"contracts/l2/gateways/L1ERC20Gateway.sol", "l2/gateways/L1ERC20Gateway.sol"},
	}
	for _, c := range cases {
		got := s.FindingTargets(finding("F-x", c.file, "f", 1, 2))
		if c.want == "" {
			if len(got) != 0 {
				t.Errorf("FindingTargets(%q) = %v, want nothing", c.file, got)
			}
			continue
		}
		if len(got) != 1 || got[0] != c.want {
			t.Errorf("FindingTargets(%q) = %v, want [%s]", c.file, got, c.want)
		}
	}
}

func TestFindingTargetsAcceptsFileAlias(t *testing.T) {
	s := mustOpen(t, miniModel())
	f := validation.VObj(
		kv("finding_id", validation.VStr("F-x")),
		kv("affected", validation.VArr(validation.VObj(
			kv("file", validation.VStr("contracts/l1/rollup/Rollup.sol")),
			kv("function", validation.VStr("commitBatch")),
			kv("lines", validation.VArr(validation.VInt(204), validation.VInt(320)))))))
	if got := s.FindingTargets(f); len(got) != 1 || got[0] != "l1/rollup/Rollup.sol" {
		t.Fatalf("file alias: %v", got)
	}
}

func TestFindingTargetsLongestModelPathWins(t *testing.T) {
	model := validation.VObj(kv("contracts", validation.VArr(
		contract("RollupRoot", "rollup/Rollup.sol"),
		contract("RollupL1", "l1/rollup/Rollup.sol"),
	)))
	s := mustOpen(t, model)
	got := s.FindingTargets(finding("F-x", "contracts/l1/rollup/Rollup.sol", "f", 1))
	if len(got) != 1 || got[0] != "l1/rollup/Rollup.sol" {
		t.Fatalf("longest path should win: %v", got)
	}
}

// TestBasenameCollisionDoesNotConverge is the F5 fixture: two contracts share
// the name L1ERC20Gateway in different dirs. Basename citations alone must
// converge NEITHER copy; once a finding cites the l1 copy by full path, the
// l1 copy converges and the l2 copy is never dragged in.
func TestBasenameCollisionDoesNotConverge(t *testing.T) {
	s := mustOpen(t, miniModel())
	rows := []validation.Value{
		surfaceRow("gw", "L1ERC20Gateway", "onDropMessage", 74,
			"finalizeWithdrawERC20", 108, 0, sibling("L1ERC20Gateway", 122)),
	}
	prios := []validation.Value{priority("Q-1", "L1ERC20Gateway")}
	// Two stores that both cite only the basename: no full path pins a copy.
	if got := s.Convergences(rows, prios, nil); len(got) != 0 {
		t.Fatalf("basename-only citations converged: %+v", got)
	}
	// A finding citing the l1 copy by full path pins it.
	findings := []validation.Value{
		finding("F-l1", "contracts/l1/gateways/L1ERC20Gateway.sol", "onDropMessage", 85, 93),
	}
	s.Index(rows, prios, findings)
	anchors := s.Convergences(rows, prios, findings)
	var l1 *Anchor
	for i := range anchors {
		if anchors[i].Path == "l2/gateways/L1ERC20Gateway.sol" {
			t.Fatalf("the unnamed l2 copy converged: %+v", anchors[i])
		}
		if anchors[i].Key == "l1/gateways/L1ERC20Gateway.sol" {
			l1 = &anchors[i]
		}
	}
	if l1 == nil {
		t.Fatalf("the pinned l1 copy did not converge: %+v", anchors)
	}
	if len(l1.Stores) != 3 || l1.Stores[0] != StoreFindings ||
		l1.Stores[1] != StorePlan || l1.Stores[2] != StoreSurface {
		t.Fatalf("l1 stores = %v", l1.Stores)
	}
	// A query about the basename still reaches the row: a search may be
	// ambiguous, a convergence claim may not.
	m := s.Query("L1ERC20Gateway.sol#onDropMessage")
	if len(m.Rows) != 1 || m.Rows[0].RowID != "gw" {
		t.Fatalf("basename query rows = %+v", m.Rows)
	}
	if len(m.Findings) != 1 || m.Findings[0] != "F-l1" {
		t.Fatalf("basename query findings = %v", m.Findings)
	}
	// The l2 full path resolves to the l2 copy only.
	if got := s.FindingTargets(finding("F-l2",
		"contracts/l2/gateways/L1ERC20Gateway.sol", "f", 1)); len(got) != 1 ||
		got[0] != "l2/gateways/L1ERC20Gateway.sol" {
		t.Fatalf("l2 resolution = %v", got)
	}
}
