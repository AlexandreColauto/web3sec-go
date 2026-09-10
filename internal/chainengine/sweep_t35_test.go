package chainengine

// T35 testmap re-triage: tests/test_design_upgrades.py section 1 — terminal
// search with capital, and the materialized-terminal annotation.

import (
	"encoding/json"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// hypoCapital is hypo with an explicit attacker document (the Python file's
// _profile and capital tests override attacker.required_capital_usd /
// attacker.capital_profile).
func hypoCapital(t *testing.T, c *state.Campaign, class string, granted,
	required []string, title string, attacker validation.Value) validation.Value {
	t.Helper()
	f, err := findings.IngestHypothesis(c, validation.VObj(
		kv("title", validation.VStr(title)),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr(class)),
			kv("description", validation.VStr(
				"mechanism described in detail here")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/V.sol")),
			kv("function", validation.VStr("f"))))),
		kv("attacker", attacker),
		kv("capabilities", validation.VObj(
			kv("granted", strArr(granted)),
			kv("required", strArr(required)))),
	), "code", "test", "")
	if err != nil {
		t.Fatalf("ingest hypothesis: %v", err)
	}
	return f
}

// eoa is the flat attacker document: profile, no capabilities, and the legacy
// required_capital_usd headline.
func eoa(capital float64, profile ...validation.KV) validation.Value {
	att := validation.VObj(
		kv("profile", validation.VStr("arbitrary EOA")),
		kv("capabilities", validation.VArr()),
		kv("required_capital_usd", validation.VFloat(capital)))
	for _, p := range profile {
		att.O = validation.SetOrAppend(att.O, p.K, p.V)
	}
	return att
}

// priceSkewPair is the file's two-finding terminal pair.
func priceSkewPair(t *testing.T, c *state.Campaign, f2Attacker validation.Value) (validation.Value, validation.Value) {
	t.Helper()
	f1 := hypo(t, c, "access-control", []string{"control_perceived_asset_price"},
		nil, "Unauthenticated price setter")
	f2 := hypoCapital(t, c, "logic-error", []string{"withdraw_unbacked_assets"},
		[]string{"control_perceived_asset_price"},
		"Rounding drift enables unbacked withdrawals", f2Attacker)
	for _, f := range []validation.Value{f1, f2} {
		confirm(t, c, objStr(f, "finding_id"), "E5", "T3")
	}
	return f1, f2
}

// hitPath returns the path document for the given finding pair.
func hitPath(t *testing.T, c *state.Campaign, ids ...string) validation.Value {
	t.Helper()
	paths, err := FindTerminalChains(c, nil, 5, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		ps := listOf(p, "path").A
		if len(ps) != len(ids) {
			continue
		}
		match := true
		for i, id := range ids {
			if pyStr(ps[i]) != id {
				match = false
			}
		}
		if match {
			return p
		}
	}
	t.Fatalf("no terminal path %v in %v", ids, paths)
	return validation.VNull()
}

func TestTerminalPathFromBaselineThroughTwoFindings(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	f1, f2 := priceSkewPair(t, c, eoa(5000))
	hit := hitPath(t, c, objStr(f1, "finding_id"), objStr(f2, "finding_id"))
	if got := objStr(hit, "terminal_capability"); got != "withdraw_unbacked_assets" {
		t.Fatalf("terminal_capability = %q", got)
	}
	if got := objStr(hit, "terminal_finding"); got != objStr(f2, "finding_id") {
		t.Fatalf("terminal_finding = %q", got)
	}
	if got := pyFloatAt(hit, "total_capital_required_usd"); got != 5000 {
		t.Fatalf("total_capital_required_usd = %v, want 5000", got)
	}
	rep, err := TerminalReport(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range listOf(rep, "shortest_by_terminal").A {
		if objStr(p, "terminal_capability") == "withdraw_unbacked_assets" {
			found = true
		}
	}
	if !found {
		t.Fatalf("shortest_by_terminal lacks the capability: %v",
			listOf(rep, "shortest_by_terminal"))
	}
}

func TestCapitalIsSummedAlongThePath(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	f1, f2 := priceSkewPair(t, c, eoa(5000))
	// f1 carries its own 2000 on top of f2's 5000: the path costs 7000.
	f1v, err := findings.LoadFinding(c, objStr(f1, "finding_id"))
	if err != nil {
		t.Fatal(err)
	}
	f1v.O = validation.SetOrAppend(f1v.O, "attacker", eoa(2000))
	if err := findings.SaveFinding(c, &f1v); err != nil {
		t.Fatal(err)
	}
	hit := hitPath(t, c, objStr(f1, "finding_id"), objStr(f2, "finding_id"))
	if got := pyFloatAt(hit, "total_capital_required_usd"); got != 7000 {
		t.Fatalf("total_capital_required_usd = %v, want 7000", got)
	}
}

func TestCapitalProfileFlowsThroughPaths(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	f1, f2 := priceSkewPair(t, c, eoa(5000,
		kv("capital_profile", validation.VObj(
			kv("required_usd", validation.VFloat(5000)),
			kv("recoverable_usd", validation.VFloat(4800)),
			kv("irrecoverable_cost_usd", validation.VFloat(200)),
			kv("atomic_usd", validation.VFloat(5000)),
			kv("borrowable_usd", validation.VFloat(3000))))))
	hit := hitPath(t, c, objStr(f1, "finding_id"), objStr(f2, "finding_id"))
	if got := pyFloatAt(hit, "total_capital_required_usd"); got != 5000 {
		t.Fatalf("legacy headline = %v, want 5000", got)
	}
	bd := objAt(hit, "capital_breakdown")
	want := map[string]float64{
		"required_usd": 5000, "recoverable_usd": 4800,
		"irrecoverable_cost_usd": 200, "atomic_usd": 5000,
		"borrowable_usd": 3000, "net_at_risk_usd": 200,
	}
	for k, w := range want {
		if got := pyFloatAt(bd, k); got != w {
			t.Errorf("capital_breakdown.%s = %v, want %v", k, got, w)
		}
	}
}

func TestCapitalBreakdownDefaultsForUnprofiledFindings(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	f1, f2 := priceSkewPair(t, c, eoa(5000))
	hit := hitPath(t, c, objStr(f1, "finding_id"), objStr(f2, "finding_id"))
	bd := objAt(hit, "capital_breakdown")
	for k, w := range map[string]float64{
		"required_usd": 5000, "recoverable_usd": 0, "borrowable_usd": 0,
		"net_at_risk_usd": 5000,
	} {
		if got := pyFloatAt(bd, k); got != w {
			t.Errorf("capital_breakdown.%s = %v, want %v", k, got, w)
		}
	}
}

func TestTerminalSearchIgnoresUnconfirmedFindings(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	hypo(t, c, "access-control", []string{"control_perceived_asset_price"},
		nil, "Unauthenticated price setter")
	hypo(t, c, "logic-error", []string{"withdraw_unbacked_assets"},
		[]string{"control_perceived_asset_price"},
		"Rounding drift enables unbacked withdrawals")
	paths, err := FindTerminalChains(c, nil, 5, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 0 {
		t.Fatalf("unconfirmed findings must not be reachable: %v", paths)
	}
}

func TestMaterializeTerminalChainAnnotatesAndVerifies(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	f1, f2 := priceSkewPair(t, c, eoa(5000))
	ids := []string{objStr(f1, "finding_id"), objStr(f2, "finding_id")}
	term := validation.VObj(
		kv("capability", validation.VStr("withdraw_unbacked_assets")),
		kv("via_finding", validation.VStr(objStr(f2, "finding_id"))),
		kv("total_capital_required_usd", validation.VFloat(0)))
	ch, err := MaterializeChain(c, ids, "Price skew to unbacked withdrawals",
		"", nil, &term)
	if err != nil {
		t.Fatal(err)
	}
	td := objAt(ch, "terminal")
	if objStr(td, "capability") != "withdraw_unbacked_assets" {
		t.Fatalf("terminal = %v", td)
	}
	if objStr(td, "via_finding") != objStr(f2, "finding_id") {
		t.Fatalf("via_finding = %v", objStr(td, "via_finding"))
	}
	all, err := findings.LoadAllFindings(c)
	if err != nil {
		t.Fatal(err)
	}
	var chain validation.Value
	for _, f := range all {
		if objStr(f, "status") == "CHAIN" {
			chain = f
		}
	}
	if chain.Kind != validation.Obj {
		t.Fatal("no CHAIN super-finding written")
	}
	if got := chainTerminalCapability(t, chain); got != "withdraw_unbacked_assets" {
		t.Fatalf("dedup_meta.terminal.capability = %q", got)
	}
	rep, err := TerminalReport(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := listOf(rep, "materialized_terminal_chains").A
	if len(got) != 1 || objStr(got[0], "chain_id") != objStr(ch, "chain_id") {
		t.Fatalf("materialized_terminal_chains = %v", got)
	}
}

// chainTerminalCapability decodes the JSON-encoded dedup_meta.terminal string
// the CHAIN super-finding carries (dedup_meta values are strings).
func chainTerminalCapability(t *testing.T, chain validation.Value) string {
	t.Helper()
	termRaw := objStr(objAt(chain, "dedup_meta"), "terminal")
	if termRaw == "" {
		t.Fatalf("dedup_meta.terminal missing: %v", objAt(chain, "dedup_meta"))
	}
	var doc struct {
		Capability string `json:"capability"`
	}
	if err := json.Unmarshal([]byte(termRaw), &doc); err != nil {
		t.Fatalf("dedup_meta.terminal = %q: %v", termRaw, err)
	}
	return doc.Capability
}
