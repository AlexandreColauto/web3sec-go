// assumptions_test.go: G10 projection — AssumptionTable + ASSUMPTION GAP rows.
//
// One row per chains[] entry (declared order); missing optionals are JSON
// null. Gaps fire only on BRIDGES hops: (a) touched chain with no assumption
// entry, (b) entry with both finality and confirmation_depth absent/null.
package protocolgraph

import (
	"sort"
	"testing"

	"websec/internal/validation"
)

// tableModel builds a minimal model literal with chains, assumptions, rels.
func tableModel(chains, assumptions, relations string) validation.Value {
	raw := `{"protocol_id":"p","name":"nn","contracts":[],"actors":[],"assets":[],"relations":` +
		relations + `,"chains":` + chains
	if assumptions != "" {
		raw += `,"chain_assumptions":` + assumptions
	}
	raw += `}`
	return mustParseJSONForTable(raw)
}

func mustParseJSONForTable(raw string) validation.Value {
	v, err := validation.ParseOrdered([]byte(raw))
	if err != nil {
		panic(err)
	}
	return v
}

// rowField extracts a row's field compact rendering ("null" for missing).
func rowField(row validation.Value, key string) string {
	for _, pair := range row.O {
		if pair.K == key {
			return validation.CanonCompact(pair.V)
		}
	}
	return "<absent>"
}

// TestAssumptionTableRows pins the row shape: declared chains[] order (NOT
// alpha), verbatim detail values, JSON null for every missing optional.
func TestAssumptionTableRows(t *testing.T) {
	m := tableModel(
		`["mainnet","arbitrum"]`,
		`[{"chain":"mainnet","finality":"probabilistic","confirmation_depth":12,"messenger":"canonical"}]`,
		`[]`,
	)
	rows, gaps := AssumptionTable(m)
	if len(gaps) != 0 {
		t.Fatalf("no relations ⇒ zero gaps, got %d", len(gaps))
	}
	if len(rows) != 2 {
		t.Fatalf("one row per chain, got %d", len(rows))
	}
	// Declared order, not alpha ("arbitrum" < "mainnet").
	if got := rowField(rows[0], "chain"); got != `"mainnet"` {
		t.Errorf("row 0 chain = %s, want mainnet", got)
	}
	if got := rowField(rows[1], "chain"); got != `"arbitrum"` {
		t.Errorf("row 1 chain = %s, want arbitrum", got)
	}
	want := map[string]string{
		"chain": `"mainnet"`, "finality": `"probabilistic"`,
		"confirmation_depth": "12", "messenger": `"canonical"`,
		"validator_set": "null", "threshold": "null", "separator": "null",
	}
	for k, w := range want {
		if got := rowField(rows[0], k); got != w {
			t.Errorf("mainnet row %s = %s, want %s", k, got, w)
		}
	}
	for _, k := range []string{"finality", "confirmation_depth", "messenger", "validator_set", "threshold", "separator"} {
		if got := rowField(rows[1], k); got != "null" {
			t.Errorf("undeclared arbitrum row %s = %s, want null", k, got)
		}
	}
}

// TestAssumptionGapsBothRules fires (a) for the undeclared chain and (b)
// for the declared-but-empty-finality entry on a single shared hop.
func TestAssumptionGapsBothRules(t *testing.T) {
	m := tableModel(
		`["mainnet","arbitrum"]`,
		`[{"chain":"mainnet","messenger":"canonical"}]`,
		`[{"from":"mainnet-bridge","rel":"BRIDGES","to":"arbitrum-inbox"}]`,
	)
	_, gaps := AssumptionTable(m)
	if len(gaps) != 2 {
		t.Fatalf("want 2 gaps (a)+(b), got %d: %s", len(gaps), validation.CanonCompact(validation.VArr(gaps...)))
	}
	// Sorted by hop then chain then reason: arbitrum < mainnet.
	if got := rowField(gaps[0], "chain"); got != `"arbitrum"` {
		t.Errorf("gap 0 chain = %s, want arbitrum", got)
	}
	if got := rowField(gaps[0], "reason"); got != `"missing-assumptions"` {
		t.Errorf("gap 0 reason = %s, want missing-assumptions", got)
	}
	if got := rowField(gaps[1], "chain"); got != `"mainnet"` {
		t.Errorf("gap 1 chain = %s, want mainnet", got)
	}
	if got := rowField(gaps[1], "reason"); got != `"finality-unspecified"` {
		t.Errorf("gap 1 reason = %s, want finality-unspecified", got)
	}
	for _, g := range gaps {
		if got := rowField(g, "hop"); got != `"mainnet-bridge->arbitrum-inbox"` {
			t.Errorf("gap hop = %s, want from->to label", got)
		}
	}
}

// TestAssumptionGapsDedupe pins one gap per (hop, chain, reason) triple:
// duplicate BRIDGES relations collapse; distinct hops sort by hop.
func TestAssumptionGapsDedupe(t *testing.T) {
	m := tableModel(
		`["mainnet"]`,
		``,
		`[{"from":"z-bridge-mainnet","rel":"BRIDGES","to":"vault"},{"from":"z-bridge-mainnet","rel":"BRIDGES","to":"vault"},{"from":"a-bridge-mainnet","rel":"BRIDGES","to":"vault"}]`,
	)
	rows, gaps := AssumptionTable(m)
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	if len(gaps) != 2 {
		t.Fatalf("dup hop dedupes, distinct hop kept ⇒ 2 gaps, got %d", len(gaps))
	}
	hops := []string{rowField(gaps[0], "hop"), rowField(gaps[1], "hop")}
	if !sort.StringsAreSorted(hops) {
		t.Errorf("gaps not sorted by hop: %v", hops)
	}
	if hops[0] != `"a-bridge-mainnet->vault"` || hops[1] != `"z-bridge-mainnet->vault"` {
		t.Errorf("unexpected hop labels: %v", hops)
	}
	for _, g := range gaps {
		if got := rowField(g, "reason"); got != `"missing-assumptions"` {
			t.Errorf("gap reason = %s, want missing-assumptions", got)
		}
	}
}

// TestAssumptionNoAssumptionsKey pins the all-null rows plus one gap per
// touched chain when chain_assumptions is absent entirely.
func TestAssumptionNoAssumptionsKey(t *testing.T) {
	m := tableModel(
		`["mainnet","arbitrum"]`,
		``,
		`[{"from":"mainnet-bridge","rel":"BRIDGES","to":"arbitrum-inbox"}]`,
	)
	rows, gaps := AssumptionTable(m)
	if len(rows) != 2 {
		t.Fatalf("want 2 rows, got %d", len(rows))
	}
	for i, r := range rows {
		for _, k := range []string{"finality", "confirmation_depth", "messenger", "validator_set", "threshold", "separator"} {
			if got := rowField(r, k); got != "null" {
				t.Errorf("row %d %s = %s, want null", i, k, got)
			}
		}
	}
	if len(gaps) != 2 {
		t.Fatalf("one gap per touched chain ⇒ 2, got %d", len(gaps))
	}
	for _, g := range gaps {
		if got := rowField(g, "reason"); got != `"missing-assumptions"` {
			t.Errorf("gap reason = %s, want missing-assumptions", got)
		}
	}
}

// TestAssumptionNoRelations pins zero gaps when no BRIDGES hop exists —
// including a model whose relations list is non-BRIDGES only.
func TestAssumptionNoRelations(t *testing.T) {
	m := tableModel(
		`["mainnet"]`,
		`[{"chain":"mainnet","finality":"instant","confirmation_depth":1}]`,
		`[{"from":"a","rel":"CALLS","to":"mainnet-vault"}]`,
	)
	rows, gaps := AssumptionTable(m)
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	if len(gaps) != 0 {
		t.Fatalf("non-BRIDGES relations ⇒ zero gaps, got %d", len(gaps))
	}
}

// TestAssumptionViaTouch pins that a hop touches a chain via the `via`
// field too, and that only the two documented reasons ever appear.
func TestAssumptionViaTouch(t *testing.T) {
	m := tableModel(
		`["mainnet","optimism"]`,
		`[{"chain":"mainnet","finality":"probabilistic","confirmation_depth":64}]`,
		`[{"from":"relayer","rel":"BRIDGES","to":"vault","via":"optimism-faucet"}]`,
	)
	_, gaps := AssumptionTable(m)
	if len(gaps) != 1 {
		t.Fatalf("via-touch on undeclared optimism ⇒ 1 gap, got %d", len(gaps))
	}
	if got := rowField(gaps[0], "chain"); got != `"optimism"` {
		t.Errorf("gap chain = %s, want optimism", got)
	}
	if got := rowField(gaps[0], "reason"); got != `"missing-assumptions"` {
		t.Errorf("gap reason = %s, want missing-assumptions", got)
	}
	for _, g := range gaps {
		r := rowField(g, "reason")
		if r != `"missing-assumptions"` && r != `"finality-unspecified"` {
			t.Errorf("undocumented reason: %s", r)
		}
	}
}
