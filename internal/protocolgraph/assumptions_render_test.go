// assumptions_render_test.go: Task 4 (G10 table rendering) — the shared
// line-builder RenderAssumptionLines fed by AssumptionTable.
//
// TDD: written BEFORE the builder; must FAIL (undefined
// RenderAssumptionLines) until protocolgraph renders it.
package protocolgraph

import (
	"testing"

	"websec/internal/validation"
)

// renderTable feeds tableModel through AssumptionTable into the builder.
func renderTable(t *testing.T, chains, assumptions, relations string) []string {
	t.Helper()
	rows, gaps := AssumptionTable(tableModel(chains, assumptions, relations))
	return RenderAssumptionLines(rows, gaps)
}

// TestRenderAssumptionRowLines pins the exact per-row format: only the four
// table columns, pyStr values, `declared: none` for null details.
func TestRenderAssumptionRowLines(t *testing.T) {
	got := renderTable(t,
		`["mainnet","arbitrum"]`,
		`[{"chain":"mainnet","finality":"probabilistic","confirmation_depth":12,"messenger":"canonical","separator":"chainid"}]`,
		`[]`,
	)
	want := []string{
		"- mainnet: finality=probabilistic confirmations=12 messenger=canonical separator=chainid",
		"- arbitrum: finality=declared: none confirmations=declared: none messenger=declared: none separator=declared: none",
	}
	if len(got) != len(want) {
		t.Fatalf("lines = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestRenderAssumptionNullDetail pins the shared-builder law: a null detail
// renders `declared: none` in its column (never empty, never "None").
func TestRenderAssumptionNullDetail(t *testing.T) {
	rows, _ := AssumptionTable(tableModel(
		`["mainnet"]`,
		`[{"chain":"mainnet","finality":"instant"}]`,
		`[]`,
	))
	got := RenderAssumptionLines(rows, nil)
	if len(got) != 1 {
		t.Fatalf("want 1 line, got %q", got)
	}
	want := "- mainnet: finality=instant confirmations=declared: none messenger=declared: none separator=declared: none"
	if got[0] != want {
		t.Errorf("line = %q, want %q", got[0], want)
	}
}

// TestRenderAssumptionGapLines pins the exact per-gap format with the
// reason rendered verbatim.
func TestRenderAssumptionGapLines(t *testing.T) {
	got := renderTable(t,
		`["mainnet","arbitrum"]`,
		``,
		`[{"from":"mainnet-bridge","rel":"BRIDGES","to":"arbitrum-inbox"}]`,
	)
	want := []string{
		"- mainnet: finality=declared: none confirmations=declared: none messenger=declared: none separator=declared: none",
		"- arbitrum: finality=declared: none confirmations=declared: none messenger=declared: none separator=declared: none",
		"- ASSUMPTION GAP mainnet-bridge->arbitrum-inbox arbitrum: missing-assumptions",
		"- ASSUMPTION GAP mainnet-bridge->arbitrum-inbox mainnet: missing-assumptions",
	}
	if len(got) != len(want) {
		t.Fatalf("lines = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestRenderAssumptionDirectRows pins the builder as a pure string function:
// hand-built rows/gaps render without touching AssumptionTable.
func TestRenderAssumptionDirectRows(t *testing.T) {
	rows := []validation.Value{validation.VObj(
		kv("chain", validation.VStr("mainnet")),
		kv("finality", validation.VNull()),
		kv("confirmation_depth", validation.VNull()),
		kv("messenger", validation.VNull()),
		kv("separator", validation.VNull()),
	)}
	gaps := []validation.Value{validation.VObj(
		kv("hop", validation.VStr("a->b")),
		kv("chain", validation.VStr("mainnet")),
		kv("reason", validation.VStr("finality-unspecified")),
	)}
	got := RenderAssumptionLines(rows, gaps)
	want := []string{
		"- mainnet: finality=declared: none confirmations=declared: none messenger=declared: none separator=declared: none",
		"- ASSUMPTION GAP a->b mainnet: finality-unspecified",
	}
	if len(got) != len(want) {
		t.Fatalf("lines = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, got[i], want[i])
		}
	}
}
