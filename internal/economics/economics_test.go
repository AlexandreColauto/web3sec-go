// economics_test.go: the Go twin of webv2.economics. Ports
// tests/test_economics_transforms.py 1:1 and pins every output against
// Python-generated vectors (testdata/golden_economics.json, catalog.json).
package economics

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/protocolgraph"
	"websec/internal/validation"
)

func readTestJson(t *testing.T, name string) validation.Value {
	t.Helper()
	v, err := validation.ReadJson(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return v
}

func dump(v validation.Value) string { return validation.DumpIndented(v) }

// setKey is dict.update for one key: replace in place, else append.
func setKey(o []validation.KV, k string, v validation.Value) []validation.KV {
	for i := range o {
		if o[i].K == k {
			o[i].V = v
			return o
		}
	}
	return append(o, kv(k, v))
}

// modelWithAsset is the Python test helper model_with_asset(**asset).
func modelWithAsset(over ...validation.KV) validation.Value {
	asset := validation.VObj(
		kv("id", validation.VStr("A")),
		kv("kind", validation.VStr("token")),
		kv("decimals", validation.VInt(18)),
	)
	for _, o := range over {
		asset.O = setKey(asset.O, o.K, o.V)
	}
	return validation.VObj(
		kv("protocol_id", validation.VStr("P1")),
		kv("name", validation.VStr("Odd Protocol")),
		kv("contracts", validation.VArr()),
		kv("actors", validation.VArr()),
		kv("assets", validation.VArr(asset)),
		kv("relations", validation.VArr()),
	)
}

// transformNames is the Python helper transform_names(model).
func transformNames(model validation.Value) map[string]bool {
	out := map[string]bool{}
	for _, t := range GenerateTransforms(model) {
		out[objStrOf(t, "name")] = true
	}
	return out
}

func objStrOf(v validation.Value, key string) string {
	for _, pair := range v.O {
		if pair.K == key {
			return pair.V.S
		}
	}
	return ""
}

// ---- ported from tests/test_economics_transforms.py -----------------------

func TestOddDecimalsFamilyFlagIsEmitted(t *testing.T) {
	m := modelWithAsset(kv("decimals", validation.VInt(7)))
	risky := protocolgraph.ExternalAssets(m)
	if len(risky) != 1 {
		t.Fatalf("risky = %s, want one row", dump(validation.VArr(risky...)))
	}
	flags := objAt(risky[0], "flags")
	if dump(flags) != "[\n  \"odd-decimals-7\"\n]" {
		t.Errorf("flags = %s, want [odd-decimals-7]", dump(flags))
	}
}

func TestOddDecimalsTransformFiresOnParameterizedFlag(t *testing.T) {
	// The regression: `_has_flag` used exact membership, so the emitter's
	// `odd-decimals-<n>` never matched and the transform silently never fired.
	m := modelWithAsset(kv("decimals", validation.VInt(7)))
	names := transformNames(m)
	if !names["odd-decimals-mismatch"] {
		t.Errorf("odd-decimals-mismatch missing: %s",
			dump(validation.VArr(GenerateTransforms(m)...)))
	}
	ids := map[string]string{}
	for _, tr := range GenerateTransforms(m) {
		ids[objStrOf(tr, "name")] = objStrOf(tr, "transform_id")
	}
	if ids["odd-decimals-mismatch"] != "TR-011" {
		t.Errorf("odd-decimals-mismatch id = %q, want TR-011",
			ids["odd-decimals-mismatch"])
	}
}

func TestOddDecimalsTransformQuietForStandardDecimals(t *testing.T) {
	names := transformNames(modelWithAsset(kv("decimals", validation.VInt(18))))
	if names["odd-decimals-mismatch"] {
		t.Errorf("odd-decimals-mismatch fired for decimals=18")
	}
	for _, want := range []string{"donation-attack", "flash-loan-amplification",
		"liquidity-withdrawal-bounded"} {
		if !names[want] {
			t.Errorf("universal transform %q missing", want)
		}
	}
}

func TestDebtAssetAddsSolvencyEquation(t *testing.T) {
	eqs := BuildEquations(modelWithAsset(
		kv("kind", validation.VStr("debt")), kv("id", validation.VStr("D"))))
	if len(eqs) != 1 {
		t.Fatalf("equations = %s, want one", dump(validation.VArr(eqs...)))
	}
	found := false
	for _, e := range eqs {
		if strings.Contains(objStrOf(e, "equation"), "liq_threshold") {
			found = true
		}
	}
	if !found {
		t.Errorf("no liq_threshold equation: %s", dump(validation.VArr(eqs...)))
	}
	breaks := objAt(eqs[0], "breakable_by")
	hasInsolvency := false
	for _, b := range breaks.A {
		if b.S == "insolvency-by-withdraw-order" {
			hasInsolvency = true
		}
	}
	if !hasInsolvency {
		t.Errorf("breakable_by = %s, want insolvency-by-withdraw-order", dump(breaks))
	}
}

// ---- byte-exact vectors (generated from the Python twin) ------------------

var goldenModels = []string{"odd_asset", "debt_asset", "share_only", "dup_eq",
	"kitchen_sink"}

// goldenCases wires each economics output to its golden key.
func goldenCases() []struct {
	key string
	run func(validation.Value) validation.Value
} {
	return []struct {
		key string
		run func(validation.Value) validation.Value
	}{
		{"build_equations", func(m validation.Value) validation.Value {
			return validation.VArr(BuildEquations(m)...)
		}},
		{"generate_transforms", func(m validation.Value) validation.Value {
			return validation.VArr(GenerateTransforms(m)...)
		}},
		{"equation_gaps", func(m validation.Value) validation.Value {
			return validation.VArr(EquationGaps(m)...)
		}},
		{"economic_summary", EconomicSummary},
	}
}

func TestGoldenEconomicsMatchPythonVectors(t *testing.T) {
	golden := readTestJson(t, "golden_economics.json")
	cases := goldenCases()
	checked := 0
	for _, name := range goldenModels {
		model := readTestJson(t, name+"_model.json")
		group := objAt(golden, name)
		if group.Kind != validation.Obj {
			t.Fatalf("golden has no %s group", name)
		}
		for _, tc := range cases {
			want := objAt(group, tc.key)
			if want.Kind == validation.Null {
				t.Errorf("golden %s/%s missing", name, tc.key)
				continue
			}
			if got := tc.run(model); dump(got) != dump(want) {
				t.Errorf("%s/%s mismatch\n got: %s\nwant: %s", name, tc.key,
					dump(got), dump(want))
			}
			checked++
		}
	}
	if checked != len(goldenModels)*len(cases) {
		t.Errorf("checked %d vectors, want %d", checked,
			len(goldenModels)*len(cases))
	}
}

// TestCatalogQuestionsAreByteExact pins every (name, question) string and the
// 1-based catalog index the TR-%03d numbering is derived from.
func TestCatalogQuestionsAreByteExact(t *testing.T) {
	catalog := readTestJson(t, "catalog.json")
	if len(catalog.A) != 12 {
		t.Fatalf("catalog rows = %d, want 12", len(catalog.A))
	}
	for i, row := range catalog.A {
		wantIdx := int64(i + 1)
		if got := objAt(row, "index"); got.I != wantIdx {
			t.Errorf("row %d index = %d, want %d", i, got.I, wantIdx)
		}
		if got, want := transformName(i), objStrOf(row, "name"); got != want {
			t.Errorf("catalog[%d] name = %q, want %q", i, got, want)
		}
		if got, want := transformQuestion(i), objStrOf(row, "question"); got != want {
			t.Errorf("catalog[%d] question\n got: %s\nwant: %s", i, got, want)
		}
	}
}

// TestTransformNumberingContinuesFromCatalogIndex pins that TR-%03d uses the
// CATALOG index, not the output position: a model that fires only entries 1,
// 9, 10, 11 yields exactly TR-001/TR-009/TR-010/TR-011.
func TestTransformNumberingContinuesFromCatalogIndex(t *testing.T) {
	odd := readTestJson(t, "odd_asset_model.json")
	got := GenerateTransforms(odd)
	ids := make([]string, 0, len(got))
	for _, tr := range got {
		ids = append(ids, objStrOf(tr, "transform_id"))
	}
	want := []string{"TR-001", "TR-009", "TR-010", "TR-011"}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Errorf("transform ids = %v, want %v", ids, want)
	}
	all := GenerateTransforms(readTestJson(t, "kitchen_sink_model.json"))
	if len(all) != 12 {
		t.Fatalf("kitchen sink transforms = %d, want 12", len(all))
	}
	for i, tr := range all {
		wantID := fmt.Sprintf("TR-%03d", i+1)
		if got := objStrOf(tr, "transform_id"); got != wantID {
			t.Errorf("transform %d id = %q, want %q", i, got, wantID)
		}
	}
}

// transformName / transformQuestion expose the unexported catalog to the
// byte-exact string check.
func transformName(i int) string     { return catalog[i].name }
func transformQuestion(i int) string { return catalog[i].question }

// TestEquationNumberingContinuesFromRecordedEquations pins EQ-%03d: the
// counter continues after the recorded economic_relations, a hand-recorded
// equation suppresses the duplicate universal one, and gaps name the missing
// enforcement/break paths.
func TestEquationNumberingContinuesFromRecordedEquations(t *testing.T) {
	sink := BuildEquations(readTestJson(t, "kitchen_sink_model.json"))
	if len(sink) != 4 {
		t.Fatalf("kitchen sink equations = %d, want 4", len(sink))
	}
	for i, want := range []string{"EQ-001", "EQ-002", "EQ-003", "EQ-004"} {
		if got := objStrOf(sink[i], "id"); got != want {
			t.Errorf("equation %d id = %q, want %q", i, got, want)
		}
	}
	dup := BuildEquations(readTestJson(t, "dup_eq_model.json"))
	if len(dup) != 1 {
		t.Fatalf("dup_eq equations = %d, want 1 (recorded suppresses universal)",
			len(dup))
	}
	if objStrOf(dup[0], "meaning") != "recorded by hand" {
		t.Errorf("dup_eq meaning = %q, want the recorded row",
			objStrOf(dup[0], "meaning"))
	}
	gaps := EquationGaps(readTestJson(t, "dup_eq_model.json"))
	if len(gaps) != 1 {
		t.Fatalf("dup_eq gaps = %s, want one", dump(validation.VArr(gaps...)))
	}
	wantMissing := validation.VArr(validation.VStr("enforced_by"),
		validation.VStr("breakable_by"))
	if dump(objAt(gaps[0], "missing")) != dump(wantMissing) {
		t.Errorf("missing = %s, want %s", dump(objAt(gaps[0], "missing")),
			dump(wantMissing))
	}
}

// TestHasFlagMatchesExactOrFamily pins _has_flag: exact match OR the
// "<flag>-<param>" family, and nothing else.
func TestHasFlagMatchesExactOrFamily(t *testing.T) {
	exact := modelWithAsset(kv("nonstandard_behaviors",
		validation.VArr(validation.VStr("odd-decimals"))))
	if !transformNames(exact)["odd-decimals-mismatch"] {
		t.Errorf("exact flag did not fire: %s", dump(validation.VArr(
			GenerateTransforms(exact)...)))
	}
	near := modelWithAsset(kv("nonstandard_behaviors",
		validation.VArr(validation.VStr("odd-decimalsX"))))
	if transformNames(near)["odd-decimals-mismatch"] {
		t.Errorf("near-miss flag fired odd-decimals-mismatch")
	}
	family := modelWithAsset(kv("nonstandard_behaviors",
		validation.VArr(validation.VStr("odd-decimals-2"))))
	if !transformNames(family)["odd-decimals-mismatch"] {
		t.Errorf("family flag did not fire")
	}
}

// TestEconomicSummaryKeyOrder pins the summary shape and key order the
// planner reads (accounting_vars, risky_assets, oracles, equations,
// equation_gaps, transforms).
func TestEconomicSummaryKeyOrder(t *testing.T) {
	summary := EconomicSummary(readTestJson(t, "kitchen_sink_model.json"))
	keys := make([]string, 0, len(summary.O))
	for _, pair := range summary.O {
		keys = append(keys, pair.K)
	}
	want := "accounting_vars,risky_assets,oracles,equations,equation_gaps,transforms"
	if strings.Join(keys, ",") != want {
		t.Errorf("summary keys = %v, want %s", keys, want)
	}
	if objAt(summary, "equations").I != 4 {
		t.Errorf("equations = %s, want 4", dump(objAt(summary, "equations")))
	}
	oracles := objAt(summary, "oracles")
	if dump(oracles) != "[\n  \"ORC-1\",\n  \"ORC-2\"\n]" {
		t.Errorf("oracles = %s", dump(oracles))
	}
}
