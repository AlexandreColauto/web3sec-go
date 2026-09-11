// corpus_test.go: 1:1 ports of tests/test_corpus_surface_inventory.py,
// tests/test_corpus_surface_scoring.py,
// tests/test_corpus_surface_report.py and the corpus-owned cases from
// tests/test_bundle_corpus_keys.py.
//
// The Python fixtures seed the real stores (eval_store / shared_memory /
// learning); those modules are the concurrent agent's P3 packages, so the
// ports install the same rows through this package's seams — the CS-side
// contract under test is identical.
package corpus

import (
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/structidx"
	"websec/internal/validation"
)

// ---- fixtures ------------------------------------------------------------

func seedRow(t *testing.T, memoryID, bugClass, summary string) validation.Value {
	t.Helper()
	return validation.VObj(
		validation.KV{K: "memory_id", V: validation.VStr(memoryID)},
		validation.KV{K: "campaign_id", V: validation.VStr("ingest:test:case")},
		validation.KV{K: "finding_id", V: validation.VNull()},
		validation.KV{K: "snapshot_id", V: validation.VNull()},
		validation.KV{K: "created_at", V: validation.VStr("2026-09-06T00:00:00+00:00")},
		validation.KV{K: "kind", V: validation.VStr("confirmed")},
		validation.KV{K: "status", V: validation.VStr("CONFIRMED")},
		validation.KV{K: "pattern", V: validation.VStr("Reentrancy Attack")},
		validation.KV{K: "bug_class", V: validation.VStr(bugClass)},
		validation.KV{K: "cwe", V: validation.VNull()},
		validation.KV{K: "evidence_summary", V: validation.VStr(summary)},
		validation.KV{K: "partition", V: validation.VStr("dev")},
		validation.KV{K: "schema_version", V: validation.VInt(2)},
		validation.KV{K: "rejection_class", V: validation.VNull()},
		validation.KV{K: "deciding_propositions", V: validation.VArr()},
		validation.KV{K: "promotion_status", V: validation.VStr("promoted")},
		validation.KV{K: "approved_by", V: validation.VStr("operator")},
		validation.KV{K: "approved_at", V: validation.VStr("2026-09-06T00:00:00+00:00")},
	)
}

func wrapRow(row validation.Value) validation.Value {
	return validation.VObj(
		validation.KV{K: "program_key", V: validation.VStr("test|other|-")},
		validation.KV{K: "published_at", V: validation.VStr("2026-09-06T00:00:00+00:00")},
		validation.KV{K: "row", V: row},
		validation.KV{K: "scope", V: validation.VStr("global")},
	)
}

func evalCase(caseID, bugClass, outcome, severity string) validation.Value {
	return validation.VObj(
		validation.KV{K: "case_id", V: validation.VStr(caseID)},
		validation.KV{K: "source", V: validation.VObj(
			validation.KV{K: "dataset", V: validation.VStr("scabench")},
			validation.KV{K: "record_id", V: validation.VStr(caseID)},
			validation.KV{K: "url", V: validation.VStr("https://example.com/" + caseID)},
		)},
		validation.KV{K: "partition", V: validation.VStr("dev")},
		validation.KV{K: "program", V: validation.VObj(
			validation.KV{K: "program", V: validation.VStr("Acme Protocol")},
			validation.KV{K: "platform", V: validation.VStr("immunefi")},
			validation.KV{K: "chains", V: validation.VArr(validation.VStr("ethereum"))},
		)},
		validation.KV{K: "gold", V: validation.VObj(
			validation.KV{K: "outcome", V: validation.VStr(outcome)},
			validation.KV{K: "bug_class", V: validation.VStr(bugClass)},
			validation.KV{K: "severity", V: validation.VStr(severity)},
			validation.KV{K: "root_cause", V: validation.VStr("external call before state update")},
			validation.KV{K: "locations", V: validation.VArr()},
		)},
		validation.KV{K: "code", V: validation.VObj(
			validation.KV{K: "repo", V: validation.VStr("acme/vault")},
			validation.KV{K: "commit", V: validation.VStr(strings.Repeat("a", 40))},
			validation.KV{K: "files", V: validation.VArr(validation.VStr("src/Vault.sol"))},
		)},
		validation.KV{K: "created_at", V: validation.VStr("2026-09-06T00:00:00+00:00")},
		validation.KV{K: "schema_version", V: validation.VInt(2)},
	)
}

// withSeams installs the shared-memory and eval-store seam data.
func withSeams(t *testing.T, rows, cases []validation.Value) {
	t.Helper()
	SetLoadSharedMemory(func(root string) ([]validation.Value, error) {
		return rows, nil
	})
	SetListEvalCases(func() ([]validation.Value, error) { return cases, nil })
	t.Cleanup(func() {
		SetLoadSharedMemory(nil)
		SetListEvalCases(nil)
	})
}

func newCampaign(t *testing.T, program string) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), program, state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// indexFor is _index: a one-file snapshot index for a source string.
func indexFor(t *testing.T, source string) validation.Value {
	t.Helper()
	root := filepath.Join(t.TempDir(), "snap")
	if err := writeFile(filepath.Join(root, "Fixture.sol"), source); err != nil {
		t.Fatal(err)
	}
	c := newCampaign(t, "test-program")
	idx, err := structidx.IndexSnapshot(c, root, structidx.DefaultBackend)
	if err != nil {
		t.Fatal(err)
	}
	return idx
}

// ---- class_inventory -----------------------------------------------------

func TestInventoryCountsBothStores(t *testing.T) {
	withSeams(t, []validation.Value{wrapRow(seedRow(t, "MEM-inv0001",
		"reentrancy", "X was exploited via Reentrancy. Reported loss: 5,000 USD."))},
		[]validation.Value{
			evalCase("CASE-"+strings.Repeat("b", 12), "reentrancy", "confirmed-exploitable", "high"),
			evalCase("CASE-"+strings.Repeat("c", 12), "logic-error", "confirmed-exploitable", "high"),
			evalCase("CASE-"+strings.Repeat("d", 12), "unmapped", "confirmed-exploitable", "high"),
		})
	inv, err := ClassInventory(newCampaign(t, "test-program"))
	if err != nil {
		t.Fatal(err)
	}
	r := objAt(objAt(inv, "classes"), "reentrancy")
	if intAt(r, "memory_rows") != 1 || intAt(r, "eval_cases") != 1 {
		t.Fatalf("reentrancy = %v, want 1 memory row + 1 eval case", r)
	}
	if floatAt(r, "loss_usd_sum") != 5000.0 {
		t.Fatalf("loss_usd_sum = %v, want 5000.0 (comma parsed)", floatAt(r, "loss_usd_sum"))
	}
	if got := validation.CanonCompact(objAt(r, "severity_counts")); got != `{"high":1}` {
		t.Fatalf("severity_counts = %s", got)
	}
	if intAt(objAt(objAt(inv, "classes"), "logic-error"), "memory_rows") != 0 {
		t.Fatal("logic-error must have zero memory rows")
	}
	if intAt(inv, "unmapped_confirmed_exploitable") != 1 {
		t.Fatalf("unmapped = %v, want 1", objAt(inv, "unmapped_confirmed_exploitable"))
	}
}

func TestInventoryIgnoresNonExploitableOutcomes(t *testing.T) {
	withSeams(t, nil, []validation.Value{
		evalCase("CASE-"+strings.Repeat("e", 12), "reentrancy",
			"confirmed-not-exploitable", "high")})
	inv, err := ClassInventory(newCampaign(t, "test-program"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findKey(objAt(inv, "classes"), "reentrancy"); ok {
		t.Fatal("a non-exploitable outcome must not create a class entry")
	}
	if intAt(inv, "unmapped_confirmed_exploitable") != 0 {
		t.Fatal("a non-exploitable outcome is not an unmapped case")
	}
}

func TestInventoryCountsEvalOnlyCases(t *testing.T) {
	// The eval-store leg in isolation: zero memory rows — a valid case must
	// still be counted, with severity aggregated from gold and loss absent.
	withSeams(t, nil, []validation.Value{
		evalCase("CASE-"+strings.Repeat("1", 12), "flash-loan", "confirmed-exploitable", "high"),
		evalCase("CASE-"+strings.Repeat("2", 12), "flash-loan", "confirmed-exploitable", "low"),
		evalCase("CASE-"+strings.Repeat("3", 12), "flash-loan", "disproved", "high"),
	})
	inv, err := ClassInventory(newCampaign(t, "test-program"))
	if err != nil {
		t.Fatal(err)
	}
	r := objAt(objAt(inv, "classes"), "flash-loan")
	if intAt(r, "eval_cases") != 2 {
		t.Fatalf("eval_cases = %v, want 2 (only confirmed-exploitable)", r)
	}
	if intAt(r, "memory_rows") != 0 {
		t.Fatal("nothing came from shared memory")
	}
	if got := validation.CanonCompact(objAt(r, "severity_counts")); got != `{"high":1,"low":1}` {
		t.Fatalf("severity_counts = %s", got)
	}
	if floatAt(r, "loss_usd_sum") != 0.0 {
		t.Fatal("loss is a memory-tier signal")
	}
}

func TestLossParseFailureIsZero(t *testing.T) {
	withSeams(t, []validation.Value{wrapRow(seedRow(t, "MEM-inv0001",
		"reentrancy", "Exploited. Loss unknown."))}, nil)
	inv, err := ClassInventory(newCampaign(t, "test-program"))
	if err != nil {
		t.Fatal(err)
	}
	r := objAt(objAt(inv, "classes"), "reentrancy")
	if floatAt(r, "loss_usd_sum") != 0.0 {
		t.Fatalf("loss_usd_sum = %v, want 0.0", floatAt(r, "loss_usd_sum"))
	}
	if intAt(r, "memory_rows") != 1 {
		t.Fatal("the row must still be counted")
	}
}

func TestLossParseDegenerateCommasIsZero(t *testing.T) {
	// Loss parsing is lenient: malformed lines are skipped, never fatal.
	// ',,,' matches LOSS_RE's digit-or-comma class but is not a number.
	withSeams(t, []validation.Value{wrapRow(seedRow(t, "MEM-inv0001",
		"reentrancy", "Drained. Reported loss: ,,, USD."))}, nil)
	inv, err := ClassInventory(newCampaign(t, "test-program"))
	if err != nil {
		t.Fatalf("class_inventory must not raise: %v", err)
	}
	r := objAt(objAt(inv, "classes"), "reentrancy")
	if floatAt(r, "loss_usd_sum") != 0.0 {
		t.Fatalf("loss_usd_sum = %v, want 0.0", floatAt(r, "loss_usd_sum"))
	}
	if intAt(r, "memory_rows") != 1 {
		t.Fatal("the row must still be counted")
	}
}

func TestInventoryDeterministic(t *testing.T) {
	withSeams(t, []validation.Value{wrapRow(seedRow(t, "MEM-inv0001",
		"reentrancy", "X. Reported loss: 5,000 USD."))},
		[]validation.Value{evalCase("CASE-"+strings.Repeat("f", 12),
			"oracle-manipulation", "confirmed-exploitable", "high")})
	c := newCampaign(t, "test-program")
	a, err := ClassInventory(c)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ClassInventory(c)
	if err != nil {
		t.Fatal(err)
	}
	if validation.DumpsOrdered(a, false) != validation.DumpsOrdered(b, false) {
		t.Fatal("class_inventory is not deterministic")
	}
	if len(objAt(a, "classes").O) != 2 {
		t.Fatalf("classes = %v, want reentrancy + oracle-manipulation",
			objAt(a, "classes"))
	}
}

// TestBothTiersVisible is test_root_and_global_tiers_both_visible's CS-side
// contract: a fresh consumer under the same root sees BOTH tiers through
// shared_memory_block and class_inventory. The publish path itself lives in
// internal/sharedmem (concurrent agent), so the rows are installed through
// the seam in the shape publish writes.
func TestBothTiersVisible(t *testing.T) {
	rootRow := wrapRow(seedRow(t, "MEM-root0001", "reentrancy",
		"root-tier confirmed row. Reported loss: 1,000 USD."))
	globalRow := validation.VObj(
		validation.KV{K: "program_key", V: validation.VStr("other|program|-")},
		validation.KV{K: "published_at", V: validation.VStr("2026-09-06T00:00:00+00:00")},
		validation.KV{K: "row", V: seedRow(t, "MEM-glob0001", "logic-error",
			"global-tier confirmed row. Reported loss: 1,000 USD.")},
		validation.KV{K: "scope", V: validation.VStr("global")},
	)
	withSeams(t, []validation.Value{rootRow, globalRow}, nil)
	c := newCampaign(t, "Consumer Program")
	block, err := SharedMemoryBlock(c, nil, 20)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, r := range listAt(block, "rows") {
		ids[objStr(r, "memory_id")] = true
	}
	if !ids["MEM-root0001"] || !ids["MEM-glob0001"] {
		t.Fatalf("rows = %v, want both tiers", ids)
	}
	if intAt(block, "total_visible") != 2 {
		t.Fatalf("total_visible = %v, want 2", objAt(block, "total_visible"))
	}
	inv, err := ClassInventory(c)
	if err != nil {
		t.Fatal(err)
	}
	if intAt(objAt(objAt(inv, "classes"), "reentrancy"), "memory_rows") != 1 ||
		intAt(objAt(objAt(inv, "classes"), "logic-error"), "memory_rows") != 1 {
		t.Fatalf("inventory = %v", objAt(inv, "classes"))
	}
}

// ---- exposure scoring ----------------------------------------------------

func invOf(t *testing.T, pairs ...string) validation.Value {
	t.Helper()
	kvs := make([]validation.KV, 0, len(pairs)/4)
	for i := 0; i+3 < len(pairs); i += 4 {
		kvs = append(kvs, validation.KV{K: pairs[i], V: validation.VObj(
			validation.KV{K: "memory_rows", V: validation.VInt(int64(atoi(t, pairs[i+1])))},
			validation.KV{K: "eval_cases", V: validation.VInt(int64(atoi(t, pairs[i+2])))},
			validation.KV{K: "loss_usd_sum", V: validation.VFloat(atof(t, pairs[i+3]))},
			validation.KV{K: "severity_counts", V: validation.VObj()},
		)})
	}
	return validation.VObj(
		validation.KV{K: "classes", V: validation.VObj(kvs...)},
		validation.KV{K: "unmapped_confirmed_exploitable", V: validation.VInt(0)},
	)
}

func probedRow(cls string, exposed bool, hits []validation.Value, conf string) validation.Value {
	return validation.VObj(
		validation.KV{K: "bug_class", V: validation.VStr(cls)},
		validation.KV{K: "exposed", V: validation.VBool(exposed)},
		validation.KV{K: "hits", V: validation.VArr(hits...)},
		validation.KV{K: "confidence", V: validation.VStr(conf)},
	)
}

func TestScoreFormula(t *testing.T) {
	inv := invOf(t, "reentrancy", "3", "2", "100.0", "x")
	rows := ExposureRows(inv, []validation.Value{probedRow("reentrancy", true,
		[]validation.Value{hit("a", "x")}, "high")})
	expected := 1 * log2(1+5) * 1.0
	if rows[0].O[6].V.F != validation.PythonRound(expected, 6) {
		t.Fatalf("score = %v, want %v", rows[0].O[6].V.F,
			validation.PythonRound(expected, 6))
	}
	if intAt(rows[0], "corpus_weight") != 5 {
		t.Fatalf("corpus_weight = %v, want 5", objAt(rows[0], "corpus_weight"))
	}
}

func TestConfidenceFactorScalesScore(t *testing.T) {
	inv := invOf(t, "reentrancy", "4", "0", "0.0", "x")
	hits := []validation.Value{hit("a", "x")}
	high := ExposureRows(inv, []validation.Value{probedRow("reentrancy", true, hits, "high")})
	low := ExposureRows(inv, []validation.Value{probedRow("reentrancy", true, hits, "low")})
	ratio := low[0].O[6].V.F / high[0].O[6].V.F
	if ratio-0.25 > 1e-9 || 0.25-ratio > 1e-9 {
		t.Fatalf("low/high = %v, want 0.25", ratio)
	}
	if high[0].O[6].V.F <= 0 {
		t.Fatal("high-confidence score must be positive")
	}
}

func TestRankingOrderAndTiebreak(t *testing.T) {
	inv := invOf(t, "a", "8", "0", "50.0", "b", "8", "0", "900.0")
	probed := []validation.Value{
		probedRow("a", true, []validation.Value{hit("1", "")}, "high"),
		probedRow("b", true, []validation.Value{hit("2", "")}, "high"),
	}
	rows := ExposureRows(inv, probed)
	// equal score -> loss tiebreak: b (900) before a (50)
	if objStr(rows[0], "bug_class") != "b" || objStr(rows[1], "bug_class") != "a" {
		t.Fatalf("order = %v, %v", objStr(rows[0], "bug_class"), objStr(rows[1], "bug_class"))
	}
	if rows[0].O[6].V.F != rows[1].O[6].V.F {
		t.Fatal("the fixture must produce an exact score tie")
	}
}

func TestNoHitsScoresZeroButStaysListed(t *testing.T) {
	inv := invOf(t, "reentrancy", "1", "1", "0.0")
	rows := ExposureRows(inv, []validation.Value{
		probedRow("reentrancy", false, nil, "high")})
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want the class still listed", len(rows))
	}
	if rows[0].O[6].V.F != 0.0 || objAt(rows[0], "exposed").B {
		t.Fatalf("row = %v, want score 0.0 and exposed false", rows[0])
	}
}

func TestExposureDeterministic(t *testing.T) {
	inv := invOf(t, "x", "2", "3", "1.0")
	probed := []validation.Value{probedRow("x", true,
		[]validation.Value{hit("n", "d")}, "medium")}
	a := validation.DumpsOrdered(validation.VArr(ExposureRows(inv, probed)...), false)
	b := validation.DumpsOrdered(validation.VArr(ExposureRows(inv, probed)...), false)
	if a != b {
		t.Fatal("exposure_rows is not deterministic")
	}
	if !strings.Contains(a, `"score"`) {
		t.Fatalf("row carries no score: %s", a)
	}
}

// scoreOf reads the "score" of one bug_class row from ExposureRows output.
func scoreOf(t *testing.T, rows []validation.Value, cls string) float64 {
	t.Helper()
	for _, r := range rows {
		if objStr(r, "bug_class") == cls {
			return objAt(r, "score").F
		}
	}
	t.Fatalf("no exposure row for class %q", cls)
	return math.NaN()
}

// TestExposureRowsSearchFactorApplied pins the G2 search-factor seam: with
// the default (all-1.0) table the score matches an independent recomputation
// of the expression here, and a swapped 2.0 factor for one class exactly
// doubles that class's rounded score. (Equality with pre-change code is NOT
// shown here — this recomputes the same expression, so it cannot catch a
// re-association; that proof is scripts/golden.sh, green with zero edits.)
// Two hits keep the doubled comparison free of double-rounding drift
// (round(2x) vs round(2*round(x)) agree here; see the report).
func TestExposureRowsSearchFactorApplied(t *testing.T) {
	inv := invOf(t, "reentrancy", "3", "2", "100.0")
	hits := []validation.Value{hit("a", "x"), hit("b", "y")}
	probed := []validation.Value{probedRow("reentrancy", true, hits, "high")}
	base := scoreOf(t, ExposureRows(inv, probed), "reentrancy")
	old := searchFactor
	defer func() { searchFactor = old }()
	searchFactor = func(cls string) float64 {
		if cls == "reentrancy" {
			return 2.0
		}
		return 1.0
	}
	doubled := scoreOf(t, ExposureRows(inv, probed), "reentrancy")
	if doubled != validation.PythonRound(base*2, 6) {
		t.Fatalf("factor 2.0 must double the score: %v vs %v", doubled, base*2)
	}
	if want := validation.PythonRound(2*log2(1+5)*1.0*2.0, 6); doubled != want {
		t.Fatalf("swapped score = %v, want %v", doubled, want)
	}
}

// ---- report + bundle blocks ---------------------------------------------

const donationVault = "contract Vault {\n" +
	"  uint256 public totalAssets;\n" +
	"  uint256 public totalShares;\n" +
	"  uint256 public pricePerShare;\n" +
	"  function deposit(uint256 amount) external {\n" +
	"    totalAssets += amount; totalShares += 1;\n" +
	"    pricePerShare = totalAssets / totalShares;\n" +
	"  }\n" +
	"}\n"

// pinVault is _pin_vault: pin a one-file source tree as the active snapshot.
func pinVault(t *testing.T, c *state.Campaign, root, sol string) validation.Value {
	t.Helper()
	src := filepath.Join(root, "src")
	if err := writeFile(filepath.Join(src, "Vault.sol"), sol); err != nil {
		t.Fatal(err)
	}
	snap, err := snapshot.PinSourceSnapshot(c, src, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func TestReportShapeAndDeterminism(t *testing.T) {
	withSeams(t, nil, nil)
	root := t.TempDir()
	c, err := state.Init(root, "report-program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	pinVault(t, c, root, donationVault)
	// an absent corpus root: the shape leg degrades, the report still forms.
	absent := filepath.Join(root, "no-such-corpus")
	a, err := BuildReport(c, &absent)
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildReport(c, &absent)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"campaign_id", "generated_at", "inventory",
		"class_exposure", "shape_matches", "unprobed_classes", "poc_missing"} {
		if _, ok := findKey(a, key); !ok {
			t.Fatalf("report lacks key %q", key)
		}
	}
	a2 := withoutKey(a, "generated_at")
	b2 := withoutKey(b, "generated_at")
	if validation.DumpsOrdered(a2, false) != validation.DumpsOrdered(b2, false) {
		t.Fatal("build_report is not deterministic modulo generated_at")
	}
	var spi validation.Value
	for _, r := range listAt(a, "class_exposure") {
		if objStr(r, "bug_class") == "share-price-inflation" {
			spi = r
		}
	}
	if spi.Kind != validation.Obj || !objAt(spi, "exposed").B {
		t.Fatalf("share-price-inflation = %v, want exposed", spi)
	}
}

func TestCLIWritesAndRegistersArtifactShape(t *testing.T) {
	// The CLI half lives in internal/cli/cmd_corpus_surface.go; this is the
	// artifact contract it writes: campaign_id + class exposure.
	withSeams(t, nil, nil)
	root := t.TempDir()
	c, err := state.Init(root, "cli-program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	pinVault(t, c, root, "contract V { uint256 public x; }")
	absent := filepath.Join(root, "no-such-corpus")
	rep, err := BuildReport(c, &absent)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(c.ArtifactsDir, CorpusSurfaceFile)
	if err := validation.WriteJson(out, rep, ""); err != nil {
		t.Fatal(err)
	}
	doc, err := validation.ReadJson(out)
	if err != nil {
		t.Fatal(err)
	}
	if objStr(doc, "campaign_id") != c.CampaignID {
		t.Fatalf("campaign_id = %q, want %q", objStr(doc, "campaign_id"), c.CampaignID)
	}
	if len(listAt(doc, "class_exposure")) == 0 {
		t.Fatal("the artifact carries no class exposure")
	}
}

func TestPrescreenReferencesCorpusSurface(t *testing.T) {
	// The prescreen section is the archetypes package's; here we pin the
	// artifact side it reads.
	withSeams(t, nil, nil)
	root := t.TempDir()
	c, err := state.Init(root, "pres-program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	pinVault(t, c, root, "contract V { uint256 public x; }")
	absent := filepath.Join(root, "no-such-corpus")
	rep, err := BuildReport(c, &absent)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(c.ArtifactsDir, CorpusSurfaceFile)
	if err := validation.WriteJson(out, rep, ""); err != nil {
		t.Fatal(err)
	}
	cs, err := CorpusSurfaceBlock(c, 10, 20)
	if err != nil {
		t.Fatal(err)
	}
	if cs.Kind != validation.Obj {
		t.Fatal("corpus_surface_block = None after the artifact was written")
	}
	if _, ok := findKey(cs, "top_exposure"); !ok {
		t.Fatal("block lacks top_exposure")
	}
	if _, ok := findKey(cs, "shape_matches"); !ok {
		t.Fatal("block lacks shape_matches")
	}
}

func TestCorpusSurfaceBlockNoneWhenEmpty(t *testing.T) {
	c := newCampaign(t, "empty-program")
	cs, err := CorpusSurfaceBlock(c, 10, 20)
	if err != nil {
		t.Fatal(err)
	}
	if cs.Kind != validation.Null {
		t.Fatalf("block = %v, want None when no artifact exists", cs)
	}
	sm, err := SharedMemoryBlock(c, nil, 20)
	if err != nil {
		t.Fatal(err)
	}
	if sm.Kind != validation.Null {
		t.Fatalf("shared_memory_block = %v, want None when the store is empty", sm)
	}
}

func TestSharedMemoryBlockFiltersByBugClass(t *testing.T) {
	re := wrapRow(seedRow(t, "MEM-b0001", "reentrancy", "X exploited via reentrancy."))
	oracle := wrapRow(seedRow(t, "MEM-b0002", "oracle-manipulation",
		"Oracle Manipulation. Reported loss: 1,000 USD."))
	withSeams(t, []validation.Value{re, oracle}, nil)
	c := newCampaign(t, "filter-program")
	cls := "reentrancy"
	block, err := SharedMemoryBlock(c, &cls, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(listAt(block, "rows")) != 1 ||
		objStr(listAt(block, "rows")[0], "memory_id") != "MEM-b0001" {
		t.Fatalf("rows = %v, want only MEM-b0001", listAt(block, "rows"))
	}
	if intAt(block, "total_visible") != 2 {
		t.Fatalf("total_visible = %v, want 2", objAt(block, "total_visible"))
	}
	if !objAt(block, "filtered_by_bug_class").B {
		t.Fatal("filtered_by_bug_class must be true")
	}
}

// TestSharedMemoryBlockClipsSummaryByRunes is the T38 (golden v5) regression:
// the reference clips `evidence_summary` with `[:300]` — CHARACTERS. The P4
// fixture's ingest rows carry em/en dashes in their descriptions, so a byte
// slice cut the summary 1-2 runes early and the backfilled proposer bundle
// diverged from the Python twin.
func TestSharedMemoryBlockClipsSummaryByRunes(t *testing.T) {
	long := strings.Repeat("abcd\u2014", 100) // 500 runes / 700 bytes
	withSeams(t, []validation.Value{
		wrapRow(seedRow(t, "MEM-b9999", "reentrancy", long))}, nil)
	c := newCampaign(t, "clip-program")
	block, err := SharedMemoryBlock(c, nil, 20)
	if err != nil {
		t.Fatal(err)
	}
	rows := listAt(block, "rows")
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	got := objStr(rows[0], "evidence_summary")
	if n := len([]rune(got)); n != 300 {
		t.Fatalf("summary runes = %d, want 300 (byte-sliced?)", n)
	}
	if !strings.HasSuffix(got, "\u2014") {
		t.Fatalf("summary cut mid-rune: %q", got)
	}
}

func TestSharedMemoryBlockFallbackWhenClassUnknown(t *testing.T) {
	withSeams(t, []validation.Value{wrapRow(seedRow(t, "MEM-b0001",
		"reentrancy", "X exploited via reentrancy."))}, nil)
	c := newCampaign(t, "fallback-program")
	block, err := SharedMemoryBlock(c, nil, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(listAt(block, "rows")) != 1 {
		t.Fatalf("rows = %v, want the single row", listAt(block, "rows"))
	}
	if objAt(block, "filtered_by_bug_class").B {
		t.Fatal("filtered_by_bug_class must be false without a bug_class")
	}
}

// ---- small test helpers --------------------------------------------------

func writeFile(path, body string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(body), 0o644)
}

func atoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func atof(t *testing.T, s string) float64 {
	t.Helper()
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func log2(x float64) float64 { return math.Log2(x) }

func withoutKey(v validation.Value, key string) validation.Value {
	out := make([]validation.KV, 0, len(v.O))
	for _, kv := range v.O {
		if kv.K != key {
			out = append(out, kv)
		}
	}
	return validation.VObj(out...)
}

func findKey(v validation.Value, key string) (validation.Value, bool) {
	if v.Kind != validation.Obj {
		return validation.VNull(), false
	}
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V, true
		}
	}
	return validation.VNull(), false
}

// TestPocAttributionSeamAnnotatesShapeMatches pins the Go-only seam that
// Python covers only through the real DeFiHackLabs checkout:
// _poc_attribution maps a PoC path to its record id (records without a
// poc_path count as poc_missing), and _attach_memory fills memory_ids +
// the FIRST row's bug_class from rows published under
// ingest:defihacklabs:<record_id>.
func TestPocAttributionSeamAnnotatesShapeMatches(t *testing.T) {
	SetLoadPocRecords(func(explorerDir, pocRoot *string) ([]validation.Value, error) {
		return []validation.Value{
			validation.VObj(
				validation.KV{K: "id", V: validation.VStr("defihacklabs-20171106-parity")},
				validation.KV{K: "exploit", V: validation.VObj(
					validation.KV{K: "poc_path", V: validation.VStr("src/Parity_exp.sol")})}),
			validation.VObj(
				validation.KV{K: "id", V: validation.VStr("defihacklabs-nopoc")},
				validation.KV{K: "exploit", V: validation.VObj()}),
		}, nil
	})
	ingestRows := []validation.Value{
		wrapRow(validation.VObj(
			validation.KV{K: "memory_id", V: validation.VStr("MEM-b0002")},
			validation.KV{K: "campaign_id", V: validation.VStr(
				"ingest:defihacklabs:defihacklabs-20171106-parity")},
			validation.KV{K: "bug_class", V: validation.VStr("reentrancy")})),
		wrapRow(validation.VObj(
			validation.KV{K: "memory_id", V: validation.VStr("MEM-b0001")},
			validation.KV{K: "campaign_id", V: validation.VStr(
				"ingest:defihacklabs:defihacklabs-20171106-parity")},
			validation.KV{K: "bug_class", V: validation.VStr("oracle-manipulation")})),
		// a non-ingest campaign id must never be attached
		wrapRow(seedRow(t, "MEM-b0003", "logic-error", "unrelated")),
	}
	SetLoadSharedMemory(func(root string) ([]validation.Value, error) {
		return ingestRows, nil
	})
	t.Cleanup(func() {
		SetLoadPocRecords(nil)
		SetLoadSharedMemory(nil)
	})
	byPath, missing, err := pocAttribution(nil)
	if err != nil {
		t.Fatal(err)
	}
	if missing != 1 {
		t.Fatalf("poc_missing = %d, want 1 (the record without a poc_path)", missing)
	}
	c := newCampaign(t, "attr-program")
	if err := attachMemory(c, byPath); err != nil {
		t.Fatal(err)
	}
	e := byPath["src/Parity_exp.sol"]
	if e == nil {
		t.Fatal("no attribution for src/Parity_exp.sol")
	}
	if e.recordID.S != "defihacklabs-20171106-parity" {
		t.Fatalf("record_id = %q", e.recordID.S)
	}
	if got := validation.CanonCompact(e.memoryIDs); got != `["MEM-b0001","MEM-b0002"]` {
		t.Fatalf("memory_ids = %s, want sorted ingest rows only", got)
	}
	if e.bugClass.S != "reentrancy" {
		t.Fatalf("bug_class = %q, want the first row's class", e.bugClass.S)
	}
}
