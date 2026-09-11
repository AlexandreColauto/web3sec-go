// bands_test.go — I3 unit battery: the locked ladder, the edge behaviour,
// the unscorable set, the fabrication census and the scope identity with
// ScoreSuite (the band denominator must be the SAME live set the existing
// precision line divides by).
package evalscore

import (
	"fmt"
	"math"
	"reflect"
	"testing"

	"websec/internal/validation"
)

// bandFinding builds a synthetic live finding carrying the keys bands.go
// reads: finding_id (the injected scorer keys on it), the anchor pair
// (root_cause.class, affected[0].path) and the two retraction signals.
func bandFinding(id, class, path, critic, status string) validation.Value {
	kvs := []validation.KV{
		kvE("finding_id", validation.VStr(id)),
		kvE("root_cause", validation.VObj(kvE("class", validation.VStr(class)))),
		kvE("affected", validation.VArr(validation.VObj(
			kvE("path", validation.VStr(path))))),
	}
	if critic != "" {
		kvs = append(kvs, kvE("verification", validation.VObj(
			kvE("critic_verdict", validation.VStr(critic)))))
	}
	if status != "" {
		kvs = append(kvs, kvE("status", validation.VStr(status)))
	}
	return validation.VObj(kvs...)
}

// scoreFrom maps finding_id -> score. An id the map does not carry reports
// ok=false; NaN and ±Inf are injected by storing them verbatim.
func scoreFrom(scores map[string]float64) ScoreFn {
	return func(f validation.Value) (float64, bool) {
		s, ok := scores[field(f, "finding_id")]
		return s, ok
	}
}

// bandSuite is one dev gold case for p1: class access-control, anchored on
// the basename of gold/Vault.sol.
func bandSuite() []validation.Value {
	return []validation.Value{
		goldCase("CASE-A", "p1", "confirmed-exploitable", "access-control",
			"gold/Vault.sol"),
	}
}

// bandsOf runs Bands over a flat p1 live set.
func bandsOf(t *testing.T, live []validation.Value, score ScoreFn) ([]BandRow, int, int, []int) {
	t.Helper()
	return Bands([]string{"p1"},
		map[string][]validation.Value{"p1": live}, bandSuite(), score)
}

// rowShape renders a row list compactly so a whole block can be pinned in
// one literal.
func rowShape(rows []BandRow) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, fmt.Sprintf("%s %d/%d %s", r.Label(), r.Anchored,
			r.Total, r.Line))
	}
	return out
}

// TestBandEdgesLocked pins the ladder: changing these numbers changes what
// the scorecard means, so it must be a deliberate, reviewed edit.
func TestBandEdgesLocked(t *testing.T) {
	if !reflect.DeepEqual(bandEdges, []float64{0, 1, 2, 4}) {
		t.Fatalf("bandEdges = %v, want [0 1 2 4] (locked)", bandEdges)
	}
}

// TestBandAssignmentAtEdges: buckets are half-open [lo, hi) except the last
// one, which is closed at +Inf — 0.999 → [0,1), 1.0 → [1,2), 2.0 → [2,4),
// 4.0 → [4+) and 8.5 → [4+).
func TestBandAssignmentAtEdges(t *testing.T) {
	var live []validation.Value
	for _, id := range []string{"F-a", "F-b", "F-c", "F-d", "F-e"} {
		live = append(live, bandFinding(id, "access-control", "src/Vault.sol", "", ""))
	}
	rows, unscorable, fabricated, fab := bandsOf(t, live, scoreFrom(map[string]float64{
		"F-a": 0.999, "F-b": 1.0, "F-c": 2.0, "F-d": 4.0, "F-e": 8.5,
	}))
	if unscorable != 0 || fabricated != 0 {
		t.Fatalf("unscorable=%d fabricated=%d, want 0/0", unscorable, fabricated)
	}
	want := []string{
		"[0,1) 1/1 precision: 1/1 (95% CI 20.7–100.0%)",
		"[1,2) 1/1 precision: 1/1 (95% CI 20.7–100.0%)",
		"[2,4) 1/1 precision: 1/1 (95% CI 20.7–100.0%)",
		"[4+) 2/2 precision: 2/2 (95% CI 34.2–100.0%)",
	}
	if got := rowShape(rows); !reflect.DeepEqual(got, want) {
		t.Fatalf("rows = %q\nwant %q", got, want)
	}
	if len(fab) != len(bandEdges) {
		t.Fatalf("fabrication_bands has %d slots, want %d (one per edge position)",
			len(fab), len(bandEdges))
	}
}

// TestEmptyBucketsOmitted: a bucket with no findings renders no row at all
// — the block never prints an empty line.
func TestEmptyBucketsOmitted(t *testing.T) {
	rows, _, _, _ := bandsOf(t,
		[]validation.Value{bandFinding("F-a", "access-control", "src/Vault.sol", "", "")},
		scoreFrom(map[string]float64{"F-a": 8.5}))
	if len(rows) != 1 || rows[0].Label() != "[4+)" {
		t.Fatalf("rows = %q, want exactly the [4+) row", rowShape(rows))
	}
}

// TestUnscorableIsNeverBucketed: a finding the scorer declines (ok=false),
// a NaN, either infinity, and a negative score (the ladder starts at 0 and
// the acceptance score is clamped there, so a negative number is not a
// position on it) all land in the unscorable count and in NO bucket — never
// silently in [0,1).
func TestUnscorableIsNeverBucketed(t *testing.T) {
	live := []validation.Value{
		bandFinding("F-ok", "access-control", "src/Vault.sol", "", ""),
		bandFinding("F-declined", "access-control", "src/Vault.sol", "", ""),
		bandFinding("F-nan", "access-control", "src/Vault.sol", "", ""),
		bandFinding("F-pinf", "access-control", "src/Vault.sol", "", ""),
		bandFinding("F-ninf", "access-control", "src/Vault.sol", "", ""),
		bandFinding("F-neg", "access-control", "src/Vault.sol", "", ""),
	}
	rows, unscorable, fabricated, _ := bandsOf(t, live, scoreFrom(map[string]float64{
		"F-ok": 1.0, "F-nan": math.NaN(), "F-pinf": math.Inf(1),
		"F-ninf": math.Inf(-1), "F-neg": -1.0,
	}))
	if unscorable != 5 {
		t.Fatalf("unscorable = %d, want 5 (declined, NaN, ±Inf, negative)", unscorable)
	}
	if fabricated != 0 {
		t.Fatalf("fabricated = %d, want 0", fabricated)
	}
	want := []string{"[1,2) 1/1 precision: 1/1 (95% CI 20.7–100.0%)"}
	if got := rowShape(rows); !reflect.DeepEqual(got, want) {
		t.Fatalf("rows = %q\nwant only the scored finding's bucket %q", got, want)
	}
}

// TestBandLinesPinned is the plan's worked example, computed by hand:
// scores 0.5 / 2.5 / 3.0 / 5.0 / 6.0 with three of the five findings
// anchored on the gold case. 0.5 lands in [0,1) (unanchored), 2.5 and 3.0
// in [2,4) (one anchored), 5.0 and 6.0 in [4+) (both anchored); [1,2) is
// empty and therefore absent. wilson.Format(0,1), (1,2) and (2,2).
func TestBandLinesPinned(t *testing.T) {
	live := []validation.Value{
		bandFinding("F-1", "oracle-manipulation", "src/Vault.sol", "", ""),
		bandFinding("F-2", "access-control", "src/Vault.sol", "", ""),
		bandFinding("F-3", "oracle-manipulation", "src/Vault.sol", "", ""),
		bandFinding("F-4", "access-control", "src/Vault.sol", "", ""),
		bandFinding("F-5", "access-control", "src/Vault.sol", "", ""),
	}
	rows, _, _, _ := bandsOf(t, live, scoreFrom(map[string]float64{
		"F-1": 0.5, "F-2": 2.5, "F-3": 3.0, "F-4": 5.0, "F-5": 6.0,
	}))
	want := []string{
		"[0,1) 0/1 precision: 0/1 (95% CI 0.0–79.3%)",
		"[2,4) 1/2 precision: 1/2 (95% CI 9.5–90.5%)",
		"[4+) 2/2 precision: 2/2 (95% CI 34.2–100.0%)",
	}
	if got := rowShape(rows); !reflect.DeepEqual(got, want) {
		t.Fatalf("rows = %q\nwant %q", got, want)
	}
}

// TestBandsScopeIsScoreSuiteScope: the bands divide the SAME live set the
// precision line divides — every row total sums to the live total, and
// every anchored row sums to the anchored count, so FP == totals −
// anchored. A scope drift between the two would move this test.
func TestBandsScopeIsScoreSuiteScope(t *testing.T) {
	live := []validation.Value{
		bandFinding("F-1", "access-control", "src/Vault.sol", "", ""),
		bandFinding("F-2", "oracle-manipulation", "src/Vault.sol", "", ""),
		bandFinding("F-3", "access-control", "src/Other.sol", "", ""),
	}
	scores := scoreFrom(map[string]float64{"F-1": 1.0, "F-2": 3.0, "F-3": 5.0})
	rows, unscorable, _, _ := bandsOf(t, live, scores)
	rep := ScoreSuite([]string{"p1"},
		map[string][]validation.Value{"p1": live}, bandSuite())
	total, anchored := 0, 0
	for _, r := range rows {
		total += r.Total
		anchored += r.Anchored
	}
	if unscorable != 0 {
		t.Fatalf("unscorable = %d, want 0", unscorable)
	}
	if total != len(live) {
		t.Fatalf("band total = %d, want the %d live findings ScoreSuite scores",
			total, len(live))
	}
	if total-anchored != rep.FP {
		t.Fatalf("totals−anchored = %d, want the precision line's FP=%d",
			total-anchored, rep.FP)
	}
	if rep.PrecisionLine != "precision: 1/3 (95% CI 6.1–79.2%)" {
		t.Fatalf("precision = %q (scope moved?)", rep.PrecisionLine)
	}
}

// TestBandsIgnoresUnmatchedPrograms: a live finding under a program with no
// matched case is out of scope — it is in neither the bands nor the ledger,
// exactly as it is in neither the recall line nor the precision denominator.
func TestBandsIgnoresUnmatchedPrograms(t *testing.T) {
	rows, _, fabricated, _ := Bands([]string{"p1"},
		map[string][]validation.Value{
			"p1": {bandFinding("F-in", "access-control", "src/Vault.sol", "", "")},
			"other": {bandFinding("F-out", "access-control", "src/Vault.sol",
				"disproved", "DISPROVED")},
		}, bandSuite(), scoreFrom(map[string]float64{"F-in": 1.0, "F-out": 5.0}))
	if fabricated != 0 {
		t.Fatalf("fabricated = %d, want 0 (the retracted row is out of scope)",
			fabricated)
	}
	total := 0
	for _, r := range rows {
		total += r.Total
	}
	if total != 1 {
		t.Fatalf("rows = %q, want only the in-scope finding", rowShape(rows))
	}
}

// TestFabricationCensus: a finding is fabricated iff the record retracted
// it — critic_verdict "disproved" OR status DISPROVED. The other terminal
// states are NOT fabrications: SUPERSEDED is a replacement, DUPLICATE is a
// dedup outcome, OUT_OF_SCOPE is a scope call, INFORMATIONAL is a
// disclosure, and a non-committal critic verdict ("possible") refutes
// nothing.
func TestFabricationCensus(t *testing.T) {
	live := []validation.Value{
		bandFinding("F-critic", "access-control", "src/Vault.sol", "disproved", ""),
		bandFinding("F-status", "access-control", "src/Vault.sol", "", "DISPROVED"),
		bandFinding("F-superseded", "access-control", "src/Vault.sol", "", "SUPERSEDED"),
		bandFinding("F-duplicate", "access-control", "src/Vault.sol", "", "DUPLICATE"),
		bandFinding("F-oos", "access-control", "src/Vault.sol", "", "OUT_OF_SCOPE"),
		bandFinding("F-info", "access-control", "src/Vault.sol", "", "INFORMATIONAL"),
		bandFinding("F-possible", "access-control", "src/Vault.sol", "possible", ""),
	}
	rows, unscorable, fabricated, fabByBand := bandsOf(t, live,
		scoreFrom(map[string]float64{
			"F-critic": 0.0, "F-status": 5.0, "F-superseded": 0.0,
			"F-duplicate": 0.0, "F-oos": 0.0, "F-info": 0.0, "F-possible": 0.0,
		}))
	if unscorable != 0 {
		t.Fatalf("unscorable = %d, want 0", unscorable)
	}
	if fabricated != 2 {
		t.Fatalf("fabricated = %d, want 2 (critic-disproved + status DISPROVED)",
			fabricated)
	}
	// The distribution indexes bandEdges POSITIONS, so an empty bucket
	// still occupies its slot: [0,1)=1 (critic-disproved), [1,2)=0,
	// [2,4)=0, [4+)=1 (status DISPROVED at score 5.0).
	if want := []int{1, 0, 0, 1}; !reflect.DeepEqual(fabByBand, want) {
		t.Fatalf("fabrication_bands = %v, want %v", fabByBand, want)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %q, want [0,1) and [4+)", rowShape(rows))
	}
}
