// classes_test.go — J-perclass Step 1: the per-class cell table over the
// SAME scope and anchor rule ScoreSuite uses.
//
// The reading of "classes with zero cases never appear" pinned here: a row
// exists iff its class has ≥1 matched gold case OR ≥1 attributed live
// finding — i.e. rows are never EMPTY. A live finding attributed to a class
// with no gold case still gets its own row (that is where its FP shows up),
// and the `unmapped` bucket is itself a zero-case row, so the alternative
// reading (gold classes only) cannot be reconciled with the locked
// "unmapped ... never dropped silently" rule at all.
package evalscore

import (
	"reflect"
	"testing"

	"websec/internal/validation"
)

// classlessFinding is a live finding with NO root_cause at all: it must be
// attributed to `unmapped` and counted, never dropped.
func classlessFinding(path string) validation.Value {
	return validation.VObj(
		kvE("affected", validation.VArr(
			validation.VObj(kvE("path", validation.VStr(path))))),
	)
}

// twoClassSuite is two gold cases for p1 (access-control, reentrancy).
func twoClassSuite() []validation.Value {
	return []validation.Value{
		goldCase("CASE-A", "p1", "confirmed-exploitable", "access-control", "gold/Vault.sol"),
		goldCase("CASE-B", "p1", "confirmed-exploitable", "reentrancy", "gold/Bank.sol"),
	}
}

func TestClassesAttributionSortedIncludingUnmapped(t *testing.T) {
	// Four live findings in one program:
	//  1. access-control @ Vault.sol      → anchors CASE-A
	//  2. "Access-Control" @ Vault.sol    → attributed to access-control
	//     (lowercased) but NOT anchored: anchor() is ScoreSuite's rule and
	//     compares the class bytes as stored.
	//  3. oracle-manipulation @ Vault.sol → no gold case of that class
	//  4. no root_cause at all            → `unmapped`
	live := map[string][]validation.Value{
		"p1": {
			finding("access-control", "src/Vault.sol"),
			finding("Access-Control", "src/Vault.sol"),
			finding("oracle-manipulation", "src/Vault.sol"),
			classlessFinding("src/Vault.sol"),
		},
	}
	got := Classes([]string{"p1"}, live, twoClassSuite())
	want := []ClassRow{
		{
			Class: "access-control", Cases: 1, Hits: 1, Live: 2, Anchored: 1,
			RecallLine:    "recall: 1/1 (95% CI 20.7–100.0%)",
			PrecisionLine: "precision: 1/2 (95% CI 9.5–90.5%)",
		},
		{
			Class: "oracle-manipulation", Cases: 0, Hits: 0, Live: 1, Anchored: 0,
			RecallLine:    "recall: 0/0 (95% CI n/a)",
			PrecisionLine: "precision: 0/1 (95% CI 0.0–79.3%)",
		},
		{
			Class: "reentrancy", Cases: 1, Hits: 0, Live: 0, Anchored: 0,
			RecallLine:    "recall: 0/1 (95% CI 0.0–79.3%)",
			PrecisionLine: "precision: 0/0 (95% CI n/a)",
		},
		{
			Class: "unmapped", Cases: 0, Hits: 0, Live: 1, Anchored: 0,
			RecallLine:    "recall: 0/0 (95% CI n/a)",
			PrecisionLine: "precision: 0/1 (95% CI 0.0–79.3%)",
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Classes =\n%+v\nwant\n%+v", got, want)
	}
	// Sorted by Class, byte order.
	for i := 1; i < len(got); i++ {
		if got[i-1].Class >= got[i].Class {
			t.Fatalf("rows not sorted by Class: %q then %q",
				got[i-1].Class, got[i].Class)
		}
	}
	// No empty rows and no taxonomy enumeration: every row carries at
	// least one case or one live finding.
	for _, r := range got {
		if r.Cases == 0 && r.Live == 0 {
			t.Fatalf("empty row rendered: %+v", r)
		}
	}
}

// TestClassesControlCaseJoinsItsClassCell: a control case (zero live
// findings = HIT) contributes to its class cell exactly as it does to the
// aggregate recall — one hit rule, one scope, no second definition.
func TestClassesControlCaseJoinsItsClassCell(t *testing.T) {
	live := map[string][]validation.Value{
		"p1":   {finding("access-control", "src/Vault.sol")},
		"ctrl": {},
	}
	got := Classes([]string{"p1", "ctrl"}, live, testSuite())
	var ctrl, ac ClassRow
	for _, r := range got {
		switch r.Class {
		case "reentrancy":
			ctrl = r
		case "access-control":
			ac = r
		}
	}
	// CASE-B (p1, reentrancy) misses; CASE-C (ctrl, reentrancy) hits the
	// control rule → reentrancy is 1/2.
	if ctrl.Cases != 2 || ctrl.Hits != 1 {
		t.Fatalf("reentrancy cell = %+v, want cases 2 hits 1", ctrl)
	}
	if ac.Cases != 1 || ac.Hits != 1 || ac.Live != 1 || ac.Anchored != 1 {
		t.Fatalf("access-control cell = %+v", ac)
	}
}

// TestClassesDecomposeScoreSuite: the per-class cells are a genuine
// decomposition of the aggregate join — no live finding is dropped, no
// gold case is double-counted, and the FP counter is exactly the
// unanchored remainder of the per-class live column.
func TestClassesDecomposeScoreSuite(t *testing.T) {
	live := map[string][]validation.Value{
		"p1": {
			finding("access-control", "src/Vault.sol"),
			finding("Access-Control", "src/Vault.sol"),
			finding("oracle-manipulation", "src/Vault.sol"),
			classlessFinding("src/Vault.sol"),
		},
		"ctrl": {finding("reentrancy", "src/Ctrl.sol")},
	}
	rep := ScoreSuite([]string{"p1", "ctrl"}, live, testSuite())
	rows := Classes([]string{"p1", "ctrl"}, live, testSuite())
	var cases, hits, liveN, anchored int
	for _, r := range rows {
		cases += r.Cases
		hits += r.Hits
		liveN += r.Live
		anchored += r.Anchored
	}
	if cases != rep.GoldTotal || hits != rep.Hits {
		t.Fatalf("gold side = %d/%d, want %d/%d",
			hits, cases, rep.Hits, rep.GoldTotal)
	}
	// Every live finding in the precision scope owns exactly one cell.
	if liveN != 5 {
		t.Fatalf("live cells sum = %d, want the 5 in-scope live findings", liveN)
	}
	if anchored != liveN-rep.FP {
		t.Fatalf("anchored cells = %d, want live(%d) - FP(%d)",
			anchored, liveN, rep.FP)
	}
}

// TestClassesNoLiveFindings: with a matched scope but an empty live set
// every gold class still gets a cell (recall only) — the section gates the
// block off, but Classes itself stays a pure join.
func TestClassesNoLiveFindings(t *testing.T) {
	got := Classes([]string{"p1"}, nil, twoClassSuite())
	want := []ClassRow{
		{
			Class: "access-control", Cases: 1, Hits: 0,
			RecallLine:    "recall: 0/1 (95% CI 0.0–79.3%)",
			PrecisionLine: "precision: 0/0 (95% CI n/a)",
		},
		{
			Class: "reentrancy", Cases: 1, Hits: 0,
			RecallLine:    "recall: 0/1 (95% CI 0.0–79.3%)",
			PrecisionLine: "precision: 0/0 (95% CI n/a)",
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Classes =\n%+v\nwant\n%+v", got, want)
	}
}

// TestClassesOutOfScopeIsSilent: a program with no matched case is out of
// scope for ScoreSuite, so it is out of scope here too — no row, no FP.
func TestClassesOutOfScopeIsSilent(t *testing.T) {
	live := map[string][]validation.Value{
		"elsewhere": {finding("access-control", "src/Vault.sol")},
	}
	got := Classes([]string{"p1"}, live, twoClassSuite())
	if len(got) != 2 {
		t.Fatalf("out-of-scope findings leaked into Classes: %+v", got)
	}
	for _, r := range got {
		if r.Live != 0 {
			t.Fatalf("out-of-scope finding counted in %q: %+v", r.Class, r)
		}
	}
}
