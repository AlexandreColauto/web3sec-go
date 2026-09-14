package evalscore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fmt"
	"websec/assets"
	"websec/internal/validation"
)

// TestShippedGoldPackLoads is the r7 blocker guard: the duplicate-anchor
// refusal was written against fields the SCORER never uses (.path for
// .file, object mechanisms for plain strings) — collapsing every row's
// location leg and refusing the project's OWN answer key. The embedded
// shipped pack must pass the CLI loader, every time.
func TestShippedGoldPackLoads(t *testing.T) {
	raw, err := assets.LoadEvalCases()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "cases.json")
	doc := validation.VArr(raw...)
	data := append([]byte(validation.DumpIndentedASCII(doc)), '\n')
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	// No sidecar next to it: digest gate skipped, anchor law enforced.
	pack, err := LoadGoldPack(p)
	if err != nil {
		t.Fatalf("the shipped pack must load through the CLI pack loader: %v",
			err)
	}
	if len(pack) < 10 {
		t.Fatalf("shipped pack read as %d rows", len(pack))
	}
}

// TestAnchorKeyKeepsDiscriminatingRows: rows differing ONLY by location
// file stay distinct anchors (the exact shape the shipped pack uses);
// identical anchors still refuse.
func TestAnchorKeyDiscrimination(t *testing.T) {
	rowA := withFile(goldPackRow("CASE-000000000a01", "Morph", "reentrancy"), "VaultA.sol")
	rowB := withFile(goldPackRow("CASE-000000000b02", "Morph", "reentrancy"), "VaultB.sol")
	if _, err := loadRows(t, rowA, rowB); err != nil {
		t.Fatalf("distinct location files are distinct anchors: %v", err)
	}
	// Identical anchor legs (same file, same class, same outcome, no
	// mechanisms) must refuse.
	rowC := withFile(goldPackRow("CASE-000000000c03", "Morph", "reentrancy"), "VaultA.sol")
	if _, err := loadRows(t, rowA, rowC); err == nil ||
		!strings.Contains(err.Error(), "same gold anchor") {
		t.Fatalf("identical anchors must refuse: %v", err)
	}
	// A different mechanism set is a different discrimination bar — legal.
	rowD := withMechs(withFile(goldPackRow("CASE-000000000d04", "Morph",
		"reentrancy"), "VaultA.sol"), "external call precedes state update")
	if _, err := loadRows(t, rowA, rowD); err != nil {
		t.Fatalf("mechanism-differentiated rows are distinct: %v", err)
	}
}

func withFile(row validation.Value, file string) validation.Value {
	loc := validation.VObj(validation.KV{K: "file", V: validation.VStr(file)})
	g := obj(row, "gold")
	g.O = validation.SetOrAppend(g.O, "locations", validation.VArr(loc))
	row.O = validation.SetOrAppend(row.O, "gold", g)
	return row
}

func withMechs(row validation.Value, phrase string) validation.Value {
	g := obj(row, "gold")
	g.O = validation.SetOrAppend(g.O, "match_mechanisms",
		validation.VArr(validation.VStr(phrase)))
	row.O = validation.SetOrAppend(row.O, "gold", g)
	return row
}

func loadRows(t *testing.T, rows ...validation.Value) ([]validation.Value, error) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "pack.json")
	data := append([]byte(validation.DumpIndentedASCII(validation.VArr(rows...))), '\n')
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return LoadGoldPack(p)
}

// TestAnchorKeyBehaviorEquality (r8-1): the guard fires on what anchor()
// cannot distinguish — repeats, order, whitespace, dead-basename
// location sets — and stays silent where the join genuinely differs.
func TestAnchorKeyBehaviorEquality(t *testing.T) {
	base := withFile(goldPackRow("CASE-00000000aa01", "Morph", "reentrancy"),
		"Vault.sol")
	// duplicated accept entry: same membership -> same anchor
	dupAcc := withFile(goldPackRow("CASE-00000000aa02", "Morph", "reentrancy"),
		"Vault.sol")
	g := obj(dupAcc, "gold")
	g.O = validation.SetOrAppend(g.O, "bug_class_accept", validation.VArr(
		validation.VStr("access-control"), validation.VStr("access-control")))
	dupAcc.O = validation.SetOrAppend(dupAcc.O, "gold", g)
	singleAcc := withFile(goldPackRow("CASE-00000000aa03", "Morph",
		"reentrancy"), "Vault.sol")
	g2 := obj(singleAcc, "gold")
	g2.O = validation.SetOrAppend(g2.O, "bug_class_accept", validation.VArr(
		validation.VStr("access-control")))
	singleAcc.O = validation.SetOrAppend(singleAcc.O, "gold", g2)
	if _, err := loadRows(t, dupAcc, singleAcc); err == nil ||
		!strings.Contains(err.Error(), "same gold anchor") {
		t.Fatalf("duplicated accept entries are the SAME anchor: %v", err)
	}
	_ = base
	// "a/" (dead basename) vs NO locations: matches-nothing is NOT
	// matches-everything — both load alongside each other, and each
	// differs from a real basename too.
	deadA := withFile(goldPackRow("CASE-00000000bb01", "Morph",
		"oracle-manipulation"), "a/")
	deadB := withFile(goldPackRow("CASE-00000000bb02", "Morph",
		"oracle-manipulation"), "b/")
	plain := goldPackRow("CASE-00000000bb03", "Morph", "oracle-manipulation")
	// deadA vs plain (class-only): DIFFERENT anchors (match-nothing vs
	// match-everything) — must load together.
	if _, err := loadRows(t,
		withFile(goldPackRow("CASE-00000000bb04", "Morph",
			"oracle-manipulation"), "a/"), plain); err != nil {
		t.Fatalf("dead-basename vs class-only are distinct anchors: %v",
			err)
	}
	// deadA vs deadB: identical (both match nothing) — refuse.
	if _, err := loadRows(t, deadA, deadB); err == nil ||
		!strings.Contains(err.Error(), "same gold anchor") {
		t.Fatalf("two dead-basename rows ARE identical anchors: %v", err)
	}
	// mechanism whitespace: "phrase" == "phrase   ".
	m1 := withMechs(withFile(goldPackRow("CASE-00000000cc01", "Morph",
		"dos-griefing"), "G.sol"), "gas stipend changes control flow")
	m2 := withMechs(withFile(goldPackRow("CASE-00000000cc02", "Morph",
		"dos-griefing"), "G.sol"), "gas stipend changes control flow   ")
	if _, err := loadRows(t, m1, m2); err == nil ||
		!strings.Contains(err.Error(), "same gold anchor") {
		t.Fatalf("trailing-space mechanism duplicates: %v", err)
	}
}

// TestAnchorKeyGateFolding (r9-2/3): the mechanism leg keys on the gate's
// BEHAVIOR — whitespace/identifier/case/stop-word folds that
// goldAcceptsMechanism cannot distinguish are refused as duplicates, and
// every way of matching NOTHING ([] , all-blank, below-bar phrases) is ONE
// anchor, distinct from no-gate at all.
func TestAnchorKeyGateFolding(t *testing.T) {
	mk := func(id, mech string) validation.Value {
		return withMechs(withFile(goldPackRow(id, "Morph", "dos-griefing"),
			"F.sol"), mech)
	}
	pairs := [][2]string{
		{"alpha  beta gamma", "alpha beta gamma"},                                      // ws runs
		{"external call precedes state update", "External Call precedes STATE update"}, // case fold only
		{"the a call precedes the state update", "call precedes state update"},         // stop-words
		{"call precedes state update", "update state precedes call"},                   // order-free
	}
	for i, pr := range pairs {
		a := mk(fmt.Sprintf("CASE-%012d", 900+i), pr[0])
		b := mk(fmt.Sprintf("CASE-%012d", 950+i), pr[1])
		if _, err := loadRows(t, a, b); err == nil ||
			!strings.Contains(err.Error(), "same gold anchor") {
			t.Fatalf("fold pair %d (%q/%q) must refuse as one gate: %v",
				i, pr[0], pr[1], err)
		}
	}
	// All-inert gates are ONE dead anchor...
	d1 := mk("CASE-00000000e001", "   ") // blank after trim: inert
	d2 := mk("CASE-00000000e002", "one") // below two-content-word bar
	if _, err := loadRows(t, d1, d2); err == nil ||
		!strings.Contains(err.Error(), "same gold anchor") {
		t.Fatalf("two inert gates anchor nothing — one anchor: %v", err)
	}
	// ...and the dead gate is DISTINCT from no gate at all.
	none := withFile(goldPackRow("CASE-00000000e003", "Morph",
		"dos-griefing"), "F.sol")
	if _, err := loadRows(t, d1, none); err != nil {
		t.Fatalf("gate-nothing vs gate-absent are different anchors: %v",
			err)
	}
	// root: spellings fold to the same class test:
	r1 := mk("CASE-00000000e004", "root: reentrancy")
	r2 := mk("CASE-00000000e005", "root:  reentrancy")
	if _, err := loadRows(t, r1, r2); err == nil ||
		!strings.Contains(err.Error(), "same gold anchor") {
		t.Fatalf("root: spellings are one test: %v", err)
	}
	// root:X and a phrase that can also only match via class remain
	// DISTINCT: one keys R:, the other P:.
	r3 := mk("CASE-00000000e006", "reentrancy into the vault twice")
	if _, err := loadRows(t, r1, r3); err != nil {
		t.Fatalf("root: test != phrase test: %v", err)
	}
}
