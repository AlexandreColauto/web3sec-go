package evalscore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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
