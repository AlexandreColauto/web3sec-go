package probes

import (
	"testing"

	"websec/internal/validation"
)

// B5: with an index, a contract that resolves to no real path must NOT be
// rendered as a bare "Name#L" citation — the pair is skipped. Without an
// index the bare name is the best available token.
func TestResolveAnchorTokenB5(t *testing.T) {
	paths := map[string]string{"Vault": "src/Vault.sol"}

	tok, ok := resolveAnchorToken(paths, true, "Vault")
	if !ok || tok != "src/Vault.sol" {
		t.Errorf("known contract: tok=%q ok=%v, want (src/Vault.sol, true)", tok, ok)
	}

	// Unknown contract WITH an index -> no pair (the pre-fix bug fabricated
	// "Missing#L45").
	if tok, ok := resolveAnchorToken(paths, true, "Missing"); ok {
		t.Errorf("unknown contract with index: got tok=%q ok=true, want ok=false", tok)
	}

	// Unknown contract WITHOUT an index -> bare name (best effort).
	if tok, ok := resolveAnchorToken(map[string]string{}, false, "Missing"); !ok || tok != "Missing" {
		t.Errorf("unknown contract without index: tok=%q ok=%v, want (Missing, true)", tok, ok)
	}

	// Empty contract without an index -> "?".
	if tok, ok := resolveAnchorToken(map[string]string{}, false, ""); !ok || tok != "?" {
		t.Errorf("empty contract without index: tok=%q ok=%v, want (?, true)", tok, ok)
	}
}

// A contract node with no source path must be omitted from the map (not
// mapped name->name), so the resolver skips it rather than fabricate a
// "Name#L" citation.
func TestContractPathsOmitsPathlessNodes(t *testing.T) {
	withPath := validation.VObj(
		kv("id", validation.VStr("a")),
		kv("kind", validation.VStr("contract")),
		kv("name", validation.VStr("WithPath")),
		kv("path", validation.VStr("src/WithPath.sol")),
	)
	noPath := validation.VObj(
		kv("id", validation.VStr("b")),
		kv("kind", validation.VStr("contract")),
		kv("name", validation.VStr("NoPath")),
	)
	index := validation.VObj(
		kv("nodes", validation.VArr(withPath, noPath)),
	)
	got := contractPaths(index)
	if got["WithPath"] != "src/WithPath.sol" {
		t.Errorf("WithPath = %q, want src/WithPath.sol", got["WithPath"])
	}
	if _, present := got["NoPath"]; present {
		t.Errorf("NoPath present in map (%q); pathless nodes must be omitted", got["NoPath"])
	}
}

// End-to-end: a row whose anchor contract is absent from the index yields no
// anchor pair (with the index) but a bare-name pair (without it).
func TestRowAnchorPairsSkipsUnknownContractWithIndex(t *testing.T) {
	row := validation.VObj(
		kv("probe", validation.VStr("assertion-strength")),
		kv("contract", validation.VStr("Ghost")),
		kv("consumer_line", validation.VInt(45)),
	)
	idxEmpty := validation.VObj(kv("nodes", validation.VArr())) // empty index
	idxMissing := validation.VObj(
		kv("nodes", validation.VArr(
			validation.VObj(
				kv("id", validation.VStr("a")),
				kv("kind", validation.VStr("contract")),
				kv("name", validation.VStr("Other")),
				kv("path", validation.VStr("src/Other.sol")),
			),
		)),
	)

	// With an index that lacks the contract -> no pair.
	if pairs := RowAnchorPairs(row, &idxMissing); len(pairs) != 0 {
		t.Errorf("with index lacking contract: pairs=%v, want none", pairs)
	}
	// With an empty index -> no pair.
	if pairs := RowAnchorPairs(row, &idxEmpty); len(pairs) != 0 {
		t.Errorf("with empty index: pairs=%v, want none", pairs)
	}
	// Without an index -> bare-name best effort.
	if pairs := RowAnchorPairs(row, nil); len(pairs) != 1 || pairs[0] != "Ghost#L45" {
		t.Errorf("without index: pairs=%v, want [Ghost#L45]", pairs)
	}
}

// surfaceAxis must return the matching axis even when a non-object precedes
// it in the raw axes list (the pre-fix bug indexed the raw list with a
// filtered-list index and returned the wrong axis).
func TestSurfaceAxisSkipsNonObjectPrefix(t *testing.T) {
	guard := validation.VObj(
		kv("axis", validation.VStr("guard")),
		kv("status", validation.VStr("blind")),
		kv("blind", validation.VArr(
			validation.VObj(kv("key", validation.VStr("k1"))),
		)),
	)
	accumulator := validation.VObj(
		kv("axis", validation.VStr("accumulator")),
		kv("status", validation.VStr("blind")),
		kv("blind", validation.VArr(
			validation.VObj(kv("key", validation.VStr("acc"))),
		)),
	)
	surface := validation.VObj(
		kv("axes", validation.VArr(validation.VNull(), guard, accumulator)),
	)
	ax := surfaceAxis(surface, "accumulator")
	if ax == nil {
		t.Fatal("surfaceAxis(accumulator) = nil, want the accumulator axis")
	}
	if got := vStr(*ax, "axis"); got != "accumulator" {
		t.Errorf("surfaceAxis(accumulator).axis = %q, want accumulator", got)
	}
}
