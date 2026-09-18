package structidx

import (
	"slices"
	"testing"

	"websec/internal/validation"
)

func writerFixture(t *testing.T) validation.Value {
	t.Helper()
	return loadJSON(t, "testdata/structural_index.json")
}

// TestWritersOfReconcilesStatements: commitBatch's writes_storage omits
// prevStateRoot, which its statement-level write proves; WritersOf reports it,
// the raw list does not.
func TestWritersOfReconcilesStatements(t *testing.T) {
	idx := writerFixture(t)
	n := nodeByShortID(t, idx, "StateRoots.commitBatch")
	raw := strList(validation.ObjAt(n, "writes_storage"))
	if slices.Contains(raw, "prevStateRoot") {
		t.Fatalf("fixture changed: writes_storage already lists prevStateRoot")
	}
	writers := WritersOf(idx, n)
	if !slices.Contains(writers, "prevStateRoot") {
		t.Errorf("WritersOf = %v, want prevStateRoot", writers)
	}
	if !slices.Contains(writers, "storedHash") {
		t.Errorf("WritersOf = %v, want the list's own storedHash", writers)
	}
	// order: the parser's own list first, then the reconciled names
	if writers[0] != raw[0] {
		t.Errorf("WritersOf dropped the list order: %v", writers)
	}
	// a non-storage statement expression must not leak in
	if slices.Contains(writers, "if") || slices.Contains(writers, "batchIndex") {
		t.Errorf("WritersOf leaked a non-storage name: %v", writers)
	}
}

// TestWritersOfPureListFunction: a function the list already describes
// completely is unchanged.
func TestWritersOfPureListFunction(t *testing.T) {
	idx := writerFixture(t)
	n := nodeByShortID(t, idx, "StateRoots.getPrevStateHash")
	if got := WritersOf(idx, n); len(got) != len(strList(validation.ObjAt(n, "writes_storage"))) {
		t.Errorf("WritersOf = %v for a function with no statement write", got)
	}
}

// TestEffectiveWritersIsTheUnion: the reference query misses prevStateRoot's
// writer; EffectiveWriters finds it.
func TestEffectiveWritersIsTheUnion(t *testing.T) {
	idx := writerFixture(t)
	raw := StorageWriters(idx, "prevStateRoot")
	full := EffectiveWriters(idx, "prevStateRoot")
	if slices.Contains(raw, "folding/StateRoots.sol#StateRoots.commitBatch") {
		t.Fatalf("fixture changed: StorageWriters already finds the writer")
	}
	if !slices.Contains(full, "folding/StateRoots.sol#StateRoots.commitBatch") {
		t.Errorf("EffectiveWriters = %v, want the commitBatch writer", full)
	}
	for _, id := range raw {
		if !slices.Contains(full, id) {
			t.Errorf("EffectiveWriters dropped %s", id)
		}
	}
	// a name no function writes stays empty
	if got := EffectiveWriters(idx, "noSuchVariable"); len(got) != 0 {
		t.Errorf("EffectiveWriters(noSuchVariable) = %v", got)
	}
}

// nodeByShortID finds a function node by its `#Contract.function` suffix.
func nodeByShortID(t *testing.T, index validation.Value, short string) validation.Value {
	t.Helper()
	for _, n := range nodesOf(index, "function") {
		if hasSuffix(validation.ObjStr(n, "id"), "#"+short) {
			return n
		}
	}
	t.Fatalf("no function node %s in the fixture", short)
	return validation.VNull()
}
