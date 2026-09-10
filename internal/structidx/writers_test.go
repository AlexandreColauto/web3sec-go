package structidx

import (
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
	raw := strList(objAt(n, "writes_storage"))
	if contains(raw, "prevStateRoot") {
		t.Fatalf("fixture changed: writes_storage already lists prevStateRoot")
	}
	writers := WritersOf(idx, n)
	if !contains(writers, "prevStateRoot") {
		t.Errorf("WritersOf = %v, want prevStateRoot", writers)
	}
	if !contains(writers, "storedHash") {
		t.Errorf("WritersOf = %v, want the list's own storedHash", writers)
	}
	// order: the parser's own list first, then the reconciled names
	if writers[0] != raw[0] {
		t.Errorf("WritersOf dropped the list order: %v", writers)
	}
	// a non-storage statement expression must not leak in
	if contains(writers, "if") || contains(writers, "batchIndex") {
		t.Errorf("WritersOf leaked a non-storage name: %v", writers)
	}
}

// TestWritersOfPureListFunction: a function the list already describes
// completely is unchanged.
func TestWritersOfPureListFunction(t *testing.T) {
	idx := writerFixture(t)
	n := nodeByShortID(t, idx, "StateRoots.getPrevStateHash")
	if got := WritersOf(idx, n); len(got) != len(strList(objAt(n, "writes_storage"))) {
		t.Errorf("WritersOf = %v for a function with no statement write", got)
	}
}

// TestEffectiveWritersIsTheUnion: the reference query misses prevStateRoot's
// writer; EffectiveWriters finds it.
func TestEffectiveWritersIsTheUnion(t *testing.T) {
	idx := writerFixture(t)
	raw := StorageWriters(idx, "prevStateRoot")
	full := EffectiveWriters(idx, "prevStateRoot")
	if contains(raw, "folding/StateRoots.sol#StateRoots.commitBatch") {
		t.Fatalf("fixture changed: StorageWriters already finds the writer")
	}
	if !contains(full, "folding/StateRoots.sol#StateRoots.commitBatch") {
		t.Errorf("EffectiveWriters = %v, want the commitBatch writer", full)
	}
	for _, id := range raw {
		if !contains(full, id) {
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
		if hasSuffix(objStr(n, "id"), "#"+short) {
			return n
		}
	}
	t.Fatalf("no function node %s in the fixture", short)
	return validation.VNull()
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
