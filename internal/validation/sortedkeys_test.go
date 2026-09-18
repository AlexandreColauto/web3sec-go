package validation

import "testing"

// TestSortedKeysAliasIsTheJvalHelper guards the re-export surface: packages
// call validation.SortedKeys, so the generic has to stay reachable from here.
func TestSortedKeysAliasIsTheJvalHelper(t *testing.T) {
	if got := SortedKeys(map[string]struct{}{"z": {}, "a": {}}); len(got) != 2 || got[0] != "a" || got[1] != "z" {
		t.Fatalf("SortedKeys = %#v, want [a z]", got)
	}
	// HasKey reports presence, not non-nullness: a key mapped to null counts.
	if !HasKey(VObj(KV{K: "k", V: VNull()}), "k") {
		t.Fatal("HasKey must see a key whose value is null")
	}
	if HasKey(VObj(KV{K: "k", V: VNull()}), "absent") {
		t.Fatal("HasKey must not see an absent key")
	}
	if AsObj(VStr("x")).Kind != Obj {
		t.Fatal("AsObj(non-object) must be an empty object")
	}
}

// TestSortedKeysMatchesTheClones covers the map-shaped clones, including the
// two set spellings they used.
func TestSortedKeysMatchesTheClones(t *testing.T) {
	boolSet := map[string]bool{"b": true, "a": true, "c": false}
	structSet := map[string]struct{}{"b": {}, "a": {}, "c": {}}
	want := []string{"a", "b", "c"}
	for _, got := range [][]string{SortedKeys(boolSet), SortedKeys(structSet)} {
		if len(got) != len(want) {
			t.Fatalf("SortedKeys len=%d, want %d", len(got), len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("SortedKeys[%d]=%q, want %q", i, got[i], want[i])
			}
		}
	}
	if got := SortedKeys(map[string]bool{}); len(got) != 0 || got == nil {
		t.Errorf("SortedKeys(empty) = %#v, want empty non-nil slice", got)
	}
}
