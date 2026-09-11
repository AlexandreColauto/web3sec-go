package solscope

import "testing"

// TestExcludedDirsAreTheSharedFive pins the exact membership of the shared
// exclude set. H4 collapsed structidx's and reproduction's hand-copied sets
// into this one; widening or narrowing it now moves BOTH walkers at once, so
// the set is pinned here and the change is deliberate.
func TestExcludedDirsAreTheSharedFive(t *testing.T) {
	want := []string{".git", "node_modules", "__pycache__", "cache", "out"}
	for _, name := range want {
		if !IsExcluded(name) {
			t.Errorf("IsExcluded(%q) = false, want true", name)
		}
	}
	// The walkers pass a directory NAME; a path or a near-miss must not
	// match (the membership check is exact, like the map lookup it replaced).
	for _, name := range []string{"", "src", "contracts", ".github",
		"node_modules_old", "out2", "node_modules/sub"} {
		if IsExcluded(name) {
			t.Errorf("IsExcluded(%q) = true, want false", name)
		}
	}
}
