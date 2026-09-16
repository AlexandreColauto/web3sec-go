package evalscore

import "testing"

// The C-12f17fd555 miss: the finding's class is a synonym of the gold
// bug_class; the location and mechanism legs pass, the class leg alone
// decided the miss.
func TestAnchorCanonicalizesSynonymClass(t *testing.T) {
	f := finding("denial-of-service", "src/Rollup.sol")
	g := goldCase("CASE-SYN", "p1", "confirmed-exploitable", "dos-griefing", "gold/Rollup.sol")
	if !anchor(f, obj(g, "gold")) {
		t.Fatal("synonym class must anchor its canonical gold bug_class")
	}
	// Gold side too: a pack that files the synonym must accept the canonical
	// finding class (the review's counter-case direction).
	f2 := finding("dos-griefing", "src/Rollup.sol")
	g2 := goldCase("CASE-SYN2", "p1", "confirmed-exploitable", "denial-of-service", "gold/Rollup.sol")
	if !anchor(f2, obj(g2, "gold")) {
		t.Fatal("canonical class must anchor a gold row filed under its synonym")
	}
	// Unknown labels still anchor nothing — fail-closed is unchanged.
	f3 := finding("totally-unknown", "src/Rollup.sol")
	if anchor(f3, obj(g, "gold")) {
		t.Fatal("unknown class must not anchor")
	}
}
