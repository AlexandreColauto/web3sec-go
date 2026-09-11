package textsim

// textsim_test pins the moved rule: it IS archetypes' _jaccard (the Python
// twin's bigram-Jaccard), which archetypes.Jaccard now delegates to, so
// these cases cover both callers — the archetype near-miss ranking and
// evalstore's I1b near-dup scan.

import "testing"

func TestJaccardIdenticalAndDisjoint(t *testing.T) {
	if got := Jaccard("totalStaked", "totalStaked"); got != 1.0 {
		t.Fatalf("identical = %v, want 1.0", got)
	}
	if got := Jaccard("totalStaked", "zzzz"); got != 0.0 {
		t.Fatalf("disjoint = %v, want 0.0", got)
	}
}

// TestBigramsLowercasesAndKeepsShortStrings: the set is lowercased, and a
// one-rune-or-shorter string is its own single gram (never an empty set,
// which would make union 0 and every comparison 0).
func TestBigramsLowercasesAndKeepsShortStrings(t *testing.T) {
	if got := Bigrams("AB"); len(got) != 1 || !got["ab"] {
		t.Fatalf("Bigrams(AB) = %v, want {ab}", got)
	}
	if got := Bigrams(""); len(got) != 1 || !got[""] {
		t.Fatalf("Bigrams(empty) = %v, want the empty gram", got)
	}
	if got := Jaccard("", ""); got != 1.0 {
		t.Fatalf("Jaccard(empty, empty) = %v, want 1.0", got)
	}
}

// TestJaccardRuneSafety: a multi-byte identifier must not be split
// mid-rune into invalid grams.
func TestJaccardRuneSafety(t *testing.T) {
	if got := Jaccard("café", "café"); got != 1.0 {
		t.Fatalf("multi-byte identical = %v, want 1.0", got)
	}
	if got := Jaccard("café", "cafe"); got >= 1.0 || got == 0.0 {
		t.Fatalf("multi-byte near = %v, want a partial score", got)
	}
}
