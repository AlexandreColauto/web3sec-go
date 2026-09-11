// Package textsim is the shared text-similarity leaf: bigram (2-gram) set
// similarity over short identifiers.
//
// WHY it is its own leaf package: the SAME rule is needed on both sides of
// an import cycle. internal/archetypes uses it to rank near-miss
// identifiers, and internal/evalstore needs it for the I1b near-dup scan.
// evalstore cannot import archetypes — archetypes reaches evalstore through
// structidx -> orchestrator -> risk -> evalstore (risk's G3 priors read the
// eval store) — and copying the bigram rule into evalstore would be exactly
// the second implementation the "one implementation" rule forbids. So the
// rule moved DOWN to a leaf that both can import, and archetypes.Jaccard is
// now a one-line delegation: same function, same behavior, same Python twin
// parity, one implementation.
package textsim

import "strings"

// Jaccard is _jaccard: bigram-Jaccard similarity of two identifiers.
func Jaccard(a, b string) float64 {
	A, B := Bigrams(a), Bigrams(b)
	inter, union := 0, len(B)
	for k := range A {
		if B[k] {
			inter++
		} else {
			union++
		}
	}
	if union == 0 {
		return 0.0
	}
	return float64(inter) / float64(union)
}

// Bigrams is _bigrams: the lowercased 2-gram set, the whole string when it
// is one rune or shorter.
func Bigrams(s string) map[string]bool {
	rs := []rune(strings.ToLower(s))
	out := map[string]bool{}
	if len(rs) > 1 {
		for i := 0; i+1 < len(rs); i++ {
			out[string(rs[i:i+2])] = true
		}
		return out
	}
	out[string(rs)] = true
	return out
}
