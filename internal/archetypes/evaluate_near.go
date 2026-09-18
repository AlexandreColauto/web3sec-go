// evaluate_near.go: near_matches split out of evaluate.go — the top-k
// almost-matched identifiers and the bigram-Jaccard alias.
package archetypes

import (
	"regexp"
	"sort"
	"websec/internal/structidx"
	"websec/internal/textsim"
	"websec/internal/validation"
)

// NearMatches is near_matches: top-k identifiers the check ALMOST matched —
// false-miss visibility. Candidate pool per check type; score is the max
// bigram-Jaccard over the check's literal tokens.
func NearMatches(check, index validation.Value, k int) []string {
	t := validation.ObjStr(check, "type")
	var cands []string
	switch t {
	case "state_var_exists", "unguarded_entry_writes",
		"threshold_without_enforcement", "relayer_single_key",
		"verifier_default_on":
		for _, n := range structidx.Nodes(index, "state-variable") {
			cands = append(cands, validation.ObjStr(n, "name"))
		}
	case "function_exists", "unguarded_function_exists",
		"sig_verify_no_separator", "merkle_verify_without_depth_gate",
		"merkle_proof_no_length_check":
		for _, n := range structidx.Nodes(index, "function") {
			cands = append(cands, validation.ObjStr(n, "name"))
		}
	case "external_call_pattern":
		for _, n := range structidx.Nodes(index, "function") {
			for _, c := range listAt(n, "calls_external") {
				if c.Kind == validation.Str {
					cands = append(cands, c.S)
				}
			}
		}
	default:
		return nil
	}
	lits := checkLiterals(check)
	if len(lits) == 0 {
		return nil
	}
	type scored struct {
		score float64
		name  string
	}
	var rows []scored
	for _, c := range dedupeStrings(cands) {
		best := 0.0
		for _, lit := range lits {
			if j := Jaccard(c, lit); j > best {
				best = j
			}
		}
		rows = append(rows, scored{best, c})
	}
	// Python: sorted((score, c) for ...), reverse=True) — score desc, then
	// the identifier desc (tuple comparison under reverse).
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].score != rows[j].score {
			return rows[i].score > rows[j].score
		}
		return rows[i].name > rows[j].name
	})
	if len(rows) > k {
		rows = rows[:k]
	}
	out := []string{}
	for _, r := range rows {
		if r.score > 0.25 {
			out = append(out, r.name)
		}
	}
	return out
}

// Jaccard is _jaccard: bigram-Jaccard similarity of two identifiers.
//
// The rule itself lives in internal/textsim. evalstore's I1b near-dup scan
// needs the SAME function, and evalstore cannot import this package (this
// package reaches evalstore through structidx -> orchestrator -> risk), so
// the leaf owns the implementation and this name stays the archetypes-facing
// alias. One implementation, two callers, no second copy to drift.
func Jaccard(a, b string) float64 { return textsim.Jaccard(a, b) }

// checkLiterals is _check_literals: the literal identifiers a check looks
// for (for near-matching) — its names plus every >3-char identifier token in
// its regex keys.
func checkLiterals(check validation.Value) []string {
	lits := []string{}
	for _, n := range listAt(check, "names") {
		if n.Kind == validation.Str {
			lits = append(lits, n.S)
		}
	}
	for _, key := range []string{"pattern", "var_pattern"} {
		if v := validation.ObjAt(check, key); v.Kind == validation.Str {
			for _, t := range wordRe.FindAllString(v.S, -1) {
				if len(t) > 3 {
					lits = append(lits, t)
				}
			}
		}
	}
	return lits
}

// wordRe is re.findall(r"[A-Za-z_]\w*", text) — \w is ASCII here, which is
// what every shipped pattern contains.
var wordRe = regexp.MustCompile(`[A-Za-z_]\w*`)
