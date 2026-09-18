// enforcement_sites.go: per-site collection and cross-function stage pairing for the enforcement table.

package structidx

import (
	"websec/internal/validation"
)

// enforcementSites collects the sites of name. Statement-level `uses` come
// first because they are both more precise (the exact line) and more complete
// than the function-level storage lists — the fixture's
// `prevStateRoot[i + 1] = stateRoot` is a statement-level write that the
// function's writes_storage does not list. The storage lists remain as the
// fallback: when a function's reads_storage/writes_storage names the variable
// but no use of that kind was recorded, the site is emitted at the function
// declaration line with granularity "function" (an index without statement
// uses still answers, coarsely).
func enforcementSites(index validation.Value, name, conceptKey string,
	storageMatch bool, depths map[string]int) []enfSite {
	out := []enfSite{}
	seen := map[string]bool{}
	statementKind := map[string]bool{}
	for _, n := range nodesOf(index, "function") {
		id := validation.ObjStr(n, "id")
		contract, function := splitNodeID(id)
		guards := enfGuardsOf(n, conceptKey)
		guarded := false
		for _, g := range guards {
			if g.about {
				guarded = true
				break
			}
		}
		depth, ok := depths[id]
		if !ok {
			depth = unReachable
		}
		base := enfSite{contract: contract, function: function, id: id,
			guards: guards, guarded: guarded, entry: boolAt(n, "is_entry_point"),
			depth: depth, hasDepth: ok}
		for _, u := range usesOf(n) {
			k := validation.ObjStr(u, "kind")
			if k != "write" && k != "read" {
				continue
			}
			if !hasConceptKey(strList(validation.ObjAt(u, "concept_keys")), conceptKey) {
				continue
			}
			line := intAt(u, "line")
			key := id + "|" + k + "|" + intText(line)
			if seen[key] {
				continue
			}
			seen[key] = true
			statementKind[id+"|"+k] = true
			s := base
			s.kind, s.line, s.gran = k, line, "statement"
			out = append(out, s)
		}
		if !storageMatch {
			continue
		}
		kinds := []string{}
		if listHas(validation.ObjAt(n, "writes_storage"), name) {
			kinds = append(kinds, "write")
		}
		if listHas(validation.ObjAt(n, "reads_storage"), name) {
			kinds = append(kinds, "read")
		}
		for _, kind := range kinds {
			if statementKind[id+"|"+kind] {
				continue
			}
			line := objLineOf(n)
			key := id + "|" + kind + "|" + intText(line)
			if seen[key] {
				continue
			}
			seen[key] = true
			s := base
			s.kind, s.line, s.gran = kind, line, "function"
			out = append(out, s)
		}
	}
	return out
}

// enforcementStages is the cross-function (write, read) pair table. A pair is
// reported only when the two sites are actually related — same contract, same
// inheritance family, or one function can reach the other over `calls` edges.
// Eight gateway contracts that each declare their own `tokenMapping` share a
// name, not a variable, and pairing them would bury the one pair that matters
// under 143 that do not. Every skipped pair is counted in stats.
func enforcementStages(index validation.Value, sites []enfSite) ([]enfPair, int) {
	families := enforcementFamilies(index)
	adj := enforcementCallGraph(index)
	reach := map[string]map[string]bool{}
	reaches := func(from, to string) bool {
		set, ok := reach[from]
		if !ok {
			set = bfsReach(adj, from, enfReachDepth)
			reach[from] = set
		}
		return set[to]
	}
	out := []enfPair{}
	skipped := 0
	for i, w := range sites {
		if w.kind != "write" {
			continue
		}
		for j, r := range sites {
			if r.kind != "read" || r.id == w.id {
				continue
			}
			if w.hasDepth && r.hasDepth && r.depth < w.depth {
				continue // the read runs upstream of the write: not this pair
			}
			if !enfRelated(families, w, r, reaches) {
				skipped++
				continue
			}
			out = append(out, enfPair{write: i, read: j,
				writeGuarded: w.guarded, readGuarded: r.guarded})
		}
	}
	return out, skipped
}

// enfReachDepth bounds the call-graph reachability test used for pairing.
const enfReachDepth = 4

// enfRelated is the pairing predicate: one variable in one contract, or two
// contracts that inherit from each other, or two functions on one call path.
func enfRelated(families map[string]string, w, r enfSite, reaches func(a, b string) bool) bool {
	if w.contract == r.contract {
		return true
	}
	if root, ok := families[w.contract]; ok {
		if other, ok2 := families[r.contract]; ok2 && root == other {
			return true
		}
	}
	return reaches(w.id, r.id) || reaches(r.id, w.id)
}
