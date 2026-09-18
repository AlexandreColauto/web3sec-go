// writers.go — IMPROVEMENTS C0: the read-side reconciliation of an index
// whose per-function write list under-reports.
//
// The parser's `writes_storage` records only some of the writes its own
// statement-level `uses` prove. Measured across the 18 fixture indexes: 52 of
// the 144 statement-proven (state variable, kind) pairs are missing from the
// lists, and every one of them is a WRITE — a compound or indexed lvalue such
// as `prevStateRoot[i+1] = root`, `tokenMapping[token] = remote`, or
// `deposits[to] += amount`. Reads are complete. So every consumer that answers
// "who writes X" from the lists alone (the reference's storage_writers query,
// the corpus prescreen probes, the archetype `unguarded_entry_writes` check,
// the recency heuristic) under-reports writers, and a reentrancy-shaped
// function whose only write is a statement-level one looks read-only.
//
// The index bytes stay exactly as the parser produced them — the parity
// goldens pin them, and the parser's own golden tests pin them more tightly
// still. This file is the read-side fix instead: `WritersOf` and its
// companions hand consumers the union of the list and the statement-proven
// writes, resolving a statement write to a variable NAME through the index's
// state-variable nodes (the same maximal-concept-key rule the enforcement
// table uses).
package structidx

import (
	"sort"

	"websec/internal/validation"
)

// storageVarNames maps every maximal concept key the index knows as a state
// variable to a representative variable name. Collisions (the same concept
// declared by several contracts — the sibling gateways' `tokenMapping`) resolve
// to the lexicographically first name, which is deterministic and is the same
// name anyway.
func storageVarNames(index validation.Value) map[string]string {
	out := map[string]string{}
	names := []string{}
	for _, n := range nodesOf(index, "state-variable") {
		names = append(names, validation.ObjStr(n, "name"))
	}
	sort.Strings(names)
	for _, name := range names {
		key := conceptKeyOf(name)
		if key == "" {
			continue
		}
		if _, seen := out[key]; !seen {
			out[key] = name
		}
	}
	return out
}

// statementWriters is the names of the state variables this function's
// statement-level write uses prove it writes, sorted. Statements whose maximal
// key belongs to no state variable the index knows (a local, a parameter, a
// library expression) are not storage writes and are dropped.
func statementWriters(vars map[string]string, n validation.Value) []string {
	keys := []string{}
	for _, u := range usesOf(n) {
		if validation.ObjStr(u, "kind") != "write" {
			continue
		}
		key := conceptKeyOf(maxKeyText(strList(validation.ObjAt(u, "concept_keys"))))
		if _, ok := vars[key]; ok {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	out := []string{}
	for _, key := range keys {
		name := vars[key]
		if len(out) == 0 || out[len(out)-1] != name {
			out = append(out, name)
		}
	}
	return out
}

// maxKeyText is the maximal concept key of a key list: splitIdent returns the
// chain of prefixes ending in the full expression's key, so the longest entry
// is the one for the whole expression.
func maxKeyText(keys []string) string {
	best := ""
	for _, k := range keys {
		if len(k) > len(best) {
			best = k
		}
	}
	return best
}

// WritersOf is the complete "this function writes" list: the parser's
// writes_storage entries in their own order, then the statement-proven writes
// the list omits, sorted and deduplicated. Consumers that answer "who writes
// X" should use this rather than the raw list (see the file comment).
func WritersOf(index, n validation.Value) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, name := range strList(validation.ObjAt(n, "writes_storage")) {
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	for _, name := range statementWriters(storageVarNames(index), n) {
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

// ReadsWritesOf is WritersOf unioned with the (complete) reads_storage list:
// for patterns that ask "does this function touch A and B" without caring
// which side is which.
func ReadsWritesOf(index, n validation.Value) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, name := range strList(validation.ObjAt(n, "reads_storage")) {
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	for _, name := range WritersOf(index, n) {
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

// EffectiveWriters is the complete storage_writers: sorted ids of the
// functions that write varName, from the lists or from a statement-level
// write. StorageWriters (the reference query, kept verbatim for parity) only
// consults the lists and is therefore under-inclusive.
func EffectiveWriters(index validation.Value, varName string) []string {
	key := conceptKeyOf(varName)
	vars := storageVarNames(index)
	seen := map[string]bool{}
	out := []string{}
	for _, n := range nodesOf(index, "function") {
		hit := listHas(validation.ObjAt(n, "writes_storage"), varName)
		if !hit && key != "" {
			if name, ok := vars[key]; ok {
				for _, w := range statementWriters(vars, n) {
					if w == name {
						hit = true
						break
					}
				}
			}
		}
		if hit {
			if id := validation.ObjStr(n, "id"); !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	sort.Strings(out)
	return out
}
