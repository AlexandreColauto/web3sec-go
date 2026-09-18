// enforcement_signals.go: the enforcement table's headline signals, ordering label and storage-name check.

package structidx

import (
	"fmt"
	"sort"
	"websec/internal/validation"
)

// enforcementSignals are the deterministic headline observations. Every row
// carries the site (or the write/read pair) it is about as machine-readable
// function ids, so a scoped table can be re-derived without re-parsing text.
func enforcementSignals(name string, sites []enfSite, pairs []enfPair) []validation.Value {
	writes, reads := 0, 0
	for _, s := range sites {
		switch s.kind {
		case "write":
			writes++
		case "read":
			reads++
		}
	}
	out := []validation.Value{}
	add := func(signal, detail string, extra ...validation.KV) {
		kvs := []validation.KV{
			{K: "signal", V: validation.VStr(signal)},
			{K: "detail", V: validation.VStr(detail)},
		}
		out = append(out, validation.VObj(append(kvs, extra...)...))
	}
	if writes == 0 && reads > 0 {
		add("no-writer", fmt.Sprintf("no function in the index writes %s; %d "+
			"read site(s) consume whatever is stored", name, reads))
	}
	if reads == 0 && writes > 0 {
		add("no-reader", fmt.Sprintf("%s is written by %d function(s) and "+
			"never read in this index", name, writes))
	}
	for _, s := range sites {
		if s.kind != "read" || s.guarded {
			continue
		}
		add("unguarded-read", fmt.Sprintf("%s.%s@%d reads %s with no assertion "+
			"about it", s.contract, s.function, s.line, name),
			validation.KV{K: "site", V: validation.VStr(s.id)},
			validation.KV{K: "line", V: validation.VInt(s.line)})
	}
	for _, p := range pairs {
		if !p.gap() {
			continue
		}
		w, r := sites[p.write], sites[p.read]
		read := "with no assertion about " + name
		if p.readGuarded {
			read = "under an assertion about " + name
		}
		add("unguarded-stage", fmt.Sprintf("the value written by %s.%s@%d "+
			"(unguarded) can reach %s.%s@%d %s", w.contract, w.function,
			w.line, r.contract, r.function, r.line, read),
			validation.KV{K: "write", V: validation.VStr(w.id)},
			validation.KV{K: "read", V: validation.VStr(r.id)})
	}
	return out
}

// enforcementOrdering is the ordering label plus the note that says when the
// ordering is only partial.
func enforcementOrdering(index validation.Value, sites []enfSite) (string, string) {
	if len(sites) == 0 {
		return "declaration", ""
	}
	entries := 0
	for _, n := range nodesOf(index, "function") {
		if boolAt(n, "is_entry_point") {
			entries++
		}
	}
	if entries == 0 {
		return "declaration", "the index has no entry point; sites are " +
			"ordered by (contract, function, line)"
	}
	unreached := 0
	for _, s := range sites {
		if !s.hasDepth {
			unreached++
		}
	}
	if unreached > 0 {
		return "partial", fmt.Sprintf("%d site(s) are not reachable from any "+
			"entry point; they are listed last", unreached)
	}
	return "call-graph", ""
}

// sortEnfSites orders by call-graph depth (unreachable last), then by
// (contract, function, line, kind) — a total, deterministic order.
func sortEnfSites(sites []enfSite) {
	sort.SliceStable(sites, func(i, j int) bool {
		a, b := sites[i], sites[j]
		if a.depth != b.depth {
			return a.depth < b.depth
		}
		if a.contract != b.contract {
			return a.contract < b.contract
		}
		if a.function != b.function {
			return a.function < b.function
		}
		if a.line != b.line {
			return a.line < b.line
		}
		return a.kind < b.kind
	})
}

// indexHasStorageName reports whether the index knows `name` as a storage
// variable: a state-variable node, or an entry of any function's
// reads_storage / writes_storage.
func indexHasStorageName(index validation.Value, name string) bool {
	for _, n := range nodesOf(index, "state-variable") {
		if validation.ObjStr(n, "name") == name {
			return true
		}
	}
	for _, n := range nodesOf(index, "function") {
		if listHas(validation.ObjAt(n, "writes_storage"), name) ||
			listHas(validation.ObjAt(n, "reads_storage"), name) {
			return true
		}
	}
	return false
}
