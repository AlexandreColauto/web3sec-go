// parser_closures.go: contract-closure attachment (reverse-MRO transitive expansion).

package structidx

import (
	"sort"
	"strings"
	"websec/internal/validation"
)

// attachClosures is _attach_closures: reverse-MRO transitive expansion, own
// definitions win, entries sorted by (name, defining_contract, line, path).
func attachClosures(nodes []*idxNode, edges []idxEdge) {
	st := &attachClosuresState{
		contracts: map[string]*idxNode{},
		fns:       map[string]map[string]*idxNode{},
		byName:    map[string][]string{},
	}
	st.attachClosuresCollectNodes(nodes)
	st.attachClosuresCollectInherits(edges)
	for _, cid := range contractIDsInOrder(nodes) {
		st.attachClosuresContractClosure(st.contracts[cid], cid)
	}
}

// attachClosuresState carries the lookup tables attachClosures builds once
// and consults while expanding every contract's closure.
type attachClosuresState struct {
	contracts map[string]*idxNode
	fns       map[string]map[string]*idxNode
	byName    map[string][]string
	inherits  map[string][]string
}

// attachClosuresEntry is one closure candidate before serialization.
type attachClosuresEntry struct {
	name, defining, path string
	line                 int64
	node                 *idxNode
}

// attachClosuresCollectNodes indexes the contract and function nodes, then
// sorts the per-name id lists.
func (st *attachClosuresState) attachClosuresCollectNodes(nodes []*idxNode) {
	for _, n := range nodes {
		switch n.kind {
		case "contract", "interface", "library":
			st.contracts[n.id] = n
			st.byName[n.name] = append(st.byName[n.name], n.id)
		case "function":
			cid := n.id[:strings.LastIndexByte(n.id, '.')]
			if st.fns[cid] == nil {
				st.fns[cid] = map[string]*idxNode{}
			}
			st.fns[cid][n.name] = n
		}
	}
	for _, ids := range st.byName {
		sort.Strings(ids)
	}
}

// attachClosuresCollectInherits flattens the "inherits" edges into
// per-contract base-name lists.
func (st *attachClosuresState) attachClosuresCollectInherits(edges []idxEdge) {
	st.inherits = map[string][]string{}
	for _, e := range edges {
		if e.rel == "inherits" {
			st.inherits[e.from] = append(st.inherits[e.from],
				e.to[strings.Index(e.to, "#")+1:])
		}
	}
}

// attachClosuresEffective is the reverse-MRO transitive expansion: bases
// applied in reverse order, own definitions win.
func (st *attachClosuresState) attachClosuresEffective(cid string,
	seen map[string]bool) map[string]*idxNode {
	out := map[string]*idxNode{}
	bases := st.inherits[cid]
	for i := len(bases) - 1; i >= 0; i-- {
		for _, baseCid := range st.byName[bases[i]] {
			if seen[baseCid] {
				continue
			}
			next := map[string]bool{}
			for k := range seen {
				next[k] = true
			}
			next[cid] = true
			for k, v := range st.attachClosuresEffective(baseCid, next) {
				out[k] = v
			}
		}
	}
	for k, v := range st.fns[cid] {
		out[k] = v
	}
	return out
}

// attachClosuresSortedEntries lists the effective members sorted by
// (name, defining_contract, line, path).
func (st *attachClosuresState) attachClosuresSortedEntries(
	eff map[string]*idxNode) []attachClosuresEntry {
	entries := []attachClosuresEntry{}
	for fname, fnode := range eff {
		defining := fname
		if d, ok := st.contracts[fnode.id[:strings.LastIndexByte(fnode.id, '.')]]; ok {
			defining = d.name
		}
		ln := int64(-1)
		if fnode.line != nil {
			ln = *fnode.line
		}
		entries = append(entries, attachClosuresEntry{name: fname,
			defining: defining, path: fnode.path, line: ln, node: fnode})
	}
	sort.SliceStable(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if a.name != b.name {
			return a.name < b.name
		}
		if a.defining != b.defining {
			return a.defining < b.defining
		}
		if a.line != b.line {
			return a.line < b.line
		}
		return a.path < b.path
	})
	return entries
}

// attachClosuresClosureValues serializes the sorted entries as
// contract_closure objects.
func (st *attachClosuresState) attachClosuresClosureValues(
	entries []attachClosuresEntry) []validation.Value {
	closure := make([]validation.Value, 0, len(entries))
	for _, e := range entries {
		closure = append(closure, validation.VObj(
			validation.KV{K: "name", V: validation.VStr(e.name)},
			validation.KV{K: "defining_contract",
				V: validation.VStr(e.defining)},
			validation.KV{K: "path", V: validation.VStr(e.node.path)},
			validation.KV{K: "line", V: lineValue(e.node.line)},
			validation.KV{K: "guards", V: guardsValue(e.node.guards)},
			validation.KV{K: "uses", V: usesValue(e.node.uses)},
		))
	}
	return closure
}

// attachClosuresContractClosure computes and attaches one contract's closure.
func (st *attachClosuresState) attachClosuresContractClosure(cnode *idxNode,
	cid string) {
	eff := st.attachClosuresEffective(cid, map[string]bool{})
	entries := st.attachClosuresSortedEntries(eff)
	cnode.closure = st.attachClosuresClosureValues(entries)
}

func contractIDsInOrder(nodes []*idxNode) []string {
	out := []string{}
	for _, n := range nodes {
		switch n.kind {
		case "contract", "interface", "library":
			out = append(out, n.id)
		}
	}
	return out
}
