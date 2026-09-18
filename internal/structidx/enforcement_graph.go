// enforcement_graph.go: inheritance families and call-graph reachability over the index.

package structidx

import (
	"sort"
	"strings"
	"websec/internal/validation"
)

// enforcementFamilies is contract id -> inheritance family root, over the
// `inherits` edges (whose target is recorded as `*#Parent`).
func enforcementFamilies(index validation.Value) map[string]string {
	parent := map[string]string{}
	var find func(string) string
	find = func(x string) string {
		p, ok := parent[x]
		if !ok || p == x {
			parent[x] = x
			return x
		}
		root := find(p)
		parent[x] = root
		return root
	}
	union := func(a, b string) {
		ra, rb := find(a), find(b)
		if ra == rb {
			return
		}
		if rb < ra {
			ra, rb = rb, ra
		}
		parent[rb] = ra
	}
	byName := map[string]string{}
	for _, n := range nodesOf(index, "") {
		switch validation.ObjStr(n, "kind") {
		case "contract", "interface", "library":
			byName[validation.ObjStr(n, "name")] = validation.ObjStr(n, "id")
			find(validation.ObjStr(n, "id"))
		}
	}
	for _, e := range edgesOf(index) {
		if validation.ObjStr(e, "rel") != "inherits" {
			continue
		}
		to := validation.ObjStr(e, "to")
		if i := strings.LastIndex(to, "#"); i >= 0 {
			to = to[i+1:]
		}
		if id, ok := byName[to]; ok {
			union(validation.ObjStr(e, "from"), id)
		}
	}
	out := map[string]string{}
	for id := range parent {
		out[id] = find(id)
	}
	return out
}

// enforcementCallGraph is the `calls` adjacency, keyed by resolved node id.
func enforcementCallGraph(index validation.Value) map[string][]string {
	known := map[string]bool{}
	short := map[string]string{}
	for _, n := range nodesOf(index, "") {
		id := validation.ObjStr(n, "id")
		known[id] = true
		if _, f := splitNodeID(id); f != "" {
			short["#"+f] = id
		}
	}
	resolve := func(to string) string {
		if known[to] {
			return to
		}
		return short[to]
	}
	adj := map[string][]string{}
	for _, e := range edgesOf(index) {
		if validation.ObjStr(e, "rel") != "calls" {
			continue
		}
		if id := resolve(validation.ObjStr(e, "to")); id != "" {
			from := validation.ObjStr(e, "from")
			adj[from] = append(adj[from], id)
		}
	}
	return adj
}

// bfsReach is the set of nodes reachable from start within depth edges.
func bfsReach(adj map[string][]string, start string, depth int) map[string]bool {
	seen := map[string]bool{start: true}
	frontier := []string{start}
	for d := 0; d < depth && len(frontier) > 0; d++ {
		next := []string{}
		for _, cur := range frontier {
			for _, to := range adj[cur] {
				if seen[to] {
					continue
				}
				seen[to] = true
				next = append(next, to)
			}
		}
		frontier = next
	}
	return seen
}

// enforcementDepths is the BFS depth of every function node reachable from an
// entry point over the `calls` edges (entry points are depth 0). A node with
// no entry is absent from the map.
func enforcementDepths(index validation.Value) map[string]int {
	adj := enforcementCallGraph(index)
	dist := map[string]int{}
	queue := []string{}
	for _, n := range nodesOf(index, "function") {
		if boolAt(n, "is_entry_point") {
			id := validation.ObjStr(n, "id")
			if _, ok := dist[id]; !ok {
				dist[id] = 0
				queue = append(queue, id)
			}
		}
	}
	sort.Strings(queue)
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		next := append([]string(nil), adj[cur]...)
		sort.Strings(next)
		for _, to := range next {
			if _, ok := dist[to]; ok {
				continue
			}
			dist[to] = dist[cur] + 1
			queue = append(queue, to)
		}
	}
	return dist
}
