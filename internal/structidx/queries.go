// queries.go: the graph queries downstream agents ask of the index —
// callers/paths, storage writers, the external surface, the value-flow
// backward slice and the amplifier signals. Every query takes the parsed
// artifact as a validation.Value, exactly as the Python functions take the
// read-back dict: no query may depend on in-process parser state.
package structidx

import (
	"path/filepath"
	"regexp"
	"sort"

	"websec/internal/state"
	"websec/internal/validation"
)

func nodesOf(index validation.Value, kind string) []validation.Value {
	out := []validation.Value{}
	arr := objAt(index, "nodes")
	if arr.Kind != validation.Arr {
		return out
	}
	for _, n := range arr.A {
		if kind == "" || objStr(n, "kind") == kind {
			out = append(out, n)
		}
	}
	return out
}

func edgesOf(index validation.Value) []validation.Value {
	arr := objAt(index, "edges")
	if arr.Kind != validation.Arr {
		return nil
	}
	return arr.A
}

func strList(v validation.Value) []string {
	if v.Kind != validation.Arr {
		return nil
	}
	out := make([]string, 0, len(v.A))
	for _, e := range v.A {
		if e.Kind == validation.Str {
			out = append(out, e.S)
		}
	}
	return out
}

func hasPrefix2(s, p string) bool {
	return len(s) >= len(p) && s[:len(p)] == p
}

// ExternalSurface is external_surface: the entry-point function nodes.
func ExternalSurface(index validation.Value) []validation.Value {
	out := []validation.Value{}
	for _, n := range nodesOf(index, "function") {
		if b := objAt(n, "is_entry_point"); b.Kind == validation.Bool && b.B {
			out = append(out, n)
		}
	}
	return out
}

// CallersOf is callers_of: sorted unique call-edge sources for a node id.
func CallersOf(index validation.Value, nodeID string) []string {
	short := nodeID
	if i := lastIndexByte(nodeID, '#'); i >= 0 {
		short = nodeID[i+1:]
	}
	seen := map[string]bool{}
	for _, e := range edgesOf(index) {
		if objStr(e, "rel") != "calls" {
			continue
		}
		to := objStr(e, "to")
		if to == nodeID || hasSuffix(to, "."+short) {
			seen[objStr(e, "from")] = true
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func hasSuffix(s, suf string) bool {
	return len(s) >= len(suf) && s[len(s)-len(suf):] == suf
}

// StorageWriters is storage_writers: sorted ids of functions writing var.
func StorageWriters(index validation.Value, varName string) []string {
	out := []string{}
	for _, n := range nodesOf(index, "function") {
		for _, w := range strList(objAt(n, "writes_storage")) {
			if w == varName {
				out = append(out, objStr(n, "id"))
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// ExternalCallSites is external_call_sites.
func ExternalCallSites(index validation.Value) []validation.Value {
	out := []validation.Value{}
	for _, n := range nodesOf(index, "function") {
		if len(strList(objAt(n, "calls_external"))) > 0 ||
			len(strList(objAt(n, "delegatecalls"))) > 0 {
			out = append(out, n)
		}
	}
	return out
}

func nodeGuardedBy(n validation.Value) []string {
	return strList(objAt(n, "guarded_by"))
}

// GuardedEntryPoints is guarded_entry_points: entry points protected by an
// AUTHORIZATION modifier (reentrancy/pausability guards do not count).
func GuardedEntryPoints(index validation.Value) []validation.Value {
	out := []validation.Value{}
	for _, n := range ExternalSurface(index) {
		for _, m := range nodeGuardedBy(n) {
			if isAuthzGuard(m) {
				out = append(out, n)
				break
			}
		}
	}
	return out
}

// UnguardedEntryPoints is unguarded_entry_points.
func UnguardedEntryPoints(index validation.Value) []validation.Value {
	out := []validation.Value{}
	for _, n := range ExternalSurface(index) {
		guarded := false
		for _, m := range nodeGuardedBy(n) {
			if isAuthzGuard(m) {
				guarded = true
				break
			}
		}
		if !guarded {
			out = append(out, n)
		}
	}
	return out
}

// PathExists is path_exists: one BFS witness path over internal call edges.
func PathExists(index validation.Value, src, dst string, maxDepth int) ([]string, bool) {
	adj := map[string][]string{}
	for _, e := range edgesOf(index) {
		to := objStr(e, "to")
		if objStr(e, "rel") == "calls" && !hasPrefix2(to, "*#") {
			adj[objStr(e, "from")] = append(adj[objStr(e, "from")], to)
		}
	}
	type item struct {
		node string
		path []string
	}
	queue := []item{{src, []string{src}}}
	visited := map[string]bool{src: true}
	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		if it.node == dst {
			return it.path, true
		}
		if len(it.path) > maxDepth {
			continue
		}
		for _, nxt := range adj[it.node] {
			if visited[nxt] {
				continue
			}
			visited[nxt] = true
			queue = append(queue, item{nxt, append(append([]string{}, it.path...), nxt)})
		}
	}
	return nil, false
}

// SinkFunctions is sink_functions: functions whose external/delegate calls
// move value by construction, sorted by function id.
func SinkFunctions(index validation.Value) []validation.Value {
	out := []validation.Value{}
	for _, n := range nodesOf(index, "function") {
		calls := append(strList(objAt(n, "calls_external")),
			strList(objAt(n, "delegatecalls"))...)
		hits := map[string]bool{}
		for _, c := range calls {
			if isSinkCall(c) {
				hits[c] = true
			}
		}
		if len(hits) == 0 {
			continue
		}
		keys := make([]string, 0, len(hits))
		for k := range hits {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out = append(out, validation.VObj(
			validation.KV{K: "function_id", V: objAt(n, "id")},
			validation.KV{K: "sink_calls", V: strArr(keys)},
		))
	}
	sort.SliceStable(out, func(i, j int) bool {
		return objStr(out[i], "function_id") < objStr(out[j], "function_id")
	})
	return out
}

// witnessPath is _witness_path: one BFS witness src -> dst over forward call
// edges, neighbors visited in sorted order.
func witnessPath(fwd map[string]map[string]bool, src, dst string,
	maxDepth int) ([]string, bool) {
	if src == dst {
		return []string{src}, true
	}
	type item struct {
		node string
		path []string
	}
	queue := []item{{src, []string{src}}}
	visited := map[string]bool{src: true}
	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		neigh := make([]string, 0, len(fwd[it.node]))
		for k := range fwd[it.node] {
			neigh = append(neigh, k)
		}
		sort.Strings(neigh)
		for _, nxt := range neigh {
			if visited[nxt] {
				continue
			}
			visited[nxt] = true
			if nxt == dst {
				return append(append([]string{}, it.path...), nxt), true
			}
			if len(it.path) < maxDepth {
				queue = append(queue, item{nxt,
					append(append([]string{}, it.path...), nxt)})
			}
		}
	}
	return nil, false
}

// BackwardSlice is backward_slice: for every sink, the reverse closure, the
// entry points in it (with their authz guard state) and the state variables
// read along one witness path per entry point.
func BackwardSlice(index validation.Value, maxDepth int) []validation.Value {
	rev := map[string]map[string]bool{}
	fwd := map[string]map[string]bool{}
	for _, e := range edgesOf(index) {
		to := objStr(e, "to")
		if objStr(e, "rel") != "calls" || hasPrefix2(to, "*#") {
			continue
		}
		from := objStr(e, "from")
		if rev[to] == nil {
			rev[to] = map[string]bool{}
		}
		rev[to][from] = true
		if fwd[from] == nil {
			fwd[from] = map[string]bool{}
		}
		fwd[from][to] = true
	}
	fns := map[string]validation.Value{}
	for _, n := range nodesOf(index, "function") {
		fns[objStr(n, "id")] = n
	}
	out := []validation.Value{}
	for _, s := range SinkFunctions(index) {
		fid := objStr(s, "function_id")
		seen := map[string]bool{fid: true}
		frontier := []string{fid}
		for depth := 0; len(frontier) > 0 && depth < maxDepth; depth++ {
			nxt := map[string]bool{}
			for _, node := range frontier {
				for caller := range rev[node] {
					if !seen[caller] {
						seen[caller] = true
						nxt[caller] = true
					}
				}
			}
			frontier = sortedKeys(nxt)
		}
		type ep struct {
			id, name string
			guarded  bool
		}
		entryPoints := []ep{}
		for _, n := range ExternalSurface(index) {
			id := objStr(n, "id")
			if !seen[id] {
				continue
			}
			guarded := false
			for _, m := range nodeGuardedBy(n) {
				if isAuthzGuard(m) {
					guarded = true
					break
				}
			}
			entryPoints = append(entryPoints, ep{id, objStr(n, "name"), guarded})
		}
		sort.SliceStable(entryPoints, func(i, j int) bool {
			return entryPoints[i].id < entryPoints[j].id
		})
		varsRead := map[string]bool{}
		for _, e := range entryPoints {
			if path, ok := witnessPath(fwd, e.id, fid, maxDepth); ok {
				for _, pid := range path {
					for _, v := range strList(objAt(fns[pid], "reads_storage")) {
						varsRead[v] = true
					}
				}
			}
		}
		epVals := make([]validation.Value, 0, len(entryPoints))
		unguarded := []string{}
		for _, e := range entryPoints {
			epVals = append(epVals, validation.VObj(
				validation.KV{K: "id", V: validation.VStr(e.id)},
				validation.KV{K: "name", V: validation.VStr(e.name)},
				validation.KV{K: "authz_guarded", V: validation.VBool(e.guarded)},
			))
			if !e.guarded {
				unguarded = append(unguarded, e.id)
			}
		}
		out = append(out, validation.VObj(
			validation.KV{K: "sink_function", V: validation.VStr(fid)},
			validation.KV{K: "sink_calls", V: objAt(s, "sink_calls")},
			validation.KV{K: "reachable_functions",
				V: strArr(sortedKeys(seen))},
			validation.KV{K: "entry_points", V: validation.VArr(epVals...)},
			validation.KV{K: "unguarded_entry_points", V: strArr(unguarded)},
			validation.KV{K: "state_vars_read_on_paths",
				V: strArr(sortedKeys(varsRead))},
		))
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ValueFlowReport is value_flow_report: the campaign-level backward-slice
// artifact, registered and logged like every other artifact (HINT-only). It
// rebuilds a stale index first (EnsureFreshIndex) so re-running after a
// re-pin converges instead of copying the old pin forward.
func ValueFlowReport(c *state.Campaign, root string) (validation.Value, error) {
	idx, err := EnsureFreshIndex(c, root)
	if err != nil {
		return validation.VNull(), err
	}
	sinks := BackwardSlice(idx, 8)
	unguarded := map[string]bool{}
	for _, s := range sinks {
		for _, e := range strList(objAt(s, "unguarded_entry_points")) {
			unguarded[e] = true
		}
	}
	head := sortedKeys(unguarded)
	if len(head) > 25 {
		head = head[:25]
	}
	report := validation.VObj(
		validation.KV{K: "generated_at", V: validation.VStr(nowIso())},
		validation.KV{K: "snapshot_id", V: objAt(idx, "snapshot_id")},
		validation.KV{K: "sinks", V: validation.VArr(sinks...)},
		validation.KV{K: "unguarded_sink_paths", V: strArr(head)},
		validation.KV{K: "stats", V: validation.VObj(
			validation.KV{K: "sinks", V: validation.VInt(int64(len(sinks)))},
			validation.KV{K: "unguarded_paths",
				V: validation.VInt(int64(len(unguarded)))},
		)},
	)
	out := filepath.Join(c.ArtifactsDir, ValueFlowFile)
	if err := validation.WriteJson(out, report, ""); err != nil {
		return validation.VNull(), err
	}
	reason := itoa(int64(len(sinks))) + " sinks, " +
		itoa(int64(len(unguarded))) + " unguarded paths"
	if _, err := c.RegisterOrRefresh("value-flow", out, "", nil, reason); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(
		validation.KV{K: "sinks", V: validation.VInt(int64(len(sinks)))},
		validation.KV{K: "unguarded_paths", V: validation.VInt(int64(len(unguarded)))},
	)
	if _, err := c.Log("valueflow.computed", nil, &data); err != nil {
		return validation.VNull(), err
	}
	return report, nil
}

// AmplifierSignals is amplifier_signals: signal name -> sorted node ids.
func AmplifierSignals(index validation.Value) validation.Value {
	out := map[string][]string{}
	for _, n := range nodesOf(index, "function") {
		id := objStr(n, "id")
		deleg := strList(objAt(n, "delegatecalls"))
		if len(deleg) > 0 {
			out["delegatecall"] = append(out["delegatecall"], id)
		}
		calls := append(append([]string{}, strList(objAt(n, "calls_external"))...),
			deleg...)
		for _, ap := range amplifierPatterns {
			for _, c := range calls {
				if ap.re.MatchString(c) {
					out[ap.sig] = append(out[ap.sig], id)
					break
				}
			}
		}
	}
	for _, kind := range []string{"contract", "interface"} {
		for _, n := range nodesOf(index, kind) {
			name := objStr(n, "name")
			id := objStr(n, "id")
			for _, sig := range []string{"bridge", "cross-chain"} {
				if ampPattern(sig).MatchString(name) && !containsStr(out[sig], id) {
					out[sig] = append(out[sig], id)
				}
			}
		}
	}
	keys := make([]string, 0, len(out))
	for k := range out {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	kvs := make([]validation.KV, 0, len(keys))
	for _, k := range keys {
		kvs = append(kvs, validation.KV{K: k,
			V: strArr(sortedKeys(dedupe(out[k])))})
	}
	return validation.VObj(kvs...)
}

func ampPattern(sig string) *regexp.Regexp {
	for _, ap := range amplifierPatterns {
		if ap.sig == sig {
			return ap.re
		}
	}
	return nil
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func dedupe(xs []string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}
