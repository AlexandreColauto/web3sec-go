// enforcement.go — IMPROVEMENTS C1: the enforcement-timing table.
//
// The assertion-strength probe finds single (assertion, consumer) pairs. The
// question that actually matters is the whole stage table for one storage
// variable: where is it written, where is it read, which of those sites is
// guarded and by what, and at which stage is the invariant enforced? The
// structural index already records everything needed (per-function
// reads_storage/writes_storage, statement-level `uses` with their concept
// keys, per-function `guards` with their class, and the `calls` edges), but
// nothing assembled it — so an operator had to infer the table by hand.
//
// EnforcementTable is that assembly, and it is deterministic: the same index
// always yields the same rows in the same order. It is the backbone for the
// G-01-class question ("prevStateRoot is read in commitBatch, read again in a
// later stage, and NOTHING in the index ever writes or checks it") which the
// model previously had to stumble onto.
//
// Matching is by the index's own concept key. `name` is a storage variable
// name when the index knows it as a state variable or as a
// reads_storage/writes_storage entry; every site is then matched through the
// maximal concept key of that name (splitIdent + synonym fold, joined by ":",
// i.e. `storedHash` -> "stored:root"). A name the index does not know is
// matched the same way, so `prev-state root` finds exactly the sites of
// `prevStateRoot`. There is no separate concept->variable map to consult:
// concept keys ARE the tokenized form of the expressions the parser saw. The
// maximal key (rather than "any shared token") is what keeps `storedHash`
// from matching every `...root...` expression: a partial token overlap is a
// different variable.
package structidx

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// unReachable is the depth rank of a site no entry point can reach: it sorts
// after every reachable site.
const unReachable = 1 << 30

// LoadIndex reads the stored structural index as-is (no freshness check, no
// source tree needed): the read-only queries answer from what is on disk.
func LoadIndex(c *state.Campaign) (validation.Value, error) {
	p := IndexPath(c)
	if _, err := os.Stat(p); err != nil {
		return validation.VNull(), fmt.Errorf(
			"no structural index for %s; run `webv2 index --src SRC %s` first",
			c.CampaignID, c.CampaignID)
	}
	return validation.ReadJson(p)
}

// enfGuard is one assertion attached to a site's containing function.
type enfGuard struct {
	line  int64
	class int64
	text  string
	about bool // the assertion's concept keys contain the queried maximal key
}

// enfSite is one write or read site of the queried variable.
type enfSite struct {
	contract string
	function string
	id       string
	kind     string // "write" | "read"
	line     int64
	gran     string // "statement" (a use was found) | "function"
	guards   []enfGuard
	guarded  bool
	entry    bool
	depth    int
	hasDepth bool
}

// EnforcementOpts scopes the table. An empty Contract is the honest default:
// every site in the index, which is what you want when a variable name is
// unique but noise when eight gateway contracts share it.
type EnforcementOpts struct {
	Contract string
}

// EnforcementTable is enforcement_table(index, name): every write and read
// site of `name`, ordered by call-graph depth from an entry point, each with
// the assertions its containing function carries, plus the (write, read) stage
// pairs between related sites, each marked with which side carries an
// assertion about the name.
func EnforcementTable(index validation.Value, name string) validation.Value {
	return EnforcementTableOpts(index, name, EnforcementOpts{})
}

// EnforcementTableOpts is EnforcementTable scoped to one contract.
func EnforcementTableOpts(index validation.Value, name string,
	opts EnforcementOpts) validation.Value {
	keys := ConceptKeys(name)
	key := conceptKeyOf(name)
	storageMatch := indexHasStorageName(index, name)
	depths := enforcementDepths(index)
	sites := enforcementSites(index, name, key, storageMatch, depths)
	if opts.Contract != "" {
		kept := make([]enfSite, 0, len(sites))
		for _, s := range sites {
			if s.contract == opts.Contract {
				kept = append(kept, s)
			}
		}
		sites = kept
	}

	match := "none"
	switch {
	case storageMatch:
		match = "storage"
	case len(sites) > 0:
		match = "concept"
	}
	sortEnfSites(sites)

	stages, skippedPairs := enforcementStages(index, sites)
	signals := enforcementSignals(name, sites, stages)

	reachable := 0
	writes, reads, unguardedWrites, unguardedReads, gaps := 0, 0, 0, 0, 0
	for _, s := range sites {
		if s.hasDepth {
			reachable++
		}
		switch s.kind {
		case "write":
			writes++
			if !s.guarded {
				unguardedWrites++
			}
		case "read":
			reads++
			if !s.guarded {
				unguardedReads++
			}
		}
	}
	stageRows := []validation.Value{}
	openGaps := 0
	for _, p := range stages {
		if p.gap() {
			gaps++
		}
		if p.open() {
			openGaps++
		}
		w, r := sites[p.write], sites[p.read]
		stageRows = append(stageRows, validation.VObj(
			validation.KV{K: "write", V: enfSiteRef(w)},
			validation.KV{K: "read", V: enfSiteRef(r)},
			validation.KV{K: "write_guarded", V: validation.VBool(p.writeGuarded)},
			validation.KV{K: "read_guarded", V: validation.VBool(p.readGuarded)},
			validation.KV{K: "gap", V: validation.VBool(p.gap())}))
	}

	kvs := []validation.KV{
		{K: "name", V: validation.VStr(name)},
		{K: "match", V: validation.VStr(match)},
		{K: "concept_key", V: validation.VStr(key)},
		{K: "concept_keys", V: strArr(keys)},
	}
	if opts.Contract != "" {
		kvs = append(kvs, validation.KV{K: "contract", V: validation.VStr(opts.Contract)})
	}
	ordering, note := enforcementOrdering(index, sites)
	if opts.Contract != "" {
		scope := "filtered to contract " + opts.Contract
		if note == "" {
			note = scope
		} else {
			note = scope + "; " + note
		}
	}
	kvs = append(kvs, validation.KV{K: "ordering", V: validation.VStr(ordering)})
	if note != "" {
		kvs = append(kvs, validation.KV{K: "note", V: validation.VStr(note)})
	}
	kvs = append(kvs,
		validation.KV{K: "sites", V: validation.VArr(enfSiteValues(sites)...)},
		validation.KV{K: "stages", V: validation.VArr(stageRows...)},
		validation.KV{K: "signals", V: validation.VArr(signals...)},
		validation.KV{K: "stats", V: validation.VObj(
			validation.KV{K: "sites", V: validation.VInt(int64(len(sites)))},
			validation.KV{K: "reachable_sites", V: validation.VInt(int64(reachable))},
			validation.KV{K: "writes", V: validation.VInt(int64(writes))},
			validation.KV{K: "reads", V: validation.VInt(int64(reads))},
			validation.KV{K: "unguarded_writes", V: validation.VInt(int64(unguardedWrites))},
			validation.KV{K: "unguarded_reads", V: validation.VInt(int64(unguardedReads))},
			validation.KV{K: "stage_pairs", V: validation.VInt(int64(len(stages)))},
			validation.KV{K: "stage_gaps", V: validation.VInt(int64(gaps))},
			validation.KV{K: "stage_open_gaps", V: validation.VInt(int64(openGaps))},
			validation.KV{K: "stage_pairs_skipped", V: validation.VInt(int64(skippedPairs))},
		)})
	return validation.VObj(kvs...)
}

// enfPair is one (write site, read site) stage pair, as indices into sites.
// Each side records whether its function carries an assertion about the
// variable. A pair is a GAP when the write side is unguarded — the value was
// committed without anything asserting about it — and it is OPEN on both ends
// when the read side is unguarded too. A guarded write reaching an unguarded
// read is neither: the write was checked, the consumer simply trusts it.
type enfPair struct {
	write, read               int
	writeGuarded, readGuarded bool
}

// gap is an unguarded write side; open is neither side guarded.
func (p enfPair) gap() bool  { return !p.writeGuarded }
func (p enfPair) open() bool { return !p.writeGuarded && !p.readGuarded }

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
		id := objStr(n, "id")
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
			k := objStr(u, "kind")
			if k != "write" && k != "read" {
				continue
			}
			if !hasConceptKey(strList(objAt(u, "concept_keys")), conceptKey) {
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
		if listHas(objAt(n, "writes_storage"), name) {
			kinds = append(kinds, "write")
		}
		if listHas(objAt(n, "reads_storage"), name) {
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
		switch objStr(n, "kind") {
		case "contract", "interface", "library":
			byName[objStr(n, "name")] = objStr(n, "id")
			find(objStr(n, "id"))
		}
	}
	for _, e := range edgesOf(index) {
		if objStr(e, "rel") != "inherits" {
			continue
		}
		to := objStr(e, "to")
		if i := strings.LastIndex(to, "#"); i >= 0 {
			to = to[i+1:]
		}
		if id, ok := byName[to]; ok {
			union(objStr(e, "from"), id)
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
		id := objStr(n, "id")
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
		if objStr(e, "rel") != "calls" {
			continue
		}
		if id := resolve(objStr(e, "to")); id != "" {
			from := objStr(e, "from")
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

// enforcementDepths is the BFS depth of every function node reachable from an
// entry point over the `calls` edges (entry points are depth 0). A node with
// no entry is absent from the map.
func enforcementDepths(index validation.Value) map[string]int {
	adj := enforcementCallGraph(index)
	dist := map[string]int{}
	queue := []string{}
	for _, n := range nodesOf(index, "function") {
		if boolAt(n, "is_entry_point") {
			id := objStr(n, "id")
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

// indexHasStorageName reports whether the index knows `name` as a storage
// variable: a state-variable node, or an entry of any function's
// reads_storage / writes_storage.
func indexHasStorageName(index validation.Value, name string) bool {
	for _, n := range nodesOf(index, "state-variable") {
		if objStr(n, "name") == name {
			return true
		}
	}
	for _, n := range nodesOf(index, "function") {
		if listHas(objAt(n, "writes_storage"), name) ||
			listHas(objAt(n, "reads_storage"), name) {
			return true
		}
	}
	return false
}

// enfGuardsOf is the containing function's assertions, each marked with
// whether it is about the queried variable (its concept keys intersect).
func enfGuardsOf(n validation.Value, conceptKey string) []enfGuard {
	out := []enfGuard{}
	for _, g := range listOf(objAt(n, "guards")) {
		rec := enfGuard{
			line:  intAt(g, "line"),
			class: intAt(g, "class"),
			text:  objStr(g, "text"),
		}
		rec.about = hasConceptKey(strList(objAt(g, "concept_keys")), conceptKey)
		out = append(out, rec)
	}
	return out
}

// useLine is the first statement-level use of the wanted keys with the given
// kind (the precise line of a write or read of the variable).
func useLine(n validation.Value, conceptKey, kind string) (int64, bool) {
	for _, u := range usesOf(n) {
		if objStr(u, "kind") != kind {
			continue
		}
		if hasConceptKey(strList(objAt(u, "concept_keys")), conceptKey) {
			return intAt(u, "line"), true
		}
	}
	return 0, false
}

func usesOf(n validation.Value) []validation.Value { return listOf(objAt(n, "uses")) }

func listOf(v validation.Value) []validation.Value {
	if v.Kind != validation.Arr {
		return nil
	}
	return v.A
}

func listHas(v validation.Value, want string) bool {
	for _, e := range strList(v) {
		if e == want {
			return true
		}
	}
	return false
}

// conceptKeyOf is the maximal concept key of a name or expression: the
// index's own tokenizer (splitIdent, which already applies the synonym fold
// and drops stopwords) joined by ":" — the exact string the index records for
// an expression that IS that name. ConceptKeys sorts its output, so the
// maximal key has to be rebuilt here rather than taken from the tail.
func conceptKeyOf(expr string) string {
	// splitIdent splits only on '_' and camelCase boundaries, so a name typed
	// the way an operator writes it ("prev-state root", "prev.state.root") is
	// first folded onto that one separator.
	clean := []byte(expr)
	for i, b := range clean {
		switch {
		case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z',
			b >= '0' && b <= '9':
		default:
			clean[i] = '_'
		}
	}
	return strings.Join(splitIdent(string(clean)), ":")
}

// hasConceptKey reports whether a recorded key list carries the wanted key. A
// partial token overlap is deliberately NOT a match: `storedHash` folds to
// "stored:root", and matching on the bare "root" token would sweep in every
// unrelated stateRoot expression in the index.
func hasConceptKey(keys []string, want string) bool {
	if want == "" {
		return false
	}
	for _, k := range keys {
		if k == want {
			return true
		}
	}
	return false
}

func boolAt(v validation.Value, key string) bool {
	x := objAt(v, key)
	return x.Kind == validation.Bool && x.B
}

func intAt(v validation.Value, key string) int64 {
	x := objAt(v, key)
	if x.Kind != validation.Int {
		return 0
	}
	return x.I
}

func objLineOf(n validation.Value) int64 { return intAt(n, "line") }

func intText(n int64) string { return fmt.Sprintf("%d", n) }

// splitNodeID splits an index node id (`path#Contract.func`, or
// `path#Contract` for a contract) into its contract and function names.
func splitNodeID(id string) (contract, function string) {
	rest := id
	if i := strings.LastIndex(id, "#"); i >= 0 {
		rest = id[i+1:]
	}
	if i := strings.LastIndex(rest, "."); i >= 0 {
		return rest[:i], rest[i+1:]
	}
	return rest, ""
}

// enfSiteValues renders the sites (and their guards) as JSON values.
func enfSiteValues(sites []enfSite) []validation.Value {
	out := make([]validation.Value, 0, len(sites))
	for _, s := range sites {
		guards := make([]validation.Value, 0, len(s.guards))
		for _, g := range s.guards {
			guards = append(guards, validation.VObj(
				validation.KV{K: "line", V: validation.VInt(g.line)},
				validation.KV{K: "class", V: validation.VInt(g.class)},
				validation.KV{K: "text", V: validation.VStr(g.text)},
				validation.KV{K: "about_variable", V: validation.VBool(g.about)}))
		}
		var depth validation.Value
		if s.hasDepth {
			depth = validation.VInt(int64(s.depth))
		} else {
			depth = validation.VNull()
		}
		out = append(out, validation.VObj(
			validation.KV{K: "contract", V: validation.VStr(s.contract)},
			validation.KV{K: "function", V: validation.VStr(s.function)},
			validation.KV{K: "function_id", V: validation.VStr(s.id)},
			validation.KV{K: "kind", V: validation.VStr(s.kind)},
			validation.KV{K: "line", V: validation.VInt(s.line)},
			validation.KV{K: "granularity", V: validation.VStr(s.gran)},
			validation.KV{K: "is_entry_point", V: validation.VBool(s.entry)},
			validation.KV{K: "depth", V: depth},
			validation.KV{K: "guarded", V: validation.VBool(s.guarded)},
			validation.KV{K: "guards", V: validation.VArr(guards...)}))
	}
	return out
}

// enfSiteRef is the compact site identity used inside a stage pair.
func enfSiteRef(s enfSite) validation.Value {
	return validation.VObj(
		validation.KV{K: "contract", V: validation.VStr(s.contract)},
		validation.KV{K: "function", V: validation.VStr(s.function)},
		validation.KV{K: "line", V: validation.VInt(s.line)},
		validation.KV{K: "kind", V: validation.VStr(s.kind)})
}
