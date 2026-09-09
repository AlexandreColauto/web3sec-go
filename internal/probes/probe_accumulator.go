package probes

import (
	"sort"
	"strings"

	"websec/internal/structidx"
	"websec/internal/validation"
)

// accumulatorTokens is _ACCUMULATOR_TOKENS: the accounting variables whose
// update is the "basis" a companion must move with. Vocabulary, not shape.
var accumulatorTokens = map[string]struct{}{}
var roundingTokens = map[string]struct{}{"div": {}, "sqrt": {}, "round": {}}

func init() {
	for _, t := range []string{"index", "idx", "rate", "share", "reward",
		"balance", "total", "accrual", "accrued", "debt", "supply", "weight",
		"price", "factor", "checkpoint", "cumulative", "interest", "fee", "apr",
		"amount", "reserve", "asset", "liquidity", "stake", "principal",
		"borrow", "credit", "collateral", "exchange", "utilization", "quota",
		"emission", "velocity"} {
		accumulatorTokens[t] = struct{}{}
	}
}

// stateVar is one (state variable name, its concept keys) pair.
type stateVar struct {
	name string
	keys map[string]struct{}
}

// probeAccumulatorBasisSkew is probe_accumulator_basis_skew: a
// rounding-limited accumulator update next to a companion state write — the
// accumulator can round to zero while the companion advances by the full
// delta.
func probeAccumulatorBasisSkew(index, model validation.Value) (probeOut, error) {
	if err := structidx.RequireParseVersion(index, "structural index"); err != nil {
		return probeOut{}, err
	}
	fns := functionNodes(index)
	vocab := stateVocab(index)
	sites := 0
	raw := []validation.Value{}
	blind := []validation.Value{}
	for _, cnode := range contractNodes(index) {
		cname := vStr(cnode, "name")
		contractVars := vocab[cname]
		for _, e := range vObjList(cnode, "contract_closure") {
			node, ok := fns[nodeID(e)]
			if !ok {
				continue
			}
			reads := readsByLine(e)
			writes := writeUses(e)
			for _, w := range writes {
				out := accumulatorRow(cname, e, node, w, writes, reads,
					contractVars, model, &sites)
				if out.raw != nil {
					raw = append(raw, *out.raw)
				}
				if out.blind != nil {
					blind = append(blind, *out.blind)
				}
			}
		}
	}
	sortBlindFields(blind, "kind", "key", "contract", "function")
	return probeOut{sites: sites, rows: raw, blind: limit50(blind),
		blindTotal: len(blind)}, nil
}

// accOutcome is either a row or a blind entry for one candidate write.
type accOutcome struct {
	raw   *validation.Value
	blind *validation.Value
}

// accumulatorRow applies the skew discriminator to one write.
func accumulatorRow(cname string, e, node, w validation.Value,
	writes []validation.Value, reads map[int]map[string]struct{},
	contractVars []stateVar, model validation.Value, sites *int) accOutcome {
	wkeys := vStrSet(w, "concept_keys")
	wline := vInt(w, "line")
	if len(wkeys) == 0 || !touchesAccumulator(wkeys) ||
		!intersects(reads[wline], roundingTokens) {
		return accOutcome{}
	}
	*sites++
	wState := stateName(wkeys, contractVars)
	accumulator := wState
	if accumulator == "" {
		accumulator = mostSpecific(wkeys)
	}
	key := cname + "::" + vStr(e, "name") + "::" + accumulator
	persisted := wState != "" || anyPersists(writes, wline, wkeys, reads, contractVars)
	if !persisted {
		return accOutcome{blind: accBlind("not-persisted", key, cname, e, wline,
			accumulator+" is rounded at line "+itoa(wline)+" but never reaches "+
				"state — the skew dies with the local")}
	}
	candidates := companionCandidates(writes, wline, wkeys, contractVars)
	if len(candidates) == 0 {
		return accOutcome{blind: accBlind("no-companion-write", key, cname, e,
			wline, accumulator+" is rounded and persisted at line "+
				itoa(wline)+", but no other state write in "+vStr(e, "name")+
				" moves with it")}
	}
	companion := minBy(candidates, func(o validation.Value) accPref {
		return companionPref(reads, wkeys, wline, o)
	})
	okeys := vStrSet(companion, "concept_keys")
	name := stateName(okeys, contractVars)
	if name == "" {
		name = mostSpecific(okeys)
	}
	mods := nodeModifiers(node)
	row := rawRow(cname, vStr(e, "name"), wline, accumulator,
		TierOfGate(mods, model), GateLabel(mods, model), 0, vStr(e, "name"),
		kv("rounded_line", validation.VInt(int64(wline))),
		kv("plain_line", validation.VInt(int64(vInt(companion, "line")))),
		kv("accumulator", validation.VStr(accumulator)),
		kv("companion", validation.VStr(name)))
	return accOutcome{raw: &row}
}

// accBlind builds one accumulator blind entry.
func accBlind(kind, key, cname string, e validation.Value, line int,
	reason string) *validation.Value {
	b := blindEntry(kind, key, validation.VNull(),
		kv("contract", validation.VStr(cname)),
		kv("function", validation.VStr(vStr(e, "name"))),
		kv("line", validation.VInt(int64(line))),
		kv("reason", validation.VStr(reason)))
	return &b
}

// touchesAccumulator is the vocabulary test over every token of the lvalue's
// concept keys.
func touchesAccumulator(wkeys map[string]struct{}) bool {
	for k := range wkeys {
		for _, tok := range strings.Split(k, ":") {
			if _, ok := accumulatorTokens[tok]; ok {
				return true
			}
		}
	}
	return false
}

// writeUses is [u for u in uses if u.kind == "write"].
func writeUses(entry validation.Value) []validation.Value {
	out := []validation.Value{}
	for _, u := range usesOf(entry) {
		if vStr(u, "kind") == "write" {
			out = append(out, u)
		}
	}
	return out
}

// readsByLine is _reads_by_line: line -> union of read concept keys.
func readsByLine(entry validation.Value) map[int]map[string]struct{} {
	out := map[int]map[string]struct{}{}
	for _, u := range usesOf(entry) {
		if vStr(u, "kind") != "read" {
			continue
		}
		line := vInt(u, "line")
		if out[line] == nil {
			out[line] = map[string]struct{}{}
		}
		for _, k := range vStrList(u, "concept_keys") {
			out[line][k] = struct{}{}
		}
	}
	return out
}

// anyPersists is the `any(...)` over the other writes.
func anyPersists(writes []validation.Value, wline int,
	wkeys map[string]struct{}, reads map[int]map[string]struct{},
	contractVars []stateVar) bool {
	for _, o := range writes {
		if vInt(o, "line") != wline &&
			persistsAccumulator(o, wkeys, reads, contractVars) {
			return true
		}
	}
	return false
}

// persistsAccumulator is _persists_accumulator.
func persistsAccumulator(o validation.Value, wkeys map[string]struct{},
	reads map[int]map[string]struct{}, contractVars []stateVar) bool {
	okeys := vStrSet(o, "concept_keys")
	if stateName(okeys, contractVars) == "" {
		return false
	}
	if intersects(reads[vInt(o, "line")], wkeys) {
		return true
	}
	_, own := okeys[accNameKey(wkeys)]
	return own
}

// persistenceOnlyWrite is _persistence_only_write.
func persistenceOnlyWrite(o validation.Value, wkeys map[string]struct{},
	contractVars []stateVar) bool {
	okeys := vStrSet(o, "concept_keys")
	if stateName(okeys, contractVars) == "" {
		return false
	}
	_, own := okeys[accNameKey(wkeys)]
	return own
}

// companionCandidates is the companion filter.
func companionCandidates(writes []validation.Value, wline int,
	wkeys map[string]struct{}, contractVars []stateVar) []validation.Value {
	out := []validation.Value{}
	for _, o := range writes {
		okeys := vStrSet(o, "concept_keys")
		if vInt(o, "line") == wline || sameSet(okeys, wkeys) ||
			stateName(okeys, contractVars) == "" ||
			persistenceOnlyWrite(o, wkeys, contractVars) {
			continue
		}
		out = append(out, o)
	}
	return out
}

// accPref is _companion_pref's tuple.
type accPref struct {
	notReader int
	after     int
	dist      int
	line      int
	name      string
}

func (a accPref) less(b accPref) bool {
	if a.notReader != b.notReader {
		return a.notReader < b.notReader
	}
	if a.after != b.after {
		return a.after < b.after
	}
	if a.dist != b.dist {
		return a.dist < b.dist
	}
	if a.line != b.line {
		return a.line < b.line
	}
	return a.name < b.name
}

// companionPref is _companion_pref: one that READS the accumulator first, then
// the nearest write after it, then the nearest before, then line order.
func companionPref(reads map[int]map[string]struct{}, wkeys map[string]struct{},
	wline int, o validation.Value) accPref {
	oline := vInt(o, "line")
	p := accPref{line: oline, name: mostSpecific(vStrSet(o, "concept_keys"))}
	if !intersects(reads[oline], wkeys) {
		p.notReader = 1
	}
	if oline <= wline {
		p.after = 1
	}
	p.dist = absInt(oline - wline)
	return p
}

// minBy is Python's min(candidates, key=...), first-wins on ties.
func minBy(items []validation.Value, key func(validation.Value) accPref) validation.Value {
	best := items[0]
	bestKey := key(best)
	for _, it := range items[1:] {
		k := key(it)
		if k.less(bestKey) {
			best, bestKey = it, k
		}
	}
	return best
}

// mostSpecific is _most_specific: most tokens, then longest text, then
// lexicographic; "" when empty.
func mostSpecific(keys map[string]struct{}) string {
	best := ""
	bestScore := [3]int{}
	for k := range keys {
		score := [3]int{strings.Count(k, ":") + 1, len(k), 0}
		if best == "" || score[0] > bestScore[0] ||
			(score[0] == bestScore[0] && (score[1] > bestScore[1] ||
				(score[1] == bestScore[1] && k > best))) {
			best, bestScore = k, score
		}
	}
	return best
}

// accNameKey is _acc_name_key.
func accNameKey(wkeys map[string]struct{}) string { return mostSpecific(wkeys) }

// stateName is _state_name: the state variable whose whole name is inside the
// lvalue's concept keys, longest name wins.
func stateName(keys map[string]struct{}, vocab []stateVar) string {
	best := ""
	for _, sv := range vocab {
		if !subset(sv.keys, keys) {
			continue
		}
		if len(sv.name) > len(best) || (len(sv.name) == len(best) && sv.name > best) {
			best = sv.name
		}
	}
	return best
}

// sameSet is `set(a) == set(b)`.
func sameSet(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	return subset(a, b)
}

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// stateVocab is _state_vocab: contract name -> its state variables, expanded
// along the inheritance chain.
func stateVocab(index validation.Value) map[string][]stateVar {
	declared := map[string][]stateVar{}
	for _, n := range vList(index, "nodes") {
		if n.Kind != validation.Obj || vStr(n, "kind") != "state-variable" {
			continue
		}
		nid := vStr(n, "id")
		hash := strings.IndexByte(nid, '#')
		if hash < 0 {
			continue
		}
		path, rest := nid[:hash], nid[hash+1:]
		contract, name := rest, ""
		if dot := strings.IndexByte(rest, '.'); dot >= 0 {
			contract, name = rest[:dot], rest[dot+1:]
		}
		if name == "" {
			continue
		}
		keys := map[string]struct{}{}
		for _, k := range structidx.ConceptKeys(name) {
			keys[k] = struct{}{}
		}
		if len(keys) > 0 {
			cid := path + "#" + contract
			declared[cid] = append(declared[cid], stateVar{name, keys})
		}
	}
	bases := map[string][]string{}
	for _, e := range vList(index, "edges") {
		if e.Kind != validation.Obj || vStr(e, "rel") != "inherits" {
			continue
		}
		frm := vStr(e, "from")
		to := vStr(e, "to")
		base := to
		if hash := strings.IndexByte(to, '#'); hash >= 0 {
			base = to[hash+1:]
		}
		if frm != "" && base != "" {
			bases[frm] = append(bases[frm], base)
		}
	}
	byName := map[string][]string{}
	for _, n := range vList(index, "nodes") {
		if n.Kind != validation.Obj {
			continue
		}
		switch vStr(n, "kind") {
		case "contract", "interface", "library":
			name := vStr(n, "name")
			byName[name] = append(byName[name], vStr(n, "id"))
		}
	}
	for name := range byName {
		sort.Strings(byName[name])
	}
	out := map[string][]stateVar{}
	for name, ids := range byName {
		if name == "" {
			continue
		}
		for _, cid := range ids {
			if _, done := out[name]; !done {
				out[name] = chainVars(cid, map[string]struct{}{}, declared,
					bases, byName)
			}
		}
	}
	return out
}

// chainVars is the recursive _vars with the `seen` cycle guard.
func chainVars(cid string, seen map[string]struct{}, declared map[string][]stateVar,
	bases map[string][]string, byName map[string][]string) []stateVar {
	out := append([]stateVar(nil), declared[cid]...)
	have := map[string]struct{}{}
	for _, sv := range out {
		have[sv.name] = struct{}{}
	}
	bs := append([]string(nil), bases[cid]...)
	for i := len(bs) - 1; i >= 0; i-- {
		for _, baseCID := range byName[bs[i]] {
			if _, dup := seen[baseCID]; dup {
				continue
			}
			next := map[string]struct{}{}
			for k := range seen {
				next[k] = struct{}{}
			}
			next[cid] = struct{}{}
			for _, sv := range chainVars(baseCID, next, declared, bases, byName) {
				if _, dup := have[sv.name]; !dup {
					out = append(out, sv)
					have[sv.name] = struct{}{}
				}
			}
		}
	}
	return out
}
