package probes

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"websec/internal/srcclass"
	"websec/internal/validation"
)

// IsTestDoublePath is is_test_double_path. The rule lives in
// internal/srcclass, which is the ONE vocabulary for "what is this file":
// the scorecard reports the same classification it scores against. A TEST
// DOUBLE is not a second site of a pattern, it is scaffolding.
func IsTestDoublePath(path string) bool { return srcclass.IsTestDouble(path) }

// site is _site: one collapsed sibling site.
func site(contract string, line int, paths map[string]string) validation.Value {
	return validation.VObj(
		kv("contract", validation.VStr(contract)),
		kv("line", validation.VInt(int64(line))),
		kv("test_double", validation.VBool(IsTestDoublePath(paths[contract]))),
	)
}

// idSlots is _id_slots: the four declared identity slots (contract, consumer,
// asserter, concept). Line numbers are deliberately absent.
func idSlots(row validation.Value) [4]string {
	pid := vStr(row, "probe")
	conceptKeys := func() string {
		keys := sortedStrings(vStrList(row, "concept_keys"))
		return strings.Join(keys, ",")
	}
	switch pid {
	case "assertion-strength":
		return [4]string{vStr(row, "contract"), vStr(row, "consumer"),
			vStr(row, "asserter"), conceptKeys()}
	case "custody-primitive":
		// A divergence row whose expected primitive is neither mint nor burn
		// omits `custody` (the schema has no label for it), so the fourth
		// slot falls back to the observed primitive: it never empties and two
		// rows that were distinct before stay distinct.
		custody := vStr(row, "custody")
		if custody == "" {
			custody = vStr(row, "observed")
		}
		return [4]string{vStr(row, "contract"), vStr(row, "consumer"), "",
			custody}
	case "trust-assumption":
		return [4]string{vStr(row, "actor"), vStr(row, "invariant"), "",
			vStr(row, "trust")}
	case "sequential-cursor":
		return [4]string{vStr(row, "contract"), vStr(row, "consumer"), "",
			vStr(row, "cursor")}
	case "short-circuitable-guard":
		return [4]string{vStr(row, "contract"), vStr(row, "consumer"), "",
			conceptKeys()}
	case "accumulator-basis-skew":
		return [4]string{vStr(row, "contract"), vStr(row, "consumer"), "",
			vStr(row, "accumulator")}
	}
	return [4]string{vStr(row, "contract"), vStr(row, "consumer"), "", ""}
}

// RowIDFor is row_id_for: sha256(probe|contract|consumer|asserter|concept)
// [:10] — stable across line moves.
func RowIDFor(row validation.Value) string {
	pid := vStr(row, "probe")
	slots := idSlots(row)
	body := pid + "|" + strings.Join(slots[:], "|")
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])[:10]
}

// gateRank is _gate_rank: weakest gate first.
type gateRank struct {
	tier, privileged int
	gate, contract   string
	line             int
}

func gateRankOf(row validation.Value) gateRank {
	priv := 1
	if vStr(row, "gate") == "unprivileged" {
		priv = 0
	}
	return gateRank{tier: vInt(row, "tier"), privileged: priv,
		gate: vStr(row, "gate"), contract: vStr(row, "contract"),
		line: vInt(row, "line")}
}

func (a gateRank) less(b gateRank) bool {
	if a.tier != b.tier {
		return a.tier < b.tier
	}
	if a.privileged != b.privileged {
		return a.privileged < b.privileged
	}
	if a.gate != b.gate {
		return a.gate < b.gate
	}
	if a.contract != b.contract {
		return a.contract < b.contract
	}
	return a.line < b.line
}

// foldState is one folded group during the sibling collapse.
type foldState struct {
	rep      *groupState
	groups   []*groupState
	gap      int
	concepts map[string]struct{}
	sites    []validation.Value
}

// collapse is _collapse: identical (contract, function, line) rows merge, then
// rows sharing (function, frozenset(concepts), tier) across contract siblings
// fold into ONE obligation carrying siblings[].
func collapse(rawRows []validation.Value, probeID string, spec *probeSpec,
	paths map[string]string) []validation.Value {
	ordered := append([]validation.Value(nil), rawRows...)
	sort.SliceStable(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		if x, y := vStr(a, "contract"), vStr(b, "contract"); x != y {
			return x < y
		}
		if x, y := vStr(a, "function"), vStr(b, "function"); x != y {
			return x < y
		}
		if x, y := vInt(a, "line"), vInt(b, "line"); x != y {
			return x < y
		}
		return vStr(a, "concept") < vStr(b, "concept")
	})
	groups := []*groupState{}
	byKey := map[string]*groupState{}
	for _, raw := range ordered {
		key := vStr(raw, "contract") + "\x00" + vStr(raw, "function") + "\x00" +
			itoa(vInt(raw, "line"))
		g, ok := byKey[key]
		if !ok {
			g = &groupState{row: raw}
			byKey[key] = g
			groups = append(groups, g)
		}
		spec.merge(g, raw)
	}
	folded := []*foldState{}
	byFold := map[string]*foldState{}
	for _, g := range groups {
		skey := vStr(g.row, "function") + "\x00" + strings.Join(sortedStrings(g.concepts), ",") +
			"\x00" + itoa(vInt(g.row, "tier"))
		rec, ok := byFold[skey]
		if !ok {
			concepts := map[string]struct{}{}
			for _, c := range g.concepts {
				concepts[c] = struct{}{}
			}
			rec = &foldState{rep: g, groups: []*groupState{g},
				gap: vInt(g.row, "assertion_gap"), concepts: concepts,
				sites: []validation.Value{site(vStr(g.row, "contract"),
					vInt(g.row, "line"), paths)}}
			byFold[skey] = rec
			folded = append(folded, rec)
			continue
		}
		rec.groups = append(rec.groups, g)
		rec.sites = append(rec.sites, site(vStr(g.row, "contract"),
			vInt(g.row, "line"), paths))
		if gap := vInt(g.row, "assertion_gap"); gap > rec.gap {
			rec.gap = gap
		}
		for _, c := range g.concepts {
			rec.concepts[c] = struct{}{}
		}
		if gateRankOf(g.row).less(gateRankOf(rec.rep.row)) {
			rec.rep = g
		}
	}
	out := []validation.Value{}
	for _, rec := range folded {
		out = append(out, foldRow(rec, probeID, paths))
	}
	return out
}

// foldRow materializes one folded group into a row.
func foldRow(rec *foldState, probeID string, paths map[string]string) validation.Value {
	rep := rec.rep
	if IsTestDoublePath(paths[vStr(rep.row, "contract")]) {
		real := []*groupState{}
		for _, g := range rec.groups {
			if !IsTestDoublePath(paths[vStr(g.row, "contract")]) {
				real = append(real, g)
			}
		}
		if len(real) > 0 {
			best := real[0]
			for _, g := range real[1:] {
				if gateRankOf(g.row).less(gateRankOf(best.row)) {
					best = g
				}
			}
			rep = best
		}
	}
	row := copyObj(rep.row)
	vSet(&row, "assertion_gap", validation.VInt(int64(rec.gap)))
	vSet(&row, "siblings", siblingSites(row, rec, paths))
	vSet(&row, "concept_keys", strArr(sortedStrSet(rec.concepts)))
	withProbe := copyObj(row)
	vSet(&withProbe, "probe", validation.VStr(probeID))
	vSet(&row, "row_id", validation.VStr(RowIDFor(withProbe)))
	return row
}

// siblingSites is the deduped, sorted site list with the representative's own
// site first.
func siblingSites(row validation.Value, rec *foldState,
	paths map[string]string) validation.Value {
	byPair := map[string]validation.Value{}
	pairs := []string{}
	for _, s := range rec.sites {
		key := vStr(s, "contract") + "\x00" + itoa(vInt(s, "line"))
		if _, dup := byPair[key]; !dup {
			byPair[key] = s
			pairs = append(pairs, key)
		}
	}
	sort.Strings(pairs)
	own := vStr(row, "contract") + "\x00" + itoa(vInt(row, "line"))
	ordered := []validation.Value{site(vStr(row, "contract"), vInt(row, "line"), paths)}
	for _, key := range pairs {
		if key != own {
			ordered = append(ordered, byPair[key])
		}
	}
	return validation.VArr(ordered...)
}

// copyObj is `dict(row)`.
func copyObj(row validation.Value) validation.Value {
	out := validation.VObj()
	out.O = append(out.O, row.O...)
	return out
}

// NSiblings is n_siblings: NON-test-double siblings only; a group whose sites
// are ALL test doubles keeps its true site count.
func NSiblings(row validation.Value) int {
	sibs := vGet(row, "siblings")
	if sibs.Kind == validation.Int {
		return int(sibs.I)
	}
	items := vList(row, "siblings")
	real := 0
	for _, s := range items {
		if s.Kind == validation.Obj && vBool(s, "test_double") {
			continue
		}
		real++
	}
	if real > 0 {
		return real
	}
	return len(items)
}

// rankRows is _rank: (tier, -assertion_gap, n_siblings, sort_name), with the
// row-id order as the stable pre-sort.
func rankRows(rows []validation.Value, spec *probeSpec) []validation.Value {
	ordered := append([]validation.Value(nil), rows...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return vStr(ordered[i], "row_id") < vStr(ordered[j], "row_id")
	})
	sort.SliceStable(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		if x, y := vInt(a, "tier"), vInt(b, "tier"); x != y {
			return x < y
		}
		if x, y := vInt(a, "assertion_gap"), vInt(b, "assertion_gap"); x != y {
			return x > y
		}
		if x, y := NSiblings(a), NSiblings(b); x != y {
			return x < y
		}
		return spec.sortName(a) < spec.sortName(b)
	})
	for i := range ordered {
		vSet(&ordered[i], "rank", validation.VInt(int64(i+1)))
	}
	return ordered
}

// finalize is _finalize: the surface row, in Python's key order.
func finalize(row validation.Value, probeID string, spec *probeSpec) validation.Value {
	out := validation.VObj(
		kv("row_id", vGet(row, "row_id")),
		kv("probe", validation.VStr(probeID)),
		kv("axis", validation.VStr(spec.axis)),
		kv("lens", validation.VStr(spec.lens)),
		kv("tier", vGet(row, "tier")),
		kv("rank", vGet(row, "rank")),
		kv("assertion_gap", vGet(row, "assertion_gap")),
		kv("gate", vGet(row, "gate")),
		kv("why", validation.VStr(formatMap(spec.whyTemplate, row))),
		kv("siblings", vGet(row, "siblings")),
	)
	for _, field := range spec.fields {
		// Every declared field is copied, absent or not: an absent one becomes
		// null, which the schema's non-nullable types reject, so emit stays
		// loud about an incomplete row. The sole exception is `custody`: the
		// schema enum is mints|burns and a divergence whose expected primitive
		// has no schema value has to reach the surface without the key at all.
		// The exception is deliberately one field wide — a generic "omit what
		// the row lacks" rule would silently swallow a nulled declared field of
		// any probe, erasing the validation failure that surfaces it.
		if field == "custody" && !vHas(row, field) {
			continue
		}
		vSet(&out, field, vGet(row, field))
	}
	return out
}

// formatMap is str.format_map(_SafeDict(row)): a missing key renders "?".
func formatMap(template string, row validation.Value) string {
	var b strings.Builder
	for i := 0; i < len(template); i++ {
		if template[i] != '{' {
			b.WriteByte(template[i])
			continue
		}
		end := strings.IndexByte(template[i:], '}')
		if end < 0 {
			b.WriteString(template[i:])
			break
		}
		name := template[i+1 : i+end]
		val, ok := vGetPresent(row, name)
		if !ok {
			b.WriteString("?")
		} else {
			b.WriteString(pyStr(val))
		}
		i += end
	}
	return b.String()
}

// vGetPresent is v[name] with an explicit presence flag.
func vGetPresent(v validation.Value, key string) (validation.Value, bool) {
	if v.Kind != validation.Obj {
		return validation.VNull(), false
	}
	for _, pair := range v.O {
		if pair.K == key {
			return pair.V, true
		}
	}
	return validation.VNull(), false
}

// RankKey is rank_key: (tier, -assertion_gap, n_siblings, name, row_id).
type RankKey struct {
	Tier, NegGap, Siblings int
	Name, RowID            string
}

// Less orders two rank keys the way the engine's tuple comparison does.
func (a RankKey) Less(b RankKey) bool {
	if a.Tier != b.Tier {
		return a.Tier < b.Tier
	}
	if a.NegGap != b.NegGap {
		return a.NegGap < b.NegGap
	}
	if a.Siblings != b.Siblings {
		return a.Siblings < b.Siblings
	}
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	return a.RowID < b.RowID
}

// RankKeyOf is rank_key(row).
func RankKeyOf(row validation.Value) RankKey {
	name := ""
	if vTruthy(vGet(row, "name")) {
		name = pyStr(vGet(row, "name"))
	} else {
		name = rowName(row)
	}
	return RankKey{Tier: vInt(row, "tier"), NegGap: -vInt(row, "assertion_gap"),
		Siblings: NSiblings(row), Name: name, RowID: pyStr(vGet(row, "row_id"))}
}

// rowName is _row_name: the probe's own sort name, falling back to the row's
// anchor fields.
func rowName(row validation.Value) string {
	spec := probesTable[vStr(row, "probe")]
	if spec != nil {
		if n := spec.sortName(row); n != "" {
			return n
		}
	}
	for _, field := range []string{"consumer", "actor", "contract", "guard", "base"} {
		if vTruthy(vGet(row, field)) {
			return pyStr(vGet(row, field))
		}
	}
	return ""
}
