// criticality.go: criticality_rank — tier every in-scope contract by how much
// the protocol's SAFETY and LIVENESS depend on it. Consumes protocol_graph
// signals (state_machines, critical_edges, oracle_chain, who_can,
// external_assets) plus sink_functions. HINT-only, like the rest of the
// module: it orders attention, it never gates a finding.
package structidx

import (
	"sort"
	"strings"

	"websec/internal/protocolgraph"
	"websec/internal/validation"
)

// critTokens is _crit_tokens: matchable tokens from a raw endpoint/id string.
func critTokens(value validation.Value) map[string]bool {
	out := map[string]bool{}
	if value.Kind != validation.Str || value.S == "" {
		return out
	}
	s := value.S
	out[s] = true
	if i := lastIndexByte(s, '#'); i >= 0 {
		out[s[i+1:]] = true
	}
	for _, part := range strings.Split(strings.ReplaceAll(s, "#", "."), ".") {
		if part != "" {
			out[part] = true
		}
	}
	return out
}

func unionInto(dst map[string]bool, src map[string]bool) {
	for k := range src {
		dst[k] = true
	}
}

// critHit is _crit_hit: case-insensitive exact-or-qualified match of a
// contract name against a token pool. Bare substring matching is deliberately
// NOT used: 'Vault' must not hit a pool that only mentions 'VaultProxy'.
func critHit(name string, tokens map[string]bool) bool {
	nl := toLowerASCII(name)
	match := func(cand string) bool {
		if nl == cand {
			return true
		}
		return hasPrefix2(cand, nl+".")
	}
	for t := range tokens {
		if t == "" {
			continue
		}
		tl := toLowerASCII(t)
		if match(tl) {
			return true
		}
		base := tl
		if i := lastIndexByte(tl, '/'); i >= 0 {
			base = tl[i+1:]
		}
		if base != tl && match(base) {
			return true
		}
		seg := tl
		if i := lastIndexByte(tl, '#'); i >= 0 {
			seg = tl[i+1:]
		}
		if seg == nl {
			return true
		}
	}
	return false
}

// critRankState carries the model/index context shared by CriticalityRank's
// section builders (plus the token pools they produce).
type critRankState struct {
	model    validation.Value
	index    validation.Value
	smTokens map[string]bool
	critical map[string]bool
	oracle   map[string]bool
	upgrades map[string]bool
	drains   map[string]bool
	ext      map[string]bool
	sinks    map[string]bool
}

// critRankSMTokens collects the state-machine token pool. State machines name
// states, not contracts, so the machine NAME is the primary host signal,
// backed by every string the machine mentions.
func (cr *critRankState) critRankSMTokens() {
	smTokens := map[string]bool{}
	for _, sm := range objList(validation.ObjAt(cr.model, "state_machines")) {
		unionInto(smTokens, critTokens(validation.ObjAt(sm, "name")))
		for _, st := range objList(validation.ObjAt(sm, "states")) {
			// States are objects ({id, terminal, ...}), not bare strings —
			// critTokens is string-only, so tokenize the state's id (the
			// state name); a bare-string state still works via the fallback.
			if st.Kind == validation.Obj {
				unionInto(smTokens, critTokens(validation.ObjAt(st, "id")))
			} else {
				unionInto(smTokens, critTokens(st))
			}
		}
		for _, tr := range objList(validation.ObjAt(sm, "transitions")) {
			for _, key := range []string{"contract", "on", "from", "to",
				"trigger", "actor"} {
				unionInto(smTokens, critTokens(validation.ObjAt(tr, key)))
			}
			for _, g := range objList(validation.ObjAt(tr, "guards")) {
				unionInto(smTokens, critTokens(g))
			}
		}
	}
	cr.smTokens = smTokens
}

// critRankCritical collects the critical mutating edges: relations carry
// from/rel/to (+via).
func (cr *critRankState) critRankCritical() {
	critical := map[string]bool{}
	for _, e := range protocolgraph.CriticalEdges(cr.model) {
		for _, key := range []string{"contract", "from", "to", "via"} {
			unionInto(critical, critTokens(validation.ObjAt(e, key)))
		}
	}
	cr.critical = critical
}

// critRankOracles collects the oracle token pool: oracles carry
// id/feeds[]/manipulable_by; feeds is a LIST, so each entry is tokenized
// individually.
func (cr *critRankState) critRankOracles() {
	oracle := map[string]bool{}
	for _, o := range protocolgraph.OracleChain(cr.model) {
		unionInto(oracle, critTokens(validation.ObjAt(o, "id")))
		unionInto(oracle, critTokens(validation.ObjAt(o, "contract")))
		unionInto(oracle, critTokens(validation.ObjAt(o, "manipulable_by")))
		feeds := validation.ObjAt(o, "feeds")
		if feeds.Kind == validation.Str {
			unionInto(oracle, critTokens(feeds))
		} else if feeds.Kind == validation.Arr {
			for _, f := range feeds.A {
				unionInto(oracle, critTokens(f))
			}
		}
	}
	cr.oracle = oracle
}

// critRankUpgrades collects the upgrade gap pool: a contract named in
// upgrade_paths can change deployed code.
func (cr *critRankState) critRankUpgrades() {
	upgrades := map[string]bool{}
	for _, u := range objList(validation.ObjAt(cr.model, "upgrade_paths")) {
		if u.Kind == validation.Obj {
			for _, key := range []string{"contract", "proxy", "implementation",
				"target", "admin", "timelock", "initializer", "gap_risk"} {
				unionInto(upgrades, critTokens(validation.ObjAt(u, key)))
			}
		} else {
			unionInto(upgrades, critTokens(u))
		}
	}
	cr.upgrades = upgrades
}

// critRankDrains collects drain-capable actors (who_can returns actor dicts
// keyed by id).
func (cr *critRankState) critRankDrains() {
	drains := map[string]bool{}
	for _, a := range protocolgraph.WhoCan(cr.model, "can_drain") {
		if a.Kind == validation.Obj {
			unionInto(drains, critTokens(validation.ObjAt(a, "id")))
		}
	}
	cr.drains = drains
}

// critRankExt collects external/risky assets, which surface only the asset id
// — the holder signal lives on the raw model assets' held_by list, so read
// both.
func (cr *critRankState) critRankExt() {
	ext := map[string]bool{}
	for _, a := range protocolgraph.ExternalAssets(cr.model) {
		if a.Kind == validation.Obj {
			unionInto(ext, critTokens(validation.ObjAt(a, "asset")))
			unionInto(ext, critTokens(validation.ObjAt(a, "contract")))
		}
	}
	for _, a := range objList(validation.ObjAt(cr.model, "assets")) {
		if a.Kind == validation.Obj {
			for _, h := range objList(validation.ObjAt(a, "held_by")) {
				unionInto(ext, critTokens(h))
			}
		}
	}
	cr.ext = ext
}

// critRankSinks collects sinks' function ids ("path#Contract.fn"); tolerate an
// index with empty/absent nodes.
func (cr *critRankState) critRankSinks() {
	sinks := map[string]bool{}
	if len(objList(validation.ObjAt(cr.index, "nodes"))) > 0 {
		for _, n := range SinkFunctions(cr.index) {
			unionInto(sinks, critTokens(validation.ObjAt(n, "contract")))
			unionInto(sinks, critTokens(validation.ObjAt(n, "function_id")))
		}
	}
	cr.sinks = sinks
}

// critRankRows builds the per-contract rows against the collected pools, then
// sorts and renders them.
func (cr *critRankState) critRankRows() []validation.Value {
	type row struct {
		contract string
		tier     string
		reasons  []string
	}
	rows := []row{}
	for _, c := range objList(validation.ObjAt(cr.model, "contracts")) {
		name := validation.ObjStr(c, "name")
		if name == "" {
			name = validation.ObjStr(c, "path")
		}
		if name == "" {
			name = "?"
		}
		reasons := []string{}
		tier := "peripheral"
		if critHit(name, cr.smTokens) {
			tier = "consensus-critical"
			reasons = append(reasons, "hosts a state machine")
		}
		if critHit(name, cr.critical) {
			tier = "consensus-critical"
			reasons = append(reasons, "critical mutating edge")
		}
		if critHit(name, cr.oracle) {
			tier = "consensus-critical"
			reasons = append(reasons, "oracle role")
		}
		if critHit(name, cr.upgrades) {
			tier = "consensus-critical"
			reasons = append(reasons, "upgrade gap")
		}
		if tier != "consensus-critical" &&
			(critHit(name, cr.ext) || critHit(name, cr.sinks) ||
				critHit(name, cr.drains)) {
			tier = "value-holding"
			reasons = append(reasons, "value-holding / drain-reachable")
		}
		if len(reasons) == 0 {
			reasons = []string{"no high-criticality signal"}
		}
		rows = append(rows, row{name, tier, reasons})
	}
	order := map[string]int{"consensus-critical": 0, "value-holding": 1,
		"peripheral": 2}
	sort.SliceStable(rows, func(i, j int) bool {
		if order[rows[i].tier] != order[rows[j].tier] {
			return order[rows[i].tier] < order[rows[j].tier]
		}
		return rows[i].contract < rows[j].contract
	})
	out := make([]validation.Value, 0, len(rows))
	for _, r := range rows {
		out = append(out, validation.VObj(
			validation.KV{K: "contract", V: validation.VStr(r.contract)},
			validation.KV{K: "tier", V: validation.VStr(r.tier)},
			validation.KV{K: "reasons", V: validation.StrArr(r.reasons)},
		))
	}
	return out
}

// CriticalityRank is criticality_rank.
func CriticalityRank(model, index validation.Value) []validation.Value {
	cr := critRankState{model: model, index: index}
	cr.critRankSMTokens()
	cr.critRankCritical()
	cr.critRankOracles()
	cr.critRankUpgrades()
	cr.critRankDrains()
	cr.critRankExt()
	cr.critRankSinks()
	return cr.critRankRows()
}

// objList is a list-typed accessor that also tolerates a scalar where a list
// is expected (the Python code iterates `sm.get("states", []) or []`, which a
// string would iterate character-wise — we keep the list semantics and treat
// non-lists as empty, matching every real model shape).
func objList(v validation.Value) []validation.Value {
	if v.Kind != validation.Arr {
		return nil
	}
	return v.A
}
