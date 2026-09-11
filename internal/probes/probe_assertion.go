package probes

import (
	"strings"

	"websec/internal/structidx"
	"websec/internal/validation"
)

// assertionSite is the strongest assertion of one concept key: (class, name,
// line).
type assertionSite struct {
	class int
	name  string
	line  int
}

// probeAssertionStrength is probe_assertion_strength: a concept asserted with
// equality-to-persisted-state (class 4) somewhere in a contract, then consumed
// by an external/public state-writing function that guards it at class <=
// sanity — the "validated here, consumed there" shape.
//
// NOTE (bug-for-bug parity): Python rebinds `rejected` inside the contract
// loop and processes it only ONCE after the loop, so the rejected-site blind
// entries come from the LAST contract only. The near-key entries are appended
// per contract. Both facts are load-bearing for byte parity.
func probeAssertionStrength(index, model validation.Value) (probeOut, error) {
	if err := structidx.RequireParseVersion(index, "structural index"); err != nil {
		return probeOut{}, err
	}
	fns := functionNodes(index)
	sites := 0
	raw := []validation.Value{}
	blind := []validation.Value{}
	var rejected []rejectedSite
	for _, cnode := range contractNodes(index) {
		cname := vStr(cnode, "name")
		entries := vObjList(cnode, "contract_closure")
		strongest := strongestAssertions(entries)
		consumedBy, joined, rej := assertionConsumers(cname, entries, fns,
			strongest, model, &sites, &raw)
		rejected = rej
		assertionNearKeys(cname, strongest, consumedBy, joined, &blind)
	}
	seen := map[[2]string]struct{}{}
	for _, b := range blind {
		seen[[2]string{vStr(b, "key"), blindNear(b)}] = struct{}{}
	}
	for _, r := range rejected {
		if anyBlindNear(blind, r) {
			continue
		}
		entry := blindEntry("rejected-site", r.key, validation.VNull(),
			kv("contract", validation.VStr(r.contract)),
			kv("function", validation.VStr(r.function)),
			kv("line", validation.VInt(int64(r.line))),
			kv("reason", validation.VStr(r.reason)))
		pair := [2]string{vStr(entry, "key"), ""}
		if _, dup := seen[pair]; dup {
			continue
		}
		seen[pair] = struct{}{}
		blind = append(blind, entry)
	}
	sortBlindFields(blind, "key", "near", "contract", "function")
	return probeOut{sites: sites, rows: raw, blind: limit50(blind),
		blindTotal: len(blind)}, nil
}

// strongestAssertions is the first pass: key -> the strongest (class, name,
// line) assertion site, ties broken by (name, line).
func strongestAssertions(entries []validation.Value) map[string]assertionSite {
	strongest := map[string]assertionSite{}
	for _, e := range entries {
		for _, g := range guardsOf(e) {
			for _, key := range vStrList(g, "concept_keys") {
				cand := assertionSite{class: guardClass(g),
					name: vStr(e, "name"), line: vInt(e, "line")}
				cur, ok := strongest[key]
				if !ok || cand.class > cur.class ||
					(cand.class == cur.class && (cand.name < cur.name ||
						(cand.name == cur.name && cand.line < cur.line))) {
					strongest[key] = cand
				}
			}
		}
	}
	return strongest
}

// rejectedSite is one site the probe rejected, carried to the blind side.
type rejectedSite struct {
	key, concept, contract, function, reason string
	line                                     int
}

// assertionConsumers is the second pass: consume each key through a
// state-writing entry point and either emit a row or record the rejection.
func assertionConsumers(cname string, entries []validation.Value,
	fns map[string]validation.Value, strongest map[string]assertionSite,
	model validation.Value, sites *int, raw *[]validation.Value) (
	map[string][]string, map[string]struct{}, []rejectedSite) {
	consumedBy := map[string][]string{}
	joined := map[string]struct{}{}
	rejected := []rejectedSite{}
	for _, e := range entries {
		node, ok := fns[nodeID(e)]
		if !ok || !vBool(node, "is_entry_point") {
			continue
		}
		uses := usesOf(e)
		if !anyWriteUse(uses) {
			continue
		}
		own := ownGuardClasses(e)
		for _, key := range sortedUsesConcepts(uses) {
			consumedBy[key] = append(consumedBy[key], vStr(e, "name"))
			st, found := strongest[key]
			if !strings.Contains(key, ":") || !found || st.class < 1 {
				continue
			}
			*sites++
			if st.class >= 4 && st.name != vStr(e, "name") && own[key] <= 1 {
				joined[key] = struct{}{}
				mods := nodeModifiers(node)
				*raw = append(*raw, rawRow(cname, vStr(e, "name"), vInt(e, "line"),
					key, TierOfGate(mods, model), GateLabel(mods, model),
					4-own[key], vStr(e, "name"),
					kv("asserter", validation.VStr(st.name)),
					kv("asserter_line", validation.VInt(int64(st.line))),
					kv("assert_class", validation.VInt(int64(st.class))),
					kv("own_class", validation.VInt(int64(own[key])))))
				continue
			}
			rejected = append(rejected, rejectedSite{
				key:      cname + "::" + vStr(e, "name") + "::" + key,
				concept:  key,
				contract: cname,
				function: vStr(e, "name"),
				line:     vInt(e, "line"),
				reason:   rejectionWhy(e, key, st, own[key]),
			})
		}
	}
	return consumedBy, joined, rejected
}

// anyWriteUse is `any(u.get("kind") == "write" for u in uses)`.
func anyWriteUse(uses []validation.Value) bool {
	for _, u := range uses {
		if vStr(u, "kind") == "write" {
			return true
		}
	}
	return false
}

// ownGuardClasses is the entry's own weakest guard class per concept key.
func ownGuardClasses(e validation.Value) map[string]int {
	own := map[string]int{}
	for _, g := range guardsOf(e) {
		for _, key := range vStrList(g, "concept_keys") {
			if c := guardClass(g); c > own[key] {
				own[key] = c
			}
		}
	}
	return own
}

// ownGuardSite is the entry's own strongest guard for one concept key:
// (class, text). Ties on class keep the first in guard order.
type ownGuardSite struct {
	class int
	text  string
}

// ownGuardSites is ownGuardClasses extended with the winning guard's text.
func ownGuardSites(e validation.Value) map[string]ownGuardSite {
	own := map[string]ownGuardSite{}
	for _, g := range guardsOf(e) {
		for _, key := range vStrList(g, "concept_keys") {
			c := guardClass(g)
			if cur, ok := own[key]; !ok || c > cur.class {
				own[key] = ownGuardSite{class: c, text: vStr(g, "text")}
			}
		}
	}
	return own
}

// rejectionWhy is the human reason a site was rejected, verbatim.
func rejectionWhy(e validation.Value, key string, st assertionSite, own int) string {
	name := vStr(e, "name")
	switch {
	case st.name == name:
		return name + " asserts " + key + " itself (class " + itoa(st.class) +
			") — no asymmetry"
	case st.class < 4:
		return key + " is asserted only at class " + itoa(st.class) + " in " +
			st.name + " — below equality-to-persisted-state"
	default:
		return name + " guards " + key + " at class " + itoa(own) +
			"; the strongest assertion (class " + itoa(st.class) +
			") adds nothing"
	}
}

// assertionNearKeys is the per-contract blind side: a class-4 assertion that
// joined nothing is a silent miss unless the near keys it declined are
// published.
func assertionNearKeys(cname string, strongest map[string]assertionSite,
	consumedBy map[string][]string, joined map[string]struct{},
	blind *[]validation.Value) {
	for _, key := range sortedKeys(strongest) {
		st := strongest[key]
		if st.class < 4 || !strings.Contains(key, ":") {
			continue
		}
		if _, ok := joined[key]; ok {
			continue
		}
		tokens := strings.Split(key, ":")
		for _, other := range sortedKeys(consumedBy) {
			if other == key || !strings.Contains(other, ":") {
				continue
			}
			if len(intersectSet(tokens, strings.Split(other, ":"))) >= 2 {
				*blind = append(*blind, blindEntry("near-key", key,
					validation.VStr(other),
					kv("contract", validation.VStr(cname)),
					kv("function", validation.VStr(st.name)),
					kv("line", validation.VInt(int64(st.line))),
					kv("reason", validation.VStr(key+" is asserted at class "+
						itoa(st.class)+" in "+st.name+" but no consumer joined "+
						"it; "+other+" is the near key"))))
			}
		}
	}
}

// anyBlindNear is the `any(... near == r.concept)` duplicate guard.
func anyBlindNear(blind []validation.Value, r rejectedSite) bool {
	for _, b := range blind {
		if vStr(b, "contract") == r.contract && vStr(b, "function") == r.function &&
			blindNear(b) == r.concept {
			return true
		}
	}
	return false
}
