// assumptions.go: G10 projection — per-hop assumption table + ASSUMPTION GAPs.
//
// AssumptionTable projects the model's `chains[]` (declared order) against
// `chain_assumptions[]` (first entry whose `chain` equals the name wins).
// Missing optionals render as JSON null, never empty string. BRIDGES hops
// touch a chain when `from`/`to`/`via` contains the chain name; the ONLY two
// gap rules are (a) touched chain with no assumption entry, and (b) an entry
// with both finality and confirmation_depth absent/null. Pure function.
package protocolgraph

import (
	"sort"
	"strings"

	"websec/internal/validation"
)

// assumptionDetailFields is the LOCKED schema field list (schema order:
// protocol_model.schema.json chain_assumptions items properties).
var assumptionDetailFields = []string{
	"finality", "confirmation_depth", "messenger",
	"validator_set", "threshold", "separator",
}

// AssumptionTable is the G10 projection: one row per chains[] entry in
// declared order, plus deduped gaps sorted by hop then chain then reason.
func AssumptionTable(model validation.Value) ([]validation.Value, []validation.Value) {
	chains := []string{}
	if v := validation.ObjAt(model, "chains"); v.Kind == validation.Arr {
		for _, c := range v.A {
			if c.Kind == validation.Str {
				chains = append(chains, c.S)
			}
		}
	}
	var assumptions []validation.Value
	if v := validation.ObjAt(model, "chain_assumptions"); v.Kind == validation.Arr {
		assumptions = v.A
	}
	// findEntry is the assumption lookup: first item whose chain equals.
	findEntry := func(name string) (validation.Value, bool) {
		for _, a := range assumptions {
			if c := validation.ObjAt(a, "chain"); c.Kind == validation.Str && c.S == name {
				return a, true
			}
		}
		return validation.VNull(), false
	}

	rows := []validation.Value{}
	for _, name := range chains {
		entry, found := findEntry(name)
		pairs := []validation.KV{kv("chain", validation.VStr(name))}
		for _, f := range assumptionDetailFields {
			val := validation.VNull()
			if found {
				// objAt is Null when absent: the declared-none rule emits
				// nulls, never empty strings.
				val = validation.ObjAt(entry, f)
			}
			pairs = append(pairs, kv(f, val))
		}
		rows = append(rows, validation.VObj(pairs...))
	}

	type gapKey struct{ hop, chain, reason string }
	seen := map[gapKey]struct{}{}
	gaps := []validation.Value{}
	for _, r := range listField(model, "relations") {
		if validation.ObjAt(r, "rel").S != "BRIDGES" {
			continue
		}
		from, to, via := pyStr(validation.ObjAt(r, "from")), pyStr(validation.ObjAt(r, "to")), pyStr(validation.ObjAt(r, "via"))
		hop := from + "->" + to
		for _, name := range chains {
			if name == "" {
				continue
			}
			if !strings.Contains(from, name) && !strings.Contains(to, name) && !strings.Contains(via, name) {
				continue
			}
			entry, found := findEntry(name)
			reason := ""
			switch {
			case !found:
				reason = "missing-assumptions"
			case validation.ObjAt(entry, "finality").Kind == validation.Null &&
				validation.ObjAt(entry, "confirmation_depth").Kind == validation.Null:
				reason = "finality-unspecified"
			}
			if reason == "" {
				continue
			}
			key := gapKey{hop, name, reason}
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			gaps = append(gaps, validation.VObj(
				kv("hop", validation.VStr(hop)),
				kv("chain", validation.VStr(name)),
				kv("reason", validation.VStr(reason)),
			))
		}
	}
	sort.Slice(gaps, func(i, j int) bool {
		gi, gj := gaps[i], gaps[j]
		if hi, hj := validation.ObjAt(gi, "hop").S, validation.ObjAt(gj, "hop").S; hi != hj {
			return hi < hj
		}
		if ci, cj := validation.ObjAt(gi, "chain").S, validation.ObjAt(gj, "chain").S; ci != cj {
			return ci < cj
		}
		return validation.ObjAt(gi, "reason").S < validation.ObjAt(gj, "reason").S
	})
	return rows, gaps
}
