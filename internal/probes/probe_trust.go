package probes

import (
	"sort"
	"strings"

	"websec/internal/structidx"
	"websec/internal/validation"
)

// assumptionTrust is _ASSUMPTION_TRUST: only these trust values carry an
// honesty assumption to invert.
var assumptionTrust = map[string]struct{}{"trusted": {}, "semi-trusted": {}}

// trustEntry is one (kind, entry) pair of the trust join, sorted by
// (kind, str(entry.id or "")).
type trustEntry struct {
	kind  string
	entry validation.Value
}

// probeTrustAssumption is probe_trust_assumption: every invariant/equation
// that names an actor whose honesty the protocol depends on. No parsing, no
// index facts beyond the version gate.
func probeTrustAssumption(index, model validation.Value) (probeOut, error) {
	if err := structidx.RequireParseVersion(index, "structural index"); err != nil {
		return probeOut{}, err
	}
	if model.Kind != validation.Obj {
		return probeOut{}, nil
	}
	entries := trustEntries(model)
	sites := 0
	raw := []validation.Value{}
	blind := []validation.Value{}
	for _, te := range entries {
		blob := validation.CanonSpaced(te.entry)
		eid := pyStr(vGet(te.entry, "id"))
		for _, actor := range actorTable(model) {
			if !wordBoundarySearch(actor.id, blob) {
				continue
			}
			sites++
			tier := tierForTrust(actor.trust)
			trustStr := pyStr(actor.trust)
			if _, assumption := assumptionTrust[trustStr]; assumption {
				raw = append(raw, rawRow(actor.id, eid, 0, actor.id, tier,
					actor.id, 0, actor.id,
					kv("actor", validation.VStr(actor.id)),
					kv("invariant", validation.VStr(eid)),
					kv("trust", validation.VStr(trustStr)),
					kv("kind", validation.VStr(te.kind)),
					kv("statement", validation.VStr(statementOf(te.entry)))))
			} else {
				blind = append(blind, blindEntry("non-assumption-actor",
					actor.id, validation.VStr(eid),
					kv("actor", validation.VStr(actor.id)),
					kv("invariant", validation.VStr(eid)),
					kv("trust", validation.VStr(trustStr)),
					kv("reason", validation.VStr(eid+" names "+actor.id+
						" (trust="+validation.PyRepr(actor.trust)+
						"), which carries no honesty assumption to invert"))))
			}
		}
	}
	sortBlindFields(blind, "kind", "key", "near")
	return probeOut{sites: sites, rows: raw, blind: limit50(blind),
		blindTotal: len(blind)}, nil
}

// trustEntries collects model invariants + economic relations, sorted by
// (kind, id).
func trustEntries(model validation.Value) []trustEntry {
	out := []trustEntry{}
	for _, inv := range vObjList(model, "invariants") {
		out = append(out, trustEntry{"invariant", inv})
	}
	for _, rel := range vObjList(model, "economic_relations") {
		out = append(out, trustEntry{"equation", rel})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].kind != out[j].kind {
			return out[i].kind < out[j].kind
		}
		return pyStr(vGet(out[i].entry, "id")) < pyStr(vGet(out[j].entry, "id"))
	})
	return out
}

// statementOf is (statement or equation or "")[:160].
func statementOf(entry validation.Value) string {
	s := vGet(entry, "statement")
	if !vTruthy(s) {
		s = vGet(entry, "equation")
	}
	if !vTruthy(s) {
		return ""
	}
	return truncRunes(pyStr(s), 160)
}

// truncRunes is s[:n] over code points.
func truncRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// lower/prefix/rsplit helpers used by the call-edge classification.
func lower(s string) string              { return strings.ToLower(s) }
func hasPrefix(s, p string) bool         { return strings.HasPrefix(s, p) }
func lastIndexByte(s string, b byte) int { return strings.LastIndexByte(s, b) }
