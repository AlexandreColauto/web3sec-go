package probes

import (
	"regexp"
	"strings"

	"websec/internal/structidx"
	"websec/internal/validation"
)

// pySpace is Python's `\s` in a unicode pattern.
const pySpace = `[\t\n\v\f\r \x{1c}-\x{1f}\x{85}\p{Z}]`

// sentinelRe is SI._GUARD_1_RE: the index's own class-1 vocabulary, so
// "sentinel" and "what the index grades as a sanity guard" cannot drift.
var sentinelRe = regexp.MustCompile(
	`!=` + pySpace + `*(?:0|bytes32\(0\)|address\(0\)|0x0+\b)|>` + pySpace +
		`*0\b|\.length` + pySpace + `*>` + pySpace + `*0`)

// probeShortCircuitableGuard is probe_short_circuitable_guard: one conjunction
// guard whose sentinel conjunct comes FIRST. A conjunction with no sentinel is
// a site the probe REJECTS (blind), not silence.
func probeShortCircuitableGuard(index, model validation.Value) (probeOut, error) {
	if err := structidx.RequireParseVersion(index, "structural index"); err != nil {
		return probeOut{}, err
	}
	fns := functionNodes(index)
	sites := 0
	raw := []validation.Value{}
	blind := []validation.Value{}
	for _, cnode := range contractNodes(index) {
		cname := vStr(cnode, "name")
		for _, e := range vObjList(cnode, "contract_closure") {
			node, ok := fns[nodeID(e)]
			if !ok {
				continue
			}
			for _, guard := range guardsOf(e) {
				text := vStr(guard, "text")
				if !strings.Contains(text, "&&") {
					continue
				}
				sites++
				conjuncts := splitConjuncts(text, 0)
				sentinels, safeties := splitSentinelConjuncts(conjuncts)
				key := cname + "::" + vStr(e, "name") + "::" + text
				if len(sentinels) == 0 || len(safeties) == 0 ||
					firstNonSentinelBefore(conjuncts) {
					blind = append(blind, blindEntry(
						conjunctBlindKind(sentinels, safeties, conjuncts), key,
						validation.VNull(),
						kv("contract", validation.VStr(cname)),
						kv("function", validation.VStr(vStr(e, "name"))),
						kv("line", vGet(guard, "line")),
						kv("reason", validation.VStr(conjunctBlindReason(
							text, sentinels, safeties, conjuncts)))))
					continue
				}
				mods := nodeModifiers(node)
				raw = append(raw, rawRow(cname, vStr(e, "name"),
					pyOrInt(vGet(guard, "line"), vInt(e, "line")),
					strings.Join(sentinels, " && "), TierOfGate(mods, model),
					GateLabel(mods, model), 0, vStr(e, "name"),
					kv("guard", validation.VStr(text)),
					kv("guard_line", validation.VInt(int64(vGetIntOr(guard, "line", 0)))),
					kv("sentinel", validation.VStr(strings.Join(sentinels, " && "))),
					kv("safety", validation.VStr(strings.Join(safeties, " && ")))))
			}
		}
	}
	sortBlindFields(blind, "kind", "key", "contract", "function")
	return probeOut{sites: sites, rows: raw, blind: limit50(blind),
		blindTotal: len(blind)}, nil
}

// splitSentinelConjuncts partitions the conjuncts by the sentinel regex.
func splitSentinelConjuncts(conjuncts []string) ([]string, []string) {
	sentinels, safeties := []string{}, []string{}
	for _, c := range conjuncts {
		if sentinelRe.MatchString(c) {
			sentinels = append(sentinels, c)
		} else {
			safeties = append(safeties, c)
		}
	}
	return sentinels, safeties
}

// firstNonSentinelBefore is `is_sent.index(False) < is_sent.index(True)`.
func firstNonSentinelBefore(conjuncts []string) bool {
	firstFalse, firstTrue := -1, -1
	for i, c := range conjuncts {
		sent := sentinelRe.MatchString(c)
		if !sent && firstFalse < 0 {
			firstFalse = i
		}
		if sent && firstTrue < 0 {
			firstTrue = i
		}
	}
	return firstFalse >= 0 && firstTrue >= 0 && firstFalse < firstTrue
}

// conjunctBlindKind names the blind entry the rejected conjunction produced.
func conjunctBlindKind(sentinels, safeties, conjuncts []string) string {
	switch {
	case len(sentinels) == 0:
		return "no-sentinel-conjunct"
	case len(safeties) == 0:
		return "no-safety-conjunct"
	default:
		return "safety-before-sentinel"
	}
}

// conjunctBlindReason is the verbatim reason for a rejected conjunction.
func conjunctBlindReason(text string, sentinels, safeties,
	conjuncts []string) string {
	switch conjunctBlindKind(sentinels, safeties, conjuncts) {
	case "no-sentinel-conjunct":
		return text + " is a conjunction but no conjunct is a non-zero/`> 0` " +
			"sentinel — nothing to short-circuit"
	case "no-safety-conjunct":
		return text + " is all sentinel: every conjunct is a non-zero sanity " +
			"check, so no check is hidden behind one"
	default:
		return text + " puts the safety conjunct before the sentinel, so the " +
			"sentinel is only a redundant check — nothing is short-circuited"
	}
}

// splitConjuncts is _split_conjuncts: top-level `&&` conjuncts, depth-aware,
// with parenthesized sub-conjunctions split again (up to depth 4).
func splitConjuncts(text string, depth int) []string {
	parts := []string{}
	depthNow := 0
	var cur strings.Builder
	for i := 0; i < len(text); i++ {
		ch := text[i]
		switch ch {
		case '(', '[', '{':
			depthNow++
		case ')', ']', '}':
			if depthNow > 0 {
				depthNow--
			}
		}
		if ch == '&' && depthNow == 0 && strings.HasPrefix(text[i:], "&&") {
			parts = append(parts, cur.String())
			cur.Reset()
			i++
			continue
		}
		cur.WriteByte(ch)
	}
	parts = append(parts, cur.String())
	out := []string{}
	for _, part := range parts {
		stripped := stripOuterParens(part)
		if depth < 4 && stripped != strip(part) && strings.Contains(stripped, "&&") {
			out = append(out, splitConjuncts(stripped, depth+1)...)
		} else if stripped != "" {
			out = append(out, stripped)
		}
	}
	return out
}

// stripOuterParens is _strip_outer_parens: only a layer that wraps the WHOLE
// conjunct.
func stripOuterParens(text string) string {
	out := strip(text)
	for strings.HasPrefix(out, "(") && strings.HasSuffix(out, ")") &&
		matchBrace(out, 0) == len(out)-1 {
		out = strip(out[1 : len(out)-1])
	}
	return out
}

// matchBrace is SI._match_brace: the index of the bracket closing the one at
// openIdx (all bracket types share one depth counter).
func matchBrace(text string, openIdx int) int {
	depth := 0
	for i := openIdx; i < len(text); i++ {
		switch text[i] {
		case '{', '(', '[':
			depth++
		case '}', ')', ']':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}
