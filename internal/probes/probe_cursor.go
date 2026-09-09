package probes

import (
	"regexp"
	"sort"
	"strings"

	"websec/internal/structidx"
	"websec/internal/validation"
)

var cursorRe = regexp.MustCompile(`(?i)(index|count|nonce|epoch|num|_id|batch|seq)`)
var arithRe = regexp.MustCompile(`\b([A-Za-z_][0-9A-Za-z_]*)\s*([+\-])\s*1\b`)
var fwdCursorRe = regexp.MustCompile(
	`\b([A-Za-z_][0-9A-Za-z_]*)\s*\+\s*1\s*==\s*([A-Za-z_][0-9A-Za-z_.\[\]]*)`)
var revCursorRe = regexp.MustCompile(
	`\b([A-Za-z_][0-9A-Za-z_.\[\]]*)\s*==\s*([A-Za-z_][0-9A-Za-z_]*)\s*\+\s*1\b`)

// probeSequentialCursor is probe_sequential_cursor: a guard of the exact form
// `cursor + 1 == arg` / `arg == cursor + 1` over a monotonic cursor — the
// entry point may only be consumed in strict order, so one blocked item
// freezes every later one.
func probeSequentialCursor(index, model validation.Value) (probeOut, error) {
	if err := structidx.RequireParseVersion(index, "structural index"); err != nil {
		return probeOut{}, err
	}
	fns := functionNodes(index)
	sites := 0
	raw := []validation.Value{}
	blind := []validation.Value{}
	for _, cnode := range contractNodes(index) {
		cname := vStr(cnode, "name")
		entries := vObjList(cnode, "contract_closure")
		for _, e := range entries {
			node, ok := fns[nodeID(e)]
			if !ok {
				continue
			}
			for _, guard := range guardsOf(e) {
				text := vStr(guard, "text")
				lhs, rhs, hasOrder := cursorOperands(text)
				cursor := ""
				if hasOrder {
					if cursorRe.MatchString(lhs) {
						cursor = lhs
					} else if cursorRe.MatchString(rhs) {
						cursor = rhs
					}
				}
				arith := arithRe.FindStringSubmatch(text)
				loose := arith != nil && anyCursorToken(arith[1:])
				if !loose && !hasOrder {
					continue
				}
				if !vBool(node, "is_entry_point") {
					continue
				}
				sites++
				if cursor == "" {
					kind := "near-guard"
					if hasOrder {
						kind = "non-cursor-operand"
					}
					blind = append(blind, blindEntry(kind, text,
						validation.VStr(cname),
						kv("contract", validation.VStr(cname)),
						kv("function", validation.VStr(vStr(e, "name"))),
						kv("line", vGet(guard, "line")),
						kv("reason", validation.VStr(text+" looks sequential "+
							"but no monotonic cursor identifier is involved"))))
					continue
				}
				stranded := strandedEntries(entries, fns, e, cursor)
				mods := nodeModifiers(node)
				raw = append(raw, rawRow(cname, vStr(e, "name"), vInt(e, "line"),
					cursor, TierOfGate(mods, model), GateLabel(mods, model), 0,
					vStr(e, "name"),
					kv("guard", validation.VStr(text)),
					kv("guard_line", validation.VInt(int64(vGetIntOr(guard, "line", 0)))),
					kv("cursor", validation.VStr(cursor)),
					kv("stranded_entry", strArr(stranded))))
			}
		}
	}
	sortBlindFields(blind, "kind", "key", "contract", "function")
	return probeOut{sites: sites, rows: raw, blind: limit50(blind),
		blindTotal: len(blind)}, nil
}

// cursorOperands is the forward/reverse cursor match, returning
// (lhs, rhs, matched).
func cursorOperands(text string) (string, string, bool) {
	if m := fwdCursorRe.FindStringSubmatch(text); m != nil {
		return m[1], m[2], true
	}
	if m := revCursorRe.FindStringSubmatch(text); m != nil {
		return m[2], m[1], true
	}
	return "", "", false
}

// anyCursorToken is `any(_CURSOR_RE.search(tok) for tok in arith.groups())`.
func anyCursorToken(groups []string) bool {
	for _, g := range groups {
		if cursorRe.MatchString(g) {
			return true
		}
	}
	return false
}

// strandedEntries is the set of other entry points that touch the cursor's
// concept keys.
func strandedEntries(entries []validation.Value, fns map[string]validation.Value,
	e validation.Value, cursor string) []string {
	cursorKeys := map[string]struct{}{}
	for _, k := range structidx.ConceptKeys(cursor) {
		cursorKeys[k] = struct{}{}
	}
	stranded := []string{}
	for _, other := range entries {
		if vStr(other, "name") == vStr(e, "name") {
			continue
		}
		onode, ok := fns[nodeID(other)]
		if !ok || !vBool(onode, "is_entry_point") {
			continue
		}
		keys := map[string]struct{}{}
		for _, g2 := range guardsOf(other) {
			for _, k := range vStrList(g2, "concept_keys") {
				keys[k] = struct{}{}
			}
		}
		for _, u2 := range usesOf(other) {
			for _, k := range vStrList(u2, "concept_keys") {
				keys[k] = struct{}{}
			}
		}
		if intersects(keys, cursorKeys) {
			stranded = append(stranded, vStr(other, "name"))
		}
	}
	sort.Strings(stranded)
	return dedupeStrings(stranded)
}

// intersects is `keys & cursor_keys` as a boolean.
func intersects(a, b map[string]struct{}) bool {
	for k := range a {
		if _, ok := b[k]; ok {
			return true
		}
	}
	return false
}

// dedupeStrings is sorted(set(x)) over an already-sorted slice.
func dedupeStrings(in []string) []string {
	out := in[:0]
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}

// vGetIntOr is v.get(key) or fallback.
func vGetIntOr(v validation.Value, key string, def int) int {
	if !vHas(v, key) || vGet(v, key).Kind != validation.Int {
		return def
	}
	return vInt(v, key)
}

// pyOrInt is `a or b` over two int-valued JSON scalars: a falsy a (missing,
// null or 0) yields b.
func pyOrInt(a validation.Value, b int) int {
	if a.Kind == validation.Int && a.I != 0 {
		return int(a.I)
	}
	return b
}

// hasColon is `":" in s`.
func hasColon(s string) bool { return strings.Contains(s, ":") }
