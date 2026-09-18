// parser_concepts.go: guards and uses — identifier folding, concept keys, guard strength and per-function guard/use extraction.

package structidx

import (
	"sort"
	"strings"
)

// ---- guards / uses ---------------------------------------------------------

// splitIdent is _split_ident: camelCase/snake_case -> folded concept tokens.
func splitIdent(name string) []string {
	name = strings.TrimLeft(strings.TrimSpace(name), "_")
	parts := splitIdentRe(name)
	folded := []string{}
	for _, p := range parts {
		if p == "" {
			continue
		}
		low := strings.ToLower(p)
		if f, ok := synonymFold[low]; ok {
			low = f
		}
		folded = append(folded, low)
	}
	out := []string{}
	for _, t := range folded {
		if len(t) > 1 && !stopwords[t] {
			out = append(out, t)
		}
	}
	return out
}

// splitIdentRe is re.split(r"(?<!^)(?=[A-Z])|_", name).
func splitIdentRe(name string) []string {
	parts := []string{}
	var cur strings.Builder
	for i := 0; i < len(name); i++ {
		ch := name[i]
		if i > 0 && ch >= 'A' && ch <= 'Z' {
			parts = append(parts, cur.String())
			cur.Reset()
		}
		if ch == '_' {
			parts = append(parts, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(ch)
	}
	parts = append(parts, cur.String())
	return parts
}

// conceptSet is _concept_set: fuzzy keys for an expression.
func conceptSet(expr string) map[string]bool {
	out := map[string]bool{}
	for _, mi := range filterBothB(expr,
		reIdentChain.FindAllStringIndex(expr, -1)) {
		m := expr[mi[0]:mi[1]]
		var toks []string
		for _, part := range strings.Split(m, ".") {
			toks = append(toks, splitIdent(part)...)
		}
		kept := toks[:0]
		for _, t := range toks {
			if !stopwords[t] {
				kept = append(kept, t)
			}
		}
		toks = kept
		for _, n := range []int{2, 3} {
			for i := 0; i+n <= len(toks); i++ {
				w := toks[i : i+n]
				if distinct(w) {
					out[strings.Join(w, ":")] = true
				}
			}
		}
		for _, t := range toks {
			out[t] = true
		}
	}
	return out
}

func distinct(w []string) bool {
	seen := map[string]bool{}
	for _, x := range w {
		if seen[x] {
			return false
		}
		seen[x] = true
	}
	return true
}

// ConceptKeys is concept_keys: sorted fuzzy concept keys for one expression.
func ConceptKeys(expr string) []string {
	set := conceptSet(expr)
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// guardStrength is _guard_strength: 0 none .. 4 equality-to-persisted/keccak.
func guardStrength(cond string) int64 {
	best := 0
	max := func(v int) {
		if v > best {
			best = v
		}
	}
	if _, ok := pyGuard1.search(cond, 0); ok {
		max(1)
	}
	if reGuard2.MatchString(cond) {
		max(2)
	}
	if _, ok := pyGuard3.search(cond, 0); ok {
		max(3)
	}
	if strings.Contains(cond, "==") && reGuard4.MatchString(cond) {
		max(4)
	} else if strings.Contains(cond, "==") {
		max(3)
	}
	return int64(best)
}

// extractGuards is _extract_guards: one entry per require/assert condition
// and per REVERTING `if`, in statement order.
func extractGuards(fbody string, baseLine int64) []guardRec {
	type found struct {
		off  int
		text string
	}
	hits := []found{}
	for _, m := range filterLeadingB(fbody,
		reRequire.FindAllStringIndex(fbody, -1)) {
		close := matchBrace(fbody, m[1]-1)
		if close < 0 {
			continue
		}
		text := normalizeWS(splitTopLevel(fbody[m[1]:close], ',')[0])
		if text != "" {
			hits = append(hits, found{m[0], text})
		}
	}
	for _, m := range filterLeadingB(fbody,
		reIfGuard.FindAllStringIndex(fbody, -1)) {
		close := matchBrace(fbody, m[1]-1)
		if close < 0 {
			continue
		}
		end := close + 161
		if end > len(fbody) {
			end = len(fbody)
		}
		if !strings.Contains(fbody[close+1:end], "revert") {
			continue
		}
		text := normalizeWS(fbody[m[1]:close])
		if text != "" {
			hits = append(hits, found{m[0], text})
		}
	}
	sort.SliceStable(hits, func(i, j int) bool {
		return hits[i].off < hits[j].off
	})
	out := make([]guardRec, 0, len(hits))
	for _, h := range hits {
		out = append(out, guardRec{
			line:  baseLine + countNL(fbody, 0, h.off),
			keys:  ConceptKeys(h.text),
			class: guardStrength(h.text),
			text:  h.text,
		})
	}
	return out
}

// extractUses is _extract_uses: statement-order read/write/param/emit sites.
func extractUses(fbody string, baseLine int64, params []string) []useRec {
	out := []useRec{}
	seen := map[string]bool{}
	add := func(line int64, kind string, keys []string) {
		if len(keys) == 0 {
			return
		}
		sig := itoa(line) + "\x00" + kind + "\x00" + strings.Join(keys, "\x01")
		if seen[sig] {
			return
		}
		seen[sig] = true
		out = append(out, useRec{line: line, keys: keys, kind: kind})
	}
	var nl int64
	cursor := 0
	for _, st := range iterStatements(fbody) {
		off := st[0].(int)
		stmt := st[1].(string)
		first := off + (len(stmt) - len(strings.TrimLeft(stmt, " \t\n\r\f\v")))
		nl += countNL(fbody, cursor, first)
		cursor = first
		line := baseLine + nl
		if em := reEmit.FindStringIndex(stmt); em != nil && pyB(stmt, em[0]) {
			close := matchBrace(stmt, em[1]-1)
			if close > 0 {
				add(line, "emit", ConceptKeys(stmt[em[1]:close]))
			}
		}
		if am, ok := pyAssign.search(stmt, 0); ok {
			if lm, ok2 := pyLvalue.search(stmt[:am[0]], 0); ok2 {
				s, e, _ := capsGroup(lm, 1)
				add(line, "write", ConceptKeys(stmt[s:e]))
			}
		}
		readKeys := map[string]bool{}
		for _, ri := range filterLeadingB(stmt,
			reMemberIndex.FindAllStringIndex(stmt, -1)) {
			for k := range conceptSet(stmt[ri[0]:ri[1]]) {
				readKeys[k] = true
			}
		}
		keys := make([]string, 0, len(readKeys))
		for k := range readKeys {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		add(line, "read", keys)
		for _, p := range params {
			if searchBareIdent(stmt, p) {
				add(line, "param", ConceptKeys(p))
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].line != out[j].line {
			return out[i].line < out[j].line
		}
		if out[i].kind != out[j].kind {
			return out[i].kind < out[j].kind
		}
		return sliceLess(out[i].keys, out[j].keys)
	})
	return out
}

func sliceLess(a, b []string) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

// searchBareIdent is re.search(rf"(?<!\.)\b{name}\b", stmt).
func searchBareIdent(stmt, name string) bool {
	rx := compilePyre(`(?<!\.)\b`+name+`\b`, false, false)
	_, ok := rx.search(stmt, 0)
	return ok
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [24]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
