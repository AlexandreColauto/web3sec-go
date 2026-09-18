// parser_scan.go: the low-level source scanners — bracket matching, statement iteration, parameter parsing and function-declaration discovery.

package structidx

import (
	"strings"
)

// ---- low-level scanners ----------------------------------------------------

// matchBrace is _match_brace: the index closing the bracket at openIdx, with
// all three bracket kinds sharing one depth counter.
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

func countNL(s string, start, end int) int64 {
	if start < 0 {
		start = 0
	}
	if end > len(s) {
		end = len(s)
	}
	if start > end {
		return 0
	}
	return int64(strings.Count(s[start:end], "\n"))
}

// splitTopLevel is _split_top_level: split on sep only at bracket depth 0.
func splitTopLevel(text string, sep byte) []string {
	parts := []string{}
	var cur strings.Builder
	depth := 0
	for i := 0; i < len(text); i++ {
		ch := text[i]
		if ch == '(' || ch == '[' || ch == '{' {
			depth++
		} else if ch == ')' || ch == ']' || ch == '}' {
			if depth > 0 {
				depth--
			}
		}
		if ch == sep && depth == 0 {
			parts = append(parts, cur.String())
			cur.Reset()
		} else {
			cur.WriteByte(ch)
		}
	}
	parts = append(parts, cur.String())
	return parts
}

func normalizeWS(text string) string {
	return strings.TrimSpace(reSpaces.ReplaceAllString(text, " "))
}

// iterStatements is _iter_statements: (offset, text) for top-level statements.
func iterStatements(body string) [][2]any {
	out := [][2]any{}
	pdepth := 0
	start := 0
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case '(', '[':
			pdepth++
		case ')', ']':
			if pdepth > 0 {
				pdepth--
			}
		case '{', '}':
			if pdepth == 0 {
				if strings.TrimSpace(body[start:i]) != "" {
					out = append(out, [2]any{start, body[start:i]})
				}
				start = i + 1
			}
		case ';':
			if pdepth == 0 {
				out = append(out, [2]any{start, body[start : i+1]})
				start = i + 1
			}
		}
	}
	if strings.TrimSpace(body[start:]) != "" {
		out = append(out, [2]any{start, body[start:]})
	}
	return out
}

// paramNames is _param_names: the declared parameter NAMES in order.
func paramNames(paramsText string) []string {
	if strings.TrimSpace(paramsText) == "" {
		return nil
	}
	parts := splitTopLevel(paramsText, ',')
	names := []string{}
	for _, p := range parts {
		var toks []string
		for _, t := range reIdent.FindAllString(p, -1) {
			if t != "calldata" && t != "memory" && t != "storage" {
				toks = append(toks, t)
			}
		}
		if len(toks) >= 2 {
			last := toks[len(toks)-1]
			found := false
			for _, n := range names {
				if n == last {
					found = true
					break
				}
			}
			if !found {
				names = append(names, last)
			}
		}
	}
	return names
}

// paramTypes is _param_types: comma-joined first-type tokens with array
// suffixes preserved.
// splitParamTypes is the depth loop INSIDE _param_types: unlike
// _split_top_level it counts only "(" and "[" (a Solidity struct literal in
// an argument list therefore splits on its own top-level commas, so
// `f({a: 1, b: 2})` yields both field names). Depth is unclamped, matching
// the reference byte-for-byte.
func splitParamTypes(text string) []string {
	parts := []string{}
	var cur strings.Builder
	depth := 0
	for i := 0; i < len(text); i++ {
		ch := text[i]
		if ch == '(' || ch == '[' {
			depth++
		} else if ch == ')' || ch == ']' {
			depth--
		}
		if ch == ',' && depth == 0 {
			parts = append(parts, cur.String())
			cur.Reset()
		} else {
			cur.WriteByte(ch)
		}
	}
	parts = append(parts, cur.String())
	return parts
}

func paramTypes(paramsText string) string {
	if strings.TrimSpace(paramsText) == "" {
		return ""
	}
	parts := splitParamTypes(paramsText)
	types := []string{}
	for _, p := range parts {
		base := ""
		have := false
		for _, m := range reIdent.FindAllString(p, -1) {
			if m == "calldata" || m == "memory" || m == "storage" {
				continue
			}
			base = m
			have = true
			break
		}
		if !have {
			types = append(types, "?")
			continue
		}
		var suffix strings.Builder
		for _, b := range reArraySuffix.FindAllString(p, -1) {
			suffix.WriteString(reSpaces.ReplaceAllString(b, ""))
		}
		types = append(types, base+suffix.String())
	}
	return strings.Join(types, ",")
}

// parseAttrs is _parse_attrs: (visibility, modifier names).
func parseAttrs(attrs, defaultVis string) (string, []string) {
	vis := defaultVis
	mods := []string{}
	attrs = replaceAllB(attrs, reReturns, " ")
	for _, tok := range reToken.FindAllString(attrs, -1) {
		word := tok
		if i := strings.IndexByte(tok, '('); i >= 0 {
			word = tok[:i]
		}
		if visSet[word] {
			vis = word
		} else if attrSet[word] || word == "returns" {
			continue
		} else {
			mods = append(mods, word)
		}
	}
	return vis, mods
}

type fnDecl struct {
	name    string
	attrs   string
	openIdx int
	params  string
	special bool
}

// iterFunctions is _iter_functions over one contract body.
func iterFunctions(body string) []fnDecl {
	out := []fnDecl{}
	for _, m := range filterLeadingB(body,
		reFunction.FindAllStringSubmatchIndex(body, -1)) {
		name := body[m[2]:m[3]]
		openParen := m[1] - 1
		closeParen := matchBrace(body, openParen)
		if closeParen < 0 {
			continue
		}
		j := closeParen + 1
		for j < len(body) && body[j] != '{' && body[j] != ';' {
			j++
		}
		if j < len(body) && body[j] == '{' {
			out = append(out, fnDecl{name: name,
				attrs:   body[closeParen+1 : j],
				openIdx: j,
				params:  body[openParen+1 : closeParen]})
		}
	}
	return out
}

// iterSpecials is _iter_specials for one keyword.
func iterSpecials(body, kw string) []fnDecl {
	out := []fnDecl{}
	rx := pySpecial[kw]
	for _, caps := range rx.findAll(body) {
		openParen := caps[1]
		closeParen := matchBrace(body, openParen)
		if closeParen < 0 {
			continue
		}
		j := closeParen + 1
		for j < len(body) && body[j] != '{' && body[j] != ';' {
			j++
		}
		if j < len(body) && body[j] == '{' {
			out = append(out, fnDecl{name: kw, attrs: body[closeParen+1 : j],
				openIdx: j, params: body[openParen+1 : closeParen],
				special: true})
		}
	}
	return out
}

// stripFunctionBodies is _strip_function_bodies: keep the braces, blank the
// bodies (newlines survive).
func stripFunctionBodies(text string) string {
	out := []byte(text)
	depth := 0
	start := -1
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case '{':
			if depth == 0 {
				start = i
			}
			depth++
		case '}':
			depth--
			if depth == 0 && start >= 0 {
				for k := start + 1; k < i; k++ {
					if out[k] != '\n' {
						out[k] = ' '
					}
				}
				start = -1
			}
		}
	}
	return string(out)
}

// iterCastCalls is _iter_cast_calls: (pos, receiver, method) for cast and
// chained call forms in source order.
func iterCastCalls(body string) []struct {
	pos  int
	recv string
	meth string
} {
	out := []struct {
		pos  int
		recv string
		meth string
	}{}
	for _, m := range filterLeadingB(body,
		reCastOpen.FindAllStringSubmatchIndex(body, -1)) {
		recv := body[m[2]:m[3]]
		close := matchBrace(body, m[1]-1)
		if close < 0 {
			continue
		}
		j := close + 1
		for j < len(body) && (body[j] == ' ' || body[j] == '\t' ||
			body[j] == '\r' || body[j] == '\n') {
			j++
		}
		if j >= len(body) || body[j] != '.' {
			continue
		}
		if caps, ok := pyMemberCall.match(body, j+1); ok {
			s, e, _ := capsGroup(caps, 1)
			out = append(out, struct {
				pos  int
				recv string
				meth string
			}{m[0], recv, body[s:e]})
		}
	}
	return out
}
