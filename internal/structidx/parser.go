// parser.go: the campaign-free parse core of webv2.structural_index — a
// regex Solidity graph over a pinned source tree, ported 1:1 (port-era provenance; twin retired 2026-09-09).
//
// The backend is honestly named "regex" (K2): no compiler, no type
// resolution. The artifact is byte-identical to the Python twin's
// artifacts/structural_index.json, which is why every pattern below either
// uses Go's regexp (where RE2 is semantically equal) or the pyre engine in
// pyre.go (where Python's lookaround/lazy/multiline semantics matter).
package structidx

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"websec/internal/solscope"
	"websec/internal/validation"
)

// ParseVersion is PARSE_VERSION: v3 adds cast/chained call edges (C2).
const ParseVersion = "3"

// CampaignPlaceholder is the campaign metavariable every campaign-less
// command template carries; the renderer substitutes the campaign in hand
// for it.
const CampaignPlaceholder = "<campaign>"

// IndexRebuildCommand is INDEX_REBUILD_COMMAND, rendered into the stale-index
// error so the operator gets the exact command that fixes it.
const IndexRebuildCommand = "webv2 index " + CampaignPlaceholder + " --src <target>"

var (
	visSet = map[string]bool{"public": true, "external": true,
		"internal": true, "private": true}
	attrSet = map[string]bool{"view": true, "pure": true, "payable": true,
		"virtual": true, "override": true, "immutable": true, "constant": true}
	builtinSet = map[string]bool{"msg": true, "block": true, "tx": true,
		"abi": true, "this": true, "super": true, "keccak256": true,
		"sha256": true, "ripemd160": true, "ecrecover": true,
		"address": true, "uint256": true, "type": true, "require": true,
		"revert": true, "assert": true, "selfdestruct": true,
		"gasleft": true, "blockhash": true, "addmod": true, "mulmod": true,
		"returns": true, "emit": true, "new": true, "delete": true,
		"if": true, "for": true, "while": true, "return": true,
		"constructor": true, "receive": true, "fallback": true}
	// extCallSkip is the receiver blacklist _EXT_CALL_RE's loop applies.
	extCallSkip = map[string]bool{"sender": true, "value": true, "data": true,
		"sig": true, "code": true, "balance": true}
)

// ---- Python-compatible compiled patterns -----------------------------------

var (
	reCastOpen    = regexp.MustCompile(`\b([A-Za-z_][\p{L}\p{N}_]*)\s*\(`)
	reToken       = regexp.MustCompile(`[A-Za-z_][\p{L}\p{N}_]*(?:\([^()]*\))?`)
	reIdentChain  = regexp.MustCompile(`\b[A-Za-z_][\p{L}\p{N}_]*(?:[\t\n\v\f\r \x{1c}-\x{1f}\x{85}\p{Z}]*\.[\t\n\v\f\r \x{1c}-\x{1f}\x{85}\p{Z}]*[A-Za-z_][\p{L}\p{N}_]*)*\b`)
	reMemberIndex = regexp.MustCompile(`\b[A-Za-z_][\p{L}\p{N}_]*(?:[\t\n\v\f\r \x{1c}-\x{1f}\x{85}\p{Z}]*\.[\t\n\v\f\r \x{1c}-\x{1f}\x{85}\p{Z}]*[A-Za-z_][\p{L}\p{N}_]*|[\t\n\v\f\r \x{1c}-\x{1f}\x{85}\p{Z}]*\[[^\]]*\])+`)
	reRequire     = regexp.MustCompile(`\b(?:require|assert)[\t\n\v\f\r \x{1c}-\x{1f}\x{85}\p{Z}]*\(`)
	reIfGuard     = regexp.MustCompile(`\bif[\t\n\v\f\r \x{1c}-\x{1f}\x{85}\p{Z}]*\(`)
	reEmit        = regexp.MustCompile(`\bemit[\t\n\v\f\r \x{1c}-\x{1f}\x{85}\p{Z}]+[A-Za-z_][\p{L}\p{N}_]*[\t\n\v\f\r \x{1c}-\x{1f}\x{85}\p{Z}]*\(`)
	reGuard1      = regexp.MustCompile(`!=[\t\n\v\f\r \x{1c}-\x{1f}\x{85}\p{Z}]*(?:0|bytes32\(0\)|address\(0\)|0x0+\b)|>[\t\n\v\f\r \x{1c}-\x{1f}\x{85}\p{Z}]*0\b|\.[\t\n\v\f\r \x{1c}-\x{1f}\x{85}\p{Z}]*length[\t\n\v\f\r \x{1c}-\x{1f}\x{85}\p{Z}]*>[\t\n\v\f\r \x{1c}-\x{1f}\x{85}\p{Z}]*0`)
	reGuard2      = regexp.MustCompile(`[<>]=?[\t\n\v\f\r \x{1c}-\x{1f}\x{85}\p{Z}]*\p{Nd}`)
	reGuard3      = regexp.MustCompile(`(?i)\b(exists|isMember|verified|trusted|whitelist|approved)\b`)
	reGuard4      = regexp.MustCompile(`\[[^\]]*\][\t\n\v\f\r \x{1c}-\x{1f}\x{85}\p{Z}]*==|==[\t\n\v\f\r \x{1c}-\x{1f}\x{85}\p{Z}]*[A-Za-z_][\p{L}\p{N}_.]*[\t\n\v\f\r \x{1c}-\x{1f}\x{85}\p{Z}]*\(|==[\t\n\v\f\r \x{1c}-\x{1f}\x{85}\p{Z}]*[\p{L}\p{N}_]+\[[\p{L}\p{N}_]+\]|keccak256|sha256`)
	reModifier    = regexp.MustCompile(`\bmodifier[\t\n\v\f\r \x{1c}-\x{1f}\x{85}\p{Z}]+([A-Za-z_][\p{L}\p{N}_]*)[\t\n\v\f\r \x{1c}-\x{1f}\x{85}\p{Z}]*(\([^)]*\))?[\t\n\v\f\r \x{1c}-\x{1f}\x{85}\p{Z}]*\{`)
	reFunction    = regexp.MustCompile(`\bfunction[\t\n\v\f\r \x{1c}-\x{1f}\x{85}\p{Z}]+([A-Za-z_][\p{L}\p{N}_]*)[\t\n\v\f\r \x{1c}-\x{1f}\x{85}\p{Z}]*\(`)
	reReturns     = regexp.MustCompile(`\breturns[\t\n\v\f\r \x{1c}-\x{1f}\x{85}\p{Z}]*\([^)]*\)`)
	reSpaces      = regexp.MustCompile(`[\t\n\v\f\r \x{1c}-\x{1f}\x{85}\p{Z}]+`)
	reIdent       = regexp.MustCompile(`[A-Za-z_][\p{L}\p{N}_]*`)
	reArraySuffix = regexp.MustCompile(`\[[^\]]*\]`)
	reCallee      = regexp.MustCompile(`\b([A-Za-z_][\p{L}\p{N}_]*)[\t\n\v\f\r \x{1c}-\x{1f}\x{85}\p{Z}]*\(`)
	reFlashLoan   = regexp.MustCompile(`(?i)^flashLoan`)
)

// The patterns Python compiles with constructs RE2 lacks: lookahead,
// lookbehind, lazy quantifiers and multiline `^`.
var (
	pyExtCall    = compilePyre(`\b([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)\s*(?=\(|\{)`, false, false)
	pyMemberCall = compilePyre(`\s*([A-Za-z_]\w*)\s*(?=\(|\{)`, false, false)
	pyLowCall    = compilePyre(`\.\s*(delegatecall|staticcall|call)\s*(?=\(|\{)`, false, false)
	pyContract   = compilePyre(`\b(?:abstract\s+)?(contract|interface|library)\s+([A-Za-z_]\w*)(?:\s+is\s+([^{;]+))?\s*(?=\{)`, false, false)
	pyState      = compilePyre(`^\s*(?:mapping\s*\([^;]*?\)|[\w\[\]\.]+(?:\s*\[[^\]]*\])*)\s+(?:public|private|internal|constant|immutable|\s)*\s*([A-Za-z_]\w*)\s*(?:=\s*[^;]+)?;`, false, true)
	pyLvalue     = compilePyre(`([A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*|\s*\[[^\]]*\])*)\s*$`, false, false)
	pyAssign     = compilePyre(`(?<![=!<>+\-*/%&|^:])=(?![=>])|\+=|-=|\*=|/=|%=|&=|\|=|\^=`, false, false)
	pySpecial    = map[string]*pyre{}
	// guard_strength's two patterns carry \b, so they run on the engine
	// (RE2's ASCII \b over-matches next to Unicode word characters, and
	// reGuard1's boundaries sit inside the alternation where a post-filter
	// cannot reach them).
	pyGuard1 = compilePyre(reGuard1.String(), false, false)
	pyGuard3 = compilePyre(reGuard3.String(), false, false)
)

func init() {
	for _, kw := range []string{"constructor", "receive", "fallback"} {
		pySpecial[kw] = compilePyre(`\b`+kw+`\s*(?=\()`, false, false)
	}
}

// wordBoundaryRe compiles Python's `\b<name>\b` over Unicode word
// characters. The Go-regexp fast path cannot: RE2 has no lookaround and its
// \b is ASCII-word based, while these names come from the source itself and
// may be non-ASCII (Python's str patterns are Unicode-aware).
func wordBoundaryRe(name string) *pyre {
	return compilePyre(`(?<!\w)`+regexp.QuoteMeta(name)+`(?!\w)`, false, false)
}

// stateWriteRe is Python's `\b<name>\b\s*(?:\+=|-=|\*=|/=|\+\+|--|=[^=])`.
func stateWriteRe(name string) *pyre {
	return compilePyre(`(?<!\w)`+regexp.QuoteMeta(name)+
		`(?!\w)\s*(?:\+=|-=|\*=|/=|\+\+|--|=[^=])`, false, false)
}

// pyB reports Python's \b at byte position pos. The Go-regexp fast path uses
// RE2's ASCII \b, which over-matches wherever a Unicode word character (which
// UTF-8 encodes as non-word bytes) sits next to a keyword or identifier; every
// \b in the patterns below is adjacent to an ASCII word character, so RE2's
// candidate set is a superset of Python's and this predicate filters it back
// to Python's set.
func pyB(s string, pos int) bool {
	return isWordBefore(s, pos) != isWordAt(s, pos)
}

// filterLeadingB drops matches whose start is not a Python \b.
func filterLeadingB(s string, ms [][]int) [][]int {
	out := ms[:0]
	for _, m := range ms {
		if pyB(s, m[0]) {
			out = append(out, m)
		}
	}
	return out
}

// filterBothB drops matches whose start or end is not a Python \b.
func filterBothB(s string, ms [][]int) [][]int {
	out := ms[:0]
	for _, m := range ms {
		if pyB(s, m[0]) && pyB(s, m[1]) {
			out = append(out, m)
		}
	}
	return out
}

// replaceAllB is Regexp.ReplaceAllString with Python's Unicode \b semantics.
func replaceAllB(s string, rx *regexp.Regexp, repl string) string {
	ms := filterLeadingB(s, rx.FindAllStringIndex(s, -1))
	if len(ms) == 0 {
		return s
	}
	var b strings.Builder
	last := 0
	for _, m := range ms {
		b.WriteString(s[last:m[0]])
		b.WriteString(repl)
		last = m[1]
	}
	b.WriteString(s[last:])
	return b.String()
}

// ---- node / edge model -----------------------------------------------------

type idxEdge struct{ from, rel, to string }

type guardRec struct {
	line  int64
	keys  []string
	class int64
	text  string
}

type useRec struct {
	line int64
	keys []string
	kind string
}

type idxNode struct {
	kind       string
	id         string
	name       string
	path       string
	line       *int64
	visibility string
	isEntry    bool
	mods       []string
	selector   *string
	reads      []string
	writes     []string
	callsInt   []string
	callsExt   []string
	deleg      []string
	guards     []guardRec
	uses       []useRec
	closure    []validation.Value
}

func (n *idxNode) toValue() validation.Value {
	kvs := []validation.KV{
		{K: "id", V: validation.VStr(n.id)},
		{K: "kind", V: validation.VStr(n.kind)},
		{K: "name", V: validation.VStr(n.name)},
		{K: "path", V: validation.VStr(n.path)},
		{K: "line", V: lineValue(n.line)},
	}
	if n.kind == "function" {
		kvs = append(kvs,
			validation.KV{K: "visibility", V: validation.VStr(n.visibility)},
			validation.KV{K: "is_entry_point", V: validation.VBool(n.isEntry)},
			validation.KV{K: "modifiers", V: validation.StrArr(n.mods)},
			validation.KV{K: "guarded_by", V: validation.StrArr(n.mods)},
			validation.KV{K: "selector", V: selValue(n.selector)},
			validation.KV{K: "reads_storage", V: validation.StrArr(n.reads)},
			validation.KV{K: "writes_storage", V: validation.StrArr(n.writes)},
			validation.KV{K: "calls_internal", V: validation.StrArr(n.callsInt)},
			validation.KV{K: "calls_external", V: validation.StrArr(n.callsExt)},
			validation.KV{K: "delegatecalls", V: validation.StrArr(n.deleg)},
			validation.KV{K: "guards", V: guardsValue(n.guards)},
			validation.KV{K: "uses", V: usesValue(n.uses)},
		)
	} else if n.kind == "modifier" {
		kvs = append(kvs,
			validation.KV{K: "reads_storage", V: validation.VArr()},
			validation.KV{K: "writes_storage", V: validation.VArr()},
			validation.KV{K: "calls_internal", V: validation.VArr()},
			validation.KV{K: "calls_external", V: validation.VArr()},
			validation.KV{K: "delegatecalls", V: validation.VArr()},
		)
	}
	if n.closure != nil {
		kvs = append(kvs, validation.KV{K: "contract_closure",
			V: validation.VArr(n.closure...)})
	}
	return validation.VObj(kvs...)
}

func lineValue(line *int64) validation.Value {
	if line == nil {
		return validation.VNull()
	}
	return validation.VInt(*line)
}

func selValue(sel *string) validation.Value {
	if sel == nil {
		return validation.VNull()
	}
	return validation.VStr(*sel)
}

func guardsValue(gs []guardRec) validation.Value {
	out := make([]validation.Value, 0, len(gs))
	for _, g := range gs {
		out = append(out, validation.VObj(
			validation.KV{K: "line", V: validation.VInt(g.line)},
			validation.KV{K: "concept_keys", V: validation.StrArr(g.keys)},
			validation.KV{K: "class", V: validation.VInt(g.class)},
			validation.KV{K: "text", V: validation.VStr(g.text)},
		))
	}
	return validation.VArr(out...)
}

func usesValue(us []useRec) validation.Value {
	out := make([]validation.Value, 0, len(us))
	for _, u := range us {
		out = append(out, validation.VObj(
			validation.KV{K: "line", V: validation.VInt(u.line)},
			validation.KV{K: "concept_keys", V: validation.StrArr(u.keys)},
			validation.KV{K: "kind", V: validation.VStr(u.kind)},
		))
	}
	return validation.VArr(out...)
}

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

// ---- the tree --------------------------------------------------------------

type treeResult struct {
	nodes         []*idxNode
	edges         []idxEdge
	solidityFiles int64
	otherFiles    int64
}

// collectFiles is the `**/*` + exclude-set + Path-order walk.
//
// H4: the exclude set is solscope's shared constant — the same one the
// post-patch scope walk uses, so the index surface and the scope surface
// cannot drift apart.
func collectFiles(root string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if path != root && solscope.IsExcluded(name) {
				return fs.SkipDir
			}
			return nil
		}
		// Regular files only: a dangling symlink (or FIFO/socket/device
		// file) is not a dir, so it would reach os.ReadFile below and abort
		// the whole index build.
		if !d.Type().IsRegular() {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
			if solscope.IsExcluded(part) {
				return nil
			}
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool {
		return partsLess(files[i], files[j], root)
	})
	return files, nil
}

// partsLess reproduces Python's PurePath ordering (compare the parts tuple).
func partsLess(a, b, root string) bool {
	ra, _ := filepath.Rel(root, a)
	rb, _ := filepath.Rel(root, b)
	pa := strings.Split(filepath.ToSlash(ra), "/")
	pb := strings.Split(filepath.ToSlash(rb), "/")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return len(pa) < len(pb)
}

// IndexTree is _index_tree: nodes + edges for one source tree, campaign-free.
func IndexTree(snapshotRoot string) (*treeResult, error) {
	files, err := collectFiles(snapshotRoot)
	if err != nil {
		return nil, err
	}
	res := &treeResult{}
	var generic []string
	for _, path := range files {
		rel, _ := filepath.Rel(snapshotRoot, path)
		rel = filepath.ToSlash(rel)
		if filepath.Ext(path) != ".sol" {
			generic = append(generic, rel)
			continue
		}
		res.solidityFiles++
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		text := validUTF8Replace(string(raw))
		indexFile(text, rel, res)
	}
	res.otherFiles = int64(len(generic))
	return res, nil
}

func validUTF8Replace(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	return strings.ToValidUTF8(s, "\uFFFD")
}

type contractRec struct {
	kind      string
	name      string
	cid       string
	inherits  []string
	line      int64
	body      string
	bodyLine0 int64
}

func indexFile(text, rel string, res *treeResult) {
	contractVars := map[string][]string{}
	allFnNames := map[string]bool{}
	contracts := []contractRec{}
	for _, caps := range pyContract.findAll(text) {
		g1s, g1e, _ := capsGroup(caps, 1)
		g2s, g2e, _ := capsGroup(caps, 2)
		g3s, g3e, has3 := capsGroup(caps, 3)
		kind := text[g1s:g1e]
		name := text[g2s:g2e]
		openIdx := strings.IndexByte(text[caps[0]:], '{') + caps[0]
		closeIdx := matchBrace(text, openIdx)
		body := ""
		if closeIdx > 0 {
			body = text[openIdx+1 : closeIdx]
		}
		inherits := []string{}
		if has3 {
			for _, x := range strings.Split(text[g3s:g3e], ",") {
				t := strings.TrimSpace(x)
				if t == "" {
					continue
				}
				inherits = append(inherits, strings.Split(t, "(")[0])
			}
		}
		line := countNL(text, 0, caps[0]) + 1
		cid := rel + "#" + name
		contracts = append(contracts, contractRec{kind: kind, name: name,
			cid: cid, inherits: inherits, line: line, body: body,
			bodyLine0: countNL(text, 0, openIdx)})
		nodeLine := line
		res.nodes = append(res.nodes, &idxNode{id: cid, kind: kind, name: name,
			path: rel, line: &nodeLine})
		for _, parent := range inherits {
			res.edges = append(res.edges, idxEdge{from: cid,
				rel: "inherits", to: "*#" + parent})
		}
		stripped := stripFunctionBodies(body)
		varsHere := []string{}
		for _, sm := range pyState.findAll(stripped) {
			s, e, ok := capsGroup(sm, 1)
			if !ok {
				continue
			}
			v := stripped[s:e]
			if v != "" && !builtinSet[v] {
				varsHere = append(varsHere, v)
				res.nodes = append(res.nodes, &idxNode{
					id: cid + "." + v, kind: "state-variable", name: v,
					path: rel, line: nil})
			}
		}
		contractVars[name] = varsHere
		for _, mm := range filterLeadingB(body,
			reModifier.FindAllStringSubmatchIndex(body, -1)) {
			mname := body[mm[2]:mm[3]]
			open2 := strings.IndexByte(body[mm[0]:], '{') + mm[0]
			close2 := matchBrace(body, open2)
			modLine := line + countNL(body, 0, mm[0])
			res.nodes = append(res.nodes, &idxNode{
				id: cid + "." + mname, kind: "modifier", name: mname,
				path: rel, line: &modLine})
			if close2 > 0 {
				allFnNames[mname] = true
			}
		}
		for _, d := range iterFunctions(body) {
			allFnNames[d.name] = true
		}
		for _, kw := range []string{"constructor", "receive", "fallback"} {
			for range iterSpecials(body, kw) {
				allFnNames[kw] = true
			}
		}
	}
	for _, c := range contracts {
		indexContract(c, rel, contractVars, allFnNames, res)
	}
}

func indexContract(c contractRec, rel string,
	contractVars map[string][]string, allFnNames map[string]bool,
	res *treeResult) {
	body := c.body
	decls := iterFunctions(body)
	for _, kw := range []string{"constructor", "receive", "fallback"} {
		decls = append(decls, iterSpecials(body, kw)...)
	}
	type modBody struct {
		name string
		body string
	}
	modifierBodies := []modBody{}
	for _, mm := range reModifier.FindAllStringSubmatchIndex(body, -1) {
		mOpen := strings.IndexByte(body[mm[0]:], '{') + mm[0]
		mClose := matchBrace(body, mOpen)
		if mClose > 0 {
			modifierBodies = append(modifierBodies, modBody{
				name: body[mm[2]:mm[3]], body: body[mOpen+1 : mClose]})
		}
	}
	for _, d := range decls {
		closeIdx := matchBrace(body, d.openIdx)
		fbody := ""
		if closeIdx > 0 {
			fbody = body[d.openIdx+1 : closeIdx]
		}
		fbodyOwn := fbody
		for _, mb := range modifierBodies {
			if _, ok := wordBoundaryRe(mb.name).search(d.attrs+" "+fbody, 0); ok {
				fbody += mb.body
			}
		}
		defaultVis := "internal"
		if c.kind == "interface" {
			defaultVis = "external"
		} else if d.name == "constructor" || d.name == "receive" ||
			d.name == "fallback" {
			defaultVis = "public"
		}
		vis, mods := parseAttrs(d.attrs, defaultVis)
		fid := c.cid + "." + d.name
		fline := c.bodyLine0 + countNL(body, 0, d.openIdx) + 1
		n := &idxNode{id: fid, kind: "function", name: d.name, path: rel,
			line: &fline, visibility: vis,
			isEntry: vis == "external" || vis == "public", mods: mods}
		if !d.special && (vis == "external" || vis == "public") {
			sel := d.name + "(" + paramTypes(d.params) + ")"
			n.selector = &sel
		}
		n.guards = extractGuards(fbodyOwn, fline)
		n.uses = extractUses(fbodyOwn, fline, paramNames(d.params))
		for _, v := range contractVars[c.name] {
			if _, ok := wordBoundaryRe(v).search(fbody, 0); ok {
				n.reads = append(n.reads, v)
				if _, ok := stateWriteRe(v).search(fbody, 0); ok {
					n.writes = append(n.writes, v)
				}
			}
		}
		for _, ci := range filterLeadingB(fbody,
			reCallee.FindAllStringSubmatchIndex(fbody, -1)) {
			callee := fbody[ci[2]:ci[3]]
			if builtinSet[callee] {
				continue
			}
			if allFnNames[callee] {
				n.callsInt = append(n.callsInt, callee)
				res.edges = append(res.edges, idxEdge{from: fid,
					rel: "calls", to: c.cid + "." + callee})
			}
		}
		// External calls in STATEMENT ORDER (C2), deduped by (method, line).
		type call struct {
			pos  int
			tgt  string
			meth string
		}
		calls := []call{}
		for _, em := range pyExtCall.findAll(fbody) {
			ts, te, _ := capsGroup(em, 1)
			ms, me, _ := capsGroup(em, 2)
			tgt, meth := fbody[ts:te], fbody[ms:me]
			if builtinSet[tgt] || extCallSkip[tgt] {
				continue
			}
			if em[0] >= 4 && fbody[em[0]-4:em[0]] == "msg." {
				continue
			}
			calls = append(calls, call{em[0], tgt, meth})
		}
		for _, cc := range iterCastCalls(fbody) {
			if builtinSet[cc.recv] {
				continue
			}
			calls = append(calls, call{cc.pos, cc.recv, cc.meth})
		}
		sort.SliceStable(calls, func(i, j int) bool {
			return calls[i].pos < calls[j].pos
		})
		seenCalls := map[string]bool{}
		for _, cl := range calls {
			site := cl.meth + "\x00" + itoa(fline+countNL(fbody, 0, cl.pos))
			if seenCalls[site] {
				continue
			}
			seenCalls[site] = true
			n.callsExt = append(n.callsExt, cl.tgt+"."+cl.meth)
			res.edges = append(res.edges, idxEdge{from: fid, rel: "calls",
				to: "*#" + cl.tgt + "." + cl.meth})
		}
		for _, lm := range pyLowCall.findAll(fbody) {
			s, e, _ := capsGroup(lm, 1)
			kind := fbody[s:e]
			label := "low-level." + kind
			if kind == "delegatecall" {
				n.deleg = append(n.deleg, label)
				res.edges = append(res.edges, idxEdge{from: fid,
					rel: "delegatecalls", to: "*#" + label})
			} else {
				n.callsExt = append(n.callsExt, label)
				res.edges = append(res.edges, idxEdge{from: fid,
					rel: "calls", to: "*#" + label})
			}
		}
		if n.isEntry {
			res.edges = append(res.edges, idxEdge{from: c.cid,
				rel: "extends-interface", to: fid})
		}
		res.nodes = append(res.nodes, n)
	}
}

// dedupeNodes is the first-wins id dedupe.
func dedupeNodes(nodes []*idxNode) []*idxNode {
	seen := map[string]bool{}
	out := make([]*idxNode, 0, len(nodes))
	for _, n := range nodes {
		if seen[n.id] {
			continue
		}
		seen[n.id] = true
		out = append(out, n)
	}
	return out
}

// attachClosures is _attach_closures: reverse-MRO transitive expansion, own
// definitions win, entries sorted by (name, defining_contract, line, path).
func attachClosures(nodes []*idxNode, edges []idxEdge) {
	contracts := map[string]*idxNode{}
	fns := map[string]map[string]*idxNode{}
	byName := map[string][]string{}
	var names []string
	for _, n := range nodes {
		switch n.kind {
		case "contract", "interface", "library":
			contracts[n.id] = n
			if _, ok := byName[n.name]; !ok {
				names = append(names, n.name)
			}
			byName[n.name] = append(byName[n.name], n.id)
		case "function":
			cid := n.id[:strings.LastIndexByte(n.id, '.')]
			if fns[cid] == nil {
				fns[cid] = map[string]*idxNode{}
			}
			fns[cid][n.name] = n
		}
	}
	for _, ids := range byName {
		sort.Strings(ids)
	}
	inherits := map[string][]string{}
	for _, e := range edges {
		if e.rel == "inherits" {
			inherits[e.from] = append(inherits[e.from],
				e.to[strings.Index(e.to, "#")+1:])
		}
	}
	var effective func(cid string, seen map[string]bool) map[string]*idxNode
	effective = func(cid string, seen map[string]bool) map[string]*idxNode {
		out := map[string]*idxNode{}
		bases := inherits[cid]
		for i := len(bases) - 1; i >= 0; i-- {
			for _, baseCid := range byName[bases[i]] {
				if seen[baseCid] {
					continue
				}
				next := map[string]bool{}
				for k := range seen {
					next[k] = true
				}
				next[cid] = true
				for k, v := range effective(baseCid, next) {
					out[k] = v
				}
			}
		}
		for k, v := range fns[cid] {
			out[k] = v
		}
		return out
	}
	for _, cid := range contractIDsInOrder(nodes) {
		cnode := contracts[cid]
		eff := effective(cid, map[string]bool{})
		type entry struct {
			name, defining, path string
			line                 int64
			node                 *idxNode
		}
		entries := []entry{}
		for fname, fnode := range eff {
			defining := fname
			if d, ok := contracts[fnode.id[:strings.LastIndexByte(fnode.id, '.')]]; ok {
				defining = d.name
			}
			ln := int64(-1)
			if fnode.line != nil {
				ln = *fnode.line
			}
			entries = append(entries, entry{name: fname, defining: defining,
				path: fnode.path, line: ln, node: fnode})
		}
		sort.SliceStable(entries, func(i, j int) bool {
			a, b := entries[i], entries[j]
			if a.name != b.name {
				return a.name < b.name
			}
			if a.defining != b.defining {
				return a.defining < b.defining
			}
			if a.line != b.line {
				return a.line < b.line
			}
			return a.path < b.path
		})
		closure := make([]validation.Value, 0, len(entries))
		for _, e := range entries {
			closure = append(closure, validation.VObj(
				validation.KV{K: "name", V: validation.VStr(e.name)},
				validation.KV{K: "defining_contract",
					V: validation.VStr(e.defining)},
				validation.KV{K: "path", V: validation.VStr(e.node.path)},
				validation.KV{K: "line", V: lineValue(e.node.line)},
				validation.KV{K: "guards", V: guardsValue(e.node.guards)},
				validation.KV{K: "uses", V: usesValue(e.node.uses)},
			))
		}
		cnode.closure = closure
	}
}

func contractIDsInOrder(nodes []*idxNode) []string {
	out := []string{}
	for _, n := range nodes {
		switch n.kind {
		case "contract", "interface", "library":
			out = append(out, n.id)
		}
	}
	return out
}
