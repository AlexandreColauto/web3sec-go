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
	"regexp"
	"strings"
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
