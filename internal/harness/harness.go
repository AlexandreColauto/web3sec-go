// Package harness renders deterministic Solidity audit-harness scaffolds
// (G8): one invariant in, one compilable skeleton out. The model may write
// ONLY the predicate body between the BODY markers; Validate re-renders the
// scaffold and rejects any byte outside that window that moved.
//
// Determinism law: Scaffold is a pure function of (kind, id, statement,
// source) — no clock, no randomness, no map iteration; every line is emitted
// in a fixed order by the template code below, so identical input yields
// byte-identical output on every machine.
//
// Lexer-naive limit: BodyRegion matches the marker SPELLINGS as raw byte
// substrings with no Solidity lexing. A marker spelling inside a string
// literal, a comment, or any other non-marker position still counts as a
// marker (duplicate/misplaced-marker error). Body authors must keep the
// exact marker spellings out of body code; the string-literal test pins
// this naive-window behavior.
package harness

import (
	"bytes"
	"fmt"
	"strings"

	"websec/internal/validation"
)

// Kind selects the harness skeleton.
type Kind string

// Skeleton kinds.
const (
	Halmos    Kind = "halmos"
	ForgeFuzz Kind = "forge-fuzz"
	// MiniCertora is the G8 third kind: a bounded SMT verifier run
	// against a .mspec rule (docs/MINICERTORA_ARCHITECTURE.md L0-L2).
	// Its scaffold is text, not Solidity — the BODY markers are
	// "//" comments, which the shipped .mspec grammar ignores
	// (spec/grammar.lark COMMENT), so BodyRegion/Validate carry over
	// unchanged.
	MiniCertora Kind = "minicertora"
)

// BODY markers. Exact, plain ASCII, each on its own line. The model writes
// ONLY between them; everything outside is scaffold bytes.
const (
	StartMarker = "// >>> BODY (model writes ONLY between these markers; outside is scaffold)"
	EndMarker   = "// <<< BODY"
)

// DummyMessage is the revert reason shared by both fresh-scaffold dummies.
// The unicode"..." prefix is load-bearing: solc rejects non-ASCII bytes in
// plain string literals, and the message keeps its em dash.
const DummyMessage = `unicode"unfilled scaffold — replace the BODY"`

// WitnessVar is the scaffold-owned state slot line emitted in every harness
// contract. Model bodies may reuse it; its writer in the dummy keeps the
// harness functions non-view (model bodies must be free to call into the
// target, so pure/view would cripple them).
//
// H14 conditional hold — DELIBERATELY NOT REMOVED, but not yet earning its
// keep either. The slot is contract-visible in the halmos symbolic context:
// a symbolic storage variable is one more piece of state the solver may
// branch on, so it is a (small, unmeasured) inference cost every invariant
// run pays. Today the only writer is the dummy scaffold's `_witness =
// block.timestamp` line, whose real job is the solc mutability warning
// (2018) — the placeholder bodies never run as proofs, so with them the
// slot is harmless. Revisit when a real invariant is written against a
// scaffold: if nothing in the live harness reads or writes it, drop the
// slot (and the mutability workaround moves with the dummy that needed it);
// until then removing it would trade a measured-zero cost for an unmeasured
// solc warning class. Note the scaffold bytes are pinned by
// harness_test.go, so any removal is a visible pin edit either way. No code
// change here on purpose — this note is the record of the deferred decision.
const WitnessVar = `uint256 private _witness;`

// DummyHalmos and DummyFuzz are the compile-valid placeholder statements
// emitted INSIDE the body window of a fresh scaffold (the "\n        "
// inside each constant is the second line's indentation — the scaffold is
// byte-pinned, so the constant carries its own layout). The model replaces
// them with the real predicate; they exist so an untouched scaffold still
// parses AND compiles with zero solc warnings. The witness write plus
// block.timestamp/seed use are load-bearing: without a state write solc
// flags "mutability can be restricted to pure/view" (2018), without the
// seed use it flags "unused parameter" (5667).
const (
	DummyHalmos = `_witness = block.timestamp;
        require(false, ` + DummyMessage + `);`
	DummyFuzz = `_witness = block.timestamp + seed;
        require(false, ` + DummyMessage + `);`
)

// invField is dict.get(key) over an invariant record (absent vs null kept
// distinct by the ok flag).
func invField(inv validation.Value, key string) (validation.Value, bool) {
	if inv.Kind != validation.Obj {
		return validation.VNull(), false
	}
	for _, e := range inv.O {
		if e.K == key {
			return e.V, true
		}
	}
	return validation.VNull(), false
}

// invID reads the invariant's id-ish key. Model records carry "id";
// registry entries carry the id as their map key, so callers pass it in as
// "id" (fallback: "invariant_id").
func invID(inv validation.Value) (string, error) {
	if v, ok := invField(inv, "id"); ok && v.Kind == validation.Str && v.S != "" {
		return v.S, nil
	}
	if v, ok := invField(inv, "invariant_id"); ok && v.Kind == validation.Str && v.S != "" {
		return v.S, nil
	}
	return "", fmt.Errorf("harness: invariant missing string \"id\" " +
		"(registry entries carry the id as their key — pass it as \"id\")")
}

// sanitizeStatement keeps the natspec line single-line: CR/LF become spaces.
func sanitizeStatement(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

// snake maps an id-ish string to a Solidity function-name slug: lowercase,
// every maximal run of non-[a-z0-9] becomes one "_", leading/trailing runs
// trimmed. INV-007a -> inv_007a. Empty when nothing nameable remains.
func snake(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	needUnd := false // a separator is pending (also swallows leading runs)
	wrote := false
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			if needUnd && wrote {
				b.WriteByte('_')
			}
			b.WriteRune(r)
			needUnd = false
			wrote = true
			continue
		}
		needUnd = true
	}
	return b.String()
}

// caml maps an id-ish string to a Solidity contract-name fragment: snake,
// split on "_", first ASCII letter of each part uppercased, joined. A
// leading digit would not compile as a contract name, so "Inv" is
// prepended. INV-007a -> Inv007a; 007 -> Inv007.
func caml(s string) string {
	sn := snake(s)
	if sn == "" {
		return ""
	}
	parts := strings.Split(sn, "_")
	var b strings.Builder
	for _, p := range parts {
		if p == "" {
			continue
		}
		c := p[0]
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		b.WriteByte(c)
		b.WriteString(p[1:])
	}
	out := b.String()
	if out == "" {
		return ""
	}
	if c := out[0]; !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z') {
		return "Inv" + out
	}
	return out
}

// Scaffold renders the harness skeleton for one invariant. Byte-deterministic:
// the ONLY variable content is the invariant data itself (id, statement,
// source); field emission order is fixed in the code below.
func Scaffold(k Kind, inv validation.Value) ([]byte, error) {
	if k != Halmos && k != ForgeFuzz && k != MiniCertora {
		return nil, fmt.Errorf("harness: unknown kind %q", string(k))
	}
	id, err := invID(inv)
	if err != nil {
		return nil, err
	}
	stV, ok := invField(inv, "statement")
	if !ok || stV.Kind != validation.Str || stV.S == "" {
		return nil, fmt.Errorf("harness: invariant %q missing string \"statement\"", id)
	}
	stmt := sanitizeStatement(stV.S)
	sn := snake(id)
	if sn == "" {
		return nil, fmt.Errorf("harness: invariant %q has no name characters", id)
	}
	// MiniCertora renders .mspec text, not Solidity: it owns a separate
	// renderer so the two byte laws cannot be edited against each other.
	// The guards above (id, statement, name characters) are shared and
	// therefore run BEFORE this branch for every kind alike.
	if k == MiniCertora {
		return scaffoldMspec(sn, stmt, inv), nil
	}
	cn := caml(id)
	var b strings.Builder
	b.WriteString("// SPDX-License-Identifier: UNLICENSED\n")
	b.WriteString("pragma solidity >=0.8.0;\n")
	b.WriteString("\n")
	b.WriteString("import \"forge-std/Test.sol\";\n")
	if k == Halmos {
		b.WriteString("import \"halmos-cheatcodes/SymTest.sol\";\n")
	}
	b.WriteString("// @custom:invariant " + stmt + "\n")
	// Source may be null (model-source invariants carry no pin): omit the
	// natspec src line cleanly rather than emitting an empty claim.
	if srcV, ok := invField(inv, "source"); ok && srcV.Kind == validation.Str && srcV.S != "" {
		b.WriteString("// @custom:src " + sanitizeStatement(srcV.S) + "\n")
	}
	b.WriteString("\n")
	if k == Halmos {
		b.WriteString("contract " + cn + "InvariantHalmos is SymTest, Test {\n")
		b.WriteString("    " + WitnessVar + "\n")
		b.WriteString("    function check_" + sn + "() external {\n")
	} else {
		b.WriteString("contract " + cn + "InvariantFuzz is Test {\n")
		b.WriteString("    " + WitnessVar + "\n")
		b.WriteString("    function fuzz_" + sn + "(uint256 seed) external {\n")
	}
	b.WriteString("        " + StartMarker + "\n")
	if k == Halmos {
		b.WriteString("        " + DummyHalmos + "\n")
	} else {
		b.WriteString("        " + DummyFuzz + "\n")
	}
	b.WriteString("        " + EndMarker + "\n")
	b.WriteString("    }\n")
	b.WriteString("}\n")
	return []byte(b.String()), nil
}

// BodyRegion locates the model-writable window: bytes in
// [start, end) — just past the start-marker line break up to the
// end-marker spelling. Matching is deliberately lexer-naive (see the
// package comment): each marker spelling must appear EXACTLY once as a raw
// substring, and the end spelling must follow the start spelling.
func BodyRegion(src []byte) (start, end int, err error) {
	ns := bytes.Count(src, []byte(StartMarker))
	ne := bytes.Count(src, []byte(EndMarker))
	switch {
	case ns == 0:
		return 0, 0, fmt.Errorf("harness: scaffold-bound: missing BODY start marker")
	case ne == 0:
		return 0, 0, fmt.Errorf("harness: scaffold-bound: missing BODY end marker")
	case ns > 1 || ne > 1:
		return 0, 0, fmt.Errorf("harness: scaffold-bound: duplicate BODY markers: start x%d end x%d",
			ns, ne)
	}
	si := bytes.Index(src, []byte(StartMarker))
	ei := bytes.Index(src, []byte(EndMarker))
	if ei < si {
		return 0, 0, fmt.Errorf("harness: scaffold-bound: BODY end marker before start marker")
	}
	start = si + len(StartMarker)
	if start < len(src) && src[start] == '\n' {
		start++
	}
	return start, ei, nil
}

// Validate re-renders the scaffold for (k, inv), locates the body window in
// both the expected and the filled bytes, and byte-compares everything
// OUTSIDE the window. Any drift names what moved; the body itself is free.
func Validate(k Kind, inv validation.Value, filled []byte) error {
	want, err := Scaffold(k, inv)
	if err != nil {
		return err
	}
	es, ee, err := BodyRegion(want)
	if err != nil {
		return fmt.Errorf("harness: internal scaffold has no body window: %v", err)
	}
	fs, fe, err := BodyRegion(filled)
	if err != nil {
		return err
	}
	if !bytes.Equal(want[:es], filled[:fs]) {
		return lineDiffErr("pre-body", want[:es], filled[:fs])
	}
	if !bytes.Equal(want[ee:], filled[fe:]) {
		return lineDiffErr("post-body", want[ee:], filled[fe:])
	}
	return nil
}

// describeScaffoldLine names a scaffold line that moved, so Validate errors
// point at the drift (e.g. "scaffold-bound: import line changed").
func describeScaffoldLine(line string) string {
	t := strings.TrimSpace(line)
	switch {
	case strings.HasPrefix(t, "import "):
		return "import line changed"
	case strings.HasPrefix(t, "pragma "):
		return "pragma line changed"
	case strings.HasPrefix(t, "// SPDX"):
		return "license header changed"
	case strings.HasPrefix(t, "// @custom:invariant"):
		return "natspec invariant line changed"
	case strings.HasPrefix(t, "// @custom:src"):
		return "natspec src line changed"
	case strings.HasPrefix(t, "contract "):
		return "contract header changed"
	case strings.HasPrefix(t, "function "):
		return "function header changed"
	case t == StartMarker || t == EndMarker:
		return "BODY marker line changed"
	case t == "":
		return "blank scaffold line changed"
	case strings.HasPrefix(t, "}"):
		return "closing brace changed"
	}
	if len(t) > 48 {
		t = t[:48] + "…"
	}
	return fmt.Sprintf("scaffold line changed (%q)", t)
}

// lineDiffErr diffs two scaffold regions line by line and reports the first
// drift, quoting the expected line and the 1-based line number.
func lineDiffErr(region string, want, got []byte) error {
	wl := strings.Split(string(want), "\n")
	gl := strings.Split(string(got), "\n")
	i := 0
	for i < len(wl) && i < len(gl) && wl[i] == gl[i] {
		i++
	}
	switch {
	case i < len(wl) && i < len(gl):
		return fmt.Errorf("harness: scaffold-bound: %s (%s line %d: want %q got %q)",
			describeScaffoldLine(wl[i]), region, i+1, wl[i], gl[i])
	case len(gl) > len(wl):
		return fmt.Errorf("harness: scaffold-bound: scaffold line added (%s line %d: %q)",
			region, i+1, gl[i])
	default:
		return fmt.Errorf("harness: scaffold-bound: scaffold line removed (%s line %d: %q)",
			region, i+1, wl[i])
	}
}
