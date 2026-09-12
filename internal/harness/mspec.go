// mspec.go: the MiniCertora renderer — the G8 third harness kind. Where
// halmos/forge-fuzz emit a Solidity contract, this kind emits .mspec text
// for the bounded SMT verifier (docs/MINICERTORA_ARCHITECTURE.md L0-L2).
//
// The BODY law carries over verbatim: the scaffold pins a rule header, the
// model writes only between StartMarker and EndMarker, and Validate
// re-renders and byte-compares everything outside that window. The marker
// spellings are plain "//" comments, which the shipped .mspec grammar
// ignores (spec/grammar.lark COMMENT + %ignore), so BodyRegion needs no
// lexer and this file owns no window logic of its own.
//
// Determinism law (identical to harness.go): the renderer is a pure
// function of the invariant data, every line is emitted in a fixed order
// by one straight-line strings.Builder, and no map is ever iterated.
package harness

import (
	"strings"

	"websec/internal/validation"
)

// MspecRuleName is the scaffold-pinned rule name for an invariant id:
// the snake slug the scaffold renders and the verdict attribution
// matches — one exported spelling so the two can never drift.
func MspecRuleName(id string) string { return snake(id) }

// DummyMspec is the placeholder inside a fresh .mspec body window. Like
// DummyHalmos/DummyFuzz it is a two-line constant whose second line
// carries its own indentation, because the scaffold bytes are pinned and
// the layout must not depend on the caller. Unlike the Solidity dummies
// it is NOT expected to compile as a proof: a bare comment window is the
// honest signal that no rule body was written, and the machinery that
// turns an unfilled window into a failed verdict lives in the runner
// (Task 2+), not in the grammar.
const DummyMspec = `// unfilled scaffold — replace with: snapshot lines, exactly one
    // call, then the assert (require lines may restrict the inputs).`

// scaffoldMspec renders the byte-pinned .mspec scaffold for one invariant.
// sn is the already-validated rule slug; stmt is the sanitized
// single-line statement. Marker spellings inside the statement are NOT
// screened here: this renderer stays a pure template, and the duplicate
// marker such a statement produces makes BodyRegion — and therefore
// Validate — refuse the result rather than mis-attribute it.
func scaffoldMspec(sn, stmt string, inv validation.Value) []byte {
	var b strings.Builder
	b.WriteString("// web3sec G8 harness scaffold — MiniCertora bounded verifier.\n")
	b.WriteString("// Deterministic bytes: the model writes ONLY the BODY window below;\n")
	b.WriteString("// everything outside is scaffold. Rule name is scaffold-pinned — the\n")
	b.WriteString("// attribution of verdict lines keys on it; do not rename.\n")
	b.WriteString("// @custom:invariant " + stmt + "\n")
	// Source may be null (model-source invariants carry no pin): omit the
	// natspec src line cleanly rather than emitting an empty claim. The
	// same rule the Solidity path follows keeps one invariant record
	// rendering the same claims under every kind.
	if srcV, ok := invField(inv, "source"); ok && srcV.Kind == validation.Str && srcV.S != "" {
		b.WriteString("// @custom:src " + sanitizeStatement(srcV.S) + "\n")
	}
	b.WriteString("rule " + sn + "(env e) {\n")
	b.WriteString("    " + StartMarker + "\n")
	b.WriteString("    " + DummyMspec + "\n")
	b.WriteString("    " + EndMarker + "\n")
	b.WriteString("}\n")
	return []byte(b.String())
}
