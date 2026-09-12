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
	"regexp"
	"strings"

	"websec/internal/validation"
)

// MspecRuleName is the scaffold-pinned rule name for an invariant id:
// the snake slug the scaffold renders and the verdict attribution
// matches — one exported spelling so the two can never drift.
func MspecRuleName(id string) string { return snake(id) }

// mspecInvariantRe is the statement form that seeds an induction scaffold:
//
//	invariant:<slug> of <Contract>.<State> <op> <expr>
//
// Groups: 1 slug (the reviewed declaration's own name, carried verbatim in
// the natspec line), 2 contract, 3 state variable, 4 operator, 5 expression.
// The rendered claim is `<State> <op> <Expr>` — exactly the state-only
// predicate shape cap.mspec uses (`assert total <= cap;`); the contract knob
// names the target but is not re-qualified inside the predicate because the
// tool loads one contract and cap.mspec qualifies nothing (the grammar's
// `_Lower.invariant` reads bare state only). Deliberately disjoint from
// mspecTemplateRe's `template:` prefix, and every capture is
// identifier/operator-safe, so a matching statement can never smuggle a
// marker spelling or punctuation into the scaffold-owned region.
// A near-miss statement (uppercase slug, `!=`, a multi-token expression,
// a trailing space) does not match and takes the plain skeleton path.
var mspecInvariantRe = regexp.MustCompile(
	`^invariant:([a-z][a-z0-9_]*) of ([A-Za-z0-9_]+)\.([A-Za-z0-9_]+) (>=|<=|==|>|<) ([A-Za-z0-9_]+)$`)

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

// DummyInvariantMspec is the placeholder inside a fresh invariant scaffold's
// body window. The reviewed claim is already pinned ABOVE the window (see the
// split note on scaffoldMspec), and the .mspec invariant grammar admits only
// `assert` statements inside the braces (spec/grammar.lark:
// `invariant: "invariant" IDENT "(" [env_param] ")" "{" assert_stmt+ "}"`, and
// _Lower refuses calls/require there), so the honest starting content is a
// comment saying exactly that — never the rule dummy's call recipe, which
// would produce a grammar-refused file if a model followed it.
//
// The plan's hypothesized "foralls"/"init" optional clauses do NOT exist in
// the shipped v0.1 grammar (verified against the vendored corpus and the
// upstream grammar at Task 4 time): init is an internal synthetic check, not
// a written clause. The window therefore holds optional EXTRA assert lines,
// which strengthen — never weaken — the reviewed claim.
const DummyInvariantMspec = `// unfilled scaffold — the reviewed claim is pinned above; extra
    // assert lines may support the induction (calls/require are refused).`

// scaffoldMspec renders the byte-pinned .mspec scaffold for one invariant.
// sn is the already-validated rule slug; stmt is the sanitized
// single-line statement. Marker spellings inside the statement are NOT
// screened here: this renderer stays a pure template, and the duplicate
// marker such a statement produces makes BodyRegion — and therefore
// Validate — refuse the result rather than mis-attribute it.
//
// A statement matching mspecTemplateRe seeds the BODY window with the
// rendered template instead of DummyMspec; every byte outside the window is
// identical either way, and an unknown template name is an error (never a
// silently empty body). A statement that does not match the regexp — including
// a malformed `template:` prefix — takes the plain skeleton path unchanged.
//
// A statement matching mspecInvariantRe renders the induction scaffold
// instead. THE SPLIT (Task 4 decision, disclosed): the vendored
// invariant-cap/cap.mspec shape is
//
//	invariant cap_respected() {
//	    assert total <= cap;
//	}
//
// — a declaration whose body is the reviewed claim. The scaffold owns the
// declaration AND the claim, so both are rendered OUTSIDE the BODY window:
// the claim is reviewed statement data, not model tuning. Validate re-renders
// and byte-compares the frame, so a weakened `<=` to `>=` is a scaffold-bound
// violation WHEN VALIDATE RUNS; today's `verify --harness-result` binds by
// exec-record input hash rather than re-rendering, so the tamper-to-tampered-
// hash path is not caught at that gate (pre-existing for halmos/forge frames
// too; wiring Validate into the run path is a deferred decision). The
// declaration name is MspecRuleName (inv_<n>) rather than the
// statement's slug, because the mapper attributes verdict lines by that name
// (harness.MspecRuleName) — the slug rides verbatim in the
// `// @custom:invariant` natspec line. The window itself holds
// DummyInvariantMspec as starting content: the grammar admits further
// `assert` lines there (the model's optional strengthening), and nothing else.
// cap.mspec's shape permits both placements (markers are `//` comments, which
// the shipped grammar ignores), so the byte-law-preserving one was chosen.
func scaffoldMspec(sn, stmt string, inv validation.Value) ([]byte, error) {
	body := "    " + DummyMspec
	decl := "rule " + sn + "(env e) {\n"
	pinned := ""
	if m := mspecTemplateRe.FindStringSubmatch(stmt); m != nil {
		rendered, err := renderTemplateBody(m[1], m[2], m[3])
		if err != nil {
			return nil, err
		}
		body = rendered
	} else if m := mspecInvariantRe.FindStringSubmatch(stmt); m != nil {
		// m[2] is the contract knob, carried in the statement line only
		// (an .mspec invariant is state-only: the tool loads one
		// contract, and cap.mspec qualifies no state variable).
		decl = "invariant " + sn + "() {\n"
		pinned = "    assert " + m[3] + " " + m[4] + " " + m[5] + ";\n"
		body = "    " + DummyInvariantMspec
	}
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
	b.WriteString(decl)
	b.WriteString(pinned)
	b.WriteString("    " + StartMarker + "\n")
	b.WriteString(body + "\n")
	b.WriteString("    " + EndMarker + "\n")
	b.WriteString("}\n")
	return []byte(b.String()), nil
}
