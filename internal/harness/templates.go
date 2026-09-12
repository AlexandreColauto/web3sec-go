// templates.go: the L5 rule-template library — seven archetype bodies that
// seed a MiniCertora BODY window from a statement, so a sweep leg can be
// declared in the statement itself:
//
//	template:<name> of <Contract>.<Function>
//
// The bodies are adapted byte-for-byte from the vendored minicertora corpus
// (internal/harness/testdata/minicertora-corpus/<name>/*.mspec — <name> is the
// corpus target DIRECTORY and the .mspec file name inside it varies, so the
// value-transfer-accounting archetype lives in payable-check-missing/): the
// `rule <id>(env e, …) {` frame is STRIPPED (the scaffold owns it, and the
// scaffold's signature is fixed at `(env e)`) and the require/assert sequence
// between the rule braces becomes the body text.
//
// Adaptations from the corpus text, all forced by the statement syntax's fixed
// knob set (Contract + Function — see mspecTemplateRe):
//
//   - the corpus rule parameters (x, caller, amount, v, before) have no home:
//     the scaffold signature cannot take them and the statement carries no
//     value knobs. The binding law, uniform across all seven bodies: `caller`
//     becomes e.msg.sender; a scalar input is pinned to the literal 1; a
//     pre-state parameter is bound to the state read the corpus names it
//     against (`uint256 before = balanceOf(e.msg.sender);`); and a corpus
//     `require` that those bindings render vacuous (`e.msg.sender == caller`,
//     `amount > 0` under the pin) is dropped. The body is starting content, not
//     a proof: the model widens the input where the archetype needs a symbolic
//     one.
//   - the corpus call is unqualified; the body qualifies it with the
//     statement's Contract so the CLI's single-contract guard names a mismatch
//     loudly instead of silently resolving to whatever contract is loaded.
//   - ONE archetype is a SEQUENCE (privilege-escalation: nominate, then
//     escalate — the corpus records that both calls are load-bearing). Only the
//     transition the corpus `assert` keys on rides {{.Function}}; the
//     permission-granting precondition call is archetype text exactly like a
//     state identifier, qualified with {{.Contract}} so it keeps the same
//     single-contract guard.
//   - ONE archetype carries an explicit value channel
//     (value-transfer-accounting, from payable-check-missing/ledger.mspec):
//     the corpus' `with { msg.value = v; }` override rides verbatim, pinned to
//     the literal 1 — the tool's value channel, never `e.msg.value`.
//
// Two names from the architecture list (docs/MINICERTORA_ARCHITECTURE.md §L5)
// are deliberately NOT here: `donation-accounting` has no corpus ground-truth
// spec to adapt from, and `cap-respected` rides the `invariant:` statement form
// (an induction scaffold, mspecInvariantRe) rather than a rule body.
//
// A body is STARTING CONTENT, not reviewed frame: it lands INSIDE the BODY
// marker window, the model may rewrite or delete it wholesale, and Validate
// judges only the bytes outside the window (same law as DummyMspec).
//
// Determinism: the renderer is a pure function of (name, contract, function)
// — an explicit name allowlist (never a directory listing) and no map
// iteration anywhere.

package harness

import (
	"embed"
	"fmt"
	"io/fs"
	"regexp"
	"strings"
	"text/template"
)

//go:embed templates/*.tmpl
var templateFS embed.FS

// templateNames is the shipped template set, in a fixed order. Membership is
// checked against this slice — an allowlist, not a directory listing, so the
// rendered bytes cannot depend on filesystem enumeration order. The original
// four keep their positions (no shipped body moves); wave L-defer T2 appended
// the three corpus-faithful sweeps.
var templateNames = []string{
	"wrap-unchecked",
	"rounding-drain",
	"access-control-mint",
	"tx-origin-auth",
	"privilege-escalation",
	"unchecked-callback",
	"value-transfer-accounting",
}

// mspecTemplateRe is the statement form that seeds a template body. It is
// deliberately strict: a statement that does not match falls through to
// today's plain skeleton (DummyMspec), so no existing scaffold bytes move.
// The prefix is disjoint from Task 4's `invariant:` prefix.
var mspecTemplateRe = regexp.MustCompile(
	`^template:([a-z0-9-]+) of ([A-Za-z0-9_]+)\.([A-Za-z0-9_]+)$`)

// templateKnobs is the whole knob set the seven bodies use (2 of the ≤6
// budget). Every other identifier a body names — `total`, `users`,
// `totalMinted`, `owner`, `balanceOf`, `role`/`nominated`, the
// `claimed`/`accrued` members, and the sequence archetype's `nominate`
// precondition call — is archetype-fixed text: deriving it would need the facts
// lookup the statement syntax forbids.
type templateKnobs struct {
	Contract string
	Function string
}

// renderTemplateBody renders the body text for one template and knob pair.
// The returned text is the exact bytes between the BODY markers: already
// indented for the rule body, with no trailing newline (the scaffold renderer
// owns the line break). An unknown name is refused — never an empty body.
func renderTemplateBody(name, contract, function string) (string, error) {
	known := false
	for _, n := range templateNames {
		if n == name {
			known = true
			break
		}
	}
	if !known {
		return "", fmt.Errorf("harness: unknown template %q", name)
	}
	raw, err := fs.ReadFile(templateFS, "templates/"+name+".tmpl")
	if err != nil {
		// Unreachable while templateNames and the embedded files agree; keep
		// the same refusal rather than leaking a filesystem error shape.
		return "", fmt.Errorf("harness: unknown template %q", name)
	}
	tpl, err := template.New(name).Parse(string(raw))
	if err != nil {
		return "", fmt.Errorf("harness: template %q: %w", name, err)
	}
	var b strings.Builder
	if err := tpl.Execute(&b, templateKnobs{Contract: contract, Function: function}); err != nil {
		return "", fmt.Errorf("harness: template %q: %w", name, err)
	}
	return strings.TrimSuffix(b.String(), "\n"), nil
}
