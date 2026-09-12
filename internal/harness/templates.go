// templates.go: the L5 rule-template library — four archetype bodies that
// seed a MiniCertora BODY window from a statement, so a sweep leg can be
// declared in the statement itself:
//
//	template:<name> of <Contract>.<Function>
//
// The bodies are adapted byte-for-byte from the vendored minicertora corpus
// (internal/harness/testdata/minicertora-corpus/<name>/*.mspec): the
// `rule <id>(env e, …) {` frame is STRIPPED (the scaffold owns it, and the
// scaffold's signature is fixed at `(env e)`) and the require/assert sequence
// between the rule braces becomes the body text.
//
// Two adaptations from the corpus text, both forced by the statement syntax's
// fixed knob set (Contract + Function — see mspecTemplateRe):
//
//   - the corpus rule parameters (x, caller, amount) have no home: the
//     scaffold signature cannot take them and the statement carries no value
//     knobs, so scalar inputs are pinned to the literal 1 and `caller` is the
//     env sender (e.msg.sender). The body is starting content, not a proof:
//     the model widens the input where the archetype needs a symbolic one.
//   - the corpus call is unqualified; the body qualifies it with the
//     statement's Contract so the CLI's single-contract guard names a mismatch
//     loudly instead of silently resolving to whatever contract is loaded.
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
// rendered bytes cannot depend on filesystem enumeration order.
var templateNames = []string{
	"wrap-unchecked",
	"rounding-drain",
	"access-control-mint",
	"tx-origin-auth",
}

// mspecTemplateRe is the statement form that seeds a template body. It is
// deliberately strict: a statement that does not match falls through to
// today's plain skeleton (DummyMspec), so no existing scaffold bytes move.
// The prefix is disjoint from Task 4's `invariant:` prefix.
var mspecTemplateRe = regexp.MustCompile(
	`^template:([a-z0-9-]+) of ([A-Za-z0-9_]+)\.([A-Za-z0-9_]+)$`)

// templateKnobs is the whole knob set the four bodies use (2 of the ≤6
// budget). Every other identifier a body names — `total`, `users`,
// `totalMinted`, `owner`, the `claimed`/`accrued` members — is archetype-fixed
// text: deriving it would need the facts lookup the statement syntax forbids.
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
