package harness

// templates_test.go: the L-system rule-template pins. Each template body is
// adapted byte-for-byte from the vendored minicertora corpus spec of the same
// name (internal/harness/testdata/minicertora-corpus/<name>/*.mspec): the
// `rule <id>(env e, …) {` frame is STRIPPED and the require/assert sequence
// between the rule braces becomes the BODY-window text. The pins below are
// written by hand from the shipped .tmpl files, so a later edit that moves a
// body trips the byte test rather than silently changing every scaffold.

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// TestRenderTemplateBodyBytes pins the four shipped bodies at one concrete
// knob pair. The two state identifiers each archetype uses (`total`, `users`,
// `totalMinted`/`owner`) are archetype-fixed, not knobs — the statement
// syntax carries only Contract.Function — so only those two vary here.
func TestRenderTemplateBodyBytes(t *testing.T) {
	cases := []struct {
		name     string
		contract string
		function string
		want     string
	}{
		{
			name: "wrap-unchecked", contract: "Counter", function: "deposit",
			want: "    uint256 before = total;\n" +
				"    Counter.deposit(e, 1);\n" +
				"    assert total >= before;",
		},
		{
			name: "rounding-drain", contract: "YieldDrain", function: "harvest",
			want: "    uint256 already = users(e.msg.sender).claimed;\n" +
				"    YieldDrain.harvest(e, e.msg.sender);\n" +
				"    assert users(e.msg.sender).claimed <= already + users(e.msg.sender).accrued;",
		},
		{
			name: "access-control-mint", contract: "Minting", function: "mint",
			want: "    require e.msg.sender != owner;\n" +
				"    uint256 before = totalMinted;\n" +
				"    Minting.mint(e, 1);\n" +
				"    assert totalMinted == before;",
		},
		{
			// Byte-identical to access-control-mint on purpose: the vendored
			// specs are byte-identical upstream (same sha256), so the bodies
			// coincide. The archetypes differ in the TARGET contract, not in
			// the rule text.
			name: "tx-origin-auth", contract: "Auth", function: "mint",
			want: "    require e.msg.sender != owner;\n" +
				"    uint256 before = totalMinted;\n" +
				"    Auth.mint(e, 1);\n" +
				"    assert totalMinted == before;",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := renderTemplateBody(tc.name, tc.contract, tc.function)
			if err != nil {
				t.Fatalf("renderTemplateBody(%q): %v", tc.name, err)
			}
			if got != tc.want {
				t.Errorf("body bytes moved:\n got:\n%s\nwant:\n%s", got, tc.want)
			}
			if strings.HasSuffix(got, "\n") {
				t.Errorf("body must not carry a trailing newline (the "+
					"renderer owns the line break): %q", got)
			}
		})
	}
}

// TestRenderTemplateBodyDeterministic pins the determinism law: identical
// knobs, identical bytes — twice in a row and across the two call paths.
func TestRenderTemplateBodyDeterministic(t *testing.T) {
	a, err := renderTemplateBody("wrap-unchecked", "Counter", "deposit")
	if err != nil {
		t.Fatal(err)
	}
	b, err := renderTemplateBody("wrap-unchecked", "Counter", "deposit")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("renderTemplateBody is not deterministic:\n%q\n%q", a, b)
	}
	c, err := renderTemplateBody("wrap-unchecked", "Vault", "settle")
	if err != nil {
		t.Fatal(err)
	}
	if a == c {
		t.Fatal("knobs must reach the body (different contract/function " +
			"produced identical bytes)")
	}
	if !strings.Contains(c, "Vault.settle(e, 1);") {
		t.Fatalf("contract/function knobs not rendered: %q", c)
	}
}

// TestRenderTemplateBodyUnknownName pins the loud-refusal rail: a name that
// matches the statement regexp but names no shipped template is an error,
// never a silent empty body.
func TestRenderTemplateBodyUnknownName(t *testing.T) {
	_, err := renderTemplateBody("nope", "Counter", "deposit")
	if err == nil {
		t.Fatal("unknown template name must be refused")
	}
	if want := `unknown template "nope"`; !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want it to contain %q", err.Error(), want)
	}
	// A near-miss of a shipped name is still unknown (no fuzzy matching).
	if _, err := renderTemplateBody("wrap-uncheck", "Counter", "deposit"); err == nil {
		t.Fatal("a near-miss name must not silently resolve")
	}
}

// TestTemplateKnobSetIsSmall pins the knob budget: the shipped bodies use at
// most six `{{.Knob}}` placeholders, and the set is exactly the two the
// statement carries (Contract, Function). Deriving more would need a facts
// lookup the statement syntax deliberately forbids.
func TestTemplateKnobSetIsSmall(t *testing.T) {
	knobRe := regexp.MustCompile(`\{\{\.[A-Za-z0-9_]+\}\}`)
	seen := map[string]bool{}
	for _, name := range templateNames {
		b, err := fs.ReadFile(templateFS, "templates/"+name+".tmpl")
		if err != nil {
			t.Fatalf("read %s.tmpl: %v", name, err)
		}
		for _, m := range knobRe.FindAllString(string(b), -1) {
			seen[m] = true
		}
	}
	if len(seen) > 6 {
		t.Errorf("knob set has %d placeholders, budget is 6: %v", len(seen), seen)
	}
	for _, want := range []string{"{{.Contract}}", "{{.Function}}"} {
		if !seen[want] {
			t.Errorf("knob %s is unused by every template", want)
		}
	}
	for k := range seen {
		if k != "{{.Contract}}" && k != "{{.Function}}" {
			t.Errorf("unexpected knob %s (the statement carries only "+
				"Contract.Function)", k)
		}
	}
}

// TestTemplateBodiesCarryNoRuleFrame pins the adaptation law: the .tmpl files
// hold the require/assert sequence ONLY — no `rule … {` frame, no closing
// brace (the scaffold owns those bytes), and no BODY markers.
func TestTemplateBodiesCarryNoRuleFrame(t *testing.T) {
	for _, name := range templateNames {
		b, err := fs.ReadFile(templateFS, "templates/"+name+".tmpl")
		if err != nil {
			t.Fatalf("read %s.tmpl: %v", name, err)
		}
		body := string(b)
		for _, bad := range []string{"rule ", StartMarker, EndMarker, "}\n"} {
			if strings.Contains(body, bad) {
				t.Errorf("%s.tmpl carries %q — the scaffold owns the rule "+
					"frame and the marker lines", name, bad)
			}
		}
	}
}
