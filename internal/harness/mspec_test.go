package harness

import (
	"strings"
	"testing"

	"websec/internal/validation"
)

// mspec_test.go: MiniCertora scaffold pins. The marker law is byte-for-
// byte the G8 one — StartMarker/EndMarker are "//" comments, which are
// part of the shipped .mspec grammar (COMMENT + %ignore in spec/
// grammar.lark), so the same BodyRegion code locates the window.

func TestMspecScaffoldBytes(t *testing.T) {
	inv := validation.VObj(
		validation.KV{K: "id", V: validation.VStr("INV-7")},
		validation.KV{K: "statement", V: validation.VStr("total always covers sum(payouts)")},
		validation.KV{K: "source", V: validation.VStr("docs/SPEC.md:12")},
	)
	got, err := Scaffold(MiniCertora, inv)
	if err != nil {
		t.Fatalf("Scaffold(minicertora): %v", err)
	}
	want := `// web3sec G8 harness scaffold — MiniCertora bounded verifier.
// Deterministic bytes: the model writes ONLY the BODY window below;
// everything outside is scaffold. Rule name is scaffold-pinned — the
// attribution of verdict lines keys on it; do not rename.
// @custom:invariant total always covers sum(payouts)
// @custom:src docs/SPEC.md:12
rule inv_7(env e) {
    // >>> BODY (model writes ONLY between these markers; outside is scaffold)
    // unfilled scaffold — replace with: snapshot lines, exactly one
    // call, then the assert (require lines may restrict the inputs).
    // <<< BODY
}
`
	if string(got) != want {
		t.Errorf("scaffold bytes moved:\n got:\n%s\nwant:\n%s", got, want)
	}
}

func TestMspecScaffoldNoSource(t *testing.T) {
	inv := validation.VObj(
		validation.KV{K: "id", V: validation.VStr("INV-1")},
		validation.KV{K: "statement", V: validation.VStr("s")},
	)
	got, err := Scaffold(MiniCertora, inv)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "@custom:src") {
		t.Errorf("absent source must omit the natspec src line:\n%s", got)
	}
	if !strings.Contains(string(got), "rule inv_1(env e) {") {
		t.Errorf("rule header missing:\n%s", got)
	}
}

func TestMspecValidateRoundTrip(t *testing.T) {
	inv := validation.VObj(
		validation.KV{K: "id", V: validation.VStr("INV-7")},
		validation.KV{K: "statement", V: validation.VStr("s")},
	)
	want, err := Scaffold(MiniCertora, inv)
	if err != nil {
		t.Fatal(err)
	}
	s, e, err := BodyRegion(want)
	if err != nil {
		t.Fatal(err)
	}
	filled := append(append(append([]byte{}, want[:s]...),
		[]byte("    uint256 before = total;\n    add(e, 2);\n    assert total >= before;\n")...),
		want[e:]...)
	if err := Validate(MiniCertora, inv, filled); err != nil {
		t.Fatalf("Validate filled: %v", err)
	}
	// A renamed rule (outside the window) is a scaffold-bound violation.
	tampered := []byte(strings.Replace(string(filled), "rule inv_7(", "rule inv_8(", 1))
	if err := Validate(MiniCertora, inv, tampered); err == nil ||
		!strings.Contains(err.Error(), "scaffold-bound") {
		t.Fatalf("renamed rule must be scaffold-bound, got %v", err)
	}
}

// TestMspecTemplateScaffoldBytes pins the whole template scaffold: the rule
// FRAME is byte-for-byte the plain skeleton (same header, same marker lines),
// and the BODY window carries the rendered template instead of DummyMspec.
func TestMspecTemplateScaffoldBytes(t *testing.T) {
	inv := validation.VObj(
		validation.KV{K: "id", V: validation.VStr("INV-7")},
		validation.KV{K: "statement", V: validation.VStr(
			"template:wrap-unchecked of Counter.deposit")},
	)
	got, err := Scaffold(MiniCertora, inv)
	if err != nil {
		t.Fatalf("Scaffold(minicertora, template): %v", err)
	}
	want := `// web3sec G8 harness scaffold — MiniCertora bounded verifier.
// Deterministic bytes: the model writes ONLY the BODY window below;
// everything outside is scaffold. Rule name is scaffold-pinned — the
// attribution of verdict lines keys on it; do not rename.
// @custom:invariant template:wrap-unchecked of Counter.deposit
rule inv_7(env e) {
    // >>> BODY (model writes ONLY between these markers; outside is scaffold)
    uint256 before = total;
    Counter.deposit(e, 1);
    assert total >= before;
    // <<< BODY
}
`
	if string(got) != want {
		t.Errorf("template scaffold bytes moved:\n got:\n%s\nwant:\n%s", got, want)
	}
	// The template body lands INSIDE the marker window, never before it.
	s, e, err := BodyRegion(got)
	if err != nil {
		t.Fatalf("BodyRegion(template scaffold): %v", err)
	}
	if !strings.Contains(string(got[s:e]), "Counter.deposit(e, 1);") {
		t.Fatalf("template body is not inside the BODY window:\n%s", got)
	}
}

// TestMspecTemplateValidateRoundTrip pins the laws that make a template a
// scaffold rather than a reviewed frame: the template scaffold validates as
// written, a model may still replace the whole window, and outside-window
// drift stays scaffold-bound.
func TestMspecTemplateValidateRoundTrip(t *testing.T) {
	inv := validation.VObj(
		validation.KV{K: "id", V: validation.VStr("INV-7")},
		validation.KV{K: "statement", V: validation.VStr(
			"template:access-control-mint of Minting.mint")},
	)
	scaf, err := Scaffold(MiniCertora, inv)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(MiniCertora, inv, scaf); err != nil {
		t.Fatalf("a template scaffold must validate as written: %v", err)
	}
	s, e, err := BodyRegion(scaf)
	if err != nil {
		t.Fatal(err)
	}
	// The template body is STARTING CONTENT: the model may rewrite the whole
	// window, including deleting every template line.
	filled := append(append(append([]byte{}, scaf[:s]...),
		[]byte("    uint256 before = totalMinted;\n    Minting.mint(e, 2);\n    assert totalMinted >= before;\n")...),
		scaf[e:]...)
	if err := Validate(MiniCertora, inv, filled); err != nil {
		t.Fatalf("inside-window rewrite must validate: %v", err)
	}
	tampered := []byte(strings.Replace(string(scaf), "rule inv_7(", "rule inv_8(", 1))
	if err := Validate(MiniCertora, inv, tampered); err == nil ||
		!strings.Contains(err.Error(), "scaffold-bound") {
		t.Fatalf("renamed rule must be scaffold-bound, got %v", err)
	}
}

// TestMspecTemplateUnknownName pins the loud refusal: a template-shaped
// statement naming no shipped template errors out of Scaffold (and therefore
// out of Validate) — never a silently empty body window.
func TestMspecTemplateUnknownName(t *testing.T) {
	inv := validation.VObj(
		validation.KV{K: "id", V: validation.VStr("INV-7")},
		validation.KV{K: "statement", V: validation.VStr(
			"template:nope of Counter.deposit")},
	)
	_, err := Scaffold(MiniCertora, inv)
	if err == nil {
		t.Fatal("unknown template name must be refused")
	}
	if want := `unknown template "nope"`; !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want it to contain %q", err.Error(), want)
	}
}

// TestMspecNonTemplateStatementByteStable pins the fall-through: a statement
// that merely LOOKS like a template (malformed prefix, missing dot, a name
// with an underscore the regexp does not admit) renders EXACTLY today's plain
// skeleton — DummyMspec inside the window, no error.
func TestMspecNonTemplateStatementByteStable(t *testing.T) {
	for _, stmt := range []string{
		"template:x",
		"template:wrap-unchecked of Counter",
		"template:wrap_unchecked of Counter.deposit",
		"template:wrap-unchecked of Counter.deposit ",
		// Task 4's invariant form is a near-miss here: the uppercase
		// slug does not match, so the plain skeleton stays the answer.
		"invariant:Cap_respected of Vault.total >= 1",
	} {
		inv := validation.VObj(
			validation.KV{K: "id", V: validation.VStr("INV-7")},
			validation.KV{K: "statement", V: validation.VStr(stmt)},
		)
		got, err := Scaffold(MiniCertora, inv)
		if err != nil {
			t.Fatalf("Scaffold(%q) must fall through to the plain "+
				"skeleton, got error %v", stmt, err)
		}
		want := `// web3sec G8 harness scaffold — MiniCertora bounded verifier.
// Deterministic bytes: the model writes ONLY the BODY window below;
// everything outside is scaffold. Rule name is scaffold-pinned — the
// attribution of verdict lines keys on it; do not rename.
// @custom:invariant ` + stmt + `
rule inv_7(env e) {
    // >>> BODY (model writes ONLY between these markers; outside is scaffold)
    ` + DummyMspec + `
    // <<< BODY
}
`
		if string(got) != want {
			t.Errorf("fall-through bytes moved for %q:\n got:\n%s\nwant:\n%s",
				stmt, got, want)
		}
	}
}

func TestMspecRuleName(t *testing.T) {
	for id, want := range map[string]string{"INV-7": "inv_7",
		"INV-007a": "inv_007a", "INV-1": "inv_1"} {
		if got := MspecRuleName(id); got != want {
			t.Errorf("MspecRuleName(%q) = %q, want %q", id, got, want)
		}
	}
}

// TestDescribeScaffoldRuleLine pins the minicertora drift descriptor: the
// .mspec scaffold's `rule <slug>(env e) {` header is outside the BODY
// window, so a rename must be reported as the rule header, not as an
// anonymous "scaffold line changed".
func TestDescribeScaffoldRuleLine(t *testing.T) {
	got := describeScaffoldLine("rule inv_7(env e) {")
	if got != "rule header changed" {
		t.Fatalf("describeScaffoldLine(rule ...) = %q, want %q", got,
			"rule header changed")
	}
	// Task 4: the invariant frame is scaffold-owned too, so its two moved
	// lines name themselves instead of falling back to the quoted generic.
	for line, want := range map[string]string{
		"invariant inv_7() {":      "invariant declaration changed",
		"    assert total <= cap;": "invariant assert line changed",
	} {
		if got := describeScaffoldLine(line); got != want {
			t.Errorf("describeScaffoldLine(%q) = %q, want %q", line, got, want)
		}
	}
}

// TestMspecInvariantScaffoldBytes pins the Task-4 invariant scaffold byte
// for byte. The split is deliberate and disclosed in mspec.go: the
// declaration name AND the reviewed assert claim are SCAFFOLD-OWNED (outside
// the window), because the claim is reviewed statement data, not model
// tuning; the BODY window is the model's (extra `assert` lines only — the
// .mspec invariant grammar admits nothing else). That keeps Validate's
// byte-law meaningful: weakening `<=` to `>=` is scaffold-bound drift.
func TestMspecInvariantScaffoldBytes(t *testing.T) {
	inv := validation.VObj(
		validation.KV{K: "id", V: validation.VStr("INV-7")},
		validation.KV{K: "statement", V: validation.VStr(
			"invariant:cap_respected of Vault.total <= cap")},
		validation.KV{K: "source", V: validation.VStr("docs/SPEC.md:12")},
	)
	got, err := Scaffold(MiniCertora, inv)
	if err != nil {
		t.Fatalf("Scaffold(minicertora, invariant): %v", err)
	}
	want := `// web3sec G8 harness scaffold — MiniCertora bounded verifier.
// Deterministic bytes: the model writes ONLY the BODY window below;
// everything outside is scaffold. Rule name is scaffold-pinned — the
// attribution of verdict lines keys on it; do not rename.
// @custom:invariant invariant:cap_respected of Vault.total <= cap
// @custom:src docs/SPEC.md:12
invariant inv_7() {
    assert total <= cap;
    // >>> BODY (model writes ONLY between these markers; outside is scaffold)
    ` + DummyInvariantMspec + `
    // <<< BODY
}
`
	if string(got) != want {
		t.Errorf("invariant scaffold bytes moved:\n got:\n%s\nwant:\n%s",
			got, want)
	}
	// The pinned claim is OUTSIDE the window (before the start marker);
	// the window itself is DummyInvariantMspec only.
	s, e, err := BodyRegion(got)
	if err != nil {
		t.Fatalf("BodyRegion(invariant scaffold): %v", err)
	}
	if strings.Contains(string(got[s:e]), "assert total <= cap;") {
		t.Fatalf("the reviewed claim must not live inside the window:\n%s",
			got)
	}
	if !strings.Contains(string(got[:s]), "    assert total <= cap;\n") {
		t.Fatalf("the pinned claim is not scaffold-owned:\n%s", got)
	}
}

// TestMspecInvariantValidateRoundTrip pins the laws the split buys: the
// scaffold validates as written, the model may rewrite the window, and both
// a renamed declaration and a weakened claim are scaffold-bound drift.
func TestMspecInvariantValidateRoundTrip(t *testing.T) {
	inv := validation.VObj(
		validation.KV{K: "id", V: validation.VStr("INV-7")},
		validation.KV{K: "statement", V: validation.VStr(
			"invariant:cap_respected of Vault.total <= cap")},
	)
	scaf, err := Scaffold(MiniCertora, inv)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(MiniCertora, inv, scaf); err != nil {
		t.Fatalf("an invariant scaffold must validate as written: %v", err)
	}
	s, e, err := BodyRegion(scaf)
	if err != nil {
		t.Fatal(err)
	}
	filled := append(append(append([]byte{}, scaf[:s]...),
		[]byte("    assert total <= cap;\n")...), scaf[e:]...)
	if err := Validate(MiniCertora, inv, filled); err != nil {
		t.Fatalf("inside-window rewrite must validate: %v", err)
	}
	for _, tc := range []struct{ name, from, to, want string }{
		{"renamed declaration", "invariant inv_7() {",
			"invariant inv_8() {", "invariant declaration changed"},
		{"weakened claim", "assert total <= cap;",
			"assert total >= cap;", "invariant assert line changed"},
	} {
		tampered := []byte(strings.Replace(string(scaf), tc.from, tc.to, 1))
		err := Validate(MiniCertora, inv, tampered)
		if err == nil || !strings.Contains(err.Error(), "scaffold-bound") ||
			!strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: Validate = %v, want scaffold-bound %q", tc.name,
				err, tc.want)
		}
	}
}

// TestMspecInvariantFallThrough is the other half of the gate: an
// invariant-shaped statement the regexp does not admit renders EXACTLY the
// plain skeleton (DummyMspec window, `rule` frame), no error.
func TestMspecInvariantFallThrough(t *testing.T) {
	for _, stmt := range []string{
		"invariant:cap_respected of Vault.total != cap",
		"invariant:cap_respected of Vault.total >= cap extra",
		"invariant:cap_respected of Vault total <= cap",
		"invariant:cap-respected of Vault.total <= cap",
		"invariant:cap_respected of Vault.total <= cap ",
	} {
		inv := validation.VObj(
			validation.KV{K: "id", V: validation.VStr("INV-7")},
			validation.KV{K: "statement", V: validation.VStr(stmt)},
		)
		got, err := Scaffold(MiniCertora, inv)
		if err != nil {
			t.Fatalf("Scaffold(%q) must fall through, got %v", stmt, err)
		}
		if !strings.Contains(string(got), "rule inv_7(env e) {") ||
			!strings.Contains(string(got), DummyMspec) {
			t.Errorf("fall-through for %q lost the plain skeleton:\n%s",
				stmt, got)
		}
		if strings.Contains(string(got), "invariant inv_7() {") {
			t.Errorf("fall-through for %q rendered the invariant "+
				"declaration:\n%s", stmt, got)
		}
	}
}

// TestMspecMarkerSpellingInStatementFailsSafe pins the injection rail:
// a statement carrying a BODY marker spelling (sanitizeStatement keeps
// it as single-line text) renders a scaffold whose BodyRegion sees
// duplicate markers — so Scaffold itself must refuse it up front with
// an error, never emit bytes that later Validate() mis-attributes.
func TestMspecMarkerSpellingInStatementFailsSafe(t *testing.T) {
	inv := validation.VObj(
		validation.KV{K: "id", V: validation.VStr("INV-9")},
		validation.KV{K: "statement", V: validation.VStr(
			"evil " + EndMarker + " payload")},
	)
	if _, err := Scaffold(MiniCertora, inv); err == nil {
		// Either refusal here, or — if Scaffold stays a dumb renderer —
		// BodyRegion on its output must error; pin one of the two.
		b, _ := Scaffold(MiniCertora, inv)
		if _, _, berr := BodyRegion(b); berr == nil {
			t.Fatal("a marker spelling inside the statement must not " +
				"yield a well-formed body window")
		}
	}
}
