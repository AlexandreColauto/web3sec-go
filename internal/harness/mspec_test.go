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
