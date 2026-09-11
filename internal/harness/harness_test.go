package harness

import (
	"bytes"
	"strings"
	"testing"

	"websec/internal/validation"
)

// mkInv builds an invariant record with the REAL field names the
// invariants package uses (id / statement / source; source VNull models a
// null/model-source record).
func mkInv(id, stmt string, source validation.Value) validation.Value {
	return validation.VObj(
		validation.KV{K: "id", V: validation.VStr(id)},
		validation.KV{K: "statement", V: validation.VStr(stmt)},
		validation.KV{K: "source", V: source},
	)
}

func mustScaffold(t *testing.T, k Kind, inv validation.Value) []byte {
	t.Helper()
	out, err := Scaffold(k, inv)
	if err != nil {
		t.Fatalf("Scaffold(%s): %v", k, err)
	}
	return out
}

// fillBody swaps the whole body window for newBody (which must carry its
// own trailing newline).
func fillBody(t *testing.T, scaf []byte, newBody string) []byte {
	t.Helper()
	s, e, err := BodyRegion(scaf)
	if err != nil {
		t.Fatalf("BodyRegion: %v", err)
	}
	out := append(append([]byte{}, scaf[:s]...), newBody...)
	return append(out, scaf[e:]...)
}

func TestScaffoldTwiceEqual(t *testing.T) {
	for _, k := range []Kind{Halmos, ForgeFuzz} {
		inv := mkInv("INV-007a", "balances cover supply", validation.VStr("doc/src/Token.sol:42"))
		a := mustScaffold(t, k, inv)
		b := mustScaffold(t, k, inv)
		if !bytes.Equal(a, b) {
			t.Fatalf("%s: render twice differs:\n%s\n---\n%s", k, a, b)
		}
	}
}

func TestScaffoldStatementIsolation(t *testing.T) {
	for _, k := range []Kind{Halmos, ForgeFuzz} {
		a := mustScaffold(t, k, mkInv("INV-1", "first statement", validation.VStr("a.sol:1")))
		b := mustScaffold(t, k, mkInv("INV-1", "second statement", validation.VStr("a.sol:1")))
		al, bl := strings.Split(string(a), "\n"), strings.Split(string(b), "\n")
		if len(al) != len(bl) {
			t.Fatalf("%s: line counts differ %d vs %d", k, len(al), len(bl))
		}
		diffs := 0
		for i := range al {
			if al[i] != bl[i] {
				diffs++
				if !strings.HasPrefix(al[i], "// @custom:invariant ") ||
					!strings.HasPrefix(bl[i], "// @custom:invariant ") {
					t.Fatalf("%s: non-natspec drift at line %d:\n%q\n%q", k, i+1, al[i], bl[i])
				}
			}
		}
		if diffs != 1 {
			t.Fatalf("%s: want exactly the natspec line to differ, got %d diffs", k, diffs)
		}
	}
}

func TestScaffoldSourceNullOmitsSrc(t *testing.T) {
	for _, k := range []Kind{Halmos, ForgeFuzz} {
		out := mustScaffold(t, k, mkInv("INV-2", "null source", validation.VNull()))
		if strings.Contains(string(out), "@custom:src") {
			t.Fatalf("%s: null source must omit the src natspec line:\n%s", k, out)
		}
		if err := Validate(k, mkInv("INV-2", "null source", validation.VNull()), out); err != nil {
			t.Fatalf("%s: untouched null-source scaffold rejected: %v", k, err)
		}
	}
}

func TestScaffoldShape(t *testing.T) {
	h := mustScaffold(t, Halmos, mkInv("INV-007a", "balances cover supply", validation.VStr("a.sol:1")))
	hs := string(h)
	for _, want := range []string{
		"// SPDX-License-Identifier: UNLICENSED\n",
		"pragma solidity >=0.8.0;\n",
		"import \"forge-std/Test.sol\";\n",
		"import \"halmos-cheatcodes/SymTest.sol\";\n",
		"// @custom:invariant balances cover supply\n",
		"// @custom:src a.sol:1\n",
		"contract Inv007aInvariantHalmos is SymTest, Test {\n",
		"    " + WitnessVar + "\n",
		"function check_inv_007a() external {\n",
		StartMarker + "\n",
		DummyHalmos + "\n",
		EndMarker + "\n",
	} {
		if !strings.Contains(hs, want) {
			t.Errorf("halmos scaffold missing %q:\n%s", want, hs)
		}
	}
	f := mustScaffold(t, ForgeFuzz, mkInv("INV-007a", "balances cover supply", validation.VStr("a.sol:1")))
	fs := string(f)
	if strings.Contains(fs, "SymTest") {
		t.Errorf("forge-fuzz scaffold must not mention SymTest:\n%s", fs)
	}
	for _, want := range []string{
		"contract Inv007aInvariantFuzz is Test {\n",
		"    " + WitnessVar + "\n",
		"function fuzz_inv_007a(uint256 seed) external {\n",
		DummyFuzz + "\n",
	} {
		if !strings.Contains(fs, want) {
			t.Errorf("forge-fuzz scaffold missing %q:\n%s", want, fs)
		}
	}
}

func TestValidateUntouched(t *testing.T) {
	for _, k := range []Kind{Halmos, ForgeFuzz} {
		inv := mkInv("INV-3", "holds", validation.VStr("s.sol:9"))
		if err := Validate(k, inv, mustScaffold(t, k, inv)); err != nil {
			t.Fatalf("%s: untouched scaffold rejected: %v", k, err)
		}
	}
}

func TestValidateBodyFilled(t *testing.T) {
	for _, k := range []Kind{Halmos, ForgeFuzz} {
		inv := mkInv("INV-4", "holds", validation.VStr("s.sol:9"))
		filled := fillBody(t, mustScaffold(t, k, inv),
			"        require(balanceAfter >= balanceBefore, \"holds\");\n")
		if err := Validate(k, inv, filled); err != nil {
			t.Fatalf("%s: body-filled scaffold rejected: %v", k, err)
		}
	}
}

func TestValidateHeaderEditRejected(t *testing.T) {
	inv := mkInv("INV-5", "holds", validation.VStr("s.sol:9"))
	scaf := mustScaffold(t, Halmos, inv)
	bad := bytes.Replace(scaf,
		[]byte("import \"forge-std/Test.sol\";"),
		[]byte("import \"forge-std/Test2.sol\";"), 1)
	err := Validate(Halmos, inv, bad)
	if err == nil {
		t.Fatal("header import edit accepted, want rejection")
	}
	if !strings.Contains(err.Error(), "scaffold-bound") || !strings.Contains(err.Error(), "import") {
		t.Fatalf("error must name the moved import, got: %v", err)
	}
}

func TestValidateAddedImportRejected(t *testing.T) {
	inv := mkInv("INV-6", "holds", validation.VStr("s.sol:9"))
	scaf := mustScaffold(t, Halmos, inv)
	bad := bytes.Replace(scaf,
		[]byte("import \"halmos-cheatcodes/SymTest.sol\";\n"),
		[]byte("import \"halmos-cheatcodes/SymTest.sol\";\nimport \"evil/Backdoor.sol\";\n"), 1)
	if err := Validate(Halmos, inv, bad); err == nil {
		t.Fatal("added import accepted, want rejection")
	} else if !strings.Contains(err.Error(), "scaffold-bound") {
		t.Fatalf("error must say scaffold-bound, got: %v", err)
	}
}

func TestValidateDuplicateMarkerRejected(t *testing.T) {
	inv := mkInv("INV-7", "holds", validation.VStr("s.sol:9"))
	scaf := mustScaffold(t, Halmos, inv)
	dup := fillBody(t, scaf, "        "+DummyHalmos+"\n        "+StartMarker+"\n")
	err := Validate(Halmos, inv, dup)
	if err == nil {
		t.Fatal("duplicate start marker accepted, want rejection")
	}
	if !strings.Contains(err.Error(), "scaffold-bound: duplicate BODY markers") {
		t.Fatalf("error must name duplicate BODY markers, got: %v", err)
	}
}

func TestValidateEndBeforeStartRejected(t *testing.T) {
	inv := mkInv("INV-8", "holds", validation.VStr("s.sol:9"))
	scaf := mustScaffold(t, Halmos, inv)
	const nonce = "___MARK___"
	tmp := bytes.Replace(scaf, []byte(StartMarker), []byte(nonce), 1)
	tmp = bytes.Replace(tmp, []byte(EndMarker), []byte(StartMarker), 1)
	swapped := bytes.Replace(tmp, []byte(nonce), []byte(EndMarker), 1)
	err := Validate(Halmos, inv, swapped)
	if err == nil {
		t.Fatal("swapped markers accepted, want rejection")
	}
	if !strings.Contains(err.Error(), "before start marker") {
		t.Fatalf("error must report end-before-start, got: %v", err)
	}
}

// TestValidateMarkerInStringPinsNaiveRule documents the lexer-naive limit:
// a marker SPELLING inside a string literal still counts as a marker, so a
// body that quotes one is rejected as a duplicate. Body authors must keep
// the exact spellings out of body code.
func TestValidateMarkerInStringPinsNaiveRule(t *testing.T) {
	inv := mkInv("INV-9", "holds", validation.VStr("s.sol:9"))
	scaf := mustScaffold(t, Halmos, inv)
	quoted := fillBody(t, scaf,
		"        string memory m = \""+StartMarker+"\";\n")
	err := Validate(Halmos, inv, quoted)
	if err == nil {
		t.Fatal("marker spelling inside a string literal accepted; " +
			"the naive window rule requires rejection")
	}
	if !strings.Contains(err.Error(), "scaffold-bound: duplicate BODY markers") {
		t.Fatalf("must pin the naive duplicate rule, got: %v", err)
	}
}

func TestSnakeCamlEdges(t *testing.T) {
	snakeCases := map[string]string{
		"INV-007a":    "inv_007a",
		"A B":         "a_b",
		"a--b":        "a_b",
		"AbC-123_XyZ": "abc_123_xyz",
		"INV/007:a":   "inv_007_a",
		"-x-":         "x",
		"--":          "",
		"":            "",
	}
	for in, want := range snakeCases {
		if got := snake(in); got != want {
			t.Errorf("snake(%q) = %q, want %q", in, got, want)
		}
	}
	camlCases := map[string]string{
		"INV-007a": "Inv007a",
		"007":      "Inv007",
		"a-b c":    "ABC",
		"x":        "X",
		"--":       "",
	}
	for in, want := range camlCases {
		if got := caml(in); got != want {
			t.Errorf("caml(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestScaffoldRejects(t *testing.T) {
	stmt := func(id string) validation.Value {
		return mkInv(id, "s", validation.VNull())
	}
	if _, err := Scaffold(Kind("halmos2"), stmt("INV-1")); err == nil {
		t.Error("unknown kind accepted")
	}
	if _, err := Scaffold(Halmos, validation.VObj()); err == nil {
		t.Error("missing id accepted")
	}
	if _, err := Scaffold(Halmos, validation.VObj(
		validation.KV{K: "id", V: validation.VStr("INV-1")},
	)); err == nil {
		t.Error("missing statement accepted")
	}
	if _, err := Scaffold(Halmos, stmt("--")); err == nil {
		t.Error("unnamable id accepted")
	}
}
