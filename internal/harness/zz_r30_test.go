package harness

// zz_r30_test.go (hostile round 30): three findings against the r29
// shell-then-click lexer, each pinned at the level it broke.
//
//	P1-1  the unreadable floor never reached the third kind:
//	      MapMinicertoraInvoc tested `invBound == BoundDegenerate`, so a
//	      record whose own COMMAND could not be lexed (an unmatched quote,
//	      a command list, an expansion in the bound value) still bound
//	      proved-bounded off an attributed PROVEN line and audited green.
//	      Both the bind and section 11's re-derivation reach that mapper
//	      through harness.DecideBound, so this test drives THAT entry
//	      point, not the mapper, and the cli's stdout bytes never move.
//	P1-2  Nd digits were mis-decoded for 36 code points: the walk-down
//	      decoder crossed out of an adjacent Nd block into the previous
//	      one, so U+1D7D8..U+1D7E0 (and 27 siblings) decoded to 9 — a
//	      forged `forge test --fuzz-runs <U+1D7D8>` blessed k=9 where the
//	      twin binds 0 and raises, and a twin-legal 1 was recorded as 9.
//	      The block table is now the TWIN's own Nd data (derived, never
//	      hand-written) and the sweep below is exhaustive.
//	P2-1  VT/FF/CR are not shell separators: /bin/sh hands the tool ONE
//	      argv element `--loop-bound\v4`, so splitting it invented a flag
//	      the tool never received. The evidence is recorded verbatim in
//	      TestR30ShellSeparators.
//
// The r28/r29 parse cases the fixes must not disturb are re-pinned at the
// bottom; the fuller tables live in outcome_test.go and
// zz_r29a_parse_test.go.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"unicode"

	"websec/internal/validation"
)

// ---------------------------------------------------------------------
// (a) P1-1: the minicertora invocation floor is BoundFloors
// ---------------------------------------------------------------------

// TestR30MinicertoraUnreadableInvocationFloors is the auditor's repro, end
// to end through the ONE decision entry point the bind and section 11
// share. Each row's command is one nothing could have executed — /bin/sh
// exits 2 on the unmatched quote, the `;` makes it a two-command list, and
// the substitution's k is not derivable from the text — so the PROVEN line
// under it is evidence of nothing: the whole record must floor with the
// invocation-unreadable reason (naming the construct), with no proof
// sidecar and no bounded_k, whatever the stdout says.
//
// The control at the top is what makes each row a finding rather than a
// tautology: the same PROVEN bytes DO map to proved-bounded (k=4) when the
// invocation is readable, so the floor is the only thing between this
// record and a blessing.
func TestR30MinicertoraUnreadableInvocationFloors(t *testing.T) {
	const rule = "inv_1"
	if rung, sum, _, bk := MapMinicertora([]byte(mcProven), 0, rule); rung !=
		RungProvedBounded || bk == nil || *bk != 4 {
		t.Fatalf("control: the fixture must prove under a readable "+
			"invocation: %q %q %v", rung, sum, bk)
	}
	inv := rdInv("total always covers sum(payouts)")
	rows := []struct {
		name    string
		command string
		want    string // fragment of the construct the parse reports
	}{
		{"unmatched quote: /bin/sh exits 2, so no process ran",
			"minicertora V.sol INV.mspec --loop-bound '4",
			"unmatched single quote"},
		{"`;`-compound command: a list, not the invocation on record",
			"minicertora V.sol INV.mspec --loop-bound 4; echo x",
			"command list (separator ';')"},
		{"command substitution in the bound value: the k the twin " +
			"really ran under is not derivable from the text",
			"minicertora V.sol INV.mspec --loop-bound $(nproc)",
			"shell expansion in the --loop-bound value ($(nproc))"},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			k, why := InvocationBoundReason(tc.command)
			if k != BoundUnreadable || !BoundFloors(k) {
				t.Fatalf("InvocationBoundReason(%q) = (%d, %q), want "+
					"BoundUnreadable with a construct", tc.command, k,
					why)
			}
			if !strings.Contains(why, tc.want) {
				t.Fatalf("construct %q lacks %q", why, tc.want)
			}
			// The auditor's own shape: a record that carries the
			// command, a clean exit status and no recorded hash (the
			// unbound arm).
			rec := rdRecord(
				validation.KV{K: "exec_id", V: validation.VStr("EXEC-1")},
				validation.KV{K: "command", V: validation.VStr(tc.command)},
				validation.KV{K: "exit_status", V: validation.VInt(0)})
			rung, summary, proof, bk := DecideBound(MiniCertora, inv,
				[]byte(mcProven), rec, nil, false, k, 0, rule)
			if rung != RungInconclusive {
				t.Fatalf("an unreadable invocation bound %q: %q", rung,
					summary)
			}
			if bk != nil {
				t.Fatalf("no bounded_k may ride the floor: %d", *bk)
			}
			if proof.Kind != validation.Null {
				t.Fatalf("no sidecar may ride the floor: %s",
					validation.CanonCompact(proof))
			}
			if !strings.Contains(summary, "degenerate-bound") ||
				!strings.Contains(summary, "invocation-unreadable: "+
					oneLine(why, maxConstruct)) {
				t.Fatalf("the floor must keep the disposition "+
					"vocabulary and name the construct: %q", summary)
			}
			// disposition.go must still classify the STORED floor: the
			// "(unbound: …)" decoration the unbound arm appends is
			// transport, and the advice is EscalateBound.
			if cls, advice, ok := Disposition(summary); !ok ||
				cls != EscalateBound || advice == "" {
				t.Fatalf("disposition.go must classify %q: %q %q %v",
					summary, cls, advice, ok)
			}
			// Section 11's arm is this same call with these same
			// arguments, so a repeated call is the audit arm: it must
			// re-derive the bind byte for byte.
			rung2, sum2, _, bk2 := DecideBound(MiniCertora, inv,
				[]byte(mcProven), rec, nil, false, k, 0, rule)
			if rung2 != rung || sum2 != summary || bk2 != nil {
				t.Fatalf("the audit must re-derive the bind: (%q %q) "+
					"vs (%q %q)", rung2, sum2, rung, summary)
			}
		})
	}
	// The BOUND arm reaches the same floor: the invocation floor sits
	// below the hash arms, so a recorded hash equal to the stored
	// scaffold's sha — a perfectly valid binding — cannot rescue a
	// command that was never executable.
	scaffold, err := Scaffold(MiniCertora, inv)
	if err != nil {
		t.Fatal(err)
	}
	cmd := "minicertora V.sol INV.mspec --loop-bound '4"
	boundRec := rdRecord(
		validation.KV{K: "exec_id", V: validation.VStr("EXEC-2")},
		validation.KV{K: "command", V: validation.VStr(cmd)},
		validation.KV{K: "exit_status", V: validation.VInt(0)},
		validation.KV{K: "input_hashes", V: validation.VObj(
			validation.KV{K: "artifacts/harness/INV-1/INV.mspec",
				V: validation.VStr(rdSHA(scaffold))})})
	rung, summary, _, bk := DecideBound(MiniCertora, inv,
		[]byte(mcProven), boundRec, scaffold, false, InvocationBound(cmd),
		0, rule)
	if rung != RungInconclusive || bk != nil {
		t.Fatalf("a bound run on an impossible command must still "+
			"floor: %q %q %v", rung, summary, bk)
	}
	if !strings.Contains(summary, "invocation-unreadable: "+
		"unmatched single quote") {
		t.Fatalf("the bound arm must name the construct too: %q", summary)
	}
	// The STATED degenerate bound keeps its own wording. boundFloorSummary
	// (outcome.go) is now the one home for both floors, so this pins the
	// very sentence minicertora_test.go pins on the mapper (r27 F1).
	if got := boundFloorSummary(BoundDegenerate); got !=
		"inconclusive (degenerate-bound: the invocation states no "+
			"bound >= 1)" {
		t.Fatalf("the degenerate-invocation wording moved: %q", got)
	}
	degCmd := "minicertora V.sol INV.mspec --loop-bound 0"
	if k := InvocationBound(degCmd); k != BoundDegenerate {
		t.Fatalf("control: --loop-bound 0 = %d, want BoundDegenerate", k)
	}
	degRec := rdRecord(
		validation.KV{K: "exec_id", V: validation.VStr("EXEC-3")},
		validation.KV{K: "command", V: validation.VStr(degCmd)},
		validation.KV{K: "exit_status", V: validation.VInt(0)})
	if rung, summary, _, bk := DecideBound(MiniCertora, inv,
		[]byte(mcProven), degRec, nil, false, BoundDegenerate, 0,
		rule); rung != RungInconclusive || bk != nil ||
		!strings.Contains(summary,
			"the invocation states no bound >= 1") {
		t.Fatalf("the stated degenerate invocation keeps its own "+
			"wording: %q %q %v", rung, summary, bk)
	}
}

// ---------------------------------------------------------------------
// (b) P1-2: Nd digits decode from the block that CONTAINS them
// ---------------------------------------------------------------------

// The twin's own Nd data, printed by the twin's interpreter READ-ONLY
// (miniprover/.venv, Python 3.14.7, unicodedata 16.0.0) — the authority
// for what click's type=int accepts:
//
//	/home/xand/Projects/miniprover/.venv/bin/python -c '
//	  import unicodedata
//	  cps=[cp for cp in range(0x110000)
//	       if unicodedata.category(chr(cp))=="Nd"]
//	  print(len(cps), [hex(cp) for cp in cps if int(chr(cp))==0])'
//	-> 760 code points over 76 blocks, the first 0x30 and the last 0x1FBF0
//
// r30TwinNdStarts is that block-start list, an INDEPENDENT second copy of
// the table outcome.go carries, so a hand-edit of the production table is
// caught here even if the digest below were recomputed by accident.
const r30TwinNdStarts = "30,660,6F0,7C0,966,9E6,A66,AE6,B66,BE6,C66,CE6," +
	"D66,DE6,E50,ED0,F20,1040,1090,17E0,1810,1946,19D0,1A80," +
	"1A90,1B50,1BB0,1C40,1C50,A620,A8D0,A900,A9D0,A9F0,AA50,ABF0," +
	"FF10,104A0,10D30,10D40,11066,110F0,11136,111D0,112F0,11450," +
	"114D0,11650,116C0,116D0,116DA,11730,118E0,11950,11BF0,11C50," +
	"11D50,11DA0,11F50,16130,16A60,16AC0,16B50,16D70,1CCF0,1D7CE," +
	"1D7D8,1D7E2,1D7EC,1D7F6,1E140,1E2F0,1E4F0,1E5F1,1E950,1FBF0"

// The twin's whole Nd set as (code point, digit value) pairs:
// r30TwinNdCount pairs, digest r30TwinNdSHA256 (sha256 over "X:val;" for
// each pair in code-point order — the SAME stream the table must
// reproduce), and the two integer sums Python printed
// (sum_cp 39891450, sum_val 3420).
const (
	r30TwinNdCount  = 760
	r30TwinNdSHA256 = "08f9cc82294d4e350463d79bee58b18f69916ad6ff706d82" +
		"5e1ab2cf6f9273d4"
	r30TwinNdSumCP  = 39891450
	r30TwinNdSumVal = 3420
	// Go 1.26.2 ships Unicode 15.0.0, whose Nd set is a strict SUBSET of
	// the twin's: r30GoNdCount code points, digest r30GoNdSHA256 over the
	// same "X:val;" stream DECODED through the table. A Go upgrade moves
	// these numbers and the test says so — the table then has to be
	// re-derived from the twin, never hand-patched.
	r30GoNdCount  = 680
	r30GoNdSHA256 = "fc96840cf7c86b83b74d49aefe0df58e3173ab484b7d682ad" +
		"658d56ae581fbe8"
)

// TestR30NdBlockTableMatchesTheTwin pins the derived table against the
// twin's own data three ways: the block-start list verbatim, the
// (code point, value) digest, and Python's two integer sums. It also pins
// the layout the decoder's binary search depends on — starts strictly
// ascending, each block ten wide and no block overlapping the next.
func TestR30NdBlockTableMatchesTheTwin(t *testing.T) {
	var want []rune
	for _, f := range strings.Split(r30TwinNdStarts, ",") {
		n, err := strconv.ParseInt(f, 16, 32)
		if err != nil {
			t.Fatalf("bad expected start %q: %v", f, err)
		}
		want = append(want, rune(n))
	}
	if len(ndBlockStarts) != len(want) {
		t.Fatalf("table has %d blocks, the twin has %d",
			len(ndBlockStarts), len(want))
	}
	for i, s := range want {
		if ndBlockStarts[i] != s {
			t.Fatalf("block %d starts at U+%04X, the twin says U+%04X",
				i, ndBlockStarts[i], s)
		}
		if i > 0 && s-ndBlockStarts[i-1] < 10 {
			t.Fatalf("blocks U+%04X and U+%04X overlap",
				ndBlockStarts[i-1], s)
		}
		if s+9 > unicode.MaxRune {
			t.Fatalf("block U+%04X runs past the last code point", s)
		}
	}
	h := sha256.New()
	pairs, sumCP, sumVal := 0, 0, 0
	for _, s := range ndBlockStarts {
		for d := rune(0); d <= 9; d++ {
			if got, ok := decimalDigit(s + d); !ok || got != int(d) {
				t.Fatalf("U+%04X must decode to %d, got (%d, %v)",
					s+d, d, got, ok)
			}
			fmt.Fprintf(h, "%X:%d;", s+d, d)
			pairs++
			sumCP += int(s) + int(d)
			sumVal += int(d)
		}
	}
	if pairs != r30TwinNdCount || sumCP != r30TwinNdSumCP ||
		sumVal != r30TwinNdSumVal {
		t.Fatalf("table covers %d pairs (sum_cp %d, sum_val %d), the "+
			"twin says %d (%d, %d)", pairs, sumCP, sumVal,
			r30TwinNdCount, r30TwinNdSumCP, r30TwinNdSumVal)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != r30TwinNdSHA256 {
		t.Fatalf("the table's (code point, value) stream digests to %s, "+
			"the twin's data to %s — re-derive ndBlockStarts from the "+
			"twin, do not hand-edit it", got, r30TwinNdSHA256)
	}
}

// TestR30DecimalDigitSweepsEveryNdCodePoint is the exhaustive proof, over
// the WHOLE code-point space:
//
//   - a rune the twin's table covers decodes to that table's value (its
//     own block's offset, never a neighbour's);
//   - a rune outside the table is UNPARSEABLE — no value, never a 9 and
//     never anything else — which is the UsageError direction;
//   - every Nd rune GO knows decodes, and the digest of Go's Nd set
//     decoded through the table equals the digest of the TWIN's values
//     for that same set. (Go knows 680 of the twin's 760 today; a Go
//     Unicode upgrade that adds an Nd block not in the twin's table fails
//     here instead of silently flooring honest runs.)
func TestR30DecimalDigitSweepsEveryNdCodePoint(t *testing.T) {
	tbl := make(map[rune]int, r30TwinNdCount)
	for _, s := range ndBlockStarts {
		for d := rune(0); d <= 9; d++ {
			tbl[s+d] = int(d)
		}
	}
	h := sha256.New()
	goNd := 0
	for r := rune(0); r <= unicode.MaxRune; r++ {
		got, ok := decimalDigit(r)
		want, in := tbl[r]
		switch {
		case in && (!ok || got != want):
			t.Fatalf("U+%04X is the twin's digit %d but decodes to "+
				"(%d, %v)", r, want, got, ok)
		case !in && ok:
			t.Fatalf("U+%04X is outside the twin's Nd table but "+
				"decoded to %d: an uncovered rune must be "+
				"unparseable, never a digit", r, got)
		}
		if !unicode.IsDigit(r) {
			continue
		}
		goNd++
		if !ok {
			t.Fatalf("Go knows Nd U+%04X, the twin's table does not "+
				"cover it: re-derive ndBlockStarts from the twin",
				r)
		}
		fmt.Fprintf(h, "%X:%d;", r, got)
	}
	if goNd != r30GoNdCount {
		t.Fatalf("Go's Nd set has %d code points, the pinned count is "+
			"%d: re-derive ndBlockStarts from the twin", goNd,
			r30GoNdCount)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != r30GoNdSHA256 {
		t.Fatalf("Go's Nd set decodes to digest %s, the twin's values "+
			"for it digest to %s", got, r30GoNdSHA256)
	}
}

// TestR30AdjacentNdBlocksDecodeHonestly names the finding's exact
// signature. Five Nd block pairs are ADJACENT (the four mathematical
// blocks and U+116D0/U+116DA), and the r29 walk-down decoder left the
// block it was given for every later one — U+1D7D8 was "9" instead of 0.
// The rows here are the code points the auditor swept, plus the parse-level
// consequence in both directions: a forged 9 stayed a blessing (k=9 where
// the twin raises on 0) and a twin-legal 1 was recorded as a 9 (a ledger
// lie).
func TestR30AdjacentNdBlocksDecodeHonestly(t *testing.T) {
	for _, tc := range []struct {
		start rune
		name  string
	}{
		{0x1D7D8, "MATHEMATICAL DOUBLE-STRUCK (after BOLD)"},
		{0x1D7E2, "MATHEMATICAL SANS-SERIF"},
		{0x1D7EC, "MATHEMATICAL SANS-SERIF BOLD"},
		{0x1D7F6, "MATHEMATICAL MONOSPACE"},
		{0x116DA, "the second adjacent block at U+116DA"},
	} {
		for d := rune(0); d <= 9; d++ {
			got, ok := decimalDigit(tc.start + d)
			if !ok || got != int(d) {
				t.Fatalf("%s: U+%04X decodes to (%d, %v), want %d",
					tc.name, tc.start+d, got, ok, d)
			}
		}
	}
	// Parse level, the twin's own answers (miniprover/.venv):
	//	int(chr(0x1D7D8)) == 0   -> VerifierFlags raises: the run is
	//	                            impossible, so the invoked bound floors
	//	int(chr(0x1D7D9)) == 1   -> an honest k=1
	//	int(ten double-struck digits) == 123456789
	zero, one := string(rune(0x1D7D8)), string(rune(0x1D7D9))
	if got := InvocationBound("forge test --fuzz-runs " + zero); got !=
		BoundDegenerate {
		t.Fatalf("U+1D7D8 is the digit 0, which the twin raises for: "+
			"got %d (the r29 walk-down read 9 and blessed it)", got)
	}
	if got := InvocationBound("forge test --fuzz-runs " + one); got != 1 {
		t.Fatalf("U+1D7D9 is the digit 1, an honest k=1: got %d", got)
	}
	ten := ""
	for d := rune(0); d <= 9; d++ {
		ten += string(rune(0x1D7E2) + d)
	}
	if got := InvocationBound("forge test --fuzz-runs " + ten); got !=
		123456789 {
		t.Fatalf("ten sans-serif digits are 123456789: got %d", got)
	}
	// A digit rune the table does not cover stays unparseable: the
	// superscript two is a digit to str.isdigit() but int("²") raises, so
	// the invocation is a UsageError, never a value.
	if d, ok := decimalDigit('\u00b2'); ok {
		t.Fatalf("superscript two must not decode: %d", d)
	}
	if got := InvocationBound("miniprover run --loop-bound \u00b2"); got !=
		BoundDegenerate {
		t.Fatalf("int('²') raises in the twin: got %d", got)
	}
}

// TestR30TwinOnlyNdBlocksStillDecode pins the direction the table's
// provenance decides. The twin's unicodedata 16.0.0 knows eight Nd blocks
// (80 code points) that Go 1.26's Unicode 15.0.0 does not, and click's
// int() accepts every one of them, so they must decode: a decoder gated on
// unicode.IsDigit would floor honest k=1..9 runs in those blocks. (On this
// Go version none of these eight starts is a `unicode.IsDigit` rune, which
// is exactly what makes the rows evidence.)
func TestR30TwinOnlyNdBlocksStillDecode(t *testing.T) {
	for _, tc := range []struct {
		start rune
		name  string
	}{
		{0x10D40, "the U+10D40 block"},
		{0x116D0, "the U+116D0 block"},
		{0x116DA, "the U+116DA block (adjacent to U+116D0)"},
		{0x11BF0, "the U+11BF0 block"},
		{0x16130, "the U+16130 block"},
		{0x16D70, "the U+16D70 block"},
		{0x1CCF0, "the U+1CCF0 block"},
		{0x1E5F1, "the U+1E5F1 block"},
	} {
		for d := rune(0); d <= 9; d++ {
			if got, ok := decimalDigit(tc.start + d); !ok ||
				got != int(d) {
				t.Fatalf("%s: U+%04X must decode to %d, got (%d, %v)",
					tc.name, tc.start+d, d, got, ok)
			}
		}
	}
	// The twin's own answers for the block Go's tables stop short of:
	// int(chr(0x11BF1)) == 1 (an honest k=1) and int(chr(0x11BF0)) == 0
	// (the value VerifierFlags raises for).
	if got := InvocationBound("miniprover run --loop-bound " +
		string(rune(0x11BF1))); got != 1 {
		t.Fatalf("the twin binds 1 for U+11BF1: got %d", got)
	}
	if got := InvocationBound("miniprover run --loop-bound " +
		string(rune(0x11BF0))); got != BoundDegenerate {
		t.Fatalf("the twin binds 0 for U+11BF0 and raises: got %d", got)
	}
}

// ---------------------------------------------------------------------
// (c) P2-1: only space, TAB and newline separate in /bin/sh
// ---------------------------------------------------------------------

// TestR30ShellSeparators records the shell evidence and pins the parse
// against it. Everything below was OBSERVED on this box with a stub that
// prints each argv element hex-encoded, driven through /bin/sh -c (the
// shell the sandbox records commands for):
//
//	stub: for a in "$@"; do printf '%s' "$a" | od -An -tx1 | tr -d ' \n';
//	      echo; done; echo count=$#
//
//	$ /bin/sh -c './stub.sh --loop-bound 4'
//	  2d2d6c6f6f702d626f756e64          (--loop-bound)
//	  34                                (4)                      count=2
//	$ /bin/sh -c './stub.sh --loop-bound<TAB>4'
//	  2d2d6c6f6f702d626f756e64 / 34                              count=2
//	$ /bin/sh -c './stub.sh --loop-bound<VT>4'
//	  2d2d6c6f6f702d626f756e640b34      (--loop-bound\x0b4)      count=1
//	$ /bin/sh -c './stub.sh --loop-bound<FF>4'
//	  2d2d6c6f6f702d626f756e640c34      (--loop-bound\x0c4)      count=1
//	$ /bin/sh -c './stub.sh --loop-bound<CR>4'
//	  2d2d6c6f6f702d626f756e640d34      (--loop-bound\x0d4)      count=1
//	$ printf './stub.sh --loop-bound\n4\n' > nl.cmd; /bin/sh nl.cmd
//	  2d2d6c6f6f702d626f756e64          (a FIRST command)       count=1
//	  nl.cmd: line 2: 4: command not found   (a SECOND command)
//
// So: space and TAB split words, a newline ends the COMMAND (it is IFS
// whitespace, but between commands it is a command separator), and CR, VT
// and FF are ordinary word characters that stay inside the element. The
// r29 lexer split on CR/VT/FF as well, which for
// `--loop-bound\v4` invented the flag `--loop-bound` and the value 4 —
// an invocation the tool never received. `int()` still strips a TRAILING
// VT/FF/CR from a value (Python: int('4\v') == 4) while an INTERIOR one
// makes it a non-integer (int('4\v4') raises), which is why the trailing
// rows below are honest bounds and the interior ones floor.
func TestR30ShellSeparators(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command string
		want    int
		wantWhy string // non-empty: the parse must refuse with this text
	}{
		{"space splits words", "miniprover run --loop-bound 4", 4, ""},
		{"TAB splits words", "miniprover run --loop-bound\t4", 4, ""},
		{"a newline ends the command, so a second line is a command " +
			"list", "miniprover run --loop-bound\n4", BoundUnreadable,
			"command list (separator '\\n')"},
		{"VT is not a separator: one argv element, so the flag names " +
			"no bound", "miniprover run --loop-bound\v4", 0, ""},
		{"FF is not a separator", "miniprover run --loop-bound\f4", 0,
			""},
		{"CR is not a separator", "miniprover run --loop-bound\r4", 0,
			""},
		{"a trailing VT stays inside the value, and int() strips it",
			"miniprover run --loop-bound 4\v", 4, ""},
		{"a trailing FF stays inside the value too",
			"miniprover run --loop-bound 4\f", 4, ""},
		{"a trailing CR stays inside the value too",
			"miniprover run --loop-bound 4\r", 4, ""},
		{"an interior VT makes the value a non-integer (int('4\\v4') " +
			"raises)", "miniprover run --loop-bound 4\v4",
			BoundDegenerate, ""},
		{"an interior CR makes it a non-integer too",
			"miniprover run --loop-bound 4\r4", BoundDegenerate, ""},
		{"a VT-only second line is a command of its own, not padding",
			"miniprover run --loop-bound 4\n\v", BoundUnreadable,
			"command list (separator '\\n')"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k, why := InvocationBoundReason(tc.command)
			if k != tc.want {
				t.Fatalf("InvocationBoundReason(%q) = (%d, %q), want %d",
					tc.command, k, why, tc.want)
			}
			if tc.wantWhy == "" && why != "" {
				t.Fatalf("a readable command must carry no construct: "+
					"%q", why)
			}
			if tc.wantWhy != "" && !strings.Contains(why, tc.wantWhy) {
				t.Fatalf("construct %q lacks %q", why, tc.wantWhy)
			}
		})
	}
}

// ---------------------------------------------------------------------
// (d) the r28/r29 parse cases the r30 fixes must not disturb
// ---------------------------------------------------------------------

// TestR30ParseRegressionsStayGreen re-pins, in one place, the parse facts
// r30 touches the neighbourhood of: click's last-wins binding, signed and
// underscored Python int literals, the Nd digit blocks, quoting, comments
// and the `--` terminator. The fuller tables are
// TestInvocationBoundIsClickShaped / TestR29InvocationBoundMatchesShellThenClick;
// these rows are the ones a future edit to the lexer or to decimalDigit is
// most likely to break.
func TestR30ParseRegressionsStayGreen(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command string
		want    int
	}{
		{"last flag wins (click binds the final occurrence)",
			"miniprover run --loop-bound 4 --loop-bound 0",
			BoundDegenerate},
		{"a signed value is a real value, not a malformed one",
			"--loop-bound +4", 4},
		{"k=1 stays honest", "--loop-bound 1", 1},
		{"a negative value is the statement the twin raises on",
			"--loop-bound -1", BoundDegenerate},
		{"4_000 is Python int syntax, never a truncated 4",
			"--loop-bound 4_000", 4000},
		{"underscores between Nd digits are legal too",
			"--loop-bound \u0664_\u0662", 42},
		{"unicode block 1 digits: arabic-indic 42",
			"--loop-bound \u0664\u0662", 42},
		{"fullwidth 42", "--loop-bound \uFF14\uFF12", 42},
		{"the first mathematical block still decodes (bold 01 -> 1)",
			"--loop-bound \U0001D7CE\U0001D7CF", 1},
		{"quoted text is ONE argv element, so it names no flag",
			"miniprover run '--loop-bound 0'", 0},
		{"a `#` comment is dropped by the shell",
			"miniprover run --loop-bound 4 # --loop-bound 0", 4},
		{"`--` ends the options, so the flag after it is positional",
			"miniprover run --loop-bound 4 -- --loop-bound 0", 4},
		{"a value the tool refuses floors instead of reading as 0",
			"--loop-bound 4.5", BoundDegenerate},
		{"an expansion that could BE the flag is unreadable",
			"miniprover run $EXTRA --loop-bound 4", BoundUnreadable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := InvocationBound(tc.command); got != tc.want {
				t.Fatalf("InvocationBound(%q) = %d, want %d",
					tc.command, got, tc.want)
			}
		})
	}
}
