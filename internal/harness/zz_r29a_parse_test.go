package harness

// zz_r29a_parse_test.go (r29 F4): InvocationBound must mirror what the
// twin's click CLI would actually RECEIVE — the command string is lexed
// the way a POSIX shell would split it, and only then are the options
// bound the way click would bind them. The old regex scanned the raw text,
// so a `#` comment's flag beat the real one, a flag inside a quoted
// argument was invented, `--` did not stop it, `4_000` truncated to 4 (a
// LEDGER LIE: a stated 4 the tool never ran under), and `4.5` / an empty
// / a missing value — each a click UsageError, i.e. a run that cannot
// exist — were blessed as a bound.
//
// Every "twin" note below is MEASURED, not assumed, against the twin's own
// click command object (miniprover/.venv, click 8.5.0):
//
//	from miniprover.cli import main      # the twin's real click command
//	ctx = main.make_context("miniprover", ["T", …])
//	ctx.params["loop_bound"]             # or click.UsageError
//
// and against /bin/sh for the splitting half (`sh -c '… "$@"'` printed the
// argv). The observed twin answers the cases below assert:
//
//	--loop-bound 4 --loop-bound 0        -> 0   (VerifierFlags raises)
//	--loop-bound +4                      -> 4
//	--loop-bound 4_000                   -> 4000
//	--loop-bound 4.5 / = / <missing>     -> UsageError
//	--loop-bound ٠ (Nd zero)             -> 0   (VerifierFlags raises)
//	--loop-bound 4 --fuzz-runs 7         -> UsageError: No such option
//	--loop-bound 4 -- --loop-bound 0     -> 4   (with extra-positional error)
//	--loop-bound ٤٢ / ４２ / 𝟎𝟏            -> 42 / 42 / 1
//	--loop-bound --loop-bound 4          -> UsageError (the flag text is
//	                                       eaten as the first option's value)
//
// The shell half is what makes rows 8-12 of the finding diverge: a `#`
// comment is dropped by the shell, `--` is passed through, a quoted
// argument stays ONE argv element, and TAB separates words. Space and TAB
// (plus newline, which separates COMMANDS here) are the ONLY IFS
// whitespace: CR, VT and FF are ordinary word characters, so
// `--loop-bound\v4` is one argv element and names no bound at all —
// measured against /bin/sh, evidence in zz_r30_test.go
// (TestR30ShellSeparators, r30 P2-1: this file used to pin VT as a
// separator, which invented a flag the tool never received).

import (
	"strings"
	"testing"
)

// TestR29InvocationBoundMatchesShellThenClick is the F4 table: every row
// of the finding, plus the regression cases the fix could plausibly break,
// each with the twin's own expectation in the case name.
func TestR29InvocationBoundMatchesShellThenClick(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command string
		want    int
	}{
		// ---- the finding's table ----------------------------------
		{"twin 0, raises | last flag wins: --loop-bound 4 --loop-bound 0",
			"miniprover run --loop-bound 4 --loop-bound 0",
			BoundDegenerate},
		{"twin 4 | +4 is an int, not an unstated bound",
			"miniprover run --loop-bound +4", 4},
		{"twin 4000 | 4_000 is Python int syntax, never a stated 4",
			"miniprover run --loop-bound 4_000", 4000},
		{"twin UsageError '4.5' is not a valid integer",
			"miniprover run --loop-bound 4.5", BoundDegenerate},
		{"twin UsageError '' is not a valid integer | --loop-bound=",
			"miniprover run --loop-bound=", BoundDegenerate},
		{"twin UsageError requires an argument | flag at end",
			"miniprover run --loop-bound", BoundDegenerate},
		{"twin 0, raises | Nd zero is a zero Python's int() accepts",
			"miniprover run --loop-bound \u0660", BoundDegenerate},
		{"shell drops the comment; twin binds 0 and raises",
			"true --loop-bound 0 # note --loop-bound 4",
			BoundDegenerate},
		{"shell drops the comment; twin binds 4 (an honest run)",
			"miniprover run --loop-bound 4 # --loop-bound 0", 4},
		{"click stops at --; twin binds the flag before it",
			"miniprover run --loop-bound 4 -- --loop-bound 0", 4},
		{"quoted: one argv element, click sees no flag at all",
			"sh -c 'miniprover run --loop-bound 99'", 0},
		{"TAB is a separator; twin binds 4",
			"miniprover run --loop-bound\t4", 4},
		{"twin UsageError No such option '--fuzz-runs' (names conflated)",
			"miniprover run --loop-bound 4 --fuzz-runs 7", BoundDegenerate},

		// ---- regressions the fix must not break -------------------
		{"plain flag", "miniprover run --loop-bound 4", 4},
		{"no flag is UNSTATED, not zero", "miniprover run --root .", 0},
		{"the documented minicertora invocation",
			"minicertora V.sol INV.mspec --solc-path /abs/solc " +
				"--loop-bound 4 --timeout-ms 30000", 4},
		{"halmos --loop", "halmos check --loop 100", 100},
		{"forge --fuzz-runs", "forge test --fuzz-runs 256", 256},
		{"flag=value form", "miniprover run --loop-bound=8", 8},
		{"flag=+value form", "miniprover run --loop-bound=+4", 4},
		{"repeats: last wins", "miniprover run --loop-bound 1 " +
			"--loop-bound 2 --loop-bound 3", 3},
		{"degenerate then honest", "miniprover run --loop-bound 0 " +
			"--loop-bound 4", 4},
		{"honest then degenerate", "halmos check --loop 100 --loop 0",
			BoundDegenerate},
		{"signed zero", "miniprover run --loop-bound -0",
			BoundDegenerate},
		{"bare minus is not an integer", "miniprover run --loop-bound -",
			BoundDegenerate},
		{"negative, both forms", "miniprover run --loop-bound -1",
			BoundDegenerate},
		{"negative, = form", "--loop-bound=-1", BoundDegenerate},
		{"absurd width, positive: UNSTATED (r28 reading)",
			"--loop-bound 99999999999999999999999999", 0},
		{"absurd width, negative: degenerate",
			"--loop-bound -99999999999999999999999999", BoundDegenerate},
		{"lookalike suffix names no flag",
			"miniprover run --loop-boundx 4", 0},
		{"lookalike prefix names no flag",
			"miniprover run --loopx 5", 0},
		{"long options are case-sensitive",
			"miniprover run --LOOP-BOUND 4", 0},

		// ---- quoting ---------------------------------------------
		{"a quoted argument is one argv element, so it is no option",
			"miniprover run '--loop-bound 0'", 0},
		{"a quoted argument containing the text is no option",
			"miniprover run --project-root '/srv/data --loop-bound 0' " +
				"--loop-bound 4", 4},
		{"the shell strips quotes, so a QUOTED flag name is still the " +
			"option", "miniprover run \"--loop-bound\" 4", 4},
		{"an escaped space joins two words into one argv element",
			"miniprover run --loop-bound\\ 4", 0},
		{"an escaped dash is still the option after quote removal",
			"miniprover run --loop\\-bound 4", 4},
		{"POSIX keeps the backslash before a non-special char in " +
			"double quotes, so click sees \\4 (not an int)",
			"miniprover run --loop-bound \"\\4\"", BoundDegenerate},
		{"an escaped $ is literal, so click sees $N (not an int)",
			"miniprover run --loop-bound \"\\$N\"", BoundDegenerate},
		{"a `#` inside a word is literal, so the value is 4#x",
			"miniprover run --loop-bound 4#x", BoundDegenerate},
		{"a quoted `#` is a word, not a comment",
			"miniprover run --loop-bound '4#x'", BoundDegenerate},
		{"a trailing comment is dropped",
			"miniprover run --loop-bound 4 # note", 4},
		{"a trailing newline ends the one command",
			"miniprover run --loop-bound 4\n", 4},
		{"trailing comment lines are not a second command",
			"miniprover run --loop-bound 4\n# note\n", 4},
		{"a trailing `&` backgrounds the one command",
			"miniprover run --loop-bound 4 &", 4},

		// ---- `--` and positional tails ---------------------------
		{"flags after -- are positional",
			"miniprover run -- --loop-bound 0", 0},
		{"flags after -- are positional, even a foreign name",
			"miniprover run --loop-bound 4 -- --fuzz-runs 7", 4},
		{"a positional tail does not disturb the bound",
			"miniprover run --loop-bound 4 extra", 4},

		// ---- values: Python int() semantics ----------------------
		{"underscores between digits", "miniprover run --loop-bound 4_0_0",
			400},
		{"a leading underscore is not an int",
			"miniprover run --loop-bound _4", BoundDegenerate},
		{"a trailing underscore is not an int",
			"miniprover run --loop-bound 4_", BoundDegenerate},
		{"a doubled underscore is not an int",
			"miniprover run --loop-bound 4__0", BoundDegenerate},
		{"a hex literal is not an int (int() defaults to base 10)",
			"miniprover run --loop-bound 0x4", BoundDegenerate},
		{"an exponent is not an int",
			"miniprover run --loop-bound 1e3", BoundDegenerate},
		{"ND digits are values: arabic-indic 42",
			"miniprover run --loop-bound \u0664\u0662", 42},
		{"ND digits are values: fullwidth 42",
			"miniprover run --loop-bound \uFF14\uFF12", 42},
		{"ND digits are values: mathematical bold 01",
			"miniprover run --loop-bound \U0001D7CE\U0001D7CF", 1},
		{"underscores work between ND digits",
			"miniprover run --loop-bound \u0664_\u0662", 42},
		{"arabic-indic double zero is a zero",
			"miniprover run --loop-bound \u0660\u0660",
			BoundDegenerate},
		{"superscript two is NOT Nd (str.isdigit is not int())",
			"miniprover run --loop-bound \u00b2", BoundDegenerate},
		{"the flag text is eaten as the first value, as click does",
			"miniprover run --loop-bound --loop-bound 4",
			BoundDegenerate},
		{"-- is eaten as the value, as click does",
			"miniprover run --loop-bound -- 4", BoundDegenerate},
		{"a repeated flag with no value still errors",
			"miniprover run --loop-bound 4 --loop-bound",
			BoundDegenerate},
		{"VT is NOT a separator: /bin/sh hands the tool ONE argv " +
			"element `--loop-bound\\v4`, which click refuses — no " +
			"bound was ever named", "miniprover run --loop-bound\v4", 0},
		{"FF is NOT a separator either",
			"miniprover run --loop-bound\f4", 0},
		{"CR is NOT a separator either",
			"miniprover run --loop-bound\r4", 0},
		{"a trailing VT stays inside the value, and Python's int() " +
			"strips it (int('4\\v') == 4)",
			"miniprover run --loop-bound 4\v", 4},
		{"a trailing CR stays inside the value too",
			"miniprover run --loop-bound 4\r", 4},
		{"an = with an empty value errors even with a following word",
			"miniprover run --loop-bound= 4", BoundDegenerate},
		{"a newline inside quotes is part of the value, and int() " +
			"strips it", "miniprover run --loop-bound \"4\n\"", 4},
		{"an escaped semicolon is a value character",
			"miniprover run --loop-bound 4\\;", BoundDegenerate},
		{"a quoted semicolon is a value character",
			"miniprover run --loop-bound '4;'", BoundDegenerate},
		{"a quoted space is part of the value",
			"miniprover run --loop-bound 'a b'", BoundDegenerate},
		{"mixed flag forms: last wins",
			"miniprover run --loop-bound 4 --loop-bound=8", 8},
		{"an inline-value option does not swallow the next flag",
			"miniprover run --solc-path=/abs/solc --loop-bound 4", 4},
		{"a leading -- must keep ending options",
			"-- --loop-bound 0", 0},

		// ---- two tools' bound flags in one command ---------------
		{"two different bound flags: no tool accepts both",
			"miniprover run --loop 100 --loop-bound 4", BoundDegenerate},

		// ---- expansions: unreadable only where they could be an
		// option, tolerated where the option stream is unaffected ----
		{"a program name is never parsed as an option",
			"$BIN run --loop-bound 4", 4},
		{"a path expansion is some other option's value",
			"miniprover run --solc-path $HOME/.local/bin/solc " +
				"--loop-bound 4", 4},
		{"a command substitution is one value word",
			"miniprover run --solc-path $(which solc) --loop-bound 4", 4},
		{"a glob is some other option's value (an ordinary forge " +
			"command)", "forge test --match-test test_* --fuzz-runs 256",
			256},
		{"a tilde is a path, never an option",
			"miniprover run --solc-path ~/bin/solc --loop-bound 4", 4},
		{"an expansion could BE the bound flag",
			"miniprover run $EXTRA --loop-bound 4", BoundUnreadable},
		{"an expansion could still add a flag after an honest one",
			"miniprover run --loop-bound 4 $EXTRA", BoundUnreadable},
		{"the bound value itself is not derivable",
			"miniprover run --loop-bound $N", BoundUnreadable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := InvocationBound(tc.command); got != tc.want {
				t.Fatalf("InvocationBound(%q) = %d, want %d",
					tc.command, got, tc.want)
			}
		})
	}
}

// TestR29UnreadableInvocationNamesTheConstruct is requirement 3's honest
// arm: a command the lexer cannot read faithfully returns BoundUnreadable
// — never a guessed number, never "unstated" — and the caller's floor
// names the construct. Each floor is shown through the summary MapRun
// (outcome.go) builds AND through disposition.go's classifier: the
// summary must keep the "degenerate-bound" prefix, because that is the
// vocabulary Disposition reads; the construct detail rides after it.
//
// MapMinicertoraInvoc (minicertora.go) used to test
// `invBound == BoundDegenerate`, so it floored a stated degenerate bound
// but NOT BoundUnreadable. r30 P1-1 widened it to BoundFloors — the same
// predicate MapRun asks — so the minicertora arm now floors an unreadable
// invocation too and names the construct; that half is pinned end to end
// in zz_r30_test.go (TestR30MinicertoraUnreadableInvocationFloors).
func TestR29UnreadableInvocationNamesTheConstruct(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command string
		want    string // fragment of the construct the parse reports
	}{
		{"unmatched single quote",
			"miniprover run --loop-bound 4 'oops",
			"unmatched single quote"},
		{"unmatched double quote",
			`miniprover run --loop-bound "4`, "unmatched double quote"},
		{"trailing backslash",
			"miniprover run --loop-bound 4 \\",
			"unterminated escape (trailing backslash)"},
		{"second command after a newline",
			"miniprover run --loop-bound 4\nforge test",
			"command list (separator '\\n')"},
		{"second command after a semicolon",
			"miniprover run --loop-bound 4; echo done",
			"command list (separator ';')"},
		{"second command after &&",
			"miniprover run --loop-bound 4 && echo done",
			"command list (separator '&')"},
		{"pipeline",
			"miniprover run --loop-bound 4 | tee log",
			"pipeline or subshell ('|')"},
		{"subshell",
			"miniprover run --loop-bound 4 (x)",
			"pipeline or subshell ('(')"},
		{"redirection",
			"miniprover run --loop-bound 4 > out.txt",
			"redirection ('>')"},
		{"brace expression",
			"miniprover run --match-test {a,b} --loop-bound 4",
			"brace expression ('{')"},
		{"unterminated command substitution",
			"miniprover run --loop-bound $(nproc",
			"unterminated command substitution"},
		{"unterminated parameter expansion",
			"miniprover run --loop-bound ${N",
			"unterminated parameter expansion"},
		{"expansion where an option could be",
			"miniprover run $EXTRA --loop-bound 4",
			"shell expansion ($EXTRA) where an option could be"},
		{"expansion in the bound value",
			"miniprover run --loop-bound $N",
			"shell expansion in the --loop-bound value ($N)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k, why := InvocationBoundReason(tc.command)
			if k != BoundUnreadable {
				t.Fatalf("InvocationBoundReason(%q) = (%d, %q), want "+
					"BoundUnreadable (%d)", tc.command, k, why,
					BoundUnreadable)
			}
			if !BoundFloors(k) {
				t.Fatalf("BoundUnreadable must floor: %d", k)
			}
			if !strings.Contains(why, tc.want) {
				t.Fatalf("construct %q lacks %q", why, tc.want)
			}
			// The floor as the halmos/forge caller builds it: whatever
			// the output says, with the construct named.
			rung, summary := MapRun(ForgeFuzz, []byte(forgePass), false,
				k, why)
			if rung != RungInconclusive {
				t.Fatalf("an unreadable invocation must not bless: "+
					"%q %q", rung, summary)
			}
			if !strings.Contains(summary, "degenerate-bound") {
				t.Fatalf("the floor must keep the disposition "+
					"vocabulary: %q", summary)
			}
			if !strings.Contains(summary, "invocation-unreadable: "+
				oneLine(why, maxConstruct)) {
				t.Fatalf("the floor must name the construct: %q",
					summary)
			}
			if cls, advice, ok := Disposition(summary); !ok ||
				cls != EscalateBound || advice == "" {
				t.Fatalf("disposition.go must classify %q: %q %q %v",
					summary, cls, advice, ok)
			}
		})
	}
}

// TestR29BoundFloorsIsTheOneQuestion pins the two sentinels' shared
// meaning. 0 is UNSTATED and every N >= 1 is honest; both negative
// sentinels floor. A caller that asks `== BoundDegenerate` catches only
// half of them — which is exactly why BoundFloors exists and why
// BoundUnreadable is its own value.
func TestR29BoundFloorsIsTheOneQuestion(t *testing.T) {
	for _, tc := range []struct {
		k    int
		want bool
	}{
		{0, false}, {1, false}, {8, false}, {4000, false},
		{BoundDegenerate, true}, {BoundUnreadable, true},
	} {
		if got := BoundFloors(tc.k); got != tc.want {
			t.Fatalf("BoundFloors(%d) = %v, want %v", tc.k, got,
				tc.want)
		}
	}
	if BoundUnreadable == BoundDegenerate {
		t.Fatal("BoundUnreadable must be its own sentinel, so a caller " +
			"can word the two floors differently")
	}
	// The class-only wording (no construct handed in) is still a
	// disposition, and still floors an output that would otherwise prove.
	rung, summary := MapRun(Halmos, []byte(halmosProvedK), false,
		BoundUnreadable)
	if rung != RungInconclusive ||
		!strings.Contains(summary, "invocation-unreadable") {
		t.Fatalf("class-only floor: %q %q", rung, summary)
	}
	if cls, _, ok := Disposition(summary); !ok || cls != EscalateBound {
		t.Fatalf("class-only floor must dispose: %q %q %v", summary,
			cls, ok)
	}
	// A readable command carries no construct, floors included: the
	// reason channel must not invent one.
	for _, cmd := range []string{
		"miniprover run --loop-bound 4",
		"miniprover run --loop-bound 0",
		"miniprover run --loop-bound 4.5",
		"miniprover run --loop-bound 4 --fuzz-runs 7",
		"",
	} {
		if k, why := InvocationBoundReason(cmd); why != "" {
			t.Fatalf("readable command %q reports construct %q (k=%d)",
				cmd, why, k)
		}
	}
}
