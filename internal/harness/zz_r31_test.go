package harness

// zz_r31_test.go (hostile round 31): the four findings, each pinned at the
// level it broke, each with the mutation that proves the pin.
//
//	F1 (P1) the '$' arm swallowed the rune after EVERY '$', so `$;` was one
//	      token: a hidden command separator stopped separating, the two-
//	      command string `forge test --match-path $; --fuzz-runs 500` bound
//	      k=500, and the audit (which re-derives through the same parse)
//	      agreed. The mirror was a ledger lie too: `--contract $
//	      --loop-bound 7` swallowed the SPACE and read as UNSTATED while
//	      /bin/sh ran the command with loop_bound 7. '$' before anything
//	      but a name start, '{', '(', a digit or a special parameter is now
//	      a LITERAL '$' and the next rune is lexed as itself.
//	F2 (P2) a stated bound above 2^62 rendered "bound UNSTATED": the r28
//	      guard collapsed MaxInt64 (which fits int64) and every wider
//	      Python int to 0, with a null bounded_k. The full int64 range now
//	      parses exactly, and a wider value saturates to MaxInt64 with a
//	      "k>=" summary (BoundCapped) instead of pretending no bound was
//	      stated.
//	F3 (P2) an option whose value slot was really a flag or a positional
//	      was read as a bound: `--timeout-ms --loop-bound 4` bound 4 where
//	      click refuses the invocation outright. Two adjacent option-
//	      looking tokens now floor as an underivable arity.
//	F4 (P3) is a docs citation (docs/IMPROVEMENTS.md), not code.
//
// The F1 differential drives an argv-printing stub through /bin/sh -c — the
// shell the sandbox records commands for — and asserts Go's token stream
// against the argv the shell really handed the program.

import (
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"websec/internal/validation"
)

// ---------------------------------------------------------------------
// F1: a shell differential for '$'
// ---------------------------------------------------------------------

// r31Stub is the argv oracle: one group per invocation — a \x01 marker,
// then each argv element NUL-terminated — written to a file of its OWN,
// named by $R31_STUB_LOG plus the stub process's pid. Its own FILE rather
// than one shared log because a pipeline or a background operator runs two
// stubs at once, and two processes appending to one file interleave their
// writes: an observed run of `stub --match-path $| stub M` recorded the two
// invocations as "\x01\x01M\0--match-path\0$\0" — one torn group that
// no longer says what either process received. A file per pid cannot tear,
// and it also answers the stdout problem: a pipeline's left command writes
// into the PIPE, so a stdout stub would be unobservable there.
const r31Stub = `#!/bin/sh
{
  printf '\001'
  for a in "$@"; do printf '%s\0' "$a"; done
} > "$R31_STUB_LOG.$$"
`

// r31ShellProgram is what the shell is asked to run: the recorded command
// string plus a trailing `wait`, which is what makes a backgrounded `$&`
// shape observable. It is a no-op for every other row and does not change
// how the shell parses the command above it.
func r31ShellProgram(cmd string) string { return cmd + "\nwait\n" }

// r31Expand substitutes the stub path for every %s in a template. A plain
// ReplaceAll rather than Sprintf: a row that names the stub twice and a row
// that names it once must both expand, and Sprintf reports an argument
// mismatch as literal "%!(EXTRA …)" text inside the command.
func r31Expand(tmpl, stub string) string {
	return strings.ReplaceAll(tmpl, "%s", stub)
}

// r31StubPath writes the argv stub and returns its path.
func r31StubPath(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "argv-stub")
	if err := os.WriteFile(p, []byte(r31Stub), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// r31Groups runs prog through /bin/sh with the stub's log pointed at a
// fresh directory and returns the argv groups it recorded. The exit status
// is deliberately ignored: a shape whose second command is not the stub
// exits 127, and that is part of the point. A shell that refuses the
// command outright records nothing.
func r31Groups(t *testing.T, prog string) [][]string {
	t.Helper()
	dir := t.TempDir()
	prefix := "argv"
	c := exec.Command("/bin/sh", "-c", prog)
	c.Env = append(os.Environ(),
		"R31_STUB_LOG="+filepath.Join(dir, prefix))
	c.Stdout, c.Stderr = io.Discard, io.Discard
	_ = c.Run()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading the stub log directory: %v", err)
	}
	var names []string
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), prefix+".") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	var groups [][]string
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatalf("reading %s: %v", n, err)
		}
		// The whole file is ONE invocation: its marker, then one
		// NUL-terminated element per argv entry (an EMPTY element is
		// still an element, hence the split after dropping the last
		// NUL).
		if len(b) == 0 || b[0] != 1 {
			t.Fatalf("the stub log %s = %q: not one marked group",
				n, b)
		}
		groups = append(groups, strings.Split(
			strings.TrimSuffix(string(b[1:]), "\x00"), "\x00"))
	}
	return groups
}

// r31ArgvMatches compares one lexed token stream with one recorded argv.
// A KNOWN token must equal the shell's element byte for byte, quote removal
// included, and an UNKNOWN one must stand exactly where a substituted
// element stands — the counts agree, so a token that SWALLOWED the
// character after a '$' changes the count and fails here (that is what
// makes this a differential for F1 rather than a shape check). Only the
// rows that set dropEmpty relax it, for the one case the parse genuinely
// cannot know: an unquoted expansion that comes out empty produces NO word
// at all (`stub --match-path ${x};` hands the stub ONE element on this box),
// while the same expansion quoted, or non-empty, produces one.
func r31ArgvMatches(toks []shToken, argv []string, dropEmpty bool) (string, bool) {
	if dropEmpty {
		if r31MatchUnknown(toks, argv) {
			return "", true
		}
		return fmt.Sprintf("%d tokens vs %d argv elements", len(toks),
			len(argv)), false
	}
	if len(toks) != len(argv) {
		return fmt.Sprintf("%d tokens vs %d argv elements", len(toks),
			len(argv)), false
	}
	for i, tk := range toks {
		if !tk.unknown && tk.text != argv[i] {
			return fmt.Sprintf("token %d = %q, shell argv %d = %q",
				i, tk.text, i, argv[i]), false
		}
	}
	return "", true
}

// r31MatchUnknown is the (small) backtracking matcher behind
// r31ArgvMatches: a known token consumes one equal element, an unknown one
// consumes zero or one.
func r31MatchUnknown(toks []shToken, argv []string) bool {
	if len(toks) == 0 {
		return len(argv) == 0
	}
	if toks[0].unknown {
		if r31MatchUnknown(toks[1:], argv) {
			return true
		}
		return len(argv) > 0 && r31MatchUnknown(toks[1:], argv[1:])
	}
	return len(argv) > 0 && toks[0].text == argv[0] &&
		r31MatchUnknown(toks[1:], argv[1:])
}

// r31GroupMatch finds the group a token stream must equal and reports the
// closest mismatch when none matches.
func r31GroupMatch(toks []shToken, groups [][]string, dropEmpty bool) (string, bool) {
	var misses []string
	for _, g := range groups {
		if why, ok := r31ArgvMatches(toks, g, dropEmpty); ok {
			return "", true
		} else {
			misses = append(misses, fmt.Sprintf("%q: %s", g, why))
		}
	}
	sort.Strings(misses)
	return strings.Join(misses, "; "), false
}

// TestR31DollarIsLexedTheShellsWay is F1's differential: every row's
// command is run through /bin/sh with a stub that records its argv, and
// Go's lexer must produce exactly that argv. OBSERVED on this box
// (/bin/sh -> bash 5.x; `<stub>` stands for the stub path):
//
//	<stub> --match-path $; <stub> M         -> TWO COMMANDS: (--match-path $) ; (M)
//	<stub> --match-path $& <stub> M         -> TWO COMMANDS: the first backgrounded
//	<stub> --match-path $| <stub> M         -> PIPELINE: (--match-path $) | (M)
//	<stub> --match-path $<newline><stub> M  -> TWO COMMANDS
//	<stub> --contract $ --loop-bound 7      -> --contract $ --loop-bound 7
//	<stub> --contract $<TAB>--loop-bound 7  -> --contract $ --loop-bound 7
//	<stub> --match-path $$;                 -> --match-path  2718565
//	<stub> --match-path ${x};               -> --match-path  (empty: the
//	                                           unquoted expansion produces
//	                                           NO element)
//	<stub> --match-path $(x);               -> --match-path  (empty too)
//	<stub> --match-path $1;                 -> --match-path  (empty too)
//	<stub> a$; <stub> b                     -> TWO COMMANDS: (a$) ; (b)
//	<stub> a$ b                             -> a$  b
//	<stub> --match-path $                   -> --match-path  $
//	<stub> --solc-path $'x --loop-bound 7'  -> --solc-path  x --loop-bound 7
//	<stub> --solc-path $"x --loop-bound 7"  -> --solc-path  x --loop-bound 7
//	<stub> --solc-path $\'x --loop-bound 7' -> the shell itself fails
//	                                           (unexpected EOF while
//	                                           looking for matching ')
//
// MUTATION (restore the r29/r30 default arm,
// `return string(rs[i:i+2]), i+1, ""`) — OBSERVED: eleven differential rows
// fail, in three shapes, plus the two e2e tests.
//
//   - the SEPARATOR shapes (`$;`, `$&`, `$|`, `$<newline>`, `a$;b`): the
//     shell ran two commands and the parse reads one, so it returns tokens
//     where it must refuse a command list;
//   - the WORD shapes (`$ `, `$<TAB>`, `a$ `): a swallowed space merges two
//     words, so 3 tokens stand where the shell handed over 2;
//   - the QUOTE shapes, in BOTH directions: `$'` and `$"` make the parse
//     refuse a command /bin/sh parses ("unmatched single quote" /
//     "unmatched double quote"), while `$\'` makes it ACCEPT a command the
//     shell refuses outright (its own "unexpected EOF").
//
// The two `$'…'` / `$"…"` rows are the ONE place this box's /bin/sh
// disagrees with the POSIX rule the parse models: bash's ANSI-C and locale
// quoting consume the quote pair and DROP the '$' (`x --loop-bound 7`),
// while POSIX — and so this parse — reads a literal '$' and a plain quoted
// region (`$x --loop-bound 7`). Both readings are ONE argv element that is
// not an option, so the bound decision is identical; those two rows
// therefore pin the POSIX text (r31 F1's required rule) and compare only
// the element COUNT against bash's argv. POSIX is the fail-closed reading:
// bash's extra '$'-dropping can only make a value look MORE like an integer
// (and so more blessable) than the literal reading does.
func TestR31DollarIsLexedTheShellsWay(t *testing.T) {
	stub := r31StubPath(t)
	for _, tc := range []struct {
		name string
		// cmd is the recorded command, %s = the stub path (twice where a
		// second command runs).
		cmd string
		// first is the FIRST command in cmd, the one the parse must read
		// token-for-token; %s = the stub path.
		first string
		// groups is the number of argv groups the shell must record.
		groups int
		// posix, when set, is the argv this parse must produce for the
		// divergent quote rows (bash drops the '$').
		posix []string
		// dropEmpty allows an unknown token to stand for NO element:
		// this box's shell drops an unquoted EMPTY expansion, so the
		// parse's one token has no argv counterpart (see
		// r31ArgvMatches). Set only where the expansion really is empty.
		dropEmpty bool
	}{
		{name: "a separator after a literal $ still separates ($; ends the command)",
			cmd:   "%s --match-path $; %s M",
			first: "%s --match-path $", groups: 2},
		{name: "a literal $ before & does not hide the background operator",
			cmd:   "%s --match-path $& %s M",
			first: "%s --match-path $", groups: 2},
		{name: "a literal $ before | leaves a pipeline, not one token",
			cmd: "%s --match-path $| %s M", first: "%s --match-path $",
			groups: 2},
		{name: "a literal $ before a newline leaves a command list",
			cmd:   "%s --match-path $\n%s M",
			first: "%s --match-path $", groups: 2},
		{name: "a space after $ separates words (the mirror direction)",
			cmd:   "%s --contract $ --loop-bound 7",
			first: "%s --contract $ --loop-bound 7", groups: 1},
		{name: "a TAB after $ separates words too",
			cmd:   "%s --contract $\t--loop-bound 7",
			first: "%s --contract $\t--loop-bound 7", groups: 1},
		{name: "$ before a single quote opens a plain quoted region",
			cmd:    "%s --solc-path $'x --loop-bound 7'",
			first:  "%s --solc-path $'x --loop-bound 7'",
			groups: 1,
			posix:  []string{"--solc-path", "$x --loop-bound 7"}},
		{name: "$ before a double quote opens a plain quoted region",
			cmd:    `%s --solc-path $"x --loop-bound 7"`,
			first:  `%s --solc-path $"x --loop-bound 7"`,
			groups: 1,
			posix:  []string{"--solc-path", "$x --loop-bound 7"}},
		{name: "$ before a backslash escapes, so a free quote is an error in both readings",
			cmd:    `%s --solc-path $\'x --loop-bound 7'`,
			first:  `%s --solc-path $\'x --loop-bound 7'`,
			groups: 0},
		{name: "$$ is a special parameter, then ';' separates",
			cmd: "%s --match-path $$;", first: "%s --match-path $$;",
			groups: 1},
		{name: "${x} is an expansion, then ';' separates",
			cmd:   "%s --match-path ${x};",
			first: "%s --match-path ${x};", groups: 1,
			dropEmpty: true},
		{name: "$(x) is a command substitution, then ';' separates",
			cmd:   "%s --match-path $(x);",
			first: "%s --match-path $(x);", groups: 1,
			dropEmpty: true},
		{name: "$1 is a positional parameter, then ';' separates",
			cmd:   "%s --match-path $1;",
			first: "%s --match-path $1;", groups: 1,
			dropEmpty: true},
		{name: "a$;b is a command list: the $ does not hide the ';'",
			cmd: "%s a$; %s b", first: "%s a$", groups: 2},
		{name: "a trailing $ is one literal character of the word",
			cmd: "%s --match-path $", first: "%s --match-path $",
			groups: 1},
		{name: "a$ before a space: two words, the $ staying on the first",
			cmd: "%s a$ b", first: "%s a$ b", groups: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := r31Expand(tc.cmd, stub)
			groups := r31Groups(t, r31ShellProgram(cmd))
			if len(groups) != tc.groups {
				t.Fatalf("the shell recorded %d argv groups (%q), "+
					"want %d", len(groups), groups, tc.groups)
			}
			// The WHOLE command is what the shell really ran, so the
			// parse's verdict on the whole string must match the
			// shell's structure: more than one argv group means a
			// command list, which must be REFUSED (a parse that reads
			// one command there is the F1 swallow, and no argv
			// comparison of the first command alone can see it).
			allToks, allConstruct := lexCommand(cmd)
			if tc.groups > 1 && allConstruct == "" {
				t.Fatalf("the shell split %q into %d commands, but "+
					"the parse read it as one (tokens %q)", cmd,
					tc.groups, tokensText(allToks))
			}
			if tc.groups == 1 && allConstruct != "" {
				t.Fatalf("the shell ran %q as ONE command, the parse "+
					"refused it: %s", cmd, allConstruct)
			}
			first := r31Expand(tc.first, stub)
			toks, construct := lexCommand(first)
			if tc.groups == 0 {
				// The shell refused the command: the parse must
				// refuse it too, never guess an argv.
				if construct == "" {
					t.Fatalf("the shell refused %q but the parse "+
						"produced %q", first, tokensText(toks))
				}
				return
			}
			if construct != "" {
				t.Fatalf("lexCommand(%q) = %q, want the argv the "+
					"shell handed over: %q", first, construct,
					groups)
			}
			if tc.posix != nil {
				if why, ok := r31ArgvMatches(toks[1:], tc.posix, false); !ok {
					t.Fatalf("lexCommand(%q) = %q, want the POSIX "+
						"reading %q (%s)", first,
						tokensText(toks), tc.posix, why)
				}
				if len(toks[1:]) != len(groups[0]) {
					t.Fatalf("bash read %q, POSIX %q: the element "+
						"count must still agree", groups[0],
						tc.posix)
				}
				return
			}
			if why, ok := r31GroupMatch(toks[1:], groups, tc.dropEmpty); !ok {
				t.Fatalf("lexCommand(%q) = %q, but the shell handed "+
					"over %q (%s)", first, tokensText(toks),
					groups, why)
			}
		})
	}
}

// tokensText renders a lexed stream for a failure message (the parse's own
// view, unknown tokens marked).
func tokensText(toks []shToken) []string {
	out := make([]string, 0, len(toks))
	for _, t := range toks {
		if t.unknown {
			out = append(out, t.text+"(?)")
			continue
		}
		out = append(out, t.text)
	}
	return out
}

// r31ExecRecord is the exec-record shape the bind and section 11 both read:
// a command, a clean exit status and no recorded harness hash — the unbound
// arm of DecideBound, which is the arm the auditor's forged record was in.
func r31ExecRecord(command string) validation.Value {
	return rdRecord(
		validation.KV{K: "exec_id", V: validation.VStr("EXEC-1")},
		validation.KV{K: "command", V: validation.VStr(command)},
		validation.KV{K: "exit_status", V: validation.VInt(0)})
}

// ---------------------------------------------------------------------
// F1: the end-to-end pin — the '$;' forge record can no longer bless k=500
// ---------------------------------------------------------------------

// TestR31DollarSeparatorRecordNoLongerBlesses is F1's end-to-end half: the
// auditor's forged record — a two-command string whose FIRST command never
// saw `--fuzz-runs` at all — must floor as a command list, through the ONE
// decision entry point the bind and section 11 share, whatever the stdout
// says. The control pins that the same bytes DO bless under a readable
// invocation, so the floor is the only thing between the record and a
// blessing.
//
// MUTATION (restore the r29/r30 default arm): `$;` becomes one token, the
// command reads as a single forge invocation with --fuzz-runs 500, and this
// test's first assertion reports k=500 instead of BoundUnreadable (the
// auditor's exact signature: "proved-bounded (forge-fuzz, k=500)" and an
// audit that re-derives the same blessing).
func TestR31DollarSeparatorRecordNoLongerBlesses(t *testing.T) {
	stub := r31StubPath(t)
	const forged = "forge test --match-path $; --fuzz-runs 500"
	k, why := InvocationBoundReason(forged)
	if k != BoundUnreadable {
		t.Fatalf("InvocationBoundReason(%q) = (%d, %q), want "+
			"BoundUnreadable: the '$' is literal and the ';' is a "+
			"separator, so the trailing --fuzz-runs was never part of "+
			"the first command", forged, k, why)
	}
	if !strings.Contains(why, "command list (separator ';')") {
		t.Fatalf("the floor must name the separator, got %q", why)
	}
	// Shell evidence for this exact string: the first command's argv ends
	// at the ';' and a SECOND command follows, so nothing ever ran a
	// forge under --fuzz-runs 500. (The stub stands in for forge; the
	// second command is not the stub, so no group is recorded for it.)
	groups := r31Groups(t, r31ShellProgram(
		r31Expand("%s test --match-path $; --fuzz-runs 500", stub)))
	if len(groups) != 1 || len(groups[0]) != 3 {
		t.Fatalf("shell argv for the first command = %q, want one "+
			"3-element command", groups)
	}
	rec := r31ExecRecord(forged)
	rung, summary, proof, bk := DecideBound(ForgeFuzz, validation.VNull(),
		[]byte(forgePass), rec, nil, false, k, 0, "INV-1")
	if rung != RungInconclusive {
		t.Fatalf("an unreadable invocation bound %q: %q", rung, summary)
	}
	if bk != nil {
		t.Fatalf("no bounded_k may ride the floor: %d", *bk)
	}
	if proof.Kind != validation.Null {
		t.Fatalf("no sidecar may ride the floor: %s",
			validation.CanonCompact(proof))
	}
	// The bind's floor summary for halmos/forge is byte-pinned to the
	// class wording (DecideBound hands the construct only to the
	// minicertora arm), so this asserts the class; the construct-bearing
	// wording is pinned two lines down through MapRun, which is the same
	// mapper with the reason supplied.
	if !strings.Contains(summary, "degenerate-bound") ||
		!strings.Contains(summary, "invocation-unreadable") {
		t.Fatalf("the floor must keep the disposition vocabulary: %q",
			summary)
	}
	if _, withWhy := MapRun(ForgeFuzz, []byte(forgePass), false, k, why); !strings.Contains(
		withWhy, "invocation-unreadable: "+oneLine(why, maxConstruct)) {
		t.Fatalf("the construct-bearing floor must name the separator: %q",
			withWhy)
	}
	// Section 11 re-derives through this same parse over the record's own
	// command, so it cannot hold a second opinion about this record.
	if got := InvocationBound(RecordCommand(rec)); got != k {
		t.Fatalf("the audit's parse = %d, the bind's = %d", got, k)
	}
	// Control: an honest forge command binds its 500 end to end.
	const okCmd = "forge test --match-path tests/Inv.t.sol --fuzz-runs 500"
	ok := InvocationBound(okCmd)
	if ok != 500 {
		t.Fatalf("control: InvocationBound(%q) = %d, want 500", okCmd, ok)
	}
	okRung, okSum, _, okBK := DecideBound(ForgeFuzz, validation.VNull(),
		[]byte(forgePass), r31ExecRecord(okCmd), nil, false, ok, 0,
		"INV-1")
	if okRung != RungProvedBounded || okBK == nil || *okBK != 500 ||
		!strings.Contains(okSum, "proved bounded (k=500)") {
		t.Fatalf("control: %q %q %v", okRung, okSum, okBK)
	}
}

// TestR31DollarMirrorAndQuoteHalvesCloseTheOtherTwoSymptoms pins F1's (b)
// and (c): the two directions the same swallow broke.
//
// (b) `--contract $ --loop-bound 7` — the r30 parse swallowed the SPACE,
// merged `$ --loop-bound` into one token and reported 0/unstated, while
// /bin/sh ran the command with --loop-bound 7 (the twin's click binds 7 the
// same way). The mirror direction is a ledger lie: it under-reports a bound
// that was really stated.
//
// (c) `--solc-path $'x --loop-bound 7'` — the r30 parse swallowed the
// OPENING quote, so the CLOSING quote opened a region and the whole command
// was refused as "unmatched single quote" for a command /bin/sh parses
// fine (this box: one word `x --loop-bound 7`).
//
// MUTATION (restore the r29/r30 default arm): the space row reads 0, and
// the quote row reports BoundUnreadable/"unmatched single quote".
func TestR31DollarMirrorAndQuoteHalvesCloseTheOtherTwoSymptoms(t *testing.T) {
	stub := r31StubPath(t)
	const mirror = "miniprover run --contract $ --loop-bound 7"
	if got := InvocationBound(mirror); got != 7 {
		t.Fatalf("InvocationBound(%q) = %d, want 7: the space after the "+
			"literal '$' separates words, so --loop-bound 7 is the real "+
			"invocation", mirror, got)
	}
	groups := r31Groups(t, r31ShellProgram(
		r31Expand("%s --contract $ --loop-bound 7", stub)))
	if len(groups) != 1 {
		t.Fatalf("shell argv groups = %q, want one command", groups)
	}
	if want := []string{"--contract", "$", "--loop-bound", "7"}; !reflect_Equal(groups[0], want) {
		t.Fatalf("shell handed over %q, want %q", groups[0], want)
	}
	// The other direction of the same case: no bound flag at all, so 0
	// (UNSTATED) — never a value invented out of the '$'.
	if got := InvocationBound("miniprover run --project-root $"); got != 0 {
		t.Fatalf("a literal '$' names no bound: %d", got)
	}
	const quoted = "minicertora V.sol INV.mspec --solc-path $'x --loop-bound 7'"
	if k, why := InvocationBoundReason(quoted); k != 0 || why != "" {
		t.Fatalf("InvocationBoundReason(%q) = (%d, %q): the '$' is "+
			"literal and the quote opens a plain region, so this is one "+
			"value and the invocation names no bound", quoted, k, why)
	}
	// The double-quoted mirror of (c): `$` before the CLOSING quote is
	// literal, so `"a$"` is one word ending in '$' — the r30 parse
	// swallowed the quote and refused the command as an unmatched double
	// quote.
	const dq = `miniprover run --solc-path "a$" --loop-bound 4`
	if k, why := InvocationBoundReason(dq); k != 4 || why != "" {
		t.Fatalf("InvocationBoundReason(%q) = (%d, %q), want 4: a literal "+
			"'$' before the closing quote is one word, not an unmatched "+
			"quote", dq, k, why)
	}
	// And a real expansion inside double quotes stays an expansion: a
	// digit after '$' IS a positional parameter, so the value is not
	// derivable and the run floors (never a guessed number).
	if k, why := InvocationBoundReason(
		`miniprover run --loop-bound "$4"`); k != BoundUnreadable ||
		!strings.Contains(why, "shell expansion in the --loop-bound "+
			"value ($4)") {
		t.Fatalf("`\"$4\"` = (%d, %q): $4 is a positional parameter, not "+
			"a literal '$' followed by 4", k, why)
	}
}

// reflect_Equal is a local slice equality (the file deliberately avoids a
// reflect import for one comparison).
func reflect_Equal(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------
// F2: the int64 range is a legal stated bound; beyond it, a lower bound
// ---------------------------------------------------------------------

// TestR31BoundRangeIsExactToInt64 pins the boundary the r28 guard got
// wrong: it rejected anything above 2^62, so MaxInt64 — which FITS in
// int64 and which Python's unbounded int/click accept — was read as "no
// bound was stated", and a record under it rendered "proved bounded (bound
// UNSTATED)" with a null bounded_k while the tool really ran under
// 9223372036854775807.
//
// MUTATION (restore `if n > 1<<62 { return 0, fmt.Errorf(...) }` in
// atoiClamped / the 1<<62 clamp in parseClickInt): the 2^62+1, MaxInt64,
// MaxInt64+1 and 2^100 rows all report 0 (UNSTATED) instead of their
// stated answers, and the halmos marker rows report the invocation's
// fallback instead of the marker.
func TestR31BoundRangeIsExactToInt64(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
		want  int
	}{
		{"2^62 (the old guard's own boundary)", "4611686018427387904",
			1 << 62},
		{"2^62+1 (one past it, still an int64)", "4611686018427387905",
			1<<62 + 1},
		{"MaxInt64 is a legal stated bound, not an overflow",
			"9223372036854775807", math.MaxInt64},
		{"MaxInt64+1 fits no int64: saturated, never UNSTATED",
			"9223372036854775808", BoundCapped},
		{"2^100", "1267650600228229401496703205376", BoundCapped},
		{"MinInt64 is stated and below 1, so it is degenerate",
			"-9223372036854775808", BoundDegenerate},
		{"MinInt64-1 is below 1 too", "-9223372036854775809",
			BoundDegenerate},
	} {
		for _, form := range []string{
			"forge test --fuzz-runs ",
			"forge test --fuzz-runs=",
			"halmos check --loop ",
			"halmos check --loop=",
			"miniprover run --loop-bound ",
			"miniprover run --loop-bound=",
		} {
			t.Run(tc.name+" / "+strings.TrimSpace(form), func(t *testing.T) {
				if got := InvocationBound(form + tc.value); got != tc.want {
					t.Fatalf("InvocationBound(%q) = %d, want %d",
						form+tc.value, got, tc.want)
				}
			})
		}
	}
	// Parse level, so the failure names the reader rather than the
	// caller: the value comes back EXACTLY inside int64 and saturates
	// past it.
	for _, tc := range []struct {
		value string
		want  int
		stat  intParse
	}{
		{"4611686018427387905", 1<<62 + 1, intOK},
		{"9223372036854775807", math.MaxInt64, intOK},
		{"9223372036854775808", 0, intOverflowPositive},
		{"-9223372036854775808", math.MinInt64, intOK},
		{"-9223372036854775809", 0, intOverflowNegative},
		{"0", 0, intOK},
		{"0009", 9, intOK},
	} {
		got, stat := parseClickInt(tc.value)
		if stat != tc.stat || (stat == intOK && got != tc.want) {
			t.Fatalf("parseClickInt(%q) = (%d, %v), want (%d, %v)",
				tc.value, got, stat, tc.want, tc.stat)
		}
	}
}

// TestR31StatedBoundIsNeverRenderedUnstated is F2's end-to-end pin: a
// stated bound at the top of int64 records a STATED bound (not null, not
// "UNSTATED"), and one past int64 records the saturating stand-in with a
// summary that says LOWER bound — so the bytes never assert a smaller
// exact number than the tool ran under.
//
// MUTATION (restore the r28 intOverflowPositive arm, `return 0, ""`): the
// MaxInt64 row renders "proved bounded (bound UNSTATED)" with a nil
// bounded_k, and the widened row does the same.
func TestR31StatedBoundIsNeverRenderedUnstated(t *testing.T) {
	const max = "9223372036854775807"
	cmd := "forge test --fuzz-runs " + max
	k := InvocationBound(cmd)
	if k != math.MaxInt64 {
		t.Fatalf("InvocationBound(%q) = %d, want MaxInt64", cmd, k)
	}
	rung, summary, _, bk := DecideBound(ForgeFuzz, validation.VNull(),
		[]byte(forgePass), r31ExecRecord(cmd), nil, false, k, 0, "INV-1")
	if rung != RungProvedBounded {
		t.Fatalf("a stated MaxInt64 bound must bind: %q %q", rung, summary)
	}
	if bk == nil || *bk != math.MaxInt64 {
		t.Fatalf("bounded_k = %v, want %d (a stated bound, never null)",
			bk, math.MaxInt64)
	}
	if !strings.Contains(summary, "proved bounded (k="+max+")") ||
		strings.Contains(summary, "UNSTATED") {
		t.Fatalf("summary = %q, want the stated MaxInt64 bound", summary)
	}
	// Beyond int64: the same saturating stand-in, said as a lower bound.
	const wide = "99999999999999999999999999"
	wk := InvocationBound("forge test --fuzz-runs " + wide)
	if wk != BoundCapped || BoundFloors(wk) {
		t.Fatalf("a bound wider than int64 is STATED (capped), not a "+
			"floor: %d floors=%v", wk, BoundFloors(wk))
	}
	wRung, wSummary, _, wBK := DecideBound(ForgeFuzz, validation.VNull(),
		[]byte(forgePass), r31ExecRecord("forge test --fuzz-runs "+wide),
		nil, false, wk, 0, "INV-1")
	if wRung != RungProvedBounded || wBK == nil || *wBK != math.MaxInt64 {
		t.Fatalf("capped record = %q %q %v, want proved-bounded with "+
			"bounded_k %d", wRung, wSummary, wBK, math.MaxInt64)
	}
	if !strings.Contains(wSummary, "proved bounded (k>="+max+")") {
		t.Fatalf("a capped bound must render as a LOWER bound: %q",
			wSummary)
	}
	if strings.Contains(wSummary, "UNSTATED") {
		t.Fatalf("a capped bound is stated: %q", wSummary)
	}
	// The halmos marker half: the output's own k=<n> is the run's
	// statement, so a marker past int64 saturates identically.
	wideMarker := strings.Replace(halmosProvedK, "k=100",
		"k=9223372036854775808", 1)
	mRung, mSummary := MapRun(Halmos, []byte(wideMarker), false, 0)
	if mRung != RungProvedBounded ||
		!strings.Contains(mSummary, "k>="+max) {
		t.Fatalf("a wider k= marker = %q %q, want a lower-bound "+
			"blessing", mRung, mSummary)
	}
	if got := BoundK(Halmos, []byte(wideMarker), 0); got != math.MaxInt64 {
		t.Fatalf("the marker's bounded_k = %d, want the saturating %d",
			got, math.MaxInt64)
	}
	// No rendering may print the sentinel itself.
	if _, s := MapRun(ForgeFuzz, nil, true, BoundCapped); strings.Contains(
		s, "-3") {
		t.Fatalf("the timeout wording must not print the sentinel: %q", s)
	}
}

// TestR31BoundFromFlagsBeyondInt64RefusalStays records r31 F2(3): the
// refusal of an out-of-int64 loop_bound is CORRECT and stays — the value
// cannot be held by the Go slot — but the REASON string it carries is a
// finding this round could not close. reportmap.go owns that string
// ("is %d — the twin refuses degenerate bounds (<1; a k=0 'proof' checks
// only the initial state)") and is outside this round's file ownership, so
// it reads v.I, which is 0 whenever the exact digits live in the value's
// Big field: for loop_bound 9223372036854775808 it reports "is 0", a value
// that is neither zero nor degenerate — the twin would run under it.
//
// This test therefore pins the REFUSAL half (which is in scope) and
// deliberately does NOT pin the false wording, so the future fix in
// reportmap.go needs no edit here.
func TestR31BoundFromFlagsBeyondInt64RefusalStays(t *testing.T) {
	flags := validation.VObj(validation.KV{K: "loop_bound",
		V: validation.VBigInt("9223372036854775808")})
	k, stated, ok, why := BoundFromFlags(flags)
	if k != 0 || stated || ok {
		t.Fatalf("BoundFromFlags(big) = (%d, %v, %v, %q), want a "+
			"refusal", k, stated, ok, why)
	}
	if why == "" {
		t.Fatal("a refusal must carry a reason")
	}
	// The reason the frozen reportmap.go produces today, for the record
	// (OBSERVED, not pinned): it describes a value that is neither zero
	// nor degenerate as "is 0 — the twin refuses degenerate bounds".
	t.Logf("frozen BoundFromFlags refusal reason: %q", why)
	// What the reason SAYS today (pinned nowhere, so the owning round can
	// reword it freely): "is 0 — the twin refuses degenerate bounds (<1;
	// a k=0 'proof' checks only the initial state)" — false for this
	// value, which is 9223372036854775808: not 0, and not below 1.
}

// ---------------------------------------------------------------------
// F3: option arity is not guessed
// ---------------------------------------------------------------------

// TestR31OptionArityIsNotGuessed is F3's end-to-end pin. The class the
// auditor found is OPTION ARITY: an option whose value slot is really a
// flag or a positional. Without the owning tool's table the parse cannot
// tell whether the first option EATS the second, and the two readings
// disagree about the bound itself — click's reading refuses the whole
// invocation, a flag's reading binds the number that follows — so the argv
// is not derivable and the parse floors as unreadable, naming the pair.
// Every row's command was checked against the twin's own click CLI
// (miniprover/.venv, click 8.5.0): each is refused before a run starts.
//
// MUTATION (delete the ambiguousOptionArity call at the top of
// boundFromArgv): the first row binds k=500, the second k=4 and the third
// k=4 — a bound for an invocation no tool ran — which is the auditor's
// exact signature for this finding.
func TestR31OptionArityIsNotGuessed(t *testing.T) {
	rows := []struct {
		name    string
		command string
		wantWhy string
		// mc drives the row through the minicertora arm, the one arm
		// whose stored floor carries the construct as well as the class
		// (DecideBound hands the reason only to MapMinicertoraInvoc).
		mc bool
	}{
		{"forge: a value-slot option followed by the bound flag",
			"forge test --timeout-ms --fuzz-runs 500",
			"option arity is ambiguous (--timeout-ms followed by " +
				"--fuzz-runs)", false},
		{"the auditor's minicertora spelling",
			"minicertora V.sol INV.mspec --contract --loop-bound 4",
			"option arity is ambiguous (--contract followed by " +
				"--loop-bound)", true},
		{"the `--` terminator followed by an option-looking token",
			"miniprover run --loop-bound 4 -- --loop-bound 0",
			"option arity is ambiguous (-- followed by --loop-bound)",
			false},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			k, why := InvocationBoundReason(tc.command)
			if k != BoundUnreadable || !BoundFloors(k) {
				t.Fatalf("InvocationBoundReason(%q) = (%d, %q), want "+
					"BoundUnreadable with a construct", tc.command,
					k, why)
			}
			if why != tc.wantWhy {
				t.Fatalf("construct = %q, want %q", why, tc.wantWhy)
			}
			kind, rule := ForgeFuzz, "INV-1"
			raw, inv := []byte(forgePass), validation.VNull()
			if tc.mc {
				kind, rule = MiniCertora, "inv_1"
				raw = []byte(mcProven)
				inv = rdInv("total always covers sum(payouts)")
			}
			// End to end: the bytes under it must not bless, and no
			// bounded_k may ride the floor.
			rung, summary, proof, bk := DecideBound(kind, inv, raw,
				r31ExecRecord(tc.command), nil, false, k, 0, rule)
			if rung != RungInconclusive || bk != nil ||
				proof.Kind != validation.Null {
				t.Fatalf("an underivable arity bound %q: %q %v %s",
					rung, summary, bk,
					validation.CanonCompact(proof))
			}
			want := "invocation-unreadable"
			if tc.mc {
				want = "invocation-unreadable: " + oneLine(why,
					maxConstruct)
			}
			if !strings.Contains(summary, "degenerate-bound") ||
				!strings.Contains(summary, want) {
				t.Fatalf("the floor must name the ambiguity: %q",
					summary)
			}
		})
	}
}

// TestR31HonestAritiesStillMap pins the other direction of the same rule:
// the arity floor must not swallow commands whose option structure IS
// derivable. A plain value, positional arguments, an unknown non-option
// token, an inline `=value` and a bound flag's own (known) arity all keep
// their bound.
func TestR31HonestAritiesStillMap(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command string
		want    int
	}{
		{"the documented minicertora invocation: plain value options",
			"minicertora V.sol INV.mspec --solc-path /usr/bin/solc " +
				"--loop-bound 4 --timeout-ms 30000", 4},
		{"positional arguments after a bound flag",
			"miniprover run --loop-bound 4 tests/Inv.t.sol", 4},
		{"an unknown non-option token",
			"miniprover run --match-path tests/Inv.t.sol " +
				"--loop-bound 4", 4},
		{"two positionals (the twin's own documented shape)",
			"minicertora V.sol INV.mspec --loop-bound 4", 4},
		{"an option carrying its value inline has no arity question",
			"miniprover run --solc-path=/abs/solc --loop-bound 4", 4},
		{"a bound flag's arity is known: the next element is its value",
			"miniprover run --loop-bound 4 --loop-bound 8", 8},
		{"a bound flag eats an option-looking value, and click refuses",
			"miniprover run --loop-bound --loop-bound 4",
			BoundDegenerate},
		{"a glob-valued option is a plain value, not an arity question",
			"forge test --match-test test_* --fuzz-runs 256", 256},
		{"a tilde-valued option likewise",
			"miniprover run --solc-path ~/bin/solc --loop-bound 4", 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := InvocationBound(tc.command); got != tc.want {
				t.Fatalf("InvocationBound(%q) = %d, want %d",
					tc.command, got, tc.want)
			}
		})
	}
	// The conservative direction, pinned as such rather than hidden: an
	// option that MIGHT take a value and is followed by an option floors
	// an honest run too (halmos's -v is a real boolean flag), because
	// without the owning tool's table the parse cannot tell a flag from a
	// value slot. Flooring an honest run is the safe direction — the
	// reference reading would bless a bound for an invocation one of the
	// family's tools refuses — and docs/MINIPROVER_INTEGRATION.md states
	// it.
	for _, cmd := range []string{
		"halmos check -v --loop 100",
		"forge test --ffi --fuzz-runs 500",
	} {
		k, why := InvocationBoundReason(cmd)
		if k != BoundUnreadable || !strings.Contains(why,
			"option arity is ambiguous") {
			t.Fatalf("InvocationBoundReason(%q) = (%d, %q): a flag "+
				"followed by an option is the conservative floor",
				cmd, k, why)
		}
	}
}

// TestR31bRangeRefusalNamesTheExactDigits pins the corrected reason: a
// report whose stated bound exceeds int64 must not be described as a
// degenerate 0 - the digits are what the twin would have run under.
func TestR31bRangeRefusalNamesTheExactDigits(t *testing.T) {
	flags := validation.VObj(validation.KV{K: "loop_bound",
		V: validation.VBigInt("9999999999999999999")})
	k, stated, ok, why := BoundFromFlags(flags)
	if k != 0 || stated || ok {
		t.Fatalf("an out-of-range bound must stay a refusal: (%d, %v, %v, %q)",
			k, stated, ok, why)
	}
	if !strings.Contains(why, "9999999999999999999") {
		t.Fatalf("the reason must quote the exact digits, got %q", why)
	}
	if strings.Contains(why, "is 0 ") {
		t.Fatalf("the reason must not claim a degenerate 0: %q", why)
	}
	if !strings.Contains(why, "wider than the int64 slot") {
		t.Fatalf("the reason must name the real state: %q", why)
	}
	neg := validation.VObj(validation.KV{K: "loop_bound",
		V: validation.VBigInt("-9999999999999999999")})
	if _, _, _, whyNeg := BoundFromFlags(neg); !strings.Contains(whyNeg,
		"degenerate bounds") {
		t.Fatalf("a negative big bound is degenerate, got %q", whyNeg)
	}
}
