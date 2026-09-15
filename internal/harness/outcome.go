// outcome.go: G8 outcome mapping (Task 18) — MapRun turns raw runner
// stdout into a rung (counterexample | proved-bounded | inconclusive) plus
// a one-line summary. Pure: no I/O, no attribution, no registry writes.
// The third kind, MiniCertora, emits JSON-lines verdicts instead of
// prose: MapMinicertora (minicertora.go) maps those under the same rung
// vocabulary and inherits both laws below.
//
// Fail-open-to-inconclusive law: a run that proves nothing must never
// promote OR demote, so every unmapped shape — empty output, mixed/noisy
// logs, contradictory signals — lands inconclusive, and proved-bounded
// additionally requires explicit bounded evidence (a k=<n> marker or the
// bounded flag text). Timeout always wins over output text: a killed run's
// bytes are partial by definition, so even a "Status: fail" fragment in
// them maps to inconclusive, never to a rung.
//
// Attribution (which EXEC belongs to which invariant) lives in
// `verify --harness-result`, never here: a stray halmos run must never be
// attributed to an invariant by guesswork.
package harness

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Rung values for verification.harness.rung.
const (
	RungCounterexample = "counterexample"
	RungProvedBounded  = "proved-bounded"
	RungInconclusive   = "inconclusive"
)

// maxExcerpt is the brief's ≤120-char cap on counterexample excerpts.
const maxExcerpt = 120

// kMarker finds halmos's bounded marker ("k=100", "k = 100").
var kMarker = regexp.MustCompile(`k\s*=\s*(\d+)`)

// BoundDegenerate is the bound a STATED-but-degenerate flag carries.
// The tools themselves refuse such invocations — halmos rejects
// --loop 0, forge rejects --fuzz-runs 0, and the miniprover twin's
// VerifierFlags.__post_init__ raises for loop_bound < 1 — so a record
// claiming a clean run under one describes something no tool can have
// executed. It is NOT "unstated" (0): that would let a k=0 rider print
// as a stated bound, and "proved bounded over zero executions" is a
// proof about nothing. MapRun therefore floors the WHOLE run (r26 F3:
// the r25 <1 floor lived only on the autoprove report path, while the
// real exec path still blessed `proved-bounded (forge-fuzz, k=0)`).
const BoundDegenerate = -1

// BoundUnreadable is the sentinel InvocationBound returns for a command
// string it cannot lex faithfully (r29 F4). It is NOT a guessed number
// and NOT "unstated": when the parse cannot derive the argv the tool
// received — an unmatched quote, a shell construct outside the modeled
// subset, an expansion sitting where an option could be — then no bound
// can be named, and the honest answer is that the invocation is
// unreadable, which floors the run exactly like a degenerate bound
// (BoundFloors). It is deliberately a value of its own: a caller that
// wants to word the floor differently must be able to tell the two
// apart, while every caller that only asks "does this floor?" uses
// BoundFloors and gets one answer for both.
//
// NOTE for the other floor sites: a test that reads `k == BoundDegenerate`
// catches a stated degenerate value but NOT this one. Ask BoundFloors(k)
// instead. MapMinicertoraInvoc (minicertora.go) was the one such site
// outside this file until r30 P1-1 widened it; every floor site now asks
// the one predicate, and a new one must too.
const BoundUnreadable = -2

// BoundFloors reports whether a parsed invocation bound floors the run:
// true for a STATED degenerate bound (BoundDegenerate) and for a command
// the parse could not read (BoundUnreadable). UNSTATED (0) and every
// stated N >= 1 do not floor — 0 is "the invocation named no bound", a
// display fact, never a boundary at which something ran.
func BoundFloors(k int) bool { return k < 0 }

// boundFloorSummary is the one-line reason a floored invocation carries.
// The "degenerate-bound" prefix is load-bearing: disposition.go
// classifies it (EscalateBound), and a distinct second wording class here
// would silently drop that advice. An unreadable invocation appends the
// construct that stopped the parse, so the summary names the exact
// observed state instead of only the class.
func boundFloorSummary(k int, unreadable ...string) string {
	const prefix = "inconclusive (degenerate-bound: "
	why := ""
	if len(unreadable) > 0 {
		why = oneLine(unreadable[0], maxConstruct)
	}
	if k == BoundUnreadable || why != "" {
		if why == "" {
			why = "the command could not be lexed faithfully"
		}
		return prefix + "invocation-unreadable: " + why + ")"
	}
	return prefix + "the invocation states no bound >= 1)"
}

// maxConstruct caps the construct a floor summary names, and oneLine
// forces it onto ONE line: a summary is a line, so a construct carrying a
// newline must not be able to forge a second one.
const maxConstruct = 60

// oneLine collapses s onto one line (control characters and newlines
// become spaces) and caps it at n runes.
func oneLine(s string, n int) string {
	return truncateRunes(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s), n)
}

// MapRun maps raw runner output to (rung, summary). kind selects the
// branch; timedOut forces inconclusive ("timeout after <k>s" — k is the
// caller-passed bound, never read from the wall); k is the bound the
// runner was invoked with (forge-fuzz proved-bounded carries it as
// bounded_k; halmos prefers a parsed k=<n> marker — see BoundK). Any
// FLOORING bound (BoundFloors: a stated bound below 1, or a command the
// invocation parse could not read at all) floors the run whatever the
// output says: no rung rides a bound no tool would have executed under.
//
// The optional unreadable argument is InvocationBoundReason's construct
// detail, so a caller that holds the command can make the stored floor
// name WHY the invocation could not be read ("invocation-unreadable:
// unmatched single quote") instead of only the class. Leaving it out is
// honest too: the summary then says the command could not be lexed
// faithfully, without pretending to a detail it was not given. Either
// way the summary keeps the "degenerate-bound" prefix disposition.go
// classifies as EscalateBound — a second wording class in that position
// would silently drop the advice (r29 F4).
func MapRun(kind Kind, out []byte, timedOut bool, k int,
	unreadable ...string) (rung string, summary string) {
	text := string(out)
	if timedOut {
		return RungInconclusive, fmt.Sprintf("timeout after %ds", k)
	}
	if BoundFloors(k) {
		return RungInconclusive, boundFloorSummary(k, unreadable...)
	}
	switch kind {
	case Halmos:
		return mapHalmos(text, k)
	case ForgeFuzz:
		return mapForgeFuzz(text, k)
	default:
		return RungInconclusive,
			fmt.Sprintf("inconclusive (unknown harness kind %q)",
				string(kind))
	}
}

// mapHalmos is the halmos branch: "Status: fail" plus a model/
// Counterexample block => counterexample (first block line, ≤120 chars);
// a success line ("Status: passed" / "Successfully proved") plus bounded
// evidence (k=<n> marker or the --loop bounded flag) => proved-bounded;
// anything else => inconclusive (never promote on partial text).
func mapHalmos(text string, k int) (string, string) {
	if hasStatusWord(text, "fail") {
		if line, ok := counterexampleLine(text); ok {
			return RungCounterexample,
				"counterexample: " + truncateRunes(line, maxExcerpt)
		}
		return RungInconclusive, "inconclusive (exit output unmapped)"
	}
	if hasStatusWord(text, "passed") || strings.Contains(text,
		"Successfully proved") {
		if n, ok := parseK(text); ok {
			// A marker that PARSES is not automatically evidence:
			// "k = 0" is the same degenerate statement the flag form
			// carries, and a blessing over zero iterations is a proof
			// about nothing (r26 F3).
			if n == BoundDegenerate {
				return RungInconclusive,
					"inconclusive (degenerate-bound: the run states " +
						"no bound >= 1)"
			}
			return RungProvedBounded,
				fmt.Sprintf("proved bounded (k=%d)", n)
		}
		if hasBoundedFlag(text) {
			n := BoundK(Halmos, []byte(text), k)
			if n < 1 {
				return RungProvedBounded,
					"proved bounded (bound UNSTATED)"
			}
			return RungProvedBounded,
				fmt.Sprintf("proved bounded (k=%d)", n)
		}
		return RungInconclusive, "inconclusive (exit output unmapped)"
	}
	return RungInconclusive, "inconclusive (exit output unmapped)"
}

// mapForgeFuzz is the forge-fuzz branch: a FAIL line with fuzz/seed
// context => counterexample (the seed line when present, else the FAIL
// line); a "---"/Suite-result summary line reading "1 passed" with
// "0 failed" and no FAIL line anywhere => proved-bounded (bounded_k is
// the k param); timed-out and everything else => inconclusive.
func mapForgeFuzz(text string, k int) (string, string) {
	failLine, hasFail := firstLineContaining(text, "FAIL")
	ctx := strings.Contains(strings.ToLower(text), "fuzz") ||
		strings.Contains(strings.ToLower(text), "seed")
	if hasFail && ctx {
		if seed, ok := firstLineContainingFold(text, "seed"); ok {
			return RungCounterexample,
				"counterexample: " + truncateRunes(seed, maxExcerpt)
		}
		return RungCounterexample,
			"counterexample: " + truncateRunes(failLine, maxExcerpt)
	}
	if !hasFail && forgePassSummary(text) {
		// r26 F3 mirror: forge's runs count rides the invocation, so an
		// invocation that named none states no bound — the summary must
		// say so rather than print a "k=0" nobody stated (F11's law:
		// a null bound renders UNSTATED).
		if k < 1 {
			return RungProvedBounded, "proved bounded (bound UNSTATED)"
		}
		return RungProvedBounded, fmt.Sprintf("proved bounded (k=%d)", k)
	}
	return RungInconclusive, "inconclusive (exit output unmapped)"
}

// BoundK is the bounded_k for a proved-bounded rung: halmos prefers the
// first k=<n> marker in the output, otherwise (and always for forge-fuzz,
// whose runs count rides the invocation) the k the runner was invoked
// with. Only meaningful when MapRun returned proved-bounded; callers must
// not consult it for other rungs (their bounded_k is null).
func BoundK(kind Kind, out []byte, k int) int {
	if kind == Halmos {
		if n, ok := parseK(string(out)); ok {
			// The output SPOKE: a degenerate marker is a statement
			// that no usable bound was proven, so it must not fall
			// back to the invocation (r26 F3) — the run is floored
			// anyway, and 0 here reads as UNSTATED, never as a bound.
			if n == BoundDegenerate {
				return 0
			}
			return n
		}
	}
	if k < 1 {
		return 0
	}
	return k
}

// parseK reads the first k=<n> marker. ok=false when absent or unparsable
// (callers fall back to the invocation k).
func parseK(text string) (n int, ok bool) {
	m := kMarker.FindStringSubmatch(text)
	if m == nil {
		return 0, false
	}
	n, err := atoiClamped(m[1])
	if err != nil {
		return 0, false
	}
	if n < 1 {
		// Parsed, but degenerate: the marker states a bound below 1.
		return BoundDegenerate, true
	}
	return n, true
}

// hasBoundedFlag is the bounded-flag-text half of halmos's bounded
// evidence: the --loop flag the bounded recipe passes. (A bare success
// line with no bound evidence is partial text and must not promote.)
func hasBoundedFlag(text string) bool {
	return strings.Contains(text, "--loop")
}

// hasStatusWord matches halmos's "Status: <word>" with a word boundary
// past the word, so "Status: failure"/"Status: failed" do not read as
// "Status: fail".
func hasStatusWord(text, word string) bool {
	needle := "Status: " + word
	for i := 0; i+len(needle) <= len(text); i++ {
		if !strings.HasPrefix(text[i:], needle) {
			continue
		}
		rest := text[i+len(needle):]
		if rest == "" || !isASCIILetter(rest[0]) {
			return true
		}
	}
	return false
}

// modelAssign names a model-value line: "model" as a word followed by a
// ":" or, within a short window, a "=" (an assignment). The window keeps
// prose like "before model construction" (no binding in sight) from
// reading as a model block.
var modelAssign = regexp.MustCompile(`(?i)\bmodel\b\s*[:=]|\bmodel\b[^:=]{0,40}=`)

// counterexampleLine is the halmos counterexample-block excerpt: the first
// block line carrying a value (an "=" binding — the model's symbolic
// values, e.g. a getSymbolicAddress line), falling back to the block
// header itself ("Counterexample:") when the block names no values. The
// "Status: fail" line itself never counts (it names no values).
func counterexampleLine(text string) (string, bool) {
	var lines []string
	blockAt := -1
	for _, ln := range strings.Split(text, "\n") {
		t := strings.TrimSpace(ln)
		if t == "" || strings.HasPrefix(t, "Status:") {
			continue
		}
		lines = append(lines, t)
		if blockAt < 0 && (strings.Contains(t, "Counterexample") ||
			modelAssign.MatchString(t)) {
			blockAt = len(lines) - 1
		}
	}
	if blockAt < 0 {
		return "", false
	}
	for _, t := range lines[blockAt:] {
		if strings.Contains(t, "=") {
			return t, true
		}
	}
	return lines[blockAt], true
}

// forgePassSummary is the proved half's summary line: "1 passed" with
// "0 failed" on a forge summary line (a "---" rule or the Suite result
// line). Callers additionally require no FAIL line anywhere, so a mixed
// log with both can never promote.
//
// H9: BOTH markers are matched on the SAME line. The Suite-result test used
// to scan the whole text, so a "1 passed; 0 failed" line from one suite
// promoted the run whenever the words "Suite result" appeared anywhere else
// in the log — a run whose suites never agreed could read as proved. The
// summary line is the claim; a claim is one line.
func forgePassSummary(text string) bool {
	for _, ln := range strings.Split(text, "\n") {
		if !strings.Contains(ln, "1 passed") ||
			!strings.Contains(ln, "0 failed") {
			continue
		}
		if strings.Contains(ln, "---") {
			return true
		}
		if strings.Contains(ln, "Suite result") {
			return true
		}
	}
	return false
}

// firstLineContaining is the first trimmed non-empty line containing sub
// (case-sensitive: forge's FAIL marker is uppercase; lowercase "failed"
// in a pass summary must not match).
func firstLineContaining(text, sub string) (string, bool) {
	for _, ln := range strings.Split(text, "\n") {
		t := strings.TrimSpace(ln)
		if t != "" && strings.Contains(t, sub) {
			return t, true
		}
	}
	return "", false
}

// firstLineContainingFold is firstLineContaining case-insensitive (for
// "seed:"/"Seed" lines, whose casing varies across forge versions).
func firstLineContainingFold(text, sub string) (string, bool) {
	for _, ln := range strings.Split(text, "\n") {
		t := strings.TrimSpace(ln)
		if t != "" && strings.Contains(strings.ToLower(t),
			strings.ToLower(sub)) {
			return t, true
		}
	}
	return "", false
}

// truncateRunes caps s at n runes (the brief's "chars" are runes, not
// bytes — a symbolic address excerpt must never split mid-rune).
func truncateRunes(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}

// atoiClamped is Atoi rejecting empty input (regexp already guarantees
// digits; the clamp guards absurd widths from shifting int range).
func atoiClamped(s string) (int, error) {
	n := 0
	for _, c := range []byte(s) {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("harness: bad k marker %q", s)
		}
		n = n*10 + int(c-'0')
		if n > 1<<62 {
			return 0, fmt.Errorf("harness: k marker %q overflows", s)
		}
	}
	return n, nil
}

func isASCIILetter(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// TimedOutBit is the MapRun timedOut bit derived from a recorded
// exit_status: -1 covers both "the timeout killed it" and "it never
// started"; 128+N is the shell's signal-death convention. Either way
// the run did not COMPLETE, so its bytes map to inconclusive, never to
// a rung (cli.harnessTimedOut delegates here — one law, one home).
func TimedOutBit(exitStatus int) bool {
	return exitStatus == -1 || exitStatus >= 128
}

// InvocationBound parses the bound flag out of an exec command string:
// halmos's --loop N, forge's --fuzz-runs N (both `--flag N` and
// `--flag=N`), minicertora's --loop-bound N. 0 = unstated: the number
// only feeds display text, never a rung. Three further answers are
// possible, and two of them floor (BoundFloors):
//
//	0                 the invocation named no bound (UNSTATED, not zero)
//	N >= 1            the value click would have bound
//	BoundDegenerate   the invocation states a bound no tool would have
//	                  executed under (a value below 1, a value that is
//	                  not a Python int, a flag with no value at all, or
//	                  two different tools' bound flags in one command)
//	BoundUnreadable   the command string cannot be lexed faithfully at
//	                  all (see InvocationBoundReason for the construct)
//
// r28 F1: the parse is CLICK-SHAPED, because the twin's CLI is a click
// option (`@click.option("--loop-bound", type=int, default=4)`) and click
// binds a repeated option LAST-WINS (ctx.params["loop_bound"] is the final
// occurrence). Reading the FIRST match called
// `miniprover run --loop-bound 4 --loop-bound 0` a k=4 proof — but the twin
// parses 0 there, VerifierFlags.__post_init__ raises for loop_bound < 1,
// and no tool output can exist under that command at all, so the first
// match was evidence for a run the twin refuses to make. LAST occurrence
// decides, exactly as click does: a degenerate flag last floors the whole
// invocation even after an honest one, while a degenerate flag followed by
// an honest one does not floor.
//
// r29 F4: it is SHELL-SHAPED first. The input is the recorded COMMAND
// STRING, not an argv, so the parse lexes it the way a POSIX shell would
// split it (lexCommand) and only then binds options the way click would
// (boundFromArgv). The old regex scanned the raw text, which read a
// `#`-comment's flag as the real one, read the flag out of a QUOTED
// argument (where click sees one positional), read a value across a `--`
// terminator (where click sees positionals), truncated `4_000` to `4` (a
// ledger lie: a stated 4 the tool never ran under), and blessed `4.5` /
// empty / missing values, which the twin refuses outright. Flags that the
// lexer cannot place are no longer guessed: the parse reports
// BoundUnreadable and the run floors.
func InvocationBound(command string) int {
	k, _ := InvocationBoundReason(command)
	return k
}

// InvocationBoundReason is InvocationBound plus the construct that made
// the command unreadable ("" for every readable command, including the
// ones that floor). Callers that hold the command pass the reason to
// MapRun so the stored floor names the exact observed state
// ("invocation-unreadable: unmatched single quote") instead of only the
// class. The exported InvocationBound keeps its signature — cli and the
// audit both call it — and delegates here.
func InvocationBoundReason(command string) (int, string) {
	toks, construct := lexCommand(command)
	if construct != "" {
		return BoundUnreadable, construct
	}
	return boundFromArgv(toks)
}

// shToken is one argv element the way a POSIX shell would hand it to the
// tool. text is the element after quote removal and escape processing;
// unknown marks an element whose exact text depends on an expansion or a
// glob, so no parse can claim to know what the tool received.
type shToken struct {
	text    string
	unknown bool
}

// boundFlagOcc is one stated bound option, in command order.
type boundFlagOcc struct {
	name  string // --loop | --loop-bound | --fuzz-runs
	value string // the raw argv text of its value
	has   bool   // a value was present (an inline `=` or a following word)
}

// boundFromArgv reads the bound out of a lexed argv the way click's parser
// and the twin's VerifierFlags would, verified against the twin's own
// click command (miniprover/.venv, click 8.5.0):
//
//	['--loop-bound','4','--loop-bound','0'] -> 0 (and VerifierFlags raises)
//	['--loop-bound','+4'] -> 4        ['--loop-bound','4_000'] -> 4000
//	['--loop-bound','4.5'] -> UsageError   ['--loop-bound'] -> UsageError
//	['--loop-bound',''] -> UsageError ['--loop-bound='] -> UsageError
//	['--loop-bound','<arabic-indic zero>'] -> 0 (and VerifierFlags raises)
//	['--loop-bound','--loop-bound','4'] -> UsageError (the flag text is
//	                                      eaten as the first value)
//	['--loop-bound','4','--','--loop-bound','0'] -> 4 (`--` ends options)
//	['--loop-bound','4','--fuzz-runs','7'] -> UsageError (no such option)
//
// An option is an argv element whose text is exactly the flag, or
// `flag=value` (the shell has already removed the quotes, so a QUOTED
// flag name is still an option while a quoted `'… --loop-bound 99'` is
// one positional argument and names none). A repeated option binds
// LAST-WINS. A value click would refuse (not a Python int, or below 1) is
// a STATED impossible invocation: BoundDegenerate, never "unstated".
//
// A command naming two DIFFERENT bound flags is one no tool could have
// run: halmos owns --loop, minicertora --loop-bound, forge-fuzz
// --fuzz-runs, and click answers "No such option" for the foreign name.
// That floors too — it is not last-wins, because there is no single tool
// whose parameter both occurrences could be.
//
// Two things are deliberately NOT modeled, and are stated rather than
// guessed at. (1) The arity of the OTHER options: an option that takes a
// value eats the next element, so in `--timeout-ms --loop-bound 4` click
// raises ("'--loop-bound' is not a valid integer" for --timeout-ms) while
// this parse reads a bound flag and its value 4. Which options take a
// value is the owning tool's table, and this ONE function is kind-blind
// on purpose (halmos, forge and minicertora share it); the r28 regex read
// the same command the same way. (2) Positional arity: the twin's CLI
// takes exactly one positional, so `--loop-bound 4 extra` is a UsageError
// there and a bound of 4 here — a positional count is not a bound
// statement, and halmos/forge take many positionals.
func boundFromArgv(toks []shToken) (int, string) {
	var occs []boundFlagOcc
	pending := -1  // occs index of a bound flag awaiting the NEXT element
	value := false // the last element was an option that may take a value
	endOpts := false
	// argv[0] is the program name and click never parses it — but the
	// callers also pass bare flag fragments ("--loop-bound 8"), and a
	// program name never begins with '-', so only a first element that
	// does not begin with '-' is treated as the program. (`--` included:
	// a leading terminator must keep ending options.)
	first := -1
	if len(toks) > 0 && !strings.HasPrefix(toks[0].text, "-") {
		first = 0
	}
	for i, t := range toks {
		if i == first {
			continue
		}
		if pending >= 0 {
			if t.unknown {
				return BoundUnreadable, "shell expansion in the " +
					occs[pending].name + " value (" +
					oneLine(t.text, 20) + ")"
			}
			occs[pending].value, occs[pending].has = t.text, true
			pending, value = -1, false
			continue
		}
		if endOpts {
			continue // positional: click is not looking for options
		}
		if t.unknown {
			if value {
				// The element before it is an option, so this is that
				// option's value — and a VALUE is never an option.
				value = false
				continue
			}
			return BoundUnreadable, "shell expansion (" +
				oneLine(t.text, 20) + ") where an option could be"
		}
		if t.text == "--" {
			endOpts, value = true, false
			continue
		}
		if !isOptionWord(t.text) {
			value = false
			continue
		}
		if name, val, hasVal, bound := boundOptionWord(t.text); bound {
			occs = append(occs, boundFlagOcc{name: name, value: val,
				has: hasVal})
			if !hasVal {
				pending = len(occs) - 1
			}
			// A bound flag never leaves the non-bound "awaiting a
			// value" flag set: without an inline value it takes the
			// NEXT element as its value (pending above), whatever that
			// element looks like — click does the same.
			value = false
			continue
		}
		// Some other option: with an inline value it consumed its own
		// (`--opt=v`), without one it takes the next element (`--opt v`).
		value = !strings.Contains(t.text, "=")
	}
	if len(occs) == 0 {
		return 0, ""
	}
	for _, o := range occs[1:] {
		if o.name != occs[0].name {
			// Two tools' bound flags in one command: whatever ran,
			// click refused one of them, so no execution exists under
			// this invocation to carry a bound.
			return BoundDegenerate, ""
		}
	}
	last := occs[len(occs)-1]
	if !last.has {
		// click: "Option '--loop-bound' requires an argument."
		return BoundDegenerate, ""
	}
	n, status := parseClickInt(last.value)
	switch status {
	case intNotAnInt:
		// click: "'4.5' is not a valid integer." The invocation is
		// impossible, so it states no bound any tool ran under.
		return BoundDegenerate, ""
	case intOverflowNegative:
		return BoundDegenerate, ""
	case intOverflowPositive:
		// Absurdly wide but positive: keep r28's reading (UNSTATED),
		// never a wrapped number. Python has bignums, so click itself
		// would accept this value — the limit is ours, and it is stated
		// as "no bound", not as a bound.
		return 0, ""
	}
	if n < 1 {
		// STATED and degenerate ("--loop 0", "--fuzz-runs=0",
		// "--loop-bound -1", "--loop-bound <Nd zero>"): not unstated,
		// and not a bound any tool would have run under.
		return BoundDegenerate, ""
	}
	return n, ""
}

// isOptionWord reports whether click's parser would read an argv element
// as an option: it begins with '-' and is not the bare "-" (stdin) or the
// "--" terminator (which boundFromArgv handles first).
func isOptionWord(w string) bool {
	return strings.HasPrefix(w, "-") && w != "-" && w != "--"
}

// boundOptionWord splits an argv element as a bound long option. ok is
// false for every other element, including a lookalike
// ("--loop-boundx 4") and a different case ("--LOOP-BOUND"), which click
// also refuses (long options are exact and case-sensitive).
func boundOptionWord(w string) (name, val string, hasVal, ok bool) {
	name = w
	if i := strings.IndexByte(w, '='); i >= 0 {
		name, val, hasVal = w[:i], w[i+1:], true
	}
	switch name {
	case "--loop", "--loop-bound", "--fuzz-runs":
		return name, val, hasVal, true
	}
	return "", "", false, false
}

// intParse is the outcome of reading a bound value the way the twin's
// click does.
type intParse int

const (
	intOK intParse = iota
	intNotAnInt
	intOverflowPositive
	intOverflowNegative
)

// parseClickInt reads a value the way click's type=int does, which is
// Python's int(str): surrounding whitespace is ignored, an optional +/-
// sign is allowed, ASCII underscores are allowed ONLY between digits, and
// any Unicode decimal digit (category Nd — int("٤٢") == 42, while "²" is
// a digit to str.isdigit() but NOT to int()) counts as its value, decoded
// by decimalDigit's block table (the twin's own Nd data). A value that is
// not an integer at all is intNotAnInt: click raises a UsageError for it,
// so the run is impossible rather than unbounded.
func parseClickInt(raw string) (int, intParse) {
	s := strings.TrimSpace(raw) // int() strips whitespace, "\n4" included
	if s == "" {
		return 0, intNotAnInt
	}
	neg := false
	i := 0
	if s[0] == '+' || s[0] == '-' {
		neg = s[0] == '-'
		i = 1
	}
	n, digits, underscore, overflow := 0, 0, false, false
	for i < len(s) {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == '_' {
			// Python: an underscore must sit between digits, so "_4",
			// "4_" and "4__0" are not integers at all.
			if digits == 0 || underscore {
				return 0, intNotAnInt
			}
			underscore = true
			i += size
			continue
		}
		d, isDigit := decimalDigit(r)
		if !isDigit {
			return 0, intNotAnInt
		}
		underscore = false
		digits++
		if !overflow {
			if n > (1<<62)/10 {
				overflow = true
			} else if n = n*10 + d; n > 1<<62 {
				overflow = true
			}
		}
		i += size
	}
	if underscore || digits == 0 {
		return 0, intNotAnInt
	}
	if overflow {
		if neg {
			return 0, intOverflowNegative
		}
		return 0, intOverflowPositive
	}
	if neg {
		n = -n
	}
	return n, intOK
}

// ndBlockStarts is the start — the ZERO — of every Unicode Nd (decimal
// digit) block the twin's Python accepts, sorted ascending. parseClickInt
// decodes a digit by locating the block that CONTAINS it, so every entry
// here is the first of ten consecutive code points.
//
// The table is DERIVED, not guessed: it is every code point whose category
// is Nd and whose int(chr(cp)) is 0, printed by the twin's own interpreter
// (read-only), whose unicodedata is the authority for what click's
// type=int accepts:
//
//	/home/xand/Projects/miniprover/.venv/bin/python -c '
//	  import unicodedata
//	  cps=[cp for cp in range(0x110000)
//	       if unicodedata.category(chr(cp))=="Nd"]
//	  print(len(cps), [hex(cp) for cp in cps if int(chr(cp))==0])'
//	-> 760 [0x30, 0x660, …, 0x1D7CE, 0x1D7D8, 0x1D7E2, 0x1D7EC,
//	        0x1D7F6, …, 0x1FBF0]        (76 blocks)
//
// 760 code points over 76 blocks, so every block is exactly ten long and
// every code point of a block decodes to (cp - start) == int(chr(cp)).
// NOTE the five ADJACENT pairs (0x116D0/0x116DA and the four mathematical
// blocks 0x1D7CE, 0x1D7D8, 0x1D7E2, 0x1D7EC, 0x1D7F6 — r30 P1-2): a
// decoder that walks DOWN to the first non-digit (the r29 implementation)
// walks out of the block it was given and into the PREVIOUS one, decoding
// all 36 later code points as 9. Locating the containing block is what
// makes adjacency harmless.
//
// This is deliberately the TWIN's data and not Go's: Go 1.26 ships Unicode
// 15.0.0, whose 680 Nd code points are a strict SUBSET of the twin's 760
// (the twin adds the 0x10D40, 0x116D0, 0x116DA, 0x11BF0, 0x16130, 0x16D70,
// 0x1CCF0 and 0x1E5F1 blocks, which click's int() accepts and which
// therefore must decode). A rune this table does not cover is UNPARSEABLE
// (decimalDigit returns false) — the UsageError direction — never a digit,
// so a Go Unicode version that ever grows past the twin's data fails
// closed instead of inventing a value.
var ndBlockStarts = []rune{
	0x30, 0x660, 0x6F0, 0x7C0, 0x966, 0x9E6,
	0xA66, 0xAE6, 0xB66, 0xBE6, 0xC66, 0xCE6,
	0xD66, 0xDE6, 0xE50, 0xED0, 0xF20, 0x1040,
	0x1090, 0x17E0, 0x1810, 0x1946, 0x19D0, 0x1A80,
	0x1A90, 0x1B50, 0x1BB0, 0x1C40, 0x1C50, 0xA620,
	0xA8D0, 0xA900, 0xA9D0, 0xA9F0, 0xAA50, 0xABF0,
	0xFF10, 0x104A0, 0x10D30, 0x10D40, 0x11066, 0x110F0,
	0x11136, 0x111D0, 0x112F0, 0x11450, 0x114D0, 0x11650,
	0x116C0, 0x116D0, 0x116DA, 0x11730, 0x118E0, 0x11950,
	0x11BF0, 0x11C50, 0x11D50, 0x11DA0, 0x11F50, 0x16130,
	0x16A60, 0x16AC0, 0x16B50, 0x16D70, 0x1CCF0, 0x1D7CE,
	0x1D7D8, 0x1D7E2, 0x1D7EC, 0x1D7F6, 0x1E140, 0x1E2F0,
	0x1E4F0, 0x1E5F1, 0x1E950, 0x1FBF0,
}

// decimalDigit maps a Unicode decimal digit to 0-9 the way Python's int()
// does. ndBlockStarts IS the definition of "decimal digit" here — not
// unicode.IsDigit, whose Nd set is Go's Unicode version rather than the
// twin's — so a rune outside the table is unparseable and lands in
// parseClickInt's intNotAnInt (click's "'…' is not a valid integer"), while
// a digit in an ADJACENT block still decodes from its own block.
func decimalDigit(r rune) (int, bool) {
	i := sort.Search(len(ndBlockStarts), func(i int) bool {
		return ndBlockStarts[i] > r
	}) - 1
	if i < 0 {
		return 0, false
	}
	d := int(r - ndBlockStarts[i])
	if d < 0 || d > 9 {
		return 0, false
	}
	return d, true
}

// lexCommand splits a recorded command string into the argv a POSIX shell
// would hand the tool, or names the construct that stopped it ("" = the
// string is one simple command we could lex). Modeled:
//
//   - space and TAB separate words — with a newline, the only IFS
//     whitespace a POSIX shell splits on. CR, VT and FF are NOT
//     separators (r30 P2-1): `/bin/sh -c 'tool --loop-bound<VT>4'` hands
//     the tool ONE argv element `--loop-bound\v4`, so splitting it would
//     invent a flag the tool never received;
//   - single quotes are literal end to end (no escapes, no expansion);
//   - in double quotes only $ ` " \ and a newline are escaped by a
//     backslash — POSIX keeps the backslash before anything else — and
//     expansions inside them are single words;
//   - outside quotes a backslash escapes the next rune, and a backslash
//     before a newline is a line continuation;
//   - '#' opens a comment only at a WORD BOUNDARY ("4#x" is a value, and
//     a quoted '#' is a word), and a comment runs to the end of the line;
//   - a `--` element is returned as itself: click's end-of-options rule
//     lives in boundFromArgv, where it belongs.
//
// NOT modeled — each returns a construct name instead of a guessed argv,
// because the argv is not derivable from the text: an unmatched quote, a
// trailing backslash, an unterminated expansion, a command LIST (a
// newline, ';' or '&' with another command after it), a pipeline or
// subshell (| ( )), a redirection (< >) and braces.
//
// An expansion ($VAR, $(...), backticks) or a glob (* ? [) is NOT an
// error by itself: it marks one token unknown, because the shell would
// have replaced the text with something this parse cannot know.
// boundFromArgv then decides whether that unknown token could have been
// an option. A tilde is ordinary text on purpose: a tilde expansion is an
// absolute path, so it can be neither an option nor a word that starts
// with one, and it cannot hide a flag.
func lexCommand(command string) ([]shToken, string) {
	rs := []rune(command)
	var (
		toks    []shToken
		word    strings.Builder
		unknown bool
		started bool
	)
	flush := func() {
		if started {
			toks = append(toks, shToken{text: word.String(),
				unknown: unknown})
		}
		word.Reset()
		unknown, started = false, false
	}
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		switch {
		case c == ' ' || c == '\t':
			// IFS whitespace, and nothing else: CR/VT/FF fall through
			// to the default arm below and stay inside the word
			// (r30 P2-1, evidence in zz_r30_test.go). A newline is
			// next, because it separates COMMANDS, not just words.
			flush()
		case c == '\n' || c == ';' || c == '&':
			flush()
			if restHasCommand(rs[i+1:]) {
				return nil, "command list (separator " +
					strconv.QuoteRune(c) + ")"
			}
			return toks, ""
		case c == '|' || c == '(' || c == ')':
			return nil, "pipeline or subshell (" +
				strconv.QuoteRune(c) + ")"
		case c == '<' || c == '>':
			return nil, "redirection (" + strconv.QuoteRune(c) + ")"
		case c == '{' || c == '}':
			return nil, "brace expression (" +
				strconv.QuoteRune(c) + ")"
		case c == '#' && !started:
			for i < len(rs) && rs[i] != '\n' {
				i++
			}
			i--
		case c == '\'':
			started = true
			j := i + 1
			for j < len(rs) && rs[j] != '\'' {
				j++
			}
			if j >= len(rs) {
				return nil, "unmatched single quote"
			}
			word.WriteString(string(rs[i+1 : j]))
			i = j
		case c == '"':
			started = true
			j, construct := lexDoubleQuoted(rs, i, &word, &unknown)
			if construct != "" {
				return nil, construct
			}
			i = j
		case c == '\\':
			started = true
			if i+1 >= len(rs) {
				return nil, "unterminated escape (trailing " +
					"backslash)"
			}
			if rs[i+1] == '\n' {
				i++ // line continuation: the shell joins the lines
				continue
			}
			word.WriteRune(rs[i+1])
			i++
		case c == '$' || c == '`':
			started, unknown = true, true
			span, last, construct := expansionSpan(rs, i)
			if construct != "" {
				return nil, construct
			}
			word.WriteString(span)
			i = last
		case c == '*' || c == '?' || c == '[':
			started, unknown = true, true
			word.WriteRune(c)
		default:
			started = true
			word.WriteRune(c)
		}
	}
	flush()
	return toks, ""
}

// restHasCommand reports whether anything after a command separator is
// another command. Whitespace, blank lines and comment lines are not: a
// command string with a trailing newline and a trailing comment is still
// one command, so it must not be refused as a list. Only real IFS
// whitespace counts here too (r30 P2-1): a CR, VT or FF after the
// separator is an ordinary character, so `cmd\n\vecho x` names a second
// command whose first word merely begins with a control byte.
func restHasCommand(rest []rune) bool {
	for i := 0; i < len(rest); {
		switch c := rest[i]; {
		case c == ' ' || c == '\t' || c == '\n':
			i++
		case c == '#':
			for i < len(rest) && rest[i] != '\n' {
				i++
			}
		default:
			return true
		}
	}
	return false
}

// lexDoubleQuoted consumes the double-quoted region beginning at rs[i]
// (== '"'), appends its text to word and returns the index of the closing
// quote. POSIX keeps a backslash literal unless it precedes $ ` " \ or a
// newline, so `--loop-bound "\4"` is the two-rune value `\4` (which click
// refuses) and not the integer 4.
func lexDoubleQuoted(rs []rune, i int, word *strings.Builder,
	unknown *bool) (int, string) {
	for j := i + 1; j < len(rs); j++ {
		switch c := rs[j]; c {
		case '"':
			return j, ""
		case '\\':
			if j+1 >= len(rs) {
				return 0, "unmatched double quote"
			}
			switch n := rs[j+1]; n {
			case '$', '`', '"', '\\':
				word.WriteRune(n)
				j++
			case '\n':
				j++ // line continuation
			default:
				word.WriteRune('\\')
			}
		case '$', '`':
			*unknown = true
			span, last, construct := expansionSpan(rs, j)
			if construct != "" {
				return 0, construct
			}
			word.WriteString(span)
			j = last
		default:
			word.WriteRune(c)
		}
	}
	return 0, "unmatched double quote"
}

// expansionSpan consumes the shell expansion that begins at rs[i] ('$' or
// '`') and returns its literal text plus the index of its last rune. The
// text is carried so a refusal can quote what the parse saw; the token is
// marked unknown either way, because the VALUE the shell substitutes is
// not derivable from the command string.
func expansionSpan(rs []rune, i int) (string, int, string) {
	if rs[i] == '`' {
		for j := i + 1; j < len(rs); j++ {
			if rs[j] == '\\' {
				j++
				continue
			}
			if rs[j] == '`' {
				return string(rs[i : j+1]), j, ""
			}
		}
		return "", 0, "unterminated command substitution (backquote)"
	}
	if i+1 >= len(rs) {
		return "$", i, "" // a trailing '$' is literal
	}
	switch n := rs[i+1]; {
	case n == '(':
		// $(...) may contain spaces and quotes, so its extent matters:
		// scan to the matching paren, ignoring quoted regions.
		depth := 1
		inSingle, inDouble := false, false
		for j := i + 2; j < len(rs); j++ {
			switch c := rs[j]; {
			case inSingle:
				inSingle = c != '\''
			case inDouble:
				switch c {
				case '\\':
					j++
				case '"':
					inDouble = false
				}
			case c == '\'':
				inSingle = true
			case c == '"':
				inDouble = true
			case c == '\\':
				j++
			case c == '(':
				depth++
			case c == ')':
				depth--
				if depth == 0 {
					return string(rs[i : j+1]), j, ""
				}
			}
		}
		return "", 0, "unterminated command substitution ($(...))"
	case n == '{':
		for j := i + 2; j < len(rs); j++ {
			if rs[j] == '}' {
				return string(rs[i : j+1]), j, ""
			}
		}
		return "", 0, "unterminated parameter expansion (${...})"
	case isNameStart(n):
		j := i + 2
		for j < len(rs) && isNameRune(rs[j]) {
			j++
		}
		return string(rs[i:j]), j - 1, ""
	default:
		return string(rs[i : i+2]), i + 1, "" // $1, $?, $@, $$, $-, ...
	}
}

// isNameStart reports a POSIX name's first rune ($VAR/$var_1 forms).
func isNameStart(r rune) bool {
	return unicode.IsLetter(r) || r == '_'
}

// isNameRune reports a rune a POSIX name may continue with.
func isNameRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_'
}
