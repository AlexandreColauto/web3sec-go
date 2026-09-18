package harness

import (
	"strings"
)

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

// boundFromArgv reads the bound out of a lexed argv the way the tool that
// owns the flag would. The KIND (r32 F1) selects that tool: the three
// harness kinds are three command-line languages, and the value semantics
// below are per FAMILY, not per kind, so the flag name alone decides which
// parser reads a value.
//
// The twin's own click command (miniprover/.venv, click 8.5.0) and the
// installed CLIs were both measured:
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
//	['--fuzz-runs','4_000'] -> clap error (invalid digit found in string)
//	['--fuzz-runs','4','--fuzz-runs','7'] -> clap error (cannot be used
//	                                      multiple times)
//
// An option is an argv element whose text is exactly the flag, or
// `flag=value` (the shell has already removed the quotes, so a QUOTED
// flag name is still an option while a quoted `'… --loop-bound 99'` is
// one positional argument and names none). A repeated option binds
// LAST-WINS — for the two Python tools, which is what their parsers do;
// forge refuses a repeat outright, because clap does. A value the owning
// tool refuses (not a Python int, below 1, not a u32 for forge) is a
// STATED impossible invocation: BoundDegenerate, never "unstated", with
// the tool and the observed reason named when there is one to name.
//
// A command naming two DIFFERENT bound flags is one no tool could have
// run: halmos owns --loop, minicertora --loop-bound, forge-fuzz
// --fuzz-runs, and every tool answers "no such option"/"unexpected
// argument" for a foreign name. That floors too — it is not last-wins,
// because there is no single tool whose parameter both occurrences could
// be. r32 F2: the SAME floor now fires for a LONE foreign flag, which is
// the shape the old two-flag-only guard missed.
//
// r31 F3: the arity of an option whose table this function does not have
// is no longer guessed at. When an option token is immediately followed by
// another option-looking token, whether the first one EATS the second is
// the owning tool's table — and the two readings disagree about the bound
// itself: click's reading (the option takes a value) refuses the
// invocation, while a boolean-flag reading binds the 4 that follows. So
// the argv is not derivable and the parse floors as unreadable, naming the
// pair (ambiguousOptionArity):
//
//	--timeout-ms --loop-bound 4   -> floor (a value slot or a flag?)
//	--contract --loop-bound 4     -> floor
//	--loop-bound 4 -- --loop-bound 0 -> floor (what follows the `--`
//	                                  terminator is option-looking, and
//	                                  the parse cannot tell an unparsed
//	                                  flag from the positional value
//	                                  click reads there)
//
// Two exceptions are deliberate. A BOUND flag's arity IS known: it takes
// the next element as its value, whatever it looks like, so
// `--loop-bound --loop-bound 4` keeps its older, accurate answer
// (BoundDegenerate: click refuses "'--loop-bound' is not a valid integer").
// An option carrying its value inline (`--solc-path=/usr/bin/solc
// --loop-bound 4`) has no arity question left to ask, so it stays honest.
//
// One thing is still deliberately NOT modeled, and is stated rather than
// guessed at: POSITIONAL arity. The twin's CLI takes exactly one
// positional, so `--loop-bound 4 extra extra2` is a UsageError there and a
// bound of 4 here (and `--loop-bound 4 -- x y` likewise) — a positional
// count is not a bound statement, halmos and forge take many positionals,
// and the documented minicertora invocation takes two
// (`minicertora V.sol INV.mspec`). docs/MINIPROVER_INTEGRATION.md states
// this residual and its direction of risk: a positional tail can still
// bless a bound for an invocation the twin's click would refuse. A
// positional token that does NOT look like an option cannot move the bound
// (it is some other option's value or a plain file), which is why only the
// option-looking pairs above floor.
func boundFromArgv(toks []shToken, kind Kind) (int, string) {
	if why := ambiguousOptionArity(toks); why != "" {
		return BoundUnreadable, "option arity is ambiguous (" + why + ")"
	}
	sc := newBoundArgvScan(toks)
	if k, why := sc.collect(); why != "" {
		return k, why
	}
	if len(sc.occs) == 0 {
		return 0, ""
	}
	if k, why, hit := boundArgvForeign(toks, sc.occs, kind); hit {
		return k, why
	}
	if k, why, hit := boundArgvMixed(sc.occs); hit {
		return k, why
	}
	return boundArgvBind(sc.occs)
}

// boundArgvScan carries the state of the argv walk that collects a
// command's bound-flag occurrences in command order (boundFromArgv's
// scan loop).
type boundArgvScan struct {
	toks    []shToken
	occs    []boundFlagOcc
	first   int
	pending int  // occs index of a bound flag awaiting the NEXT element
	value   bool // the last element was an option that may take a value
	endOpts bool
}

// newBoundArgvScan seeds the walk. argv[0] is the program name and click
// never parses it — but the callers also pass bare flag fragments
// ("--loop-bound 8"), and a program name never begins with '-', so only a
// first element that does not begin with '-' is treated as the program.
// (`--` included: a leading terminator must keep ending options.)
func newBoundArgvScan(toks []shToken) *boundArgvScan {
	s := &boundArgvScan{toks: toks, first: -1, pending: -1}
	if len(toks) > 0 && !strings.HasPrefix(toks[0].text, "-") {
		s.first = 0
	}
	return s
}

// collect walks the argv and records every bound-flag occurrence, in
// command order. It returns a floor (BoundUnreadable and the construct)
// when an element's text is not derivable where an option or a bound
// value could sit; otherwise it returns (0, "") and leaves the
// occurrences in s.occs.
func (s *boundArgvScan) collect() (int, string) {
	for i, t := range s.toks {
		if i == s.first {
			continue
		}
		if s.pending >= 0 {
			if t.unknown {
				return BoundUnreadable, "shell expansion in the " +
					s.occs[s.pending].name + " value (" +
					oneLine(t.text, 20) + ")"
			}
			s.occs[s.pending].value, s.occs[s.pending].has = t.text, true
			s.pending, s.value = -1, false
			continue
		}
		if s.endOpts {
			continue // positional: click is not looking for options
		}
		if t.unknown {
			if s.value {
				// The element before it is an option, so this is that
				// option's value — and a VALUE is never an option.
				s.value = false
				continue
			}
			return BoundUnreadable, "shell expansion (" +
				oneLine(t.text, 20) + ") where an option could be"
		}
		if t.text == "--" {
			s.endOpts, s.value = true, false
			continue
		}
		if !isOptionWord(t.text) {
			s.value = false
			continue
		}
		if name, val, hasVal, bound := boundOptionWord(t.text); bound {
			s.occs = append(s.occs, boundFlagOcc{name: name, value: val,
				has: hasVal})
			if !hasVal {
				s.pending = len(s.occs) - 1
			}
			// A bound flag never leaves the non-bound "awaiting a
			// value" flag set: without an inline value it takes the
			// NEXT element as its value (pending above), whatever that
			// element looks like — click does the same.
			s.value = false
			continue
		}
		// Some other option: with an inline value it consumed its own
		// (`--opt=v`), without one it takes the next element (`--opt v`).
		s.value = !strings.Contains(t.text, "=")
	}
	return 0, ""
}

// boundArgvForeign names the foreign-flag floor (r32 F2): a bound-looking
// flag that ANOTHER family owns is a flag the tool named by the kind (or
// by argv[0], for the kind-free reader) does not have, and its argument
// parser refuses the whole command: `forge test --loop 3` -> "error:
// unexpected argument '--loop' found", `halmos --fuzz-runs 500` ->
// "unrecognized arguments", `minicertora --fuzz-runs 200` -> "No such
// option". The old guard fired only when TWO of the known bound flags
// appeared together, so a LONE foreign flag bound proved-bounded
// (forge-fuzz, k=3) for a run real forge never started. The floor names
// the flag and the tool (the one that would refuse), and it stays a FLOOR
// rather than last-wins: there is no single tool whose parameter these
// occurrences could all be. hit=false when no foreign flag is present.
func boundArgvForeign(toks []shToken, occs []boundFlagOcc,
	kind Kind) (int, string, bool) {
	if want, known := invocationToolOf(toks, occs, kind); known {
		for _, o := range occs {
			if owner, bound := toolForBoundFlag(o.name); bound &&
				owner != want {
				return BoundDegenerate, want.String() + " has no " +
					o.name + " option (" + toolRefusal(want) + ")", true
			}
		}
	}
	return 0, "", false
}

// boundArgvMixed names the floor for two different tools' bound flags in
// one command, when not even the program name settles which tool ran:
// whatever it was, it refused one of them, so no execution exists under
// this invocation to carry a bound. hit=false when every occurrence names
// the same flag.
func boundArgvMixed(occs []boundFlagOcc) (int, string, bool) {
	for _, o := range occs[1:] {
		if o.name != occs[0].name {
			return BoundDegenerate, "two tools' bound flags in one " +
				"command (" + occs[0].name + " and " + o.name + ")", true
		}
	}
	return 0, "", false
}

// boundArgvBind binds the LAST occurrence the way its owning tool would:
// last-wins is the Python tools' rule, and the degenerate arms below are
// the refusals their parsers (and forge's clap) produce.
func boundArgvBind(occs []boundFlagOcc) (int, string) {
	last := occs[len(occs)-1]
	tool, _ := toolForBoundFlag(last.name)
	if !last.has {
		// The tool's own rule: click's "Option '--loop-bound' requires an
		// argument", clap's "a value is required for '--fuzz-runs <RUNS>'
		// but none was supplied". No value was stated, so the invocation
		// is impossible, never unbounded. The wording stays the r26/r27
		// class-only one (no reason): a missing value is not a value the
		// tool's parser REFUSED, it is one that never arrived.
		return BoundDegenerate, ""
	}
	if tool == toolForge && len(occs) > 1 {
		// clap refuses a repeated --fuzz-runs outright (OBSERVED:
		// "forge test --fuzz-runs 0 --fuzz-runs 7" -> "error: the
		// argument '--fuzz-runs <RUNS>' cannot be used multiple
		// times", exit 2). Last-wins is click's rule, not forge's, so
		// `--fuzz-runs 0 --fuzz-runs 7` bound k=7 for a command no
		// forge process ever accepted (r32 F1).
		return BoundDegenerate, "forge: repeated " + last.name +
			" (cannot be used multiple times)"
	}
	n, why := parseBoundValue(tool, last.value)
	if why != "" {
		return BoundDegenerate, why
	}
	if BoundFloors(n) {
		// A stated value below 1 (or a Python-int-wide one): the class
		// wording is pinned, so the reason stays empty.
		return n, ""
	}
	return n, ""
}

// isOptionWord reports whether click's parser would read an argv element
// as an option: it begins with '-' and is not the bare "-" (stdin) or the
// "--" terminator (which boundFromArgv handles first).
func isOptionWord(w string) bool {
	return strings.HasPrefix(w, "-") && w != "-" && w != "--"
}

// looksLikeOption is the WIDER textual test the arity floor asks (r31 F3):
// it begins with '-' and is not the bare "-". It counts the `--`
// terminator (the requirement's own definition of option-looking), because
// a `-`-prefixed element after `--` is exactly where an unparsed flag and a
// positional value become indistinguishable — and it counts an element
// carrying its value inline, which ambiguousOptionArity then excepts by
// text, not by position.
func looksLikeOption(w string) bool {
	return strings.HasPrefix(w, "-") && w != "-"
}

// ambiguousOptionArity names the first adjacent pair of option-looking
// tokens whose option arity this parse cannot derive (r31 F3), "" when
// there is none. A pair is skipped when the FIRST of the two settles its
// own arity: an inline `=` gives it its value in place, and a bound flag
// takes the next element as its value by click's own rule (so its shape
// lands in the bound parser's accurate degenerate arm instead of here).
//
// The pair is reported as text for the floor summary, which caps and
// one-lines it: the reason must name the ambiguity, not merely its class.
func ambiguousOptionArity(toks []shToken) string {
	for i := 0; i+1 < len(toks); i++ {
		a, b := toks[i].text, toks[i+1].text
		if !looksLikeOption(a) || !looksLikeOption(b) {
			continue
		}
		if strings.Contains(a, "=") {
			continue // `--opt=v`: arity settled without a table
		}
		if _, _, _, bound := boundOptionWord(a); bound {
			continue // a bound flag's arity is known: one value
		}
		return oneLine(a, 40) + " followed by " + oneLine(b, 40)
	}
	return ""
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
