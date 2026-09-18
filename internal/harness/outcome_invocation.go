package harness

import (
	"fmt"
	"path/filepath"
	"strings"
)

// InvocationBound parses the bound flag out of an exec command string:
// halmos's --loop N, forge's --fuzz-runs N (both `--flag N` and
// `--flag=N`), minicertora's --loop-bound N. 0 = unstated: the number
// only feeds display text, never a rung. Four further answers are
// possible, and two of them floor (BoundFloors):
//
//	0                 the invocation named no bound (UNSTATED, not zero)
//	N >= 1            the value the owning tool's parser bound (MaxInt64
//	                  included, for the two Python tools)
//	BoundCapped       the invocation stated a bound WIDER than int64;
//	                  a stated bound, so it does NOT floor, and its
//	                  summary renders a lower bound (r31 F2). Reachable
//	                  only through Python's bignums: forge's u32 refuses
//	                  such a value outright (r32 F1)
//	BoundDegenerate   the invocation states a bound no tool would have
//	                  executed under (a value below 1, a value the owning
//	                  parser refuses, a repeated --fuzz-runs, a flag with
//	                  no value at all, or two different tools' bound
//	                  flags in one command)
//	BoundUnreadable   the command string cannot be lexed faithfully at
//	                  all, or its option arity is underivable (see
//	                  InvocationBoundReason for the construct)
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
// an honest one does not floor. r32 F1 narrows that rule to the tools it
// is true of: click and argparse bind last-wins, clap does not, so a
// repeated --fuzz-runs floors.
//
// r29 F4: it is SHELL-SHAPED first. The input is the recorded COMMAND
// STRING, not an argv, so the parse lexes it the way a POSIX shell would
// split it (lexCommand) and only then binds options the way the tool would
// (boundFromArgv). The old regex scanned the raw text, which read a
// `#`-comment's flag as the real one, read the flag out of a QUOTED
// argument (where click sees one positional), read a value across a `--`
// terminator (where click sees positionals), truncated `4_000` to `4` (a
// ledger lie: a stated 4 the tool never ran under), and blessed `4.5` /
// empty / missing values, which the twin refuses outright. Flags that the
// lexer cannot place are no longer guessed: the parse reports
// BoundUnreadable and the run floors.
//
// r32 F1/F2: it is TOOL-SHAPED too, and this kind-free entry point has no
// kind to shape it with — it derives the tool from the command itself (the
// program name argv[0], else the single bound-flag family the command
// names). Callers that hold the harness kind (the bind) must use
// InvocationBoundKind so the value semantics are the owning tool's.
func InvocationBound(command string) int {
	k, _ := InvocationBoundReason(command)
	return k
}

// InvocationBoundKind is InvocationBound for a caller that KNOWS the
// harness kind (r32 F1/F2). The kind decides which tool's command line the
// record's command must be read with, and the three tools do not agree:
//
//   - forge (forge-fuzz) is Rust/clap over foundry's config: --fuzz-runs
//     takes ASCII digits only, at most u32, at least 1, and the flag may
//     not repeat;
//   - halmos and minicertora are Python CLIs (argparse / click), whose
//     type=int is Python's int(): surrounding whitespace, a sign,
//     underscores between digits and any Nd digit are all values, and a
//     repeated flag is last-wins.
//
// The cli's wrapper used to take this kind and throw it away (`_ = kind`),
// so ONE Python-flavoured parse was applied to all three and real forge
// rejections ("--fuzz-runs 4_000" -> "invalid digit found in string")
// still blessed a bound no forge ever ran under. This is that wrapper's
// parse, with the kind kept.
func InvocationBoundKind(kind Kind, command string) int {
	k, _ := InvocationBoundKindReason(kind, command)
	return k
}

// InvocationBoundKindReason is InvocationBoundKind plus the construct or
// refusal that made the invocation unusable ("" for every invocation the
// tool would accept, including the ones that name no bound).
func InvocationBoundKindReason(kind Kind, command string) (int, string) {
	toks, construct := lexCommand(command)
	if construct != "" {
		return BoundUnreadable, construct
	}
	return boundFromArgv(toks, kind)
}

// InvocationBoundReason is InvocationBound plus the construct that made
// the command unreadable ("" for every readable command, including the
// ones that floor). Callers that hold the command pass the reason to
// MapRun so the stored floor names the exact observed state
// ("invocation-unreadable: unmatched single quote") instead of only the
// class. The exported InvocationBound keeps its signature — cli and the
// audit both call it — and delegates here.
//
// It is the KIND-FREE reading: with no kind, the tool is derived from the
// command itself (its argv[0] when that names one of the three tools,
// else the single bound-flag family it states), which is what section 11's
// re-derivation can do with the record alone. Callers that know the kind
// (the bind does: --kind or the scaffold's suffix) must use
// InvocationBoundKindReason instead, so the value semantics are the owning
// tool's.
func InvocationBoundReason(command string) (int, string) {
	return InvocationBoundKindReason("", command)
}

// ---------------------------------------------------------------------
// r32 F1/F2: which tool owns a bound flag, and what each tool's command
// line actually accepts.
// ---------------------------------------------------------------------

// invocationTool names the real CLI whose command line a record's command
// must be, and therefore whose argument parser decides whether the
// invocation exists at all.
type invocationTool uint8

const (
	toolForge invocationTool = iota
	toolHalmos
	toolMiniCertora
)

// String is the program name a floor summary names.
func (t invocationTool) String() string {
	switch t {
	case toolForge:
		return "forge"
	case toolHalmos:
		return "halmos"
	}
	return "minicertora"
}

// boundFlag is the ONE bound flag the tool actually has, VERIFIED against
// the installed binaries (r32 F2):
//
//	forge test --loop 3        -> error: unexpected argument '--loop' found
//	forge test --loop-bound 3  -> error: unexpected argument '--loop-bound'
//	halmos --fuzz-runs 500     -> halmos: error: unrecognized arguments:
//	                              --fuzz-runs 500
//	minicertora --fuzz-runs 200 a.sol a.mspec -> Error: No such option
//	                              '--fuzz-runs'.
func (t invocationTool) boundFlag() string {
	switch t {
	case toolForge:
		return "--fuzz-runs"
	case toolHalmos:
		return "--loop"
	}
	return "--loop-bound"
}

// toolForBoundFlag maps a bound flag NAME to its owning tool. ok=false for
// every other word, so only the three bound-looking names are ever
// cross-checked: an unrelated unknown option keeps its current behaviour
// (r32 F2 is deliberately NOT "any unknown option floors").
func toolForBoundFlag(name string) (invocationTool, bool) {
	switch name {
	case "--fuzz-runs":
		return toolForge, true
	case "--loop":
		return toolHalmos, true
	case "--loop-bound":
		return toolMiniCertora, true
	}
	return 0, false
}

// toolForKind maps a harness kind to the tool whose command line the
// record must be. ok=false for a kind with no bound flag of its own — the
// report-bound kind "miniprover", the empty kind, and every unknown
// spelling — which keep the kind-free reading.
func toolForKind(kind Kind) (invocationTool, bool) {
	switch kind {
	case ForgeFuzz:
		return toolForge, true
	case Halmos:
		return toolHalmos, true
	case MiniCertora:
		return toolMiniCertora, true
	}
	return 0, false
}

// toolForProgram names the tool an argv[0] denotes, by BASENAME: a
// recorded command may run an absolute path
// ("/root/.foundry/bin/forge"). It is the fallback the KIND-FREE reader
// has, and it is what makes `forge test --loop 3` floor for a caller that
// holds only the command string. The twin answers to two names — the Go
// kind's MiniCertora and the Python CLI's own "miniprover".
func toolForProgram(arg0 string) (invocationTool, bool) {
	switch filepath.Base(arg0) {
	case "forge":
		return toolForge, true
	case "halmos":
		return toolHalmos, true
	case "minicertora", "miniprover":
		return toolMiniCertora, true
	}
	return 0, false
}

// invocationToolOf names the tool whose command line this argv is, in the
// order the evidence is trusted: the KIND when the caller has one (the
// harness kind is the bind's own statement about which tool ran), else the
// program argv[0] names, else the single bound-flag family the command
// states. ok=false when none of the three exists (an unrecognized program
// and two families), which leaves the mixed-family rule below to floor.
func invocationToolOf(toks []shToken, occs []boundFlagOcc,
	kind Kind) (invocationTool, bool) {
	if t, ok := toolForKind(kind); ok {
		return t, true
	}
	if len(toks) > 0 && !toks[0].unknown &&
		!strings.HasPrefix(toks[0].text, "-") {
		if t, ok := toolForProgram(toks[0].text); ok {
			return t, true
		}
	}
	first, _ := toolForBoundFlag(occs[0].name)
	for _, o := range occs[1:] {
		if t, _ := toolForBoundFlag(o.name); t != first {
			return 0, false
		}
	}
	return first, true
}

// toolRefusal is the tool's own wording for an option it does not have,
// OBSERVED on this box (r32 F2). It rides the floor summary after the flag
// the tool refuses, so the ledger names both the flag and the observed
// rejection rather than only a class.
func toolRefusal(t invocationTool) string {
	switch t {
	case toolForge:
		return "unexpected argument"
	case toolHalmos:
		return "unrecognized arguments"
	}
	return "No such option"
}

// forgeMaxRuns is u32's top: foundry's fuzz.runs is a u32 and the config
// layer refuses anything wider ("foundry config error: invalid value
// unsigned int `4294967296`, expected u32 for setting `fuzz.runs`").
const forgeMaxRuns = int64(4294967295)

// parseBoundValue reads a bound flag's value the way the tool that OWNS
// the flag does, and returns the bound plus the refusal to name when the
// tool would not have run this invocation at all ("" = accepted).
//
// forge (r32 F1) — Rust's u32 FromStr plus foundry's own config check.
// OBSERVED with the installed forge 1.8.1:
//
//	forge test --fuzz-runs 4_000      -> error: invalid value '4_000' for
//	                                     '--fuzz-runs <RUNS>': invalid digit
//	                                     found in string              (exit 2)
//	forge test --fuzz-runs ٤٢         -> same "invalid digit found in string"
//	forge test --fuzz-runs $'500\r'   -> same "invalid digit found in string"
//	forge test --fuzz-runs ' 5'       -> same "invalid digit found in string"
//	forge test --fuzz-runs ''         -> "cannot parse integer from empty
//	                                     string"
//	forge test --fuzz-runs +5         -> accepted (u32::from_str takes '+')
//	forge test --fuzz-runs 0005       -> accepted (5)
//	forge test --fuzz-runs 4294967295 -> accepted (u32::MAX)
//	forge test --fuzz-runs 4294967296 -> Error: failed to extract foundry
//	                                     config: ... expected u32 for
//	                                     setting `fuzz.runs`          (exit 1)
//	forge test --fuzz-runs 0          -> foundry config error: `fuzz.runs`
//	                                     must be greater than 0
//	forge test --fuzz-runs=-1         -> "invalid digit found in string"
//
// So: an optional leading '+' then ASCII digits only — no whitespace, no
// underscores, no Unicode Nd digit, no '-', and the value must fit u32 and
// be at least 1. BoundCapped is unreachable here on purpose: a value
// beyond u32 is one forge REFUSES, not a stated bound too wide for our
// slot (r31 F2's capped reading held only because the parse assumed every
// tool spoke Python bignums).
//
// Every other family keeps Python's int semantics, which is what click and
// argparse really do — OBSERVED:
//
//	halmos --loop 4_000 / ٤٢ / +5 / 0 / -1 / 4294967296 -> all accepted
//	halmos --loop 0x10 / 1e3 / ''  -> usage error (exit 2)
//	halmos --loop 4 --loop 7       -> accepted, last wins (argparse)
//	minicertora --loop-bound 4_000 a.sol a.mspec -> accepted (click)
//	minicertora --loop-bound 0x10 a.sol a.mspec  -> Error: Invalid value
//	                                     for '--loop-bound': '0x10' is not
//	                                     a valid integer.
//	minicertora --loop-bound 0 a.sol a.mspec -> {"verdict": "UNKNOWN",
//	                                     "details": "--loop-bound must be
//	                                     >= 1, got 0"}
//	minicertora --loop-bound 4 --loop-bound 0 a.sol a.mspec -> the 0 wins
//
// The <1 floor on the Python side is the twin's own rule (the minicertora
// CLI answers "must be >= 1", and the twin raises in VerifierFlags), which
// is why a stated 0 still floors rather than binding a proof about nothing
// (r26 F3).
func parseBoundValue(tool invocationTool, raw string) (int, string) {
	if tool == toolForge {
		return parseForgeRuns(raw)
	}
	n, status := parseClickInt(raw)
	switch status {
	case intNotAnInt:
		// click/argparse: "'4.5' is not a valid integer." The
		// invocation is impossible, so it states no bound any tool ran
		// under. No reason string: the r26/r27 wording for a stated
		// degenerate value is pinned byte-for-byte.
		return BoundDegenerate, ""
	case intOverflowNegative:
		return BoundDegenerate, ""
	case intOverflowPositive:
		// Python bignums accept this value, so the tool really bound
		// it (r31 F2: the invocation DID state a bound, and calling it
		// "unstated" rendered "proved bounded (bound UNSTATED)" with a
		// null bounded_k). Still no reason: it is accepted, not refused.
		return BoundCapped, ""
	}
	if n < 1 {
		return BoundDegenerate, ""
	}
	return n, ""
}

// parseForgeRuns reads --fuzz-runs the way forge 1.8.1 does (evidence in
// parseBoundValue's comment) and names the tool and the observed reason
// when the value is one forge rejects.
func parseForgeRuns(raw string) (int, string) {
	bad := func(reason string) (int, string) {
		return BoundDegenerate, fmt.Sprintf("forge --fuzz-runs %s: %s",
			oneLine(raw, 16), reason)
	}
	if raw == "" {
		return bad(`cannot parse integer from empty string`)
	}
	i := 0
	if raw[0] == '+' {
		i = 1
	}
	if i == len(raw) {
		return bad("invalid digit found in string")
	}
	n := int64(0)
	for ; i < len(raw); i++ {
		c := raw[i]
		if c < '0' || c > '9' {
			return bad("invalid digit found in string")
		}
		n = n*10 + int64(c-'0')
		if n > forgeMaxRuns {
			return bad("expected u32 for fuzz.runs")
		}
	}
	if n < 1 {
		return bad("fuzz.runs must be greater than 0")
	}
	return int(n), ""
}
