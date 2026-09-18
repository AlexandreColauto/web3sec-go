package harness

import (
	"math"
	"strconv"
)

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
// the one predicate, and a new one must too. BoundCapped is the reason the
// predicate is not spelled `k < 0` at the call sites either: it is a
// STATED bound, so a caller that floored every negative would refuse a run
// that really named a bound (r31 F2).
const BoundUnreadable = -2

// BoundCapped is a STATED bound whose exact value does not fit in int64
// (r31 F2). Python's int — and therefore click's type=int and the twin's
// VerifierFlags — is arbitrary precision, so
// `forge test --fuzz-runs 99999999999999999999999999` really did run under
// that bound; only OUR parse cannot hold it. It is therefore NOT
// "unstated" (the r28 reading: the value was mapped to 0 and the run
// rendered "proved bounded (bound UNSTATED)" with a null bounded_k) and
// NOT a floor: the invocation did state a bound.
//
// It is its own value so every rendering can say LOWER BOUND rather than
// assert a smaller EXACT number than the tool ran under (boundText renders
// ">=9223372036854775807"), while BoundK saturates the recorded bounded_k
// to MaxInt64 — the same stand-in (and the same carried digits) the cli's
// own Python-int reader uses for an unbounded `--max-stages`
// (parsePyInt). A value that is exactly MaxInt64 is NOT capped: the whole
// int64 range is a legal stated bound.
const BoundCapped = -3

// BoundFloors reports whether a parsed invocation bound floors the run:
// true for a STATED degenerate bound (BoundDegenerate) and for a command
// the parse could not read (BoundUnreadable). UNSTATED (0) and every
// stated N >= 1 do not floor — 0 is "the invocation named no bound", a
// display fact, never a boundary at which something ran.
//
// BoundCapped is the one negative value that does NOT floor (r31 F2): it
// is a stated bound that is merely too wide for int64. The test stays
// written as `k < 0` minus that exception on purpose — a NEW negative
// sentinel a future round adds floors by default (fail-closed) instead of
// riding along as a stated bound because someone forgot to list it.
func BoundFloors(k int) bool { return k < 0 && k != BoundCapped }

// boundText renders a stated bound as the NUMBER inside a summary: a
// capped bound must never render as a smaller EXACT number than the tool
// ran under (r31 F2), so it renders as a lower bound; every other value is
// its own digits.
func boundText(k int) string {
	if k == BoundCapped {
		return ">=" + strconv.FormatInt(math.MaxInt64, 10)
	}
	return strconv.Itoa(k)
}

// boundClause is boundText with the "k" the proved-bounded summaries carry:
// "k=4" for a stated value, "k>=9223372036854775807" for a capped one.
func boundClause(k int) string {
	if k == BoundCapped {
		return "k" + boundText(k)
	}
	return "k=" + boundText(k)
}

// boundFloorSummary is the one-line reason a floored invocation carries.
// The "degenerate-bound" prefix is load-bearing: disposition.go
// classifies it (EscalateBound), and a distinct second wording class here
// would silently drop that advice. It is the ONE wording home for every
// floor — MapRun, MapMinicertoraInvoc and the minicertora timeout arm all
// call it — so the label can never drift between the arms.
//
// Two labels, one class. "invocation-unreadable" is the r29/r30 vocabulary
// for a command the parse could not read faithfully (the construct is
// appended); "invocation-refused" is the r32 F1/F2 vocabulary for an
// invocation the parse READ, whose own tool would refuse it — a value the
// tool's argument parser rejects, or a bound flag another tool family
// owns. Both are the same floor class and the same predicate
// (BoundFloors); only the sentence differs, because an unreadable command
// and a refused one are different observations and the summary must not
// claim either it did not make.
func boundFloorSummary(k int, unreadable ...string) string {
	const prefix = "inconclusive (degenerate-bound: "
	why := ""
	if len(unreadable) > 0 {
		why = oneLine(unreadable[0], maxConstruct)
	}
	if why != "" && k == BoundDegenerate {
		return prefix + "invocation-refused: " + why + ")"
	}
	if k == BoundUnreadable || why != "" {
		if why == "" {
			why = "the command could not be lexed faithfully"
		}
		return prefix + "invocation-unreadable: " + why + ")"
	}
	return prefix + "the invocation states no bound >= 1)"
}
