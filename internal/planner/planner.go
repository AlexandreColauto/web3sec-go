// Package planner ports webv2.planner: the contract between strategy and
// execution. It validates the plan, enforces orthogonality between discovery
// trajectories, computes the decision rule (prior risk x validation cost),
// and hands the orchestrator an ORDERED, BOUNDED work list.
//
// The orchestrator decides whether and when a stage runs. The plan is data it
// consumes — never a script the model executes.
package planner

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"unicode"

	"websec/internal/validation"
)

// LensIDs is LENS_IDS: the canonical check families, in order.
var LensIDs = []string{"liveness", "incentive-inversion", "enforcement-timing",
	"primitive-symmetry"}

// MinDistinctClasses is MIN_DISTINCT_CLASSES.
const MinDistinctClasses = 4

// ProbeRowDispositioned is PROBE_ROW_DISPOSITIONED: a probe row is
// DISPOSITIONED by an affirmative closure or by a reasoned `deprioritized` —
// plan Risks 1: "`deprioritized --reason` is a legitimate terminal
// disposition", and `work_queue` already skips it, so the queue and the lens
// gate agree on what a park means. `blocked` stays out: it is not a decision
// to stop looking, so the lens remains open.
var ProbeRowDispositioned = []string{"answered", "not-applicable",
	"deprioritized"}

// AdjacentRequiredMsg is ADJACENT_REQUIRED_MSG.
const AdjacentRequiredMsg = "DISPROVED on a lifecycle finding must name the " +
	"adjacent unchecked property (--adjacent '...') or attest it clear " +
	"(--adjacent-clear --reason R)"

// lensQuestions is _LENS_QUESTIONS. Every template's only format slot is
// {machines}; formatLens substitutes it the way str.format would.
var lensQuestions = map[string]string{
	"liveness": "LIVENESS: is there a reachable state from which an intended " +
		"transition (finalize, withdraw, challenge, claim) is " +
		"permanently impossible? At which layer, and who can reach " +
		"that state? For every liveness hypothesis, file the " +
		"adversarial_game clause at ingest — the gate requires it. " +
		"State machines in the model: {machines}",
	"incentive-inversion": "INCENTIVE-INVERSION: does the protocol ever PAY " +
		"an attacker or PUNISH an honest actor (challenge, slash, claim, " +
		"delegate) under any reachable state? Trace what the honest " +
		"participant gets for being right. State machines in the model: " +
		"{machines}",
	"enforcement-timing": "ENFORCEMENT-TIMING: for each security-critical " +
		"check, is it enforced at the EARLIEST lifecycle stage it could be " +
		"(intake, not execution)? A check that exists only at " +
		"finalize/execute time is a candidate. State machines in the " +
		"model: {machines}",
	"primitive-symmetry": "PRIMITIVE-SYMMETRY: group functions into sibling " +
		"lifecycle families (deposit <-> withdraw <-> drop <-> refund) and " +
		"compare primitives + access control across siblings. A family " +
		"that burns on one path and mints/safeTransfers on another is a " +
		"candidate. State machines in the model: {machines}",
}

// lifecycleVerbs is _LIFECYCLE_VERBS.
var lifecycleVerbs = []string{"deposit", "withdraw", "drop", "refund", "mint",
	"burn", "claim", "finalize", "challenge", "complete", "lock", "unlock",
	"stake", "unstake"}

// formatLens is str.format(machines=...): every template slot is {machines},
// so a literal substitution is exact (verified against the Python twin).
func formatLens(template, machines string) string {
	return strings.ReplaceAll(template, "{machines}", machines)
}

// ---- Python value helpers ------------------------------------------------

// kv is the keyed KV constructor.
func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

// fieldAt is v[key] when present.
func fieldAt(v validation.Value, key string) (validation.Value, bool) {
	if v.Kind != validation.Obj {
		return validation.VNull(), false
	}
	for _, pair := range v.O {
		if pair.K == key {
			return pair.V, true
		}
	}
	return validation.VNull(), false
}

// hasKey is `key in v`.
func hasKey(v validation.Value, key string) bool {
	_, ok := fieldAt(v, key)
	return ok
}

// dropKey is `o.pop(key, None)`.
func dropKey(o []validation.KV, key string) []validation.KV {
	for i := range o {
		if o[i].K == key {
			return append(o[:i:i], o[i+1:]...)
		}
	}
	return o
}

// pyTruthyBigNonEmpty is a DIVERGENT pyTruthy variant (Wave J Task 7), NOT the
// canonical form; it is named so the divergence is visible.
// Rule: exactly validation.PyTruthy, except that an Int with any non-empty Big
// text is truthy — including Big == "0", which validation.PyTruthy (and
// CPython) reads falsy. The divergence is reachable only for Values that
// violate jval's invariant that Big is set only when the integer does not fit
// int64.
func pyTruthyBigNonEmpty(v validation.Value) bool {
	switch v.Kind {
	case validation.Null:
		return false
	case validation.Bool:
		return v.B
	case validation.Int:
		return v.Big != "" || v.I != 0
	case validation.Flt:
		return v.F != 0
	case validation.Str:
		return v.S != ""
	case validation.Arr:
		return len(v.A) > 0
	case validation.Obj:
		return len(v.O) > 0
	}
	return false
}

// pyStr is str(v) for the JSON-shaped subset.
func pyStr(v validation.Value) string {
	switch v.Kind {
	case validation.Null:
		return "None"
	case validation.Bool:
		if v.B {
			return "True"
		}
		return "False"
	case validation.Int:
		return validation.IntText(v)
	case validation.Flt:
		return validation.PythonFloat(v.F)
	case validation.Str:
		return v.S
	}
	return validation.PyRepr(v)
}

// pyIsSpace is Python str.isspace(): the Unicode whitespace property plus the
// four ASCII information separators Python also treats as whitespace.
func pyIsSpace(r rune) bool {
	if r >= 0x1c && r <= 0x1f {
		return true
	}
	return unicode.IsSpace(r)
}

// pyStrip is Python str.strip().
func pyStrip(s string) string {
	return strings.TrimFunc(s, pyIsSpace)
}

// listOf is v.get(key) as a list (empty when absent/not a list).
func listOf(v validation.Value, key string) []validation.Value {
	got := validation.ObjAt(v, key)
	if got.Kind != validation.Arr {
		return nil
	}
	return got.A
}

// sortedKeys is sorted(m) for a set of strings.

// sortedMapKeys is sorted(m) for a map of any values.
func sortedMapKeys[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sortStrings is Python's sorted() over str (Go's byte-wise order on UTF-8
// equals code-point order).

// itoa is str(n) for a non-negative int.
func itoa(n int) string { return strconv.Itoa(n) }

// atoi is int(s) when s is a valid integer.
func atoi(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return n, true
}

// statFile is Path.exists().
func statFile(p string) (os.FileInfo, error) { return os.Stat(p) }

// errValue is `raise ValueError(msg)`: str(ValueError) is the message.
func errValue(msg string) error { return fmt.Errorf("%s", msg) }

// errKey is `raise KeyError(msg)`: str(KeyError) is repr(msg).
func errKey(msg string) error {
	return fmt.Errorf("%s", validation.PyReprStr(msg))
}
