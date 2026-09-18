// Package reproduction ports webv2.reproduction: tiered reproduction as a
// search problem, the attempt ledger, and the E4/E5/E6 minting paths.
//
// Key property (from the Python docstring): a FAILED attempt is a structured
// record, not a dead end. When an attempt fails with
// failure_class=environment/setup, the retry is mandated as FRESH CONTEXT.
package reproduction

import (
	"errors"
	"fmt"
	"strings"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// TierOrder is TIER_ORDER.
var TierOrder = []string{"none", "T0", "T1", "T2", "T3", "T4"}

// freshContextClasses is _FRESH_CONTEXT_CLASSES.
var freshContextClasses = map[string]struct{}{
	"environment": {}, "setup": {}, "precondition-unmet": {},
}

// hypothesisWrongClasses is _HYPOTHESIS_WRONG_CLASSES.
var hypothesisWrongClasses = map[string]struct{}{
	"logic": {}, "hypothesis-wrong": {},
}

// MintableTypes is _MINTABLE_TYPES: the evidence types a reproduction mint
// may claim (mirrors the schema enum).
var MintableTypes = []string{"reasoning", "static-analysis", "reachability",
	"unit-test", "foundry-test", "fuzz", "invariant-test", "symbolic-witness",
	"fork-test", "trace", "balance-delta", "differential", "historical-analog",
	"manual"}

// MintError is the ValueError/RuntimeError/KeyError family cmd_mint maps to
// `mint failed: ...` + exit 2. Everything else (a missing exec record, a
// missing finding) is the generic exit-1 handler's business.
type MintError struct{ Msg string }

func (e *MintError) Error() string { return e.Msg }

func mintErrf(format string, a ...any) error {
	return &MintError{Msg: fmt.Sprintf(format, a...)}
}

// mintWrap marks an error from the evidence gate as mint-class (Python's
// add_evidence raises ValueError, which cmd_mint catches).
func mintWrap(err error) error {
	if err == nil {
		return nil
	}
	var me *MintError
	if errors.As(err, &me) {
		return err
	}
	return &MintError{Msg: err.Error()}
}

// TierOf is tier_of (delegated to findings.ReproTierOf so the ingest exec_ref
// path reads the recorded tier through the same reader — wave N, T2).
func TierOf(repro validation.Value) string {
	return findings.ReproTierOf(repro)
}

// NextTier is next_tier: the next rung, or None at the end (Python's
// ValueError for a tier name that is not in TIER_ORDER).
func NextTier(current string) (string, bool, error) {
	for i, tier := range TierOrder {
		if tier == current {
			if i+1 < len(TierOrder) {
				return TierOrder[i+1], true, nil
			}
			return "", false, nil
		}
	}
	return "", false, fmt.Errorf("%s is not in list",
		validation.PyReprStr(current))
}

// --- helpers ----------------------------------------------------------------

func tierIndex(tier string) int {
	for i, t := range TierOrder {
		if t == tier {
			return i
		}
	}
	return -1
}

func inSet(set map[string]struct{}, key string) bool {
	_, ok := set[key]
	return ok
}

// tupleRepr is Python's repr of a tuple of strings.
func tupleRepr(items []string) string {
	parts := make([]string, 0, len(items))
	for _, s := range items {
		parts = append(parts, validation.PyReprStr(s))
	}
	if len(parts) == 1 {
		return "(" + parts[0] + ",)"
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

// pyReprScalar is Python's repr for the JSON scalars an exec field holds.
func pyReprScalar(v validation.Value) string {
	if v.Kind == validation.Str {
		return validation.PyReprStr(v.S)
	}
	return validation.PyRepr(v)
}

// asDict is Python's `x if isinstance(x, dict) else {}` used by the
// setdefault chains (a fresh dict that the caller then stores).
func asDict(v validation.Value) validation.Value {
	if v.Kind == validation.Obj {
		return validation.Value{Kind: validation.Obj,
			O: append([]validation.KV(nil), v.O...)}
	}
	return validation.VObj()
}

func setKey(v validation.Value, key string, val validation.Value) validation.Value {
	out := validation.Value{Kind: validation.Obj, O: append(
		[]validation.KV(nil), v.O...)}
	for i := range out.O {
		if out.O[i].K == key {
			out.O[i].V = val
			return out
		}
	}
	out.O = append(out.O, validation.KV{K: key, V: val})
	return out
}

func dropKey(v validation.Value, key string) validation.Value {
	out := validation.Value{Kind: validation.Obj}
	for _, kv := range v.O {
		if kv.K != key {
			out.O = append(out.O, kv)
		}
	}
	return out
}

func optField(v validation.Value, key string) *string {
	f := validation.ObjAt(v, key)
	if f.Kind == validation.Str {
		s := f.S
		return &s
	}
	return nil
}

func intOf(v validation.Value) int {
	if v.Kind == validation.Int {
		return int(v.I)
	}
	return 0
}

func shortID(n int) string {
	parts := strings.SplitN(state.NewID("x", n), "-", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return ""
}
