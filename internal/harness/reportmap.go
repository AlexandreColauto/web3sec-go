package harness

import (
	"fmt"
	"strings"

	"websec/internal/validation"
)

// MapReport is the autoprove decision function — the rollup-over-
// per_rule authority law (r19 P1), the symmetry rails (r20 F5), the
// UNSTATED wording (r20 F11), and the typed bound (r24 F3 / r25 F3)
// — extracted so the AUDIT can re-derive exactly what the mapper
// decided from the report bytes a bind pinned (r25 F2: the
// REPORT-* recheck was ownership-only; a chain-valid forgery over
// honest registry bytes rendered k=100/9 rules while the pinned
// report said k=0/1-rule, audit-green). Pure: (outcome, per_rule,
// bound) in, rung/summary/bounded_k out. cli.verifyAutoprove is now
// a caller; drift between bind-time and audit-time decisions is
// structurally impossible.
func MapReport(outcome string, perRule validation.Value, k int,
	kStated bool) (rung, summary string, bk *int) {
	switch outcome {
	case "PROVEN":
		kvs := rpKVs(perRule)
		if perRule.Kind == validation.Arr || len(kvs) == 0 {
			if perRule.Kind == validation.Arr {
				return RungInconclusive, "inconclusive (malformed " +
					"per_rule: an ARRAY has no rule keys — the mapper " +
					"is rule-keyed by contract)", nil
			}
			return RungInconclusive, "inconclusive (UNATTRIBUTED: the " +
				"property claims PROVEN with no per-rule outcomes)", nil
		}
		bad := []string{}
		for _, kv := range kvs {
			if rpScalar(kv.V) != "PROVEN" {
				bad = append(bad, kv.K+"="+rpScalar(kv.V))
			}
		}
		if len(bad) > 0 {
			return RungInconclusive, "inconclusive " +
				"(report-contradiction: rollup says PROVEN but " +
				"per_rule carries " + rpHead(bad, 5) + ")", nil
		}
		n := len(kvs)
		if kStated {
			s := fmt.Sprintf("autoproved bounded (k=%d, %d rules)", k, n)
			kp := k
			return RungProvedBounded, s, &kp
		}
		return RungProvedBounded, fmt.Sprintf(
			"autoproved bounded (bound UNSTATED, %d rules)", n), nil
	case "VIOLATED":
		viol := []string{}
		for _, kv := range rpKVs(perRule) {
			if rpScalar(kv.V) == "VIOLATED" {
				viol = append(viol, kv.K)
			}
		}
		if len(viol) == 0 {
			return RungInconclusive, "inconclusive " +
				"(report-contradiction: rollup says VIOLATED but " +
				"per_rule carries no violated line)", nil
		}
		return RungCounterexample, "counterexample (autoprove refuted " +
			"rules: " + rpHead(viol, 5) + ")", nil
	default:
		return RungInconclusive,
			"inconclusive (prover rollup: " + outcome + ")", nil
	}
}

// BoundFromFlags types the loop_bound read (r24 F3): ok=false with a
// reason when the shape is foreign (float/string/big/negative-or-zero
// int — the twin raises for <1, so 0 means FOREIGN, not stated).
// stated=false only for absent/null.
func BoundFromFlags(flags validation.Value) (k int, stated, ok bool,
	reason string) {
	v := objAtRP(flags, "loop_bound")
	switch v.Kind {
	case validation.Null:
		return 0, false, true, ""
	case validation.Int:
		if v.I < 1 {
			return 0, false, false, fmt.Sprintf(
				"is %d — the twin refuses degenerate bounds (<1; a "+
					"k=0 'proof' checks only the initial state)", v.I)
		}
		return int(v.I), true, true, ""
	default:
		return 0, false, false, fmt.Sprintf(
			"is not an integer (kind %v: %s)", v.Kind, rpScalar(v))
	}
}

func objAtRP(o validation.Value, key string) validation.Value {
	if o.Kind != validation.Obj {
		return validation.VNull()
	}
	for _, kv := range o.O {
		if kv.K == key {
			return kv.V
		}
	}
	return validation.VNull()
}

func rpKVs(v validation.Value) []validation.KV {
	if v.Kind != validation.Obj {
		return nil
	}
	return v.O
}

func rpScalar(v validation.Value) string {
	switch v.Kind {
	case validation.Str:
		return v.S
	case validation.Int:
		return validation.IntText(v)
	case validation.Bool:
		if v.B {
			return "True"
		}
		return "False"
	case validation.Null:
		return "None"
	case validation.Flt:
		return validation.PythonFloat(v.F)
	default:
		return validation.CanonCompact(v)
	}
}

// rpHead mirrors cli.joinHead BYTE-FOR-BYTE ("none attributed" for the
// empty list is load-bearing event text).
func rpHead(xs []string, n int) string {
	if len(xs) == 0 {
		return "none attributed"
	}
	if len(xs) > n {
		return strings.Join(xs[:n], ", ") + fmt.Sprintf(" (+%d more)",
			len(xs)-n)
	}
	return strings.Join(xs, ", ")
}
