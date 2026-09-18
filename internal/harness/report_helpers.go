package harness

import (
	"fmt"
	"strings"

	"websec/internal/validation"
)

// ReportProperty resolves property_outcomes[name] the way the BIND does:
// cli.fieldOf's EXACT key lookup, nothing else (r32b F1). The audit used to
// fold case and edges here, so a forged event naming "P1" for a report
// keyed "p1" re-derived a mapping the bind can never make — the bind
// refuses those very bytes and that very name with "is not in this run …
// exact-match only". One lookup, the stricter and documented one.
func ReportProperty(rep validation.Value, name string) (validation.Value,
	bool) {
	po := objAtRP(rep, "property_outcomes")
	if po.Kind != validation.Obj {
		return validation.VNull(), false
	}
	for _, kv := range po.O {
		if kv.K == name {
			return kv.V, true
		}
	}
	return validation.VNull(), false
}

// reportPublished is the report-level published read (validation.PyTruthy —
// see DecideReport's note).
func reportPublished(rep validation.Value) bool {
	return validation.PyTruthy(objAtRP(rep, "published"))
}

// ReportSuspects renders the reasons of SUSPECT review findings for one
// property ("" when none) — PROVEN must not bind over them. Moved out of
// cli.verifyAutoprove verbatim so the bind's gate and the audit's
// re-derivation are the same code.
func ReportSuspects(rep validation.Value, property string) string {
	out := []string{}
	for _, f := range objAtRP(rep, "review_findings").A {
		// r20 F2: the prover stores the review LLM's verdict VERBATIM —
		// "SUSPECT"/"Suspect" is the same word and the same danger; the
		// gate is case-insensitive by law.
		// r21 F2: the gate is FAIL-CLOSED against the shapes an LLM review
		// actually emits: verdict is TRIMMED as well as case-folded
		// (" suspect " is the same flag), and a finding element that is
		// not an object (a bare string was the critic's dodge) has NO
		// property to match — it counts against EVERY property.
		// Unparseable warning is never cleared warning.
		if f.Kind != validation.Obj {
			out = append(out, "malformed review finding (non-object): "+
				rpScalar(f))
			continue
		}
		v := strings.ToLower(strings.TrimSpace(rpObjStr(f, "verdict")))
		if v != "" && v != "suspect" {
			continue
		}
		if f2 := objAtRP(f, "property"); f2.Kind != validation.Str {
			out = append(out, "suspect-flagged finding with no property "+
				"attribution — counted against every property")
			continue
		}
		if !rpSameName(rpObjStr(f, "property"), property) {
			continue
		}
		out = append(out, rpScalar(objAtRP(f, "reason")))
	}
	return strings.Join(out, "; ")
}

// rpSameName was cli.autoproveSameName verbatim: property titles are
// AGENT-authored strings — the same verbatim-slop class r21 F2 fixed for
// verdicts. Attribution and consumption fold case + edges (display keeps
// the first spelling; identity is the folded form). NOTE this is the
// SUSPECT gate's matching rule only: the property whose OUTCOME is read is
// resolved by ReportProperty's exact lookup.
//
// r33 F2 collapsed the two copies (this one and the cli helper) into
// SamePropertyName: a fold spelled twice is a fold that can drift, and
// section 11's duplicate rail must collide exactly where the bind does.
// rpSameName is the SUSPECT gate's spelling of SamePropertyName — the same
// fold the bind's property-holder scan uses (r33 F2), so a review finding
// flagged against " P1 " is a finding against the property "p1" the bind
// would collide on.
func rpSameName(a, b string) bool {
	return SamePropertyName(a, b)
}

// rpObjStr mirrors cli.objStr BYTE-FOR-BYTE: the string only when the field
// IS a string, "" for absent/null/any other shape. (rpScalar is the
// f-string renderer and would turn an absent field into "None" — which
// would flip three gates: review_error would "fire" on its own absence,
// an absent verdict would stop being fail-closed, and an absent outcome
// would map "inconclusive (prover rollup: None)" instead of the bind's
// "inconclusive (prover rollup: )".)
func rpObjStr(o validation.Value, key string) string {
	if v := objAtRP(o, key); v.Kind == validation.Str {
		return v.S
	}
	return ""
}

// rpJoinOrDash mirrors cli.joinOrDash for the veto-list rendering.
func rpJoinOrDash(xs []string) string {
	if len(xs) == 0 {
		return "-"
	}
	return strings.Join(xs, "; ")
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
		// r31 F2: when the exact digits live in Big, v.I is a truncated
		// 0 — reporting that as "is 0" would name a degenerate bound the
		// twin never saw. Name the real state instead (the refusal
		// itself is unchanged: this ledger's slot cannot hold it).
		if v.Big != "" {
			exact := validation.IntText(v)
			if strings.HasPrefix(exact, "-") {
				return 0, false, false, fmt.Sprintf(
					"is %s — the twin refuses degenerate bounds (<1; a "+
						"k=0 'proof' checks only the initial state)",
					exact)
			}
			return 0, false, false, fmt.Sprintf(
				"is %s — wider than the int64 slot this ledger holds "+
					"(the twin would run under it)", exact)
		}
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

// rpEntries mirrors cli.objKVs for the VETO LIST's emptiness read: an
// object's entries, or one entry per element of an array. rpKVs is the
// per_rule reader (an object is the contract there; an ARRAY per_rule is
// the malformed shape MapReport names), and using it for publish_problems
// would read every non-empty ARRAY as empty — switching the whole veto gate
// off, the exact class this round is closing.
func rpEntries(o validation.Value) []validation.KV {
	if o.Kind == validation.Obj {
		return o.O
	}
	if o.Kind == validation.Arr {
		out := make([]validation.KV, 0, len(o.A))
		for _, v := range o.A {
			out = append(out, validation.KV{V: v})
		}
		return out
	}
	return nil
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
