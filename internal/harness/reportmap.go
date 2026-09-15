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

// ---------------------------------------------------------------------
// r32b F1: the five report gates, ONE implementation.
//
// cli.verifyAutoprove's run-level gates used to exist only in that file, and
// section 11's recheckRegistryEvidence re-derived only rung/summary/
// bounded_k through MapReport. A content-address-consistent replacement of
// the stored report copy whose ONLY difference was
// review_findings:[{verdict:"SUSPECT"}] (or published:false) therefore
// audited green over bytes a fresh bind refuses with exit 2 — a rung the
// bind refuses, blessed by the audit. The docs' claim ("the audit must
// re-derive EVERY decision the bind made, through the SAME code path with
// the SAME arguments") was false for these five gates.
//
// DecideReport is now that ONE path: the five gates (publish_problems'
// shape and emptiness, published, review_error, the review_findings SHAPE,
// SUSPECT attribution), the EXACT property lookup, the typed bound read,
// and then MapReport. cli.verifyAutoprove calls it; section 11 calls it
// over the pinned copy's bytes with the property name the event binds.
// Refusal carries the bind's own sentence — everything the bind prints
// after its "verify --autoprove: " prefix — so the two callers cannot
// drift apart in wording either.
//
// MapReport keeps its frozen (outcome, per_rule, k, kStated) signature: the
// gates need the whole report, which those inputs never carry, and other
// callers pin that mapping entry point. DecideReport is the sibling that
// both the bind and the audit run, and it ends by calling MapReport — one
// mapping implementation, one gate implementation.
// ---------------------------------------------------------------------

// ReportGate names the decision that refused a report. GateNone means every
// gate passed and the report mapped.
type ReportGate string

const (
	GateNone                 ReportGate = ""
	GatePublishProblemsShape ReportGate = "publish_problems-shape"
	GatePublishProblems      ReportGate = "publish_problems"
	GatePublished            ReportGate = "published"
	GatePropertyOutcomes     ReportGate = "property_outcomes"
	GateProperty             ReportGate = "property attribution"
	GateReviewError          ReportGate = "review_error"
	GateReviewFindingsShape  ReportGate = "review_findings-shape"
	GateSuspect              ReportGate = "suspect"
	GateLoopBound            ReportGate = "flags.loop_bound"
)

// ReportDecision is DecideReport's answer: either Gate != GateNone with the
// bind's Refusal sentence, or the mapped rung/summary/bounded_k.
type ReportDecision struct {
	Gate     ReportGate
	Refusal  string
	Rung     string
	Summary  string
	BoundedK *int
	// Outcome is the bound property's own rollup string (cli.objStr
	// semantics) — the artifact note names it.
	Outcome string
}

// DecideReport is the bind's and the audit's ONE autoprove decision path
// (r32b F1). It returns the first gate that refuses the report, in the
// bind's own order, or the MapReport mapping of the property's rollup.
//
// The published read is validation.PyTruthy — the canonical predicate. It is
// the one deliberate divergence from cli.t26Truthy (which the old inline
// gate used): no twin emits a non-bool `published`, and PyTruthy makes a
// foreign shape (an out-of-int64 zero) read as NOT published, which
// refuses. The bind's bytes are unchanged for every shape the report
// contract can carry.
func DecideReport(rep validation.Value, property string) ReportDecision {
	probsPre := objAtRP(rep, "publish_problems")
	if probsPre.Kind != validation.Null && probsPre.Kind != validation.Arr {
		// r20 F6: the veto list is a LIST by contract — a scalar there is
		// either a lie or a bug; both refuse better than bind.
		return ReportDecision{Gate: GatePublishProblemsShape,
			Refusal: fmt.Sprintf("malformed publish_problems (kind %v, "+
				"contract: array) — the veto list is machine-authored; "+
				"refusing to read a broken contract\n", probsPre.Kind)}
	}
	if len(rpEntries(probsPre)) > 0 {
		// r19 P2: publish_problems is the prover's own veto list — binding
		// a rollup over a report that carries problems (even with published
		// true, a contradiction the prover itself refuses to emit)
		// launders them.
		msgs := []string{}
		for _, pv := range probsPre.A {
			msgs = append(msgs, rpScalar(pv))
		}
		return ReportDecision{Gate: GatePublishProblems,
			Refusal: fmt.Sprintf("the report carries publish_problems "+
				"(%s)%s\n", rpJoinOrDash(msgs), map[bool]string{
				true: " while claiming published — internally " +
					"contradictory; nothing binds",
				false: " — the run is unpublished; nothing binds",
			}[reportPublished(rep)])}
	}
	if !reportPublished(rep) {
		probs := []string{}
		for _, p := range objAtRP(rep, "publish_problems").A {
			probs = append(probs, rpScalar(p))
		}
		return ReportDecision{Gate: GatePublished,
			Refusal: fmt.Sprintf("the prover did NOT publish this run — "+
				"nothing is blessed (problems: %s)\n",
				rpJoinOrDash(probs))}
	}
	po := objAtRP(rep, "property_outcomes")
	if po.Kind != validation.Obj {
		return ReportDecision{Gate: GatePropertyOutcomes,
			Refusal: "report carries no property_outcomes map — " +
				"contract broken\n"}
	}
	prop, ok := ReportProperty(rep, property)
	if !ok {
		names := []string{}
		for _, kv := range po.O {
			names = append(names, kv.K)
		}
		return ReportDecision{Gate: GateProperty,
			Refusal: fmt.Sprintf("property %s is not in this run (the "+
				"prover attempted: %s) — exact-match only\n",
				validation.PyReprStr(property), rpJoinOrDash(names))}
	}
	// r22 F2: the prover records review_error precisely so "no findings"
	// and "no review" never look alike — a run whose review role CRASHED
	// carries an EMPTY findings list that means nothing. Law: an unmade
	// check is never a cleared check.
	if re := rpObjStr(rep, "review_error"); re != "" {
		return ReportDecision{Gate: GateReviewError,
			Refusal: fmt.Sprintf("the independent review NEVER RAN (%s) — "+
				"PROVEN binds without it only by inattention; "+
				"refusing\n", re)}
	}
	if v := objAtRP(rep, "review_findings"); v.Kind != validation.Arr {
		// r22 F5: the twin ALWAYS emits an array — null, absent, or scalar
		// are all foreign contracts. An unreadable gate input reads as
		// "nothing flagged" to nothing: refuse.
		return ReportDecision{Gate: GateReviewFindingsShape,
			Refusal: fmt.Sprintf("malformed review_findings (kind %v, "+
				"contract: array) — the gate reads the review's output; "+
				"a broken one is never empty enough to pass\n", v.Kind)}
	}
	if sus := ReportSuspects(rep, property); sus != "" {
		return ReportDecision{Gate: GateSuspect,
			Refusal: fmt.Sprintf("the independent review flagged property "+
				"%s as SUSPECT — %s — a PROVEN verdict next to a suspect "+
				"review is the most expensive state there is; the rung "+
				"is refused, fix the rule or waive with reason\n",
				property, sus)}
	}
	// r24 F3: the bound is READ TYPED — a float is truncation, a
	// string/big is a foreign shape, and the twin's VerifierFlags raises
	// for loop_bound<1 (measured 2026-09-13 against miniprover 0.1.0:
	// `miniprover --loop-bound 0 …` dies with "loop_bound must be >= 1;
	// minicertora refuses degenerate flags"), so 0 is by definition NOT
	// twin output.
	k, kStated, kOK, kWhy := BoundFromFlags(objAtRP(rep, "flags"))
	if !kOK {
		return ReportDecision{Gate: GateLoopBound,
			Refusal: fmt.Sprintf("flags.loop_bound %s; this report is not "+
				"a twin output and will not bind\n", kWhy)}
	}
	rung, summary, bk := MapReport(rpObjStr(prop, "outcome"),
		objAtRP(prop, "per_rule"), k, kStated)
	return ReportDecision{Rung: rung, Summary: summary, BoundedK: bk,
		Outcome: rpObjStr(prop, "outcome")}
}

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

// rpSameName is cli.autoproveSameName verbatim: property titles are
// AGENT-authored strings — the same verbatim-slop class r21 F2 fixed for
// verdicts. Attribution and consumption fold case + edges (display keeps
// the first spelling; identity is the folded form). NOTE this is the
// SUSPECT gate's matching rule only: the property whose OUTCOME is read is
// resolved by ReportProperty's exact lookup.
func rpSameName(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
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
