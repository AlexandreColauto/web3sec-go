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
	GateSchemaVersion        ReportGate = "schema_version"
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

// ReportSchemaMajor is the schema_version family this build speaks: the
// report contract is 1.x, so "1.0" and the "1.0.3" patch form are both
// understood while "2.0" (a future major) and an ABSENT version (the
// pre-1.0 shape) are not.
//
// r33 F3: this constant used to live only in package cli
// (autoproveSchemaMajor, cmd_verify_autoprove.go), where the verb refused
// the report at its own door — while harness.DecideReport never read
// schema_version at all. A chain-valid forged campaign pinning a report
// whose schema_version was "2.0" (or absent) therefore audited GREEN with a
// blessing line, and a fresh bind of those very bytes exited 2: one byte
// string, two verdicts, because the gate lived on one side only. It now
// rides the ONE decision (DecideReportSchema, called first by DecideReport
// and by the verb's own early arm), so the refusal sentence and the state
// it names exist once.
const ReportSchemaMajor = "1."

// reportSchemaAbsent names the state a report with no readable
// schema_version is in. It is the verb's own wording (the ABSENT default its
// door applied, moved here with the gate) because the refusal sentence is
// one string.
const reportSchemaAbsent = "ABSENT (pre-1.0 report)"

// DecideReportSchema is the schema_version gate as a decision of its own:
// GateSchemaVersion with the bind's Refusal sentence when the report's
// schema_version does not belong to ReportSchemaMajor's family (an absent or
// non-string version reads as "" and refuses, naming the ABSENT state), else
// GateNone.
//
// It is a separate exported entry point only so the verb can ask the
// question at its historical position — before it touches links, the
// property-holder ledger scan or the exec ledger — while the sentence stays
// the ONE decision's. DecideReport calls it first, so the audit re-derives
// exactly what the verb's door refused (r33 F3).
func DecideReportSchema(rep validation.Value) ReportDecision {
	sv := rpObjStr(rep, "schema_version")
	if strings.HasPrefix(sv, ReportSchemaMajor) {
		return ReportDecision{}
	}
	name := sv
	if name == "" {
		name = reportSchemaAbsent
	}
	return ReportDecision{Gate: GateSchemaVersion,
		Refusal: fmt.Sprintf("report schema_version %s is not understood "+
			"(this build speaks %s0.x) — refusing to best-effort a "+
			"contract change\n", validation.PyReprStr(name),
			ReportSchemaMajor)}
}

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
	c := decRepCtx{rep: rep, property: property}
	// r33 F3: the schema gate is the FIRST gate, because it is the first
	// gate at the bind's own door (cli.verifyAutoprove checks it before it
	// loads links or scans the ledger). A report whose contract this build
	// does not speak cannot be read at all, so nothing below it may fire.
	if dec := DecideReportSchema(rep); dec.Gate != GateNone {
		return dec
	}
	if dec, refused := c.decRepPublishShape(); refused {
		return dec
	}
	if dec, refused := c.decRepProblems(); refused {
		return dec
	}
	if dec, refused := c.decRepPublished(); refused {
		return dec
	}
	if dec, refused := c.decRepOutcomes(); refused {
		return dec
	}
	prop, dec, refused := c.decRepProperty()
	if refused {
		return dec
	}
	if dec, refused := c.decRepReviewError(); refused {
		return dec
	}
	if dec, refused := c.decRepFindings(); refused {
		return dec
	}
	if dec, refused := c.decRepSuspect(); refused {
		return dec
	}
	return c.decRepBound(prop)
}

// decRepCtx carries the report and the property DecideReport's gates read,
// so each gate is one method over the same shared inputs.
type decRepCtx struct {
	rep      validation.Value
	property string
}

// decRepPublishShape is the publish_problems SHAPE gate: the veto list is
// a LIST by contract, so a scalar there refuses before it is read.
func (c decRepCtx) decRepPublishShape() (ReportDecision, bool) {
	probsPre := objAtRP(c.rep, "publish_problems")
	if probsPre.Kind != validation.Null && probsPre.Kind != validation.Arr {
		// r20 F6: the veto list is a LIST by contract — a scalar there is
		// either a lie or a bug; both refuse better than bind.
		return ReportDecision{Gate: GatePublishProblemsShape,
			Refusal: fmt.Sprintf("malformed publish_problems (kind %v, "+
				"contract: array) — the veto list is machine-authored; "+
				"refusing to read a broken contract\n", probsPre.Kind)}, true
	}
	return ReportDecision{}, false
}

// decRepProblems is the veto gate: a report that CARRIES problems refuses
// whatever its published flag says.
func (c decRepCtx) decRepProblems() (ReportDecision, bool) {
	probsPre := objAtRP(c.rep, "publish_problems")
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
			}[reportPublished(c.rep)])}, true
	}
	return ReportDecision{}, false
}

// decRepPublished is the published gate: an unpublished run blesses
// nothing, and its refusal names the (empty-dash) problems.
func (c decRepCtx) decRepPublished() (ReportDecision, bool) {
	if !reportPublished(c.rep) {
		probs := []string{}
		for _, p := range objAtRP(c.rep, "publish_problems").A {
			probs = append(probs, rpScalar(p))
		}
		return ReportDecision{Gate: GatePublished,
			Refusal: fmt.Sprintf("the prover did NOT publish this run — "+
				"nothing is blessed (problems: %s)\n",
				rpJoinOrDash(probs))}, true
	}
	return ReportDecision{}, false
}

// decRepOutcomes is the property_outcomes SHAPE gate: a report without the
// map cannot attribute any rule.
func (c decRepCtx) decRepOutcomes() (ReportDecision, bool) {
	po := objAtRP(c.rep, "property_outcomes")
	if po.Kind != validation.Obj {
		return ReportDecision{Gate: GatePropertyOutcomes,
			Refusal: "report carries no property_outcomes map — " +
				"contract broken\n"}, true
	}
	return ReportDecision{}, false
}

// decRepProperty resolves the bound property with ReportProperty's exact
// lookup and refuses, naming the attempted properties, when it is absent.
func (c decRepCtx) decRepProperty() (validation.Value, ReportDecision,
	bool) {
	prop, ok := ReportProperty(c.rep, c.property)
	if !ok {
		names := []string{}
		for _, kv := range objAtRP(c.rep, "property_outcomes").O {
			names = append(names, kv.K)
		}
		return validation.VNull(), ReportDecision{Gate: GateProperty,
			Refusal: fmt.Sprintf("property %s is not in this run (the "+
				"prover attempted: %s) — exact-match only\n",
				validation.PyReprStr(c.property), rpJoinOrDash(names))}, true
	}
	return prop, ReportDecision{}, false
}

// decRepReviewError is the review_error gate.
func (c decRepCtx) decRepReviewError() (ReportDecision, bool) {
	// r22 F2: the prover records review_error precisely so "no findings"
	// and "no review" never look alike — a run whose review role CRASHED
	// carries an EMPTY findings list that means nothing. Law: an unmade
	// check is never a cleared check.
	if re := rpObjStr(c.rep, "review_error"); re != "" {
		return ReportDecision{Gate: GateReviewError,
			Refusal: fmt.Sprintf("the independent review NEVER RAN (%s) — "+
				"PROVEN binds without it only by inattention; "+
				"refusing\n", re)}, true
	}
	return ReportDecision{}, false
}

// decRepFindings is the review_findings SHAPE gate.
func (c decRepCtx) decRepFindings() (ReportDecision, bool) {
	if v := objAtRP(c.rep, "review_findings"); v.Kind != validation.Arr {
		// r22 F5: the twin ALWAYS emits an array — null, absent, or scalar
		// are all foreign contracts. An unreadable gate input reads as
		// "nothing flagged" to nothing: refuse.
		return ReportDecision{Gate: GateReviewFindingsShape,
			Refusal: fmt.Sprintf("malformed review_findings (kind %v, "+
				"contract: array) — the gate reads the review's output; "+
				"a broken one is never empty enough to pass\n", v.Kind)}, true
	}
	return ReportDecision{}, false
}

// decRepSuspect is the SUSPECT-attribution gate.
func (c decRepCtx) decRepSuspect() (ReportDecision, bool) {
	if sus := ReportSuspects(c.rep, c.property); sus != "" {
		return ReportDecision{Gate: GateSuspect,
			Refusal: fmt.Sprintf("the independent review flagged property "+
				"%s as SUSPECT — %s — a PROVEN verdict next to a suspect "+
				"review is the most expensive state there is; the rung "+
				"is refused, fix the rule or waive with reason\n",
				c.property, sus)}, true
	}
	return ReportDecision{}, false
}

// decRepBound reads the typed loop_bound and maps the property's rollup
// through MapReport — the decision's non-refusing tail.
func (c decRepCtx) decRepBound(prop validation.Value) ReportDecision {
	// r24 F3: the bound is READ TYPED — a float is truncation, a
	// string/big is a foreign shape, and the twin's VerifierFlags raises
	// for loop_bound<1 (measured 2026-09-13 against miniprover 0.1.0:
	// `miniprover --loop-bound 0 …` dies with "loop_bound must be >= 1;
	// minicertora refuses degenerate flags"), so 0 is by definition NOT
	// twin output.
	k, kStated, kOK, kWhy := BoundFromFlags(objAtRP(c.rep, "flags"))
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
