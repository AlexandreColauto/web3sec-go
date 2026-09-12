// disposition.go: the L3 escalation plane's table — reason codes are router
// inputs, not verdicts. An inconclusive rung is not a dead end: the tool's
// reason code names the next action, and every next action is one more
// budgeted EXEC.
//
// Dispositions are ADVISORY. §L3 renders each named next action where
// verdicts are consumed; the CLI never auto-spawns escalation execs — that
// stays `exec`'s job and the model's decision, budgeted.
//
// The table is pure data: one row per code in the closed set
// (`corpus/runner.py::REASON_CODES`, 25 names). MapRun's mapper
// (minicertora.go) is the only producer of the summary strings this reads.
//
// Two floors are not reason codes and are matched on the INNER text,
// before the `reason: details` separator:
//   - the four separator-free plumbing floors, all ok=false — the run never
//     produced a usable verdict line ("exit output unmapped", "output is not
//     JSONL", "duplicate verdict lines for rule …", "no verdict line for
//     rule …") — matched pre-cut so a rule name containing ": " cannot
//     masquerade as a reason code; the fifth plumbing refusal,
//     "report-contradiction", carries its own separator and is matched
//     after the cut by exact reason equality (see plumbingReasons);
//   - the one NAMED runtime floor, the killed/timed-out
//     "no clean completion" shape, which disposes to EscalateRuntime —
//     the run never completed, so it maps no verdict, but it still names
//     a next action (a larger wall-clock), per §L3's law that an
//     inconclusive rung names what to do next.
package harness

import "strings"

// The nine disposition classes of docs/MINICERTORA_ARCHITECTURE.md §L3:
// the eight REASON_CODES classes plus the named runtime floor.
// Exported for tests and for consumers that route on a class rather than an
// advice string.
const (
	// EscalateBound re-runs the same scaffold at a higher loop bound.
	EscalateBound = "escalate-bound"
	// EscalateFlag re-runs the same scaffold with a wider path cap, then
	// with splitting lowering.
	EscalateFlag = "escalate-flag"
	// EscalateSolver re-runs once with a quadrupled solver timeout.
	EscalateSolver = "escalate-solver"
	// EscalateRuntime re-runs a killed/timed-out run with a larger
	// --timeout-ms or exec wall-clock: the run never completed, so no
	// verdict was mapped at all.
	EscalateRuntime = "escalate-runtime"
	// SpecRewrite routes the rule body back to the spec queue.
	SpecRewrite = "spec-rewrite"
	// HonestRefusal records the shape as a model gap and downgrades the
	// prover leg for this program.
	HonestRefusal = "honest-refusal"
	// ToolError escalates to the operator, never a retry.
	ToolError = "tool-error"
	// ModelBug is upstream issue material.
	ModelBug = "model-bug"
	// WitnessTriage feeds the report's machine-checkable witness to
	// promotion triage.
	WitnessTriage = "witness-triage"
)

// dispositionUnknown is the class of a reason code outside the closed set:
// the refusal is still a refusal (ok=true), it just names nothing the
// table knows.
const dispositionUnknown = "unmapped"

// adviceGeneric is the unknown code's next action.
const adviceGeneric = "review the spec and the tool version; the refusal " +
	"names no known disposition"

// dispositionAdvice is the verbatim next action of each class; every class
// the switch below emits — plus the runtime floor — has exactly one row
// here.
var dispositionAdvice = map[string]string{
	EscalateBound: "re-run the same scaffold at --loop-bound 8, then 16, " +
		"ceiling 32",
	EscalateFlag: "re-run the same scaffold once with --path-cap 256; if " +
		"still capped, --lowering splitting",
	EscalateSolver: "re-run once with --timeout-ms quadrupled within the " +
		"exec wall-clock",
	EscalateRuntime: "the run never completed — re-run with a larger " +
		"--timeout-ms or a longer exec wall-clock; a killed or timed-out " +
		"run maps no verdict",
	SpecRewrite: "the rule body proves nothing about the contract — " +
		"rewrite BODY within the same scaffold (infeasible or malformed " +
		"spec)",
	HonestRefusal: "feature unprovable by this tool on this shape — " +
		"record the gap, downgrade prover legs for this program, do not " +
		"retry blindly",
	ToolError: "escalate to the operator; never retried automatically",
	ModelBug: "upstream modelling bug — harvest the report for an issue, " +
		"do not re-spec around it",
	WitnessTriage: "machine-checkable witness rides the report — triage " +
		"for promotion; fork-repro the call sequence, never gate credit " +
		"on the prover's model",
}

// dispositionOf is the closed set as DATA: one row per reason code in
// `corpus/runner.py::REASON_CODES` (25 names), mapping the code to its §L3
// class. It replaces the old `switch reason` — behavior is identical, but the
// set is now inspectable, which is what makes IsReasonCode possible and lets
// the vendored-corpus tripwires (corpus_test.go) assert that every
// expected.json reason code names a code the router knows.
//
// A code absent from this map is not a code in the tool's vocabulary:
// Disposition still calls it a refusal (ok=true) with the unknown class.
//
// RUN-VERIFIED (2026-09-12, the operator's first real evalsuite run;
// docs/minicertora-eval/2026-09-12/): the live tool stored five codes —
// assertion-violated, malformed-spec, rejected-feature, solver-timeout and
// unsupported-feature — and every one of them was already a row here, so the
// run added NO code to the closed set (still 25). The names reported as
// apparently-new resolve as follows:
//   - unsupported-feature: already a row (honest-refusal); the run stored it
//     twice (a rule with no call), so this one is run-observed;
//   - unrecognized-dispatcher: already a row (honest-refusal). It is raisable
//     in the live tool (vcgen/invariants.py binds it for unbindable dispatcher
//     targets) but did NOT appear among this run's stored lines; the row needed
//     no change either way;
//   - solver-timeout: already a row (escalate-solver, NOT escalate-bound — a
//     solver that gave up on the VC is re-run with a quadrupled timeout, not
//     with more unrolling); run-observed on LPOracleSpot with EMPTY details,
//     where the mapper's "reason: details" template still leaves the ": "
//     separator that the cut below needs;
//   - `unsupported-type:<Contract>.<field>`: NOT a reason code. It is the
//     tool's FEATURE half, emitted with reason `rejected-feature`
//     (spec/parser.py raises SpecUnsupported("unsupported-type:int256",
//     reason="rejected-feature"); frontend/artifacts.py files the loader
//     refusal as feature `unsupported-type:<Contract>.<field>` under
//     LoaderError's `rejected-feature` default), and the run stored it exactly
//     that way. Deliberately absent: a row here would make IsReasonCode accept
//     a name the tool never puts in its `reason` field, breaking the
//     single-source law this table exists for.
//     Same for the string-literal abort, whose stored details open with their
//     own `rejected-feature: ` prefix while the line's reason stays
//     `rejected-feature` — the first ": " cut already names the real code.
var dispositionOf = map[string]string{
	// --- escalate-bound: the unrolling could not prove its own bound ---
	"loop-bound-may-be-exceeded": EscalateBound,
	// --- escalate-flag: the exploration hit its path cap ---
	"path-limit-reached": EscalateFlag,
	// --- escalate-solver: the VC outlived its budget ---
	"solver-timeout": EscalateSolver,
	// --- spec-rewrite: a finding about the spec, not the contract ---
	"vacuous-rule":   SpecRewrite,
	"vacuous-block":  SpecRewrite,
	"malformed-spec": SpecRewrite,
	// --- honest-refusal: a shape this tool cannot express or check ---
	"unsupported-feature":              HonestRefusal,
	"unsupported-opcode":               HonestRefusal,
	"unsupported-storage-layout":       HonestRefusal,
	"rejected-feature":                 HonestRefusal,
	"unrecognized-dispatcher":          HonestRefusal,
	"external-call-abstraction":        HonestRefusal,
	"summary-unverified":               HonestRefusal,
	"multi-call-ambiguous-call-site":   HonestRefusal,
	"multi-call-inner-arg-unsupported": HonestRefusal,
	"multi-call-stmt-between-calls":    HonestRefusal,
	"invariant-uninitialized":          HonestRefusal,
	"invariant-unchecked-functions":    HonestRefusal,
	// --- tool-error: genuine breakage ---
	"tool-error": ToolError,
	// --- model-bug: the pipeline disagreed with itself ---
	"unresolved-phi-source":   ModelBug,
	"unresolved-branch-cond":  ModelBug,
	"modelling-inconsistency": ModelBug,
	"solver-disagreement":     ModelBug,
	// --- witness-triage: violation verdicts; consumers of proof.reason
	// need their class even though the counterexample summary is an
	// excerpt form ("counterexample: <expr>") that never reaches here ---
	"assertion-violated":     WitnessTriage,
	"expect-revert-violated": WitnessTriage,
}

// IsReasonCode reports whether code is a member of the closed reason-code set
// (`corpus/runner.py::REASON_CODES`, 25 names) — the single source of that
// membership test now lives here in Go. It is the same set Disposition routes
// on: a code is a reason code iff it has a disposition row. Only the exact
// bytes match (no trimming, no case folding): the codes are tool vocabulary,
// not user input.
func IsReasonCode(code string) bool {
	_, ok := dispositionOf[code]
	return ok
}

// plumbingReasons are reason-shaped keys that belong to the mapper, not to
// the tool's spec vocabulary: a report-contradiction refusal throws its own
// verdict line away, so it names no disposition. Unlike the separator-free
// floors it contains its own ": ", so it is matched AFTER the separator cut
// by exact reason equality (see Disposition).
var plumbingReasons = map[string]bool{
	"report-contradiction": true,
	// "aborted" is belt-and-braces: the mapper's abort floor carries no
	// "inconclusive (" wrapper today, but must stay plumbing if it ever does.
	"aborted": true,
}

// Disposition classifies the EXACT inconclusive summary a minicertora run
// stored (shape `inconclusive (reason: details…)`) into its §L3 class and
// names that class's next action.
//
// Four plumbing floors are matched on the inner text BEFORE the
// `reason: details` separator, so a rule name containing ": " cannot
// masquerade as a reason code: "exit output unmapped", "output is not
// JSONL", "duplicate verdict lines for rule …", "no verdict line for
// rule …". "report-contradiction" is matched after the cut by exact
// equality. All five return ok=false — the run never produced a usable
// verdict line, so there is nothing to dispose of.
//
// The named runtime floor is matched next: an inner text starting
// "no clean completion" (both stored shapes — the bare
// `inconclusive (no clean completion)` and the
// `inconclusive (no clean completion; loop bound was N)` variant) is a
// killed or timed-out run, and returns (EscalateRuntime, advice, true): no
// verdict was mapped, but the refusal still names its next action.
//
// Everything else is a `reason: details` refusal. A reason code outside the
// closed set returns (dispositionUnknown, adviceGeneric, true): still a
// refusal, just an unrecognised one.
func Disposition(summary string) (class, advice string, ok bool) {
	// A stored summary may carry the CLI's binding decoration — the
	// " (unbound: …)" suffix harnessMapBound appends in
	// cmd_verify_harness.go. The decoration is transport metadata, not part
	// of the reason: strip it, then classify the base refusal. (Without
	// this, a decorated FLOOR's decoration ": " was read as the reason
	// separator, so "inconclusive (exit output unmapped) (unbound: …)"
	// parses reason "exit output unmapped) (unbound", falls through the
	// plumbing checks, and renders bogus "unmapped" advice.) A decorated
	// MAPPED reason keeps its real class; a decorated floor still floors.
	if strings.HasSuffix(summary, ")") {
		if head, _, decorated := strings.Cut(
			strings.TrimSuffix(summary, ")"), " (unbound:"); decorated {
			summary = head + ")"
		}
	}
	const prefix = "inconclusive ("
	if !strings.HasPrefix(summary, prefix) || !strings.HasSuffix(summary, ")") {
		return "", "", false
	}
	inner := summary[len(prefix) : len(summary)-1]
	// FIRST the floors, on the inner text before any separator cut: the
	// plumbing floors (the run never produced a usable verdict line) and
	// the named runtime floor (the run never completed). Matching here,
	// not on the cut reason, is what keeps a rule name containing ": "
	// ("no verdict line for rule a: b") from sneaking past as an
	// unknown reason and rendering bogus "unmapped" advice.
	switch {
	case inner == "exit output unmapped",
		inner == "output is not JSONL",
		strings.HasPrefix(inner, "duplicate verdict lines for rule"),
		strings.HasPrefix(inner, "no verdict line for rule"):
		// No verdict line ever existed: plumbing, not a spec
		// disposition.
		return "", "", false
	}
	if strings.HasPrefix(inner, "no clean completion") {
		// The named runtime floor (a killed/timed-out run — both the
		// bare shape and the "; loop bound was N" variant). The run
		// never completed, so it maps no verdict, but it is a NAMED
		// disposition: re-run with a larger wall-clock.
		return EscalateRuntime, dispositionAdvice[EscalateRuntime], true
	}
	reason, _, found := strings.Cut(inner, ": ")
	if !found || reason == "" {
		// No separator: a separator-less plumbing floor the switch
		// above did not name, or a malformed summary. Not a
		// disposition either way.
		return "", "", false
	}
	if plumbingReasons[reason] {
		// report-contradiction: a verdict line existed and was discarded
		// as untrustworthy, so it is plumbing too, not a disposition.
		return "", "", false
	}
	cls, known := dispositionOf[reason]
	if !known {
		// A code outside the closed set: still a refusal, just an
		// unrecognised one.
		return dispositionUnknown, adviceGeneric, true
	}
	return cls, dispositionAdvice[cls], true
}
