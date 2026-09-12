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
package harness

import "strings"

// The eight disposition classes of docs/MINICERTORA_ARCHITECTURE.md §L3.
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
// in the switch below has exactly one row here.
var dispositionAdvice = map[string]string{
	EscalateBound: "re-run the same scaffold at --loop-bound 8, then 16, " +
		"ceiling 32",
	EscalateFlag: "re-run the same scaffold once with --path-cap 256; if " +
		"still capped, --lowering splitting",
	EscalateSolver: "re-run once with --timeout-ms quadrupled within the " +
		"exec wall-clock",
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

// plumbingReasons are reason-shaped keys that belong to the mapper, not to
// the tool's spec vocabulary: a report-contradiction refusal throws its own
// verdict line away, so it names no disposition. The other plumbing
// refusals carry no ": " separator at all (see Disposition).
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
// ok=false for a summary that is not an inconclusive refusal at all (a
// proved/counterexample rung's text, the `aborted: …` floor) and for the
// mapper's plumbing refusals — those are not spec dispositions; the run
// never produced a usable verdict line, so there is nothing to dispose of.
// A reason code outside the closed set returns
// (dispositionUnknown, adviceGeneric, true): still a refusal, just an
// unrecognised one.
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
	reason, _, found := strings.Cut(inner, ": ")
	if !found || reason == "" {
		// The mapper's separator-less plumbing floors: "exit output
		// unmapped", "output is not JSONL", "duplicate verdict lines for
		// rule", "no verdict line for rule <name>". None of them is a spec
		// disposition; the run never produced a verdict line.
		return "", "", false
	}
	if plumbingReasons[reason] {
		// report-contradiction: a verdict line existed and was discarded
		// as untrustworthy, so it is plumbing too, not a disposition.
		return "", "", false
	}
	switch reason {
	// --- escalate-bound: the unrolling could not prove its own bound ---
	case "loop-bound-may-be-exceeded":
		class = EscalateBound
	// --- escalate-flag: the exploration hit its path cap ---
	case "path-limit-reached":
		class = EscalateFlag
	// --- escalate-solver: the VC outlived its budget ---
	case "solver-timeout":
		class = EscalateSolver
	// --- spec-rewrite: a finding about the spec, not the contract ---
	case "vacuous-rule", "vacuous-block", "malformed-spec":
		class = SpecRewrite
	// --- honest-refusal: a shape this tool cannot express or check ---
	case "unsupported-feature", "unsupported-opcode",
		"unsupported-storage-layout", "rejected-feature",
		"unrecognized-dispatcher", "external-call-abstraction",
		"summary-unverified", "multi-call-ambiguous-call-site",
		"multi-call-inner-arg-unsupported", "multi-call-stmt-between-calls",
		"invariant-uninitialized", "invariant-unchecked-functions":
		class = HonestRefusal
	// --- tool-error: genuine breakage ---
	case "tool-error":
		class = ToolError
	// --- model-bug: the pipeline disagreed with itself ---
	case "unresolved-phi-source", "unresolved-branch-cond",
		"modelling-inconsistency", "solver-disagreement":
		class = ModelBug
	// --- witness-triage: violation verdicts; consumers of proof.reason
	// need their class even though the counterexample summary is an
	// excerpt form ("counterexample: <expr>") that never reaches here ---
	case "assertion-violated", "expect-revert-violated":
		class = WitnessTriage
	default:
		return dispositionUnknown, adviceGeneric, true
	}
	return class, dispositionAdvice[class], true
}
