// regressionsuite.go is the v1.6 Part 3a regression-suite section: the reader
// for the target and run records internal/regression writes.
//
// PRESENCE-GATED, deliberately. scripts/verify-full.sh's p2_sections_ok and
// scripts/check-golden.py's EXPECTED_SECTIONS both pin the rendered section
// list for campaigns that are not regression targets; a campaign with no
// target record returns ErrSkip and renders nothing, so neither gate script
// changes when this section lands. A campaign that IS a regression target
// always renders it.
//
// problems carries the five states that cannot be true of a healthy suite,
// the same five assets/runbook/RUNBOOK.md §11 lists. Target-side, from
// targetProblems: a target with no resolved SHA (the exit criterion is "every
// snapshot carries a resolved SHA"), a resolved SHA that is not a 40-hex
// commit, and a target carrying a SHA but no snapshot binding. Run-side, from
// suiteRuns: a run naming a target that has no target record, and a run whose
// measurement label is not the D8 rediscovery label.
//
// The pin's EQUALITY rule — the bound snapshot's source.git_commit must equal
// the resolved SHA — is enforced on the WRITE path (internal/regression's
// checkPin), and is deliberately NOT re-verified here: this section reads
// target and run records only and never opens a snapshot. An earlier revision
// of this comment claimed the section performed that check; it did not, and a
// doc comment that describes a check no code performs is worse than no
// comment at all.
package sections

import (
	"fmt"
	"regexp"
	"strconv"

	"websec/internal/regression"
	"websec/internal/state"
	"websec/internal/validation"
)

// sha40 is the only pin shape the suite accepts (internal/regression's own
// rule; small helpers are duplicated, not exported — the house rule).
var sha40 = regexp.MustCompile(`^[0-9a-f]{40}$`)

// controlKind is §3a's target kind for the already-exploited control target and
// the record key its block lives under (internal/regression's own constant, not
// imported: it is unexported there, and this is the reader's copy of the word).
const controlKind = "control"

// RegressionSuite is the section: {checked, targets, runs, measurement,
// problems, ok} or ErrSkip when the campaign has no regression target.
func RegressionSuite(c *state.Campaign) (validation.Value, error) {
	targets, err := regression.LoadTargets(c)
	if err != nil {
		return validation.Value{}, err
	}
	if len(targets) == 0 {
		return validation.Value{}, ErrSkip
	}
	runs, err := regression.LoadRuns(c)
	if err != nil {
		return validation.Value{}, err
	}
	byID := map[string]bool{}
	for _, t := range targets {
		byID[validation.ObjStr(t, "target_id")] = true
	}
	targetRows, problems := suiteTargets(targets, runs)
	runRows, runProblems := suiteRuns(runs, byID)
	problems = append(problems, runProblems...)
	return validation.VObj(
		KV("checked", validation.VInt(int64(len(targets)+len(runs)))),
		KV("targets", validation.VArr(targetRows...)),
		KV("runs", validation.VArr(runRows...)),
		KV("measurement", validation.VStr("rediscovery")),
		KV("problems", validation.VArr(problems...)),
		KV("ok", validation.VBool(len(problems) == 0)),
	), nil
}

// runsFor counts the runs recorded against one target.
func runsFor(runs []validation.Value, tid string) int {
	n := 0
	for _, run := range runs {
		if validation.ObjStr(run, "target_id") == tid {
			n++
		}
	}
	return n
}

// suiteTargets renders one row per target and collects the target-side
// problems.
func suiteTargets(targets, runs []validation.Value) ([]validation.Value, []validation.Value) {
	rows := make([]validation.Value, 0, len(targets))
	problems := []validation.Value{}
	for _, t := range targets {
		tid := validation.ObjStr(t, "target_id")
		sha := validation.ObjStr(t, "resolved_sha")
		sid := validation.ObjStr(t, "snapshot_id")
		rows = append(rows, validation.VObj(
			KV("target_id", validation.VStr(tid)),
			KV("kind", validation.VStr(validation.ObjStr(t, "kind"))),
			KV("program", validation.VStr(validation.ObjStr(t, "program"))),
			KV("shape", validation.VStr(validation.ObjStr(t, "shape"))),
			KV("commit_hint", validation.VStr(validation.ObjStr(t, "commit_hint"))),
			KV("resolved_sha", validation.VStr(sha)),
			KV("snapshot_id", validation.VStr(sid)),
			KV("runs", validation.VInt(int64(runsFor(runs, tid)))),
			// The control target's own facts. The extractable figure is TEXT
			// and empty when absent: a section may not print a zero that reads
			// as a measurement.
			KV("control_pre_patch_sha", validation.VStr(validation.ObjStr(
				validation.ObjAt(t, "control"), "pre_patch_sha"))),
			KV("handoff_finding_id", validation.VStr(validation.ObjStr(
				validation.ObjAt(t, "handoff"), "finding_id"))),
			KV("handoff_extractable_usd", validation.VStr(handoffUSDText(t))),
		))
		problems = append(problems, targetProblems(t, sha, sid)...)
		problems = append(problems, controlProblems(t)...)
	}
	return rows, problems
}

// handoffUSDText renders the handoff's extractable figure as text, empty when
// there is no handoff — the same "absence is not a zero" rule the rest of this
// section follows.
func handoffUSDText(t validation.Value) string {
	usd := validation.ObjAt(validation.ObjAt(t, "handoff"), "extractable_usd")
	if usd.Kind != validation.Flt && usd.Kind != validation.Int {
		return ""
	}
	return strconv.FormatFloat(usd.F, 'f', -1, 64)
}

// controlProblems is the two half-finished states of §3a's control target: no
// control block (no sourced incident, no pre-patch pin, no harness) and no P1
// handoff (the Phase 2 spike's extraction half stays blocked). A control
// target that carries both is the only state this section calls healthy.
func controlProblems(t validation.Value) []validation.Value {
	if validation.ObjStr(t, "kind") != controlKind {
		return nil
	}
	tid := validation.ObjStr(t, "target_id")
	problems := []validation.Value{}
	if !validation.HasKey(t, controlKind) {
		problems = append(problems, validation.VStr(fmt.Sprintf(
			"control target %s carries no control block (incident + pre-patch "+
				"pin + harness) — §3a's control target is sourced separately, "+
				"pinned pre-patch and run under its own harness", tid)))
	}
	if !validation.HasKey(t, "handoff") {
		problems = append(problems, validation.VStr(fmt.Sprintf(
			"control target %s carries no P1 handoff — the Phase 2 spike's "+
				"extraction half stays blocked until a CONFIRMED finding and "+
				"its extractable_usd are recorded here", tid)))
	}
	return problems
}

// targetProblems is the three unpinned/ill-pinned states of one target.
func targetProblems(t validation.Value, sha, sid string) []validation.Value {
	tid := validation.ObjStr(t, "target_id")
	switch {
	case sha == "":
		return []validation.Value{validation.VStr(fmt.Sprintf(
			"target %s (%s) carries no resolved_sha — Phase 0 exits only when "+
				"every snapshot carries a resolved SHA", tid,
			validation.ObjStr(t, "program")))}
	case !sha40.MatchString(sha):
		return []validation.Value{validation.VStr(fmt.Sprintf(
			"target %s resolved_sha %q is not a 40-hex commit", tid, sha))}
	case sid == "":
		return []validation.Value{validation.VStr(fmt.Sprintf(
			"target %s carries a resolved SHA but no snapshot binding", tid))}
	}
	return nil
}

// suiteRuns renders one row per run and collects the run-side problems.
func suiteRuns(runs []validation.Value, byID map[string]bool) ([]validation.Value, []validation.Value) {
	rows := make([]validation.Value, 0, len(runs))
	problems := []validation.Value{}
	for _, run := range runs {
		tid := validation.ObjStr(run, "target_id")
		rid := validation.ObjStr(run, "run_id")
		rows = append(rows, validation.VObj(
			KV("run_id", validation.VStr(rid)),
			KV("target_id", validation.VStr(tid)),
			KV("scorer", validation.VStr(validation.ObjStr(run, "scorer"))),
			KV("score", validation.ObjAt(run, "score")),
			KV("measurement", validation.VStr(validation.ObjStr(run, "measurement"))),
		))
		if !byID[tid] {
			problems = append(problems, validation.VStr(fmt.Sprintf(
				"run %s names target %s, which has no target record", rid, tid)))
		}
		if got := validation.ObjStr(run, "measurement"); got != "rediscovery" {
			problems = append(problems, validation.VStr(fmt.Sprintf(
				"run %s carries measurement %q, not the D8 rediscovery label",
				rid, got)))
		}
	}
	return rows, problems
}
