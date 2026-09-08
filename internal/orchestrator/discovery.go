// discovery.go: phase 6 (DISCOVERY) — the context bundles and the hypothesis
// ingest that closes the plan loop.
package orchestrator

import (
	"path/filepath"

	"websec/internal/findings"
	"websec/internal/pipeline"
	"websec/internal/planner"
	"websec/internal/validation"
)

// DiscoveryContext is discovery_context(): the bounded context bundle a
// specialist stage needs. It goes through the adapter seam pipeline owns
// (Python calls adapter.build_context directly; the Go port has exactly one
// adapter seam, so both call sites route through it).
func (o *Orchestrator) DiscoveryContext(stage string,
	extra []string) (validation.Value, error) {
	return pipeline.BuildContext(o.C, stage, extra)
}

// CriticContext is critic_context(): the adversarial-critic bundle.
func (o *Orchestrator) CriticContext() (validation.Value, error) {
	if err := o.C.SetPhase("HOSTILE_REVIEW", "hostile review"); err != nil {
		return validation.VNull(), err
	}
	return pipeline.BuildContext(o.C, "adversarial-critic", nil)
}

// IngestOpts is ingest()'s keyword tail. Trajectory "" is Python's "code",
// Stage/Model "" is Python's None, PriorityOutcome "" is "answered".
type IngestOpts struct {
	Trajectory      string
	Stage           string
	Model           string
	AnswersPriority string
	PriorityOutcome string
}

// Ingest is ingest(): ingest one model-produced hypothesis.
// answers_priority closes the loop back to the campaign plan: the plan
// question this finding resolves is marked, so the work queue stops offering
// it.
func (o *Orchestrator) Ingest(payload validation.Value,
	opts IngestOpts) (validation.Value, error) {
	trajectory := opts.Trajectory
	if trajectory == "" {
		trajectory = "code"
	}
	outcome := opts.PriorityOutcome
	if outcome == "" {
		outcome = "answered"
	}
	f, err := findings.IngestHypothesis(o.C, payload, trajectory, opts.Stage,
		opts.Model)
	if err != nil {
		return validation.VNull(), err
	}
	fid := strAt(f, "finding_id")
	note := "ingested " + fid
	if err := o.C.SetStage("discovery-specialist", "needs-model",
		validation.VStr(note), nil); err != nil {
		return validation.VNull(), err
	}
	if opts.AnswersPriority != "" {
		planPath := filepath.Join(o.C.ArtifactsDir, "campaign_plan.json")
		if fileExists(planPath) {
			// the closure carries its evidence: the finding IS the answer
			// (run-2: a priority closed with a sentence and no ref was
			// invisible to everything).
			plan, err := validation.ReadJson(planPath)
			if err != nil {
				return validation.VNull(), err
			}
			reason := "answered by finding " + fid
			ref := fid
			if _, err := planner.MarkAnswered(o.C, plan, opts.AnswersPriority,
				outcome, planner.AnsweredOpts{Reason: &reason, Ref: &ref,
					Actor: "ingest"}); err != nil {
				return validation.VNull(), err
			}
		} else {
			data := validation.VObj(
				kvOf("finding", validation.VStr(fid)),
				kvOf("reason", validation.VStr("no campaign plan loaded")),
			)
			ref := opts.AnswersPriority
			if _, err := o.C.Log("plan.answer_orphaned", &ref, &data); err != nil {
				return validation.VNull(), err
			}
		}
	}
	return f, nil
}
