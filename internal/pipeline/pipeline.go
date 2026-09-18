// Package pipeline is the port of webv2/pipeline.py: the campaign lifecycle
// as a DAG that halts honestly at model boundaries.
//
// Two layers, deliberately kept separate:
//
//   - PHASE = the deterministic campaign lifecycle (SCOPE -> SNAPSHOT -> ...
//     -> LEARNING). It is the honest progress axis of the campaign state.
//   - STAGE = a schedulable DAG node. Each stage declares its dependencies
//     (STAGE_JOINS); a stage is *ready* when its join over its predecessors
//     is satisfied.
//
// The scheduler runs every ready branch: one blocked model task must not
// prevent completely independent research from progressing. A stage declared
// "model" with no handler does not silently "skip" as if it had happened — it
// is marked needs-model with the exact context bundle the operator needs, and
// the scheduler keeps running the other ready stages. A stage that FAILS
// still halts the run: a failed deterministic stage is a real error, unlike
// an unattended model stage.
package pipeline

import (
	"fmt"
	"strconv"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// Handler is one stage implementation: it returns the stage note (Python's
// handler return value) or an error whose text becomes the recorded note.
type Handler func(*state.Campaign) (validation.Value, error)

// Pipeline is the resumable stage runner over the campaign's own state store.
type Pipeline struct {
	C        *state.Campaign
	O        OrchestratorAPI
	Handlers map[string]Handler
}

// New is Pipeline.__init__.
func New(c *state.Campaign, o OrchestratorAPI, handlers map[string]Handler) *Pipeline {
	h := map[string]Handler{}
	for k, v := range handlers {
		h[k] = v
	}
	return &Pipeline{C: c, O: o, Handlers: h}
}

// ---- progress -------------------------------------------------------------

// Completed is completed(): the stage ids whose ledger status is "done".
func (p *Pipeline) Completed() ([]string, error) {
	st, err := p.C.State()
	if err != nil {
		return nil, err
	}
	stages := validation.ObjAt(st, "stages")
	out := []string{}
	for _, sid := range StageIDs {
		entry := validation.ObjAt(stages, sid)
		if entry.Kind != validation.Obj {
			continue
		}
		if validation.ObjStr(entry, "status") == "done" {
			out = append(out, sid)
		}
	}
	return out, nil
}

// NextStage is next_stage: the first ready stage in topological order, or nil.
func (p *Pipeline) NextStage() (*string, error) {
	ready, err := p.ReadyStages()
	if err != nil {
		return nil, err
	}
	if len(ready) == 0 {
		return nil, nil
	}
	sid := ready[0]
	return &sid, nil
}

// ReadyStages is ready_stages: all stages whose join over predecessors is
// satisfied and which are not done themselves.
func (p *Pipeline) ReadyStages() ([]string, error) {
	completed, err := p.Completed()
	if err != nil {
		return nil, err
	}
	done := map[string]bool{}
	for _, sid := range completed {
		done[sid] = true
	}
	return p.readyIn(done, map[string]bool{})
}

// readyIn is the scheduler's frontier: not done, not blocked, join satisfied.
func (p *Pipeline) readyIn(done, blocked map[string]bool) ([]string, error) {
	out := []string{}
	for _, sid := range StageIDs {
		if done[sid] || blocked[sid] {
			continue
		}
		ok, err := JoinSatisfied(StageJoins[sid], done, p.C)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, sid)
		}
	}
	return out, nil
}

// ---- execution ------------------------------------------------------------

// RunOpts are run()'s keyword-only arguments.
type RunOpts struct {
	Until     *string
	MaxStages *int64
}

// Run is run(): schedule the DAG and run every ready stage.
//
// A model stage without a handler is FIRST checked against its completion
// proof: if the campaign's artifacts already PROVE the stage done, the stage
// is auto-completed with executor="derived" and the scheduler continues. Only
// a stage whose proof FAILS is marked needs-model — with the exact missing
// items — and the scheduler CONTINUES with the other ready branches, so one
// blocked model task must not starve independent research. The run ends when
// no branch is ready, `until` is reached, or `max_stages` is consumed. A
// stage that FAILS still halts: that is a real error.
func (p *Pipeline) Run(opts RunOpts) (validation.Value, error) {
	if opts.Until != nil && !isStageID(*opts.Until) {
		return validation.VNull(), fmt.Errorf("unknown stage %s; stages: %s",
			validation.PyReprStr(*opts.Until), validation.PyListRepr(StageIDs))
	}
	skipped, err := p.Completed()
	if err != nil {
		return validation.VNull(), err
	}
	summary := newSummary(skipped)
	done := map[string]bool{}
	for _, sid := range skipped {
		done[sid] = true
	}
	blocked := map[string]bool{}
	var ran int64
	for {
		halted, err := p.costHalt(&summary)
		if err != nil {
			return validation.VNull(), err
		}
		if halted {
			break
		}
		ready, err := p.readyIn(done, blocked)
		if err != nil {
			return validation.VNull(), err
		}
		if len(ready) == 0 {
			break
		}
		out, err := p.step(ready[0], done, blocked, &summary, &ran, opts)
		if err != nil {
			return validation.VNull(), err
		}
		if out != outcomeContinue {
			break
		}
	}
	if len(blocked) > 0 && validation.ObjStr(summary, "status") == "complete" {
		vset(&summary, "status", validation.VStr("needs-model"))
		vset(&summary, "halt", validation.VStr("blocked on model stages: "+
			validation.PyListRepr(validation.SortedKeys(blocked))))
	}
	return summary, nil
}

// runOutcome is what one scheduling step implies for the run loop.
type runOutcome int

const (
	outcomeContinue runOutcome = iota
	outcomeHalt                // the stage failed; summary already says so
	outcomeStop                // until / max_stages reached
)

// newSummary is the run summary in the Python insertion order.
func newSummary(skipped []string) validation.Value {
	return validation.VObj(
		kvOf("ran", validation.VArr()),
		kvOf("skipped_completed", validation.StrArr(skipped)),
		kvOf("halt", validation.VNull()),
		kvOf("needs_model", validation.VNull()),
		kvOf("blocked_stages", validation.VArr()),
		kvOf("auto_completed", validation.VArr()),
		kvOf("status", validation.VStr("complete")),
	)
}

// step runs the head of the ready frontier: a model stage without a handler
// consults its completion proof first, everything else runs handler-or-builtin.
func (p *Pipeline) step(sid string, done, blocked map[string]bool,
	summary *validation.Value, ran *int64, opts RunOpts) (runOutcome, error) {
	stage, _ := stageByID(sid)
	handler := p.Handlers[sid]
	if handler == nil && stage.Kind == "model" {
		stop, err := p.blockModel(sid, stage, done, blocked, summary, opts.Until)
		if err != nil {
			return outcomeContinue, err
		}
		if stop {
			return outcomeStop, nil
		}
		return outcomeContinue, nil
	}
	return p.execute(sid, stage, handler, done, summary, ran, opts)
}

// execute runs one stage to completion: handler/builtin, failure-becomes-state,
// then the done record, the phase advance and the stage_done event.
func (p *Pipeline) execute(sid string, stage Stage, handler Handler,
	done map[string]bool, summary *validation.Value, ran *int64,
	opts RunOpts) (runOutcome, error) {
	var detail validation.Value
	var err error
	if handler != nil {
		detail, err = handler(p.C)
	} else {
		detail, err = p.builtin(sid)
	}
	if err != nil {
		if e := p.failStage(sid, stage.Kind, err, summary); e != nil {
			return outcomeContinue, e
		}
		return outcomeHalt, nil
	}
	done[sid] = true
	note := detail
	if !validation.PyTruthy(detail) {
		note = validation.VStr("")
	}
	if err := p.C.SetStage(sid, "done", note, executorFor(stage.Kind)); err != nil {
		return outcomeContinue, err
	}
	if err := p.advancePhase(stage.Phase, "pipeline stage "+sid); err != nil {
		return outcomeContinue, err
	}
	appendTo(summary, "ran", validation.VStr(sid))
	*ran = *ran + 1
	data := validation.VObj(kvOf("kind", validation.VStr(stage.Kind)),
		kvOf("phase", validation.VStr(stage.Phase)))
	if _, err := p.C.Log("pipeline.stage_done", &sid, &data); err != nil {
		return outcomeContinue, err
	}
	return stopAfter(sid, *ran, opts, summary), nil
}

// stopAfter applies the operator-requested stop conditions in Python's order:
// `until` first (a requested stop is not an error), then the stage budget.
func stopAfter(sid string, ran int64, opts RunOpts,
	summary *validation.Value) runOutcome {
	if opts.Until != nil && sid == *opts.Until {
		vset(summary, "halt", validation.VStr("until="+*opts.Until))
		vset(summary, "status", validation.VStr("until-reached"))
		return outcomeStop
	}
	if opts.MaxStages != nil && ran >= *opts.MaxStages {
		vset(summary, "halt", validation.VStr("max_stages="+
			strconv.FormatInt(*opts.MaxStages, 10)))
		vset(summary, "status", validation.VStr("halted"))
		return outcomeStop
	}
	return outcomeContinue
}

// costHalt is the cost-ceiling check at the top of every scheduling round: an
// overrun must be an explicit operator decision (raise max_total_cost_usd or
// stop), never a silent one.
func (p *Pipeline) costHalt(summary *validation.Value) (bool, error) {
	bstat, err := costsImpl.BudgetStatus(p.C)
	if err != nil {
		return false, err
	}
	if validation.ObjStr(bstat, "status") != "exceeded" {
		return false, nil
	}
	spent, err := moneyField(bstat, "spent_usd")
	if err != nil {
		return false, err
	}
	limit, err := moneyField(bstat, "limit_usd")
	if err != nil {
		return false, err
	}
	over, err := moneyField(bstat, "over_by_usd")
	if err != nil {
		return false, err
	}
	halt := "cost ceiling exceeded: spent $" + spent + " > limit $" + limit +
		" (over by $" + over + ") — raise max_total_cost_usd in the campaign " +
		"budget or stop; an overrun is a decision the operator makes, not one " +
		"the pipeline makes for them"
	vset(summary, "halt", validation.VStr(halt))
	vset(summary, "status", validation.VStr("halted"))
	data := validation.VObj(
		kvOf("spent_usd", validation.ObjAt(bstat, "spent_usd")),
		kvOf("limit_usd", validation.ObjAt(bstat, "limit_usd")),
	)
	if _, err := p.C.Log("pipeline.budget_halt", nil, &data); err != nil {
		return false, err
	}
	return true, nil
}

// failStage records a failed stage as the stage's own output data (note +
// event) and halts the run. The exception text is data, never re-raised.
func (p *Pipeline) failStage(sid, kind string, cause error, summary *validation.Value) error {
	text := cause.Error()
	if err := p.C.SetStage(sid, "failed", validation.VStr(text),
		executorFor(kind)); err != nil {
		return err
	}
	vset(summary, "halt", validation.VStr("stage "+validation.PyReprStr(sid)+
		" failed: "+text))
	vset(summary, "status", validation.VStr("halted"))
	data := validation.VObj(kvOf("error", validation.VStr(text)))
	_, err := p.C.Log("pipeline.stage_failed", &sid, &data)
	return err
}

// blockModel handles a handler-less model stage: proof-driven auto-completion
// first, then the actionable needs-model bundle. It reports whether the run
// must stop (an operator-requested until was reached).
func (p *Pipeline) blockModel(sid string, stage Stage, done, blocked map[string]bool,
	summary *validation.Value, until *string) (bool, error) {
	proof, err := completionImpl.ProofStatus(p.C, sid)
	if err != nil {
		return false, err
	}
	if proof.Kind == validation.Obj && validation.PyTruthy(validation.ObjAt(proof, "done")) {
		done[sid] = true
		note := validation.VStr("auto-completed: completion proof holds")
		if err := p.C.SetStage(sid, "done", note, strPtr("derived")); err != nil {
			return false, err
		}
		if err := p.advancePhase(stage.Phase, "pipeline stage "+sid+" (proof)"); err != nil {
			return false, err
		}
		appendTo(summary, "auto_completed", validation.VStr(sid))
		appendTo(summary, "ran", validation.VStr(sid))
		data := validation.VObj(kvOf("kind", validation.VStr(stage.Kind)),
			kvOf("phase", validation.VStr(stage.Phase)),
			kvOf("note", validation.ObjAt(proof, "note")))
		if _, err := p.C.Log("pipeline.stage_auto_completed", &sid, &data); err != nil {
			return false, err
		}
		// Python's proof path checks `until` and skips the max_stages check.
		if until != nil && sid == *until {
			vset(summary, "halt", validation.VStr("until="+*until))
			vset(summary, "status", validation.VStr("until-reached"))
			return true, nil
		}
		return false, nil
	}
	bundle, err := p.modelBundle(sid)
	if err != nil {
		return false, err
	}
	blocked[sid] = true
	if validation.ObjAt(*summary, "needs_model").Kind == validation.Null {
		vset(summary, "needs_model", bundle)
	}
	appendTo(summary, "blocked_stages", validation.VStr(sid))
	missing := []string{"no completion proof declared"}
	missingData := validation.VArr()
	if proof.Kind == validation.Obj {
		mv := validation.ObjAt(proof, "missing")
		missingData = mv
		if validation.PyTruthy(mv) {
			missing = stringSlice(mv, 3)
		}
	}
	note := "blocked: model stage without handler (" + validation.ObjStr(bundle, "prompt_path") +
		") — missing: " + strings.Join(missing, "; ")
	if err := p.C.SetStage(sid, "needs-model", validation.VStr(note), strPtr("model")); err != nil {
		return false, err
	}
	data := validation.VObj(
		kvOf("reason", validation.VStr("model stage without handler")),
		kvOf("prompt", validation.VStr(validation.ObjStr(bundle, "prompt_path"))),
		kvOf("missing", missingData),
	)
	if _, err := p.C.Log("pipeline.blocked", &sid, &data); err != nil {
		return false, err
	}
	return false, nil
}

// advancePhase is _advance_phase: forward-only. Orchestrator builtins advance
// the phase themselves, so a pipeline stage whose builtin already ran ahead
// must never drag the phase backwards.
func (p *Pipeline) advancePhase(phase, reason string) error {
	st, err := p.C.State()
	if err != nil {
		return err
	}
	cur, okCur := phaseIndex(validation.ObjStr(st, "phase"))
	next, okNext := phaseIndex(phase)
	if okCur && okNext && next > cur {
		return p.C.SetPhase(phase, reason)
	}
	return nil
}

// ---- helpers --------------------------------------------------------------
