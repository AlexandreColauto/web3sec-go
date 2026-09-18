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
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// Stage is one row of STAGES: (stage id, kind, campaign phase it advances).
//
//	deterministic — code performs it
//	model         — a model stage; the runner halts unless a handler is given
//	mixed         — code bootstraps it, a model may refine it
type Stage struct {
	ID    string
	Kind  string
	Phase string
}

// Stages is the canonical STAGES table, transcribed verbatim from the Python
// constants (golden-tested against the Python twin).
var Stages = []Stage{
	{"scope", "deterministic", "SCOPE"},
	{"snapshot", "deterministic", "SNAPSHOT"},
	{"structural-index", "deterministic", "STRUCTURAL_INDEX"},
	{"protocol-model", "model", "PROTOCOL_INTELLIGENCE"},
	{"campaign-planning", "mixed", "CAMPAIGN_PLANNING"},
	{"discovery", "model", "DISCOVERY"},
	{"dedup", "mixed", "CANDIDATE_INTEL"},
	{"hostile-review", "model", "HOSTILE_REVIEW"},
	{"reproduction", "mixed", "REPRODUCTION"},
	{"chaining", "deterministic", "CHAINING"},
	{"maximal-exploitation", "model", "MAXIMAL_EXPLOITATION"},
	{"independent-verification", "model", "INDEPENDENT_VERIFICATION"},
	{"risk-calibration", "deterministic", "RISK_CALIBRATION"},
	{"mainnet-fork-poc", "model", "MAINNET_FORK_POC"},
	{"bounty-gate", "deterministic", "BOUNTY_GATE"},
	{"report", "deterministic", "REPORTING"},
	{"learning", "model", "LEARNING"},
}

// StageIDs is STAGE_IDS.
var StageIDs = stageIDs()

func stageIDs() []string {
	out := make([]string, len(Stages))
	for i, s := range Stages {
		out[i] = s.ID
	}
	return out
}

func stageByID(sid string) (Stage, bool) {
	for _, s := range Stages {
		if s.ID == sid {
			return s, true
		}
	}
	return Stage{}, false
}

// StageKind is stage_kind.
func StageKind(sid string) string {
	s, _ := stageByID(sid)
	return s.Kind
}

// StagePhase is _PHASE[sid].
func StagePhase(sid string) string {
	s, _ := stageByID(sid)
	return s.Phase
}

func isStageID(sid string) bool {
	_, ok := stageByID(sid)
	return ok
}

// ---- join semantics -------------------------------------------------------
//
// A stage becomes ready when its JOIN over its predecessors is satisfied. The
// join kind is part of the stage's definition, so behavior cannot drift
// silently later:
//
//	JOIN_ALL       — every predecessor must be done. The default and the only
//	                 kind the canonical stages use.
//	JOIN_ANY       — ready when ANY ONE predecessor is done (first-success
//	                 fan-in).
//	JOIN_QUORUM    — ready when at least `quorum` predecessors are done.
//	JOIN_PREDICATE — ready when a pure, deterministic callable
//	                 `(campaign) -> bool` says so; the DAG's escape hatch.
//
// A predecessor that is BLOCKED (needs-model) or FAILED is simply not done:
// with JOIN_ALL it holds the stage back, with JOIN_ANY/QUORUM the other
// predecessors can still carry it.
const (
	JoinAll       = "all"
	JoinAny       = "any"
	JoinQuorum    = "quorum"
	JoinPredicate = "predicate"
)

// JoinKinds is JOIN_KINDS (a Python tuple; pyTupleRepr renders the repr).
var JoinKinds = []string{JoinAll, JoinAny, JoinQuorum, JoinPredicate}

// JoinSpec is one join spec.
type JoinSpec struct {
	Kind      string
	Deps      []string
	Quorum    *int
	Predicate func(*state.Campaign) bool
}

// Join is join(): build and validate one join spec.
//
// Deviation: Python rejects a bool quorum (isinstance(quorum, bool)) with
// "... got True"; a Go *int can never be a bool, so that branch is
// unreachable here (same deviation as state.SetDiscoveryBudget).
func Join(kind string, deps []string, quorum *int,
	predicate func(*state.Campaign) bool) (JoinSpec, error) {
	if !containsStr(JoinKinds, kind) {
		return JoinSpec{}, fmt.Errorf("join kind must be one of %s, got %s",
			pyTupleRepr(JoinKinds), validation.PyReprStr(kind))
	}
	spec := JoinSpec{Kind: kind, Deps: append([]string{}, deps...),
		Quorum: quorum, Predicate: predicate}
	if kind == JoinQuorum {
		limit := len(spec.Deps)
		if limit < 1 {
			limit = 1
		}
		if quorum == nil || *quorum < 1 || *quorum > limit {
			return JoinSpec{}, fmt.Errorf(
				"quorum join needs 1 <= quorum <= len(deps)=%d, got %s",
				len(spec.Deps), pyOptIntRepr(quorum))
		}
	}
	if kind == JoinPredicate && predicate == nil {
		return JoinSpec{}, errors.New("predicate join needs a callable (campaign) -> bool")
	}
	return spec, nil
}

// JoinSatisfied is join_satisfied: evaluate one join spec against the set of
// done stages.
func JoinSatisfied(spec JoinSpec, completed map[string]bool,
	campaign *state.Campaign) (bool, error) {
	switch spec.Kind {
	case JoinAll:
		for _, d := range spec.Deps {
			if !completed[d] {
				return false, nil
			}
		}
		return true, nil
	case JoinAny:
		for _, d := range spec.Deps {
			if completed[d] {
				return true, nil
			}
		}
		return false, nil
	case JoinQuorum:
		n := 0
		for _, d := range spec.Deps {
			if completed[d] {
				n++
			}
		}
		quorum := 0
		if spec.Quorum != nil {
			quorum = *spec.Quorum
		}
		return n >= quorum, nil
	case JoinPredicate:
		if spec.Predicate == nil {
			return false, nil
		}
		return spec.Predicate(campaign), nil
	}
	return false, fmt.Errorf("unknown join kind %s", validation.PyReprStr(spec.Kind))
}

// StageJoins is STAGE_JOINS: the dependency DAG over the canonical stages.
// The linear STAGES list is its topological fallback (every dependency sorts
// before its dependents), so next_stage's linear scan stays valid; what the
// DAG adds is the real parallel edge: hostile-review and reproduction are
// INDEPENDENT branches — both need dedup, neither needs the other — and
// chaining joins them.
var StageJoins = buildStageJoins()

// stageJoinOrder is the STAGE_JOINS insertion order (== StageIDs), needed
// wherever Python iterates the dict.
var stageJoinOrder = StageIDs

func buildStageJoins() map[string]JoinSpec {
	specs := []struct {
		sid  string
		deps []string
	}{
		{"scope", []string{}},
		{"snapshot", []string{"scope"}},
		{"structural-index", []string{"snapshot"}},
		{"protocol-model", []string{"structural-index"}},
		{"campaign-planning", []string{"protocol-model"}},
		{"discovery", []string{"campaign-planning"}},
		{"dedup", []string{"discovery"}},
		{"hostile-review", []string{"dedup"}},
		{"reproduction", []string{"dedup"}},
		{"chaining", []string{"hostile-review", "reproduction"}},
		{"maximal-exploitation", []string{"chaining"}},
		{"independent-verification", []string{"maximal-exploitation"}},
		{"risk-calibration", []string{"independent-verification"}},
		{"mainnet-fork-poc", []string{"risk-calibration"}},
		{"bounty-gate", []string{"mainnet-fork-poc"}},
		{"report", []string{"bounty-gate"}},
		{"learning", []string{"report"}},
	}
	out := make(map[string]JoinSpec, len(specs))
	for _, s := range specs {
		spec, err := Join(JoinAll, s.deps, nil, nil)
		if err != nil {
			panic("pipeline: STAGE_JOINS: " + err.Error())
		}
		out[s.sid] = spec
	}
	return out
}

// StageDeps is STAGE_DEPS: the predecessor list per stage, regardless of kind.
var StageDeps = buildStageDeps()

func buildStageDeps() map[string][]string {
	out := make(map[string][]string, len(StageJoins))
	for _, sid := range stageJoinOrder {
		out[sid] = append([]string{}, StageJoins[sid].Deps...)
	}
	return out
}

// StageDepsOf is stage_deps.
func StageDepsOf(stage string) []string {
	return append([]string{}, StageJoins[stage].Deps...)
}

// StageJoin is stage_join: a copy of one join spec.
func StageJoin(stage string) JoinSpec {
	spec := StageJoins[stage]
	spec.Deps = append([]string{}, spec.Deps...)
	return spec
}

// TopologicalOrder is topological_order: the DAG in deterministic
// topological order (the linear fallback).
func TopologicalOrder() ([]string, error) {
	order := []string{}
	placed := map[string]bool{}
	for len(order) < len(StageIDs) {
		progressed := false
		for _, sid := range StageIDs {
			if placed[sid] {
				continue
			}
			ready := true
			for _, d := range StageDeps[sid] {
				if !placed[d] {
					ready = false
					break
				}
			}
			if ready {
				order = append(order, sid)
				placed[sid] = true
				progressed = true
			}
		}
		if !progressed {
			return nil, errors.New("cycle in STAGE_DEPS")
		}
	}
	return order, nil
}

// ---- seams (unported collaborators) ---------------------------------------

// ErrAdapterNotWired marks the default adapter seam's error. The pipeline
// treats it exactly like Python's FileNotFoundError (no prompt for this
// stage): the model bundle carries prompt_path "unmapped" plus the error.
var ErrAdapterNotWired = errors.New("adapter not wired")

// AdapterAPI is the adapter.py seam (P2, unported). BuildContext is the only
// entry point pipeline.py uses.
type AdapterAPI interface {
	BuildContext(c *state.Campaign, stage string, extraPaths []string) (validation.Value, error)
}

type notWiredAdapter struct{}

func (notWiredAdapter) BuildContext(_ *state.Campaign, stage string,
	_ []string) (validation.Value, error) {
	return validation.VNull(), fmt.Errorf("%w: no context builder for stage %s",
		ErrAdapterNotWired, validation.PyReprStr(stage))
}

var adapterImpl AdapterAPI = notWiredAdapter{}

// SetAdapter installs the adapter implementation; nil restores the default
// (a clear not-wired error on the only path that builds a model bundle).
func SetAdapter(a AdapterAPI) {
	if a == nil {
		a = notWiredAdapter{}
	}
	adapterImpl = a
}

// BuildContext is adapter.build_context through the one adapter seam.
// orchestrator.discovery_context / critic_context call adapter.build_context
// directly in Python; the Go port routes them here so there is a single
// adapter owner (a test fake installed with SetAdapter covers both call
// sites, and P2 wires the real module once).
func BuildContext(c *state.Campaign, stage string,
	extraPaths []string) (validation.Value, error) {
	return adapterImpl.BuildContext(c, stage, extraPaths)
}

// CompletionAPI is the completion.py seam (P2, unported). ProofStatus returns
// the proof dict, or Null when the stage declares no proof (Python's None).
type CompletionAPI interface {
	ProofStatus(c *state.Campaign, stage string) (validation.Value, error)
}

type noProofs struct{}

func (noProofs) ProofStatus(*state.Campaign, string) (validation.Value, error) {
	return validation.VNull(), nil
}

var completionImpl CompletionAPI = noProofs{}

// SetCompletion installs the completion-proof implementation; nil restores
// the default (PROOFS = {}: no stage declares a proof, so every handler-less
// model stage is blocked with "no completion proof declared").
func SetCompletion(a CompletionAPI) {
	if a == nil {
		a = noProofs{}
	}
	completionImpl = a
}

// MaximizationAPI is the maximization.py seam (P2, unported): the variant
// ladder the two verification stages attach as extra context.
type MaximizationAPI interface {
	LoadLadder(c *state.Campaign, findingID string) (validation.Value, error)
}

type noLadders struct{}

func (noLadders) LoadLadder(*state.Campaign, string) (validation.Value, error) {
	return validation.VNull(), nil
}

var maximizationImpl MaximizationAPI = noLadders{}

// SetMaximization installs the ladder loader; nil restores the default
// (load_ladder returns None: no ladder is ever attached).
func SetMaximization(m MaximizationAPI) {
	if m == nil {
		m = noLadders{}
	}
	maximizationImpl = m
}

// CostsAPI is the costs.py seam (P1, unported): budget_status.
type CostsAPI interface {
	BudgetStatus(c *state.Campaign) (validation.Value, error)
}

type defaultCosts struct{}

// BudgetStatus is budget_status without the cost ledger: an unset ceiling is
// exactly Python's "no-limit" answer (spend is unbounded and no cost row is
// recorded); a ceiling with no ledger reads as spent 0.0 ("within"), the
// safe feature-absent behavior — wire costs.SetBudgetStatus to read
// costs.jsonl for the real halt.
func (defaultCosts) BudgetStatus(c *state.Campaign) (validation.Value, error) {
	b, err := c.Budget()
	if err != nil {
		return validation.VNull(), err
	}
	limit := validation.ObjAt(b, "max_total_cost_usd")
	if limit.Kind == validation.Null {
		return validation.VObj(
			kvOf("limit_usd", validation.VNull()),
			kvOf("spent_usd", validation.VFloat(0)),
			kvOf("status", validation.VStr("no-limit")),
			kvOf("remaining_usd", validation.VNull()),
			kvOf("note", validation.VStr("no max_total_cost_usd set — spend is "+
				"unbounded; set one in the campaign budget to halt the pipeline "+
				"when the ceiling is crossed")),
		), nil
	}
	f, err := valueFloat(limit)
	if err != nil {
		return validation.VNull(), err
	}
	return validation.VObj(
		kvOf("limit_usd", validation.VFloat(f)),
		kvOf("spent_usd", validation.VFloat(0)),
		kvOf("status", validation.VStr("within")),
		kvOf("remaining_usd", validation.VFloat(f)),
		kvOf("over_by_usd", validation.VFloat(0)),
	), nil
}

var costsImpl CostsAPI = defaultCosts{}

// SetCosts installs the cost/budget implementation; nil restores the default.
func SetCosts(a CostsAPI) {
	if a == nil {
		a = defaultCosts{}
	}
	costsImpl = a
}

// ReportAPI is the report.py seam (P1, unported). Generate returns the report
// path whose str() becomes the stage note.
type ReportAPI interface {
	Generate(c *state.Campaign) (string, error)
}

type noReport struct{}

func (noReport) Generate(*state.Campaign) (string, error) {
	return "", errors.New("report module not wired: cannot run stage 'report'")
}

var reportImpl ReportAPI = noReport{}

// SetReport installs the report generator; nil restores the default.
func SetReport(r ReportAPI) {
	if r == nil {
		r = noReport{}
	}
	reportImpl = r
}

// OrchestratorAPI is the orchestrator.py seam (P2, unported): the default
// implementations of the deterministic/mixed stages, so there is one owner of
// each. Only the methods the builtins call are declared — the snapshot
// builtin reads the campaign's own active snapshot and needs no orchestrator.
type OrchestratorAPI interface {
	Scope() (validation.Value, error)
	BuildStructuralIndex() (validation.Value, error)
	RunDedup() (validation.Value, error)
	Chaining() (validation.Value, error)
	CalibrateAll() (validation.Value, error)
	BountyGateAll() (validation.Value, error)
	Plan() (validation.Value, error)
	ReproductionQueue() (validation.Value, error)
}

// defaultOrchestrator is the package-level fallback for pipelines built
// without one (Python: Pipeline(campaign) with orchestrator=None).
var defaultOrchestrator OrchestratorAPI

// SetOrchestrator installs the package-level fallback orchestrator.
func SetOrchestrator(o OrchestratorAPI) { defaultOrchestrator = o }

// ---- pipeline -------------------------------------------------------------

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
			validation.PyReprStr(*opts.Until), pyListRepr(StageIDs))
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
			pyListRepr(sortedKeys(blocked))))
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

// modelBundle is _model_bundle: the bounded context a model stage needs. The
// runner never calls a model; it hands over exactly what the operator does.
func (p *Pipeline) modelBundle(sid string) (validation.Value, error) {
	stage := sid
	if mapped, ok := ModelStagePrompt[sid]; ok {
		stage = mapped
	}
	proof, err := completionImpl.ProofStatus(p.C, sid)
	if err != nil {
		return validation.VNull(), err
	}
	missing := validation.VArr()
	if proof.Kind == validation.Obj {
		missing = validation.ObjAt(proof, "missing")
	}
	bundle := validation.VObj(
		kvOf("stage", validation.VStr(sid)),
		kvOf("completion_missing", missing),
	)
	extra, err := p.ladderPaths(stage)
	if err != nil {
		return validation.VNull(), err
	}
	ctx, err := adapterImpl.BuildContext(p.C, stage, extra)
	if err != nil {
		if isAdapterAbsent(err) {
			bundle.O = append(bundle.O,
				kvOf("adapter_stage", validation.VStr(stage)),
				kvOf("prompt_path", validation.VStr("unmapped")),
				kvOf("error", validation.VStr(err.Error())))
			return bundle, nil
		}
		return validation.VNull(), err
	}
	for _, key := range []string{"prompt_path", "budget_class"} {
		if !hasKey(ctx, key) {
			return adapterKeyError(bundle, stage, key), nil
		}
	}
	blocksVal := validation.ObjAt(ctx, "blocks")
	if blocksVal.Kind != validation.Arr {
		return validation.VNull(), errors.New("adapter context blocks is not a list")
	}
	blocks := []validation.Value{}
	for _, b := range blocksVal.A {
		if !hasKey(b, "title") {
			return adapterKeyError(bundle, stage, "title"), nil
		}
		blocks = append(blocks, validation.ObjAt(b, "title"))
	}
	if !hasKey(ctx, "structured_outputs") {
		return adapterKeyError(bundle, stage, "structured_outputs"), nil
	}
	bundle.O = append(bundle.O,
		kvOf("adapter_stage", validation.VStr(stage)),
		kvOf("prompt_path", validation.ObjAt(ctx, "prompt_path")),
		kvOf("budget_class", validation.ObjAt(ctx, "budget_class")),
		kvOf("blocks", validation.VArr(blocks...)),
		kvOf("how_to_feed_back", validation.ObjAt(ctx, "structured_outputs")))
	return bundle, nil
}

// adapterKeyError is Python's `except KeyError`: str(KeyError(key)) is the
// repr of the missing key, and the bundle degrades to prompt_path "unmapped".
func adapterKeyError(bundle validation.Value, stage, key string) validation.Value {
	bundle.O = append(bundle.O,
		kvOf("adapter_stage", validation.VStr(stage)),
		kvOf("prompt_path", validation.VStr("unmapped")),
		kvOf("error", validation.VStr(validation.PyReprStr(key))))
	return bundle
}

// ladderPaths is _model_bundle's extra list: the working artifact for both
// verification stages (the maximizer extends it, the verifier attacks it).
func (p *Pipeline) ladderPaths(stage string) ([]string, error) {
	extra := []string{}
	if stage != "maximal-exploitation" && stage != "independent-verification" {
		return extra, nil
	}
	ladders, err := p.ladderFindings()
	if err != nil {
		return nil, err
	}
	for _, f := range ladders {
		fid := validation.ObjStr(f, "finding_id")
		lad, err := maximizationImpl.LoadLadder(p.C, fid)
		if err != nil {
			return nil, err
		}
		if lad.Kind != validation.Null {
			extra = append(extra, filepath.Join(p.C.Dir, "ladders", fid+".json"))
		}
	}
	return extra, nil
}

// ladderFindings is _ladder_findings: findings that carry a variant ladder.
func (p *Pipeline) ladderFindings() ([]validation.Value, error) {
	all, err := findings.LoadAllFindings(p.C)
	if err != nil {
		return nil, err
	}
	out := []validation.Value{}
	for _, f := range all {
		if validation.PyTruthy(validation.ObjAt(validation.ObjAt(f, "maximization"), "ladder_id")) {
			out = append(out, f)
		}
	}
	return out, nil
}

// builtin is _builtin: the default implementations for the deterministic and
// mixed stages, delegating to the orchestrator so there is one owner of each.
func (p *Pipeline) builtin(sid string) (validation.Value, error) {
	o := p.O
	if o == nil {
		o = defaultOrchestrator
	}
	if o == nil {
		return validation.VNull(), fmt.Errorf(
			"no orchestrator wired; cannot run stage %s", validation.PyReprStr(sid))
	}
	switch sid {
	case "scope":
		return o.Scope()
	case "structural-index":
		index, err := o.BuildStructuralIndex()
		if err != nil {
			return validation.VNull(), err
		}
		stats := validation.ObjAt(index, "stats")
		return validation.VObj(
			kvOf("solidity_files", objOr(stats, "solidity_files", validation.VInt(0))),
			kvOf("contracts", objOr(stats, "contracts", validation.VInt(0))),
			kvOf("functions", objOr(stats, "functions", validation.VInt(0))),
			kvOf("entry_points", objOr(stats, "entry_points", validation.VInt(0))),
			kvOf("entry_count", objOr(index, "entry_count", validation.VInt(0))),
			kvOf("artifact", validation.VStr("artifacts/structural_index.json")),
		), nil
	case "dedup":
		return o.RunDedup()
	case "chaining":
		return o.Chaining()
	case "risk-calibration":
		return o.CalibrateAll()
	case "bounty-gate":
		return o.BountyGateAll()
	case "report":
		path, err := reportImpl.Generate(p.C)
		if err != nil {
			return validation.VNull(), err
		}
		return validation.VStr(path), nil
	case "campaign-planning":
		return p.builtinCampaignPlanning(o)
	case "snapshot":
		active, err := p.C.ActiveSnapshotIDOrNone()
		if err != nil {
			return validation.VNull(), err
		}
		if active != nil {
			return validation.VStr("already pinned: " + *active), nil
		}
		return validation.VNull(), errors.New("snapshot needs a target path: " +
			"call orchestrator.snapshot(target) or register a handler for the " +
			"'snapshot' stage")
	case "reproduction":
		return o.ReproductionQueue()
	}
	return validation.VNull(), fmt.Errorf("no builtin for stage %s; register a handler",
		validation.PyReprStr(sid))
}

// builtinCampaignPlanning is the campaign-planning builtin (B1/D1): a plan
// already on disk is the campaign's CONTRACT, so the stage reuses it instead
// of regenerating it. Returning the raw result would bury that in a capped
// JSON blob (state cap_note); the operator gets one line saying WHAT
// happened and HOW to regenerate.
func (p *Pipeline) builtinCampaignPlanning(
	o OrchestratorAPI) (validation.Value, error) {
	res, err := o.Plan()
	if err != nil {
		return validation.VNull(), err
	}
	if res.Kind == validation.Obj && validation.PyTruthy(validation.ObjAt(res, "read_only")) {
		return validation.VStr("existing plan reused read-only — " +
			"`webv2 plan " + p.C.CampaignID + " --rebuild` to regenerate"), nil
	}
	return res, nil
}

// ModelStagePrompt is _MODEL_STAGE_PROMPT: pipeline stage -> adapter stage id
// (the prompt to run for a model stage).
var ModelStagePrompt = map[string]string{
	"protocol-model":           "protocol-model",
	"discovery":                "discovery-specialist",
	"hostile-review":           "adversarial-critic",
	"maximal-exploitation":     "maximal-exploitation",
	"independent-verification": "independent-verification",
	"mainnet-fork-poc":         "mainnet-fork-poc",
	"learning":                 "reflection",
}

// Status is status(): the DAG's progress view.
func Status(c *state.Campaign) (validation.Value, error) {
	p := New(c, nil, nil)
	completed, err := p.Completed()
	if err != nil {
		return validation.VNull(), err
	}
	next, err := p.NextStage()
	if err != nil {
		return validation.VNull(), err
	}
	ready, err := p.ReadyStages()
	if err != nil {
		return validation.VNull(), err
	}
	deps := []validation.KV{}
	joins := []validation.KV{}
	for _, sid := range stageJoinOrder {
		deps = append(deps, kvOf(sid, validation.StrArr(StageDeps[sid])))
		joins = append(joins, kvOf(sid, validation.VStr(StageJoins[sid].Kind)))
	}
	nextV := validation.VNull()
	if next != nil {
		nextV = validation.VStr(*next)
	}
	return validation.VObj(
		kvOf("completed", validation.StrArr(completed)),
		kvOf("next", nextV),
		kvOf("ready", validation.StrArr(ready)),
		kvOf("stages", validation.StrArr(StageIDs)),
		kvOf("deps", validation.VObj(deps...)),
		kvOf("joins", validation.VObj(joins...)),
		kvOf("updated_at", validation.VStr(state.NowIso())),
	), nil
}

// ---- small helpers --------------------------------------------------------

func kvOf(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

func objOr(v validation.Value, key string, def validation.Value) validation.Value {
	if hasKey(v, key) {
		return validation.ObjAt(v, key)
	}
	return def
}

func hasKey(v validation.Value, key string) bool {
	if v.Kind != validation.Obj {
		return false
	}
	for _, kv := range v.O {
		if kv.K == key {
			return true
		}
	}
	return false
}

func vset(v *validation.Value, key string, val validation.Value) {
	for i := range v.O {
		if v.O[i].K == key {
			v.O[i].V = val
			return
		}
	}
	v.O = append(v.O, kvOf(key, val))
}

func appendTo(v *validation.Value, key string, val validation.Value) {
	for i := range v.O {
		if v.O[i].K == key {
			v.O[i].V.A = append(v.O[i].V.A, val)
			return
		}
	}
	v.O = append(v.O, kvOf(key, validation.VArr(val)))
}

func strPtr(s string) *string { return &s }

func executorFor(kind string) *string {
	if kind == "model" {
		return strPtr("model")
	}
	return strPtr("deterministic")
}

func containsStr(items []string, want string) bool {
	for _, s := range items {
		if s == want {
			return true
		}
	}
	return false
}

// pyTupleRepr renders a Python tuple repr: ('a', 'b'). JOIN_KINDS is a tuple,
// so its repr carries parentheses (not the list brackets of PyRepr).
func pyTupleRepr(items []string) string {
	parts := make([]string, len(items))
	for i, s := range items {
		parts[i] = validation.PyReprStr(s)
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

// pyListRepr is Python's repr of a list of strings.
func pyListRepr(items []string) string {
	return validation.PyRepr(validation.StrArr(items))
}

func pyOptIntRepr(v *int) string {
	if v == nil {
		return "None"
	}
	return strconv.Itoa(*v)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func stringSlice(v validation.Value, limit int) []string {
	out := []string{}
	if v.Kind != validation.Arr {
		return out
	}
	for i, e := range v.A {
		if i >= limit {
			break
		}
		out = append(out, e.S)
	}
	return out
}

func phaseIndex(phase string) (int, bool) {
	for i, p := range state.Phases {
		if p == phase {
			return i, true
		}
	}
	return 0, false
}

// isAdapterAbsent maps the adapter seam's failures onto Python's
// `except (KeyError, FileNotFoundError)`: a missing prompt is not fatal.
func isAdapterAbsent(err error) bool {
	return errors.Is(err, ErrAdapterNotWired) || errors.Is(err, os.ErrNotExist) ||
		errors.Is(err, errFileNotFound)
}

// errFileNotFound lets an adapter seam report Python's FileNotFoundError
// without importing os (it wraps os.ErrNotExist for errors.Is).
var errFileNotFound = fmt.Errorf("file not found: %w", os.ErrNotExist)

// moneyField formats one budget_status field as Python f"{x:,.2f}".
func moneyField(bstat validation.Value, key string) (string, error) {
	v := validation.ObjAt(bstat, key)
	switch v.Kind {
	case validation.Flt:
		return pyMoney2f(v.F), nil
	case validation.Int:
		f, err := valueFloat(v)
		if err != nil {
			return "", err
		}
		return pyMoney2f(f), nil
	}
	return "", fmt.Errorf("cost status %s is not a number", validation.PyReprStr(key))
}

func valueFloat(v validation.Value) (float64, error) {
	switch v.Kind {
	case validation.Flt:
		return v.F, nil
	case validation.Int:
		if v.Big != "" {
			f, err := strconv.ParseFloat(v.Big, 64)
			if err != nil {
				return 0, errors.New("int too large to convert to float")
			}
			return f, nil
		}
		return float64(v.I), nil
	}
	return 0, fmt.Errorf("float() argument must be a string or a real number, "+
		"not %s", validation.PyReprStr(kindName(v)))
}

func kindName(v validation.Value) string {
	switch v.Kind {
	case validation.Null:
		return "NoneType"
	case validation.Bool:
		return "bool"
	case validation.Int:
		return "int"
	case validation.Flt:
		return "float"
	case validation.Str:
		return "str"
	case validation.Arr:
		return "list"
	case validation.Obj:
		return "dict"
	}
	return "NoneType"
}

// pyMoney2f is Python's f"{x:,.2f}": thousands-grouped, two decimals,
// round-half-even on the exact binary value, with CPython's nan/inf
// spellings and a signed "-0.00".
func pyMoney2f(x float64) string {
	switch {
	case math.IsNaN(x):
		return "nan"
	case math.IsInf(x, 1):
		return "inf"
	case math.IsInf(x, -1):
		return "-inf"
	}
	r := validation.PythonRound(x, 2)
	neg := math.Signbit(r)
	s := strconv.FormatFloat(math.Abs(r), 'f', 2, 64)
	intPart, frac := s, "00"
	if i := strings.IndexByte(s, '.'); i >= 0 {
		intPart, frac = s[:i], s[i+1:]
	}
	out := groupThousands(intPart) + "." + frac
	if neg {
		return "-" + out
	}
	return out
}

// groupThousands inserts "," every three digits from the right.
func groupThousands(digits string) string {
	if len(digits) <= 3 {
		return digits
	}
	var b strings.Builder
	lead := len(digits) % 3
	if lead > 0 {
		b.WriteString(digits[:lead])
	}
	for i := lead; i < len(digits); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(digits[i : i+3])
	}
	return b.String()
}
