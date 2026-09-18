// Pipeline seams — the adapter/completion/maximization/costs/report/orchestrator seams and their not-wired defaults (split from pipeline.go; pure structural move).

package pipeline

import (
	"errors"
	"fmt"

	"websec/internal/state"
	"websec/internal/validation"
)

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
