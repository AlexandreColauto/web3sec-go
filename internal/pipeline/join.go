// Pipeline joins — join specs, the dependency DAG and readiness evaluation (split from pipeline.go; pure structural move).

package pipeline

import (
	"errors"
	"fmt"
	"slices"

	"websec/internal/state"
	"websec/internal/validation"
)

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
	if !slices.Contains(JoinKinds, kind) {
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
			// aislop-ignore-next-line ai-slop/go-library-panic — deliberate: embedded STAGE_JOINS parsed at init, the template.Must contract
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
