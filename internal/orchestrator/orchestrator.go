// Package orchestrator is the port of webv2/orchestrator.py: the deterministic
// facade over the campaign state machine.
//
// THIS package owns the campaign state machine. The LLM does not. Each phase
// entry validates preconditions, runs deterministic work in-process, emits a
// work list for model stages, and records stage status. Every side effect goes
// through the event log; every phase transition goes through SetPhase.
//
// Phase map (the 8 subsystems of the architecture):
//
//	SCOPE                     policy loaded, targets named          (deterministic)
//	SNAPSHOT                  source+deployment+chain pins          (deterministic)
//	STRUCTURAL_INDEX          program graph                         (deterministic)
//	PROTOCOL_INTELLIGENCE     model+invariants+economics            (model + checks)
//	CAMPAIGN_PLANNING         plan + work queue                     (model + bootstrap)
//	DISCOVERY                 specialist sweeps                     (model)
//	CANDIDATE_INTEL           dedup + triage                        (deterministic + model)
//	HOSTILE_REVIEW            critic verdicts                       (model)
//	REPRODUCTION              T0..T4 ladder                         (deterministic + sandbox)
//	CHAINING                  capability graph                      (deterministic)
//	MAXIMAL_EXPLOITATION      variant ladder per CONFIRMED finding  (model + sandbox)
//	INDEPENDENT_VERIFICATION  fresh-context repro of CONFIRMED      (model + sandbox)
//	RISK_CALIBRATION          3-pass risk                           (deterministic)
//	BOUNTY_GATE               policy gate                           (deterministic)
//	REPORTING                 markdown views                        (deterministic)
//	LEARNING                  memory queue + reflection             (human-gated)
//
// Seams (unported collaborators, P2/P3): structural_index (index.go),
// reproduction + sequence_poc (reproduction.go), chain_engine (chain.go) and
// the two planner B1/D1 writers the planner port does not export yet
// (planstore.go). Every seam has a safe default: the behavior of Python when
// the feature has no data (empty queues, empty reports) or a clear
// "not wired" error on the paths that cannot degrade.
package orchestrator

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// OrchestrationError is orchestrator.OrchestrationError: a deterministic
// precondition failure. The CLI renders str(e) as "error: <msg>", so every
// message is transcribed character-for-character from the Python raise.
type OrchestrationError struct {
	Msg string
}

// Error is str(OrchestrationError).
func (e *OrchestrationError) Error() string { return e.Msg }

// orchestrationError mints the Python raise.
func orchestrationError(msg string) error { return &OrchestrationError{Msg: msg} }

// StatusNoteCap is STATUS_NOTE_CAP: the display cap for stage notes in
// status(). The state file keeps the full (4 KB-capped) note; stdout must
// stay small.
const StatusNoteCap = 200

// Orchestrator is orchestrator.Orchestrator: the deterministic facade.
type Orchestrator struct {
	C *state.Campaign
}

// New is Orchestrator.__init__.
func New(c *state.Campaign) *Orchestrator { return &Orchestrator{C: c} }

// ---- small ordered-object helpers -----------------------------------------
//
// The Python code treats every on-disk block as a dict and mutates it in
// place; validation.Value keeps that key order, so the helpers below mirror
// dict access without sorting anything.

func kvOf(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

// objAt is d.get(key, None): Null when the key is absent or v is not a dict.
func objAt(v validation.Value, key string) validation.Value {
	if v.Kind != validation.Obj {
		return validation.VNull()
	}
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V
		}
	}
	return validation.VNull()
}

// hasKey is `key in d`.
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

// asDict is findings._as_dict: a non-dict block behaves as an absent block.
func asDict(v validation.Value) validation.Value {
	if v.Kind == validation.Obj {
		return v
	}
	return validation.VObj()
}

// orEmptyObj is Python's `x or {}`: a falsy value (absent, empty) is {}.
func orEmptyObj(v validation.Value) validation.Value {
	if v.Kind == validation.Obj {
		return v
	}
	return validation.VObj()
}

// listAt is d.get(key, []) for list values; a non-list reads as empty.
func listAt(v validation.Value, key string) []validation.Value {
	e := objAt(v, key)
	if e.Kind != validation.Arr {
		return nil
	}
	return e.A
}

// strAt is d.get(key, "") for string values.
func strAt(v validation.Value, key string) string {
	e := objAt(v, key)
	if e.Kind == validation.Str {
		return e.S
	}
	return ""
}

// numAt is d.get(key, 0.0) for numeric values.
func numAt(v validation.Value, key string) float64 {
	e := objAt(v, key)
	switch e.Kind {
	case validation.Flt:
		return e.F
	case validation.Int:
		if e.Big != "" {
			f, err := strconv.ParseFloat(e.Big, 64)
			if err != nil {
				return 0
			}
			return f
		}
		return float64(e.I)
	}
	return 0
}

// statFile reports whether p exists (any stat error is Python's absent path).
func statFile(p string) (bool, error) {
	if _, err := os.Stat(p); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// intAt is d.get(key, 0) for integer values.
func intAt(v validation.Value, key string) int64 {
	e := objAt(v, key)
	if e.Kind == validation.Int {
		return e.I
	}
	return 0
}

// boolAt is d.get(key, False) for boolean values.
func boolAt(v validation.Value, key string) bool {
	e := objAt(v, key)
	return e.Kind == validation.Bool && e.B
}

// pyTruthy is Python's bool(x) for the JSON-shaped values this package reads.
func pyTruthy(v validation.Value) bool {
	switch v.Kind {
	case validation.Null:
		return false
	case validation.Bool:
		return v.B
	case validation.Int:
		return v.I != 0 || v.Big != ""
	case validation.Flt:
		return v.F != 0
	case validation.Str:
		return v.S != ""
	case validation.Arr:
		return len(v.A) > 0
	case validation.Obj:
		return len(v.O) > 0
	}
	return false
}

// pyLen is len(x) for lists, dicts and strings.
func pyLen(v validation.Value) int {
	switch v.Kind {
	case validation.Arr:
		return len(v.A)
	case validation.Obj:
		return len(v.O)
	case validation.Str:
		return len([]rune(v.S))
	}
	return 0
}

// copyObj is dict(entry): a shallow copy that can be mutated in place.
func copyObj(v validation.Value) validation.Value {
	if v.Kind != validation.Obj {
		return v
	}
	kvs := make([]validation.KV, len(v.O))
	copy(kvs, v.O)
	return validation.VObj(kvs...)
}

// strList is `[str(x) for x in list]` for the string lists this package reads.
func strList(vs []validation.Value) []string {
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		out = append(out, pyStr(v))
	}
	return out
}

// pyStr is Python's str(v) for the values that reach an f-string here.
func pyStr(v validation.Value) string {
	if v.Kind == validation.Str {
		return v.S
	}
	return validation.PyRepr(v)
}

// strArr boxes a Go string slice as a JSON array.
func strArr(ss []string) validation.Value {
	items := make([]validation.Value, 0, len(ss))
	for _, s := range ss {
		items = append(items, validation.VStr(s))
	}
	return validation.VArr(items...)
}

// valueArr boxes a slice of already-built values.
func valueArr(vs []validation.Value) validation.Value {
	items := make([]validation.Value, len(vs))
	copy(items, vs)
	return validation.VArr(items...)
}

// runeLen is len(str): Python counts characters, not bytes.
func runeLen(s string) int { return len([]rune(s)) }

// fileExists is Path.exists() for the regular-file paths this package reads.
func fileExists(p string) bool {
	st, err := statFile(p)
	return err == nil && st
}

// ptr returns a pointer to s (executor arguments of SetStage).
func ptr(s string) *string { return &s }

// itoa is Python's str(int).
func itoa(n int) string { return fmt.Sprintf("%d", n) }

// pad4 is Python's f"{n:04d}".
func pad4(n int) string { return fmt.Sprintf("%04d", n) }

// errText is `raise ValueError(msg)`: str(e) is the message itself.
func errText(msg string) error { return fmt.Errorf("%s", msg) }

// PipelineAdapter presents the Python-shaped Orchestrator to pipeline's
// no-argument OrchestratorAPI (pipeline._builtin calls scope()/plan() with no
// arguments, exactly like the bare `webv2 scope C` / `webv2 plan C` CLI).
//
// It exists because the Python-shaped methods take the CLI's optional
// arguments, which Go cannot overload: the adapter is the one-line bridge a
// pipeline construction site installs (pipeline.New(c, orch.PipelineAdapter{O: o}, nil)).
type PipelineAdapter struct {
	O *Orchestrator
}

// Scope is Orchestrator.scope() with no policy (Python: policy_path=None).
func (a PipelineAdapter) Scope() (validation.Value, error) { return a.O.Scope("") }

// BuildStructuralIndex is Orchestrator.build_structural_index().
func (a PipelineAdapter) BuildStructuralIndex() (validation.Value, error) {
	return a.O.BuildStructuralIndex()
}

// RunDedup is Orchestrator.run_dedup().
func (a PipelineAdapter) RunDedup() (validation.Value, error) { return a.O.RunDedup() }

// Chaining is Orchestrator.chaining().
func (a PipelineAdapter) Chaining() (validation.Value, error) { return a.O.Chaining() }

// CalibrateAll is Orchestrator.calibrate_all().
func (a PipelineAdapter) CalibrateAll() (validation.Value, error) {
	return a.O.CalibrateAll()
}

// BountyGateAll is Orchestrator.bounty_gate_all().
func (a PipelineAdapter) BountyGateAll() (validation.Value, error) {
	return a.O.BountyGateAll()
}

// Plan is Orchestrator.plan() with no arguments (bootstrap from the model).
func (a PipelineAdapter) Plan() (validation.Value, error) {
	return a.O.Plan(validation.VNull(), validation.VNull(), false)
}

// ReproductionQueue is Orchestrator.reproduction_queue().
func (a PipelineAdapter) ReproductionQueue() (validation.Value, error) {
	return a.O.ReproductionQueue()
}

// joinActions is Python's "; ".join(list).
func joinActions(items []string) string { return strings.Join(items, "; ") }
