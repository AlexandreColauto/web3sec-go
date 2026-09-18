// Package maximization is the variant ladder (base -> amplified -> maximal):
// a 1:1 port of webv2/maximization.py (port-era provenance; twin retired 2026-09-09).
//
// Chaining composes ACROSS confirmed findings; this module searches WITHIN
// one, along five fixed axes. Integrity rules: a rung above base counts only
// when REPRODUCED (its own EXEC, E4+ profile, real evidence); a rung can be
// DISPROVED with a written reason and is queued as negative memory; the
// ladder closes with a disposition (complete or waived), never silently open;
// the finding's claim pins to the maximal reproduced rung.
package maximization

import (
	"fmt"
	"sort"
	"strings"
	"websec/internal/state"
	"websec/internal/validation"
)

// Axes is AXES: the five fixed-order maximization axes.
var Axes = []string{"capital-minimization", "precondition-removal",
	"role-conflation", "ordering-permutation", "cap-saturation"}

// AxeChecklist is AXE_CHECKLIST: the verbatim operator prompts per axis.
var AxeChecklist = map[string]string{
	"capital-minimization": "What is the TRUE minimum attacker capital? " +
		"Dust the pool with the smallest unit the code accepts (1 wei?). " +
		"Was the $ figure in the base PoC a protocol requirement or the " +
		"analyst's convenience?",
	"precondition-removal": "Which base preconditions does the CODE " +
		"actually enforce? For each: can the exploit run WITHOUT it (victim " +
		"only deposits, never stakes)? A precondition nobody asserted is a " +
		"rung waiting to happen.",
	"role-conflation": "Can the attacker occupy the victim's seat? First " +
		"staker, first depositor, last withdrawer — is any 'victim' role " +
		"open to anyone, including the attacker?",
	"ordering-permutation": "Does entry ORDER change the economics? " +
		"Front-run the donation, sandwich the update, drain before the " +
		"accounting catches up.",
	"cap-saturation": "Is there a payout cap per call/per block/per actor? " +
		"Can repeated timed calls saturate it to 100%? Does the cap bind " +
		"BEFORE full extraction — and can timing defeat it?",
}

// ---- learning seam (P3, unported) -----------------------------------------

// MemoryRequest is one learning.queue_memory call.
type MemoryRequest struct {
	Kind            string
	Status          string
	Pattern         string
	FindingID       *string
	BugClass        *string
	EvidenceSummary string
	Negative        *validation.Value
}

// queueMemory is learning.queue_memory. Unported module: the safe default is
// a no-op (Python's absent-data behavior — the disproof is still recorded on
// the ladder and the log, only the negative-memory row is missing).
var queueMemory = func(*state.Campaign, MemoryRequest) (validation.Value, error) {
	return validation.VNull(), nil
}

// SetQueueMemory installs learning.queue_memory; nil restores the no-op.
func SetQueueMemory(f func(*state.Campaign, MemoryRequest) (validation.Value, error)) {
	if f == nil {
		f = func(*state.Campaign, MemoryRequest) (validation.Value, error) {
			return validation.VNull(), nil
		}
	}
	queueMemory = f
}

// ---- helpers --------------------------------------------------------------

func kvOf(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

// asObj is `d.get(key) or {}`.

func listOf(v validation.Value, key string) validation.Value {
	if f := validation.ObjAt(v, key); f.Kind == validation.Arr {
		return f
	}
	return validation.VArr()
}

// pyListRepr is Python's repr() of a list of strings.

// pyTupleRepr is Python's repr() of a tuple of strings.
func pyTupleRepr(items []string) string {
	parts := make([]string, 0, len(items))
	for _, s := range items {
		parts = append(parts, validation.PyReprStr(s))
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

// noneText is Python's f"{finding_id}" for a possibly-absent CLI positional:
// the empty string stands in for None (ids are never empty in the model).
func noneText(s string) string {
	if s == "" {
		return "None"
	}
	return s
}

// idRepr is Python's {id!r} for a possibly-absent CLI positional.
func idRepr(s string) string {
	if s == "" {
		return "None"
	}
	return validation.PyReprStr(s)
}

// hasKey is `key in d`.

// numOf is float(v) for the int/float/bool shapes JSON carries.
func numOf(v validation.Value) (float64, bool) {
	switch v.Kind {
	case validation.Int:
		return float64(v.I), true
	case validation.Flt:
		return v.F, true
	case validation.Bool:
		if v.B {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}

// requireOpen is _require_open: only a COMPLETE ladder refuses mutation (a
// waived ladder is re-openable by adding work).
func requireOpen(lad validation.Value) error {
	if validation.ObjStr(validation.AsObj(validation.ObjAt(lad, "disposition")), "state") == "complete" {
		return fmt.Errorf("ladder disposition is complete; reopen it with an " +
			"explicit reason before adding work (webv2 ladder reopen)")
	}
	return nil
}

// listStrings renders an array value as Go strings.
func listStrings(v validation.Value) []string {
	out := make([]string, 0, len(v.A))
	for _, it := range v.A {
		if it.Kind == validation.Str {
			out = append(out, it.S)
		}
	}
	return out
}

// SortAxes is a helper for deterministic diagnostics.
func SortAxes(items []string) []string {
	out := append([]string{}, items...)
	sort.Strings(out)
	return out
}
