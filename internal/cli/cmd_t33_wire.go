package cli

// cmd_t33_wire: the T33 dataset-tooling seams (Python's import-time
// connections for eval_store, in one place).
//
// D25: trajectory.case_partition / metrics.case_partition read
// eval_store.load_case, and corpus.class_inventory reads
// eval_store.list_cases. All three seams defaulted to "store absent", so
// every case-linked derivation failed closed even when the store existed.
//
// The dataset record loader (corpus.SetLoadPocRecords) stays on its
// absent-clone default: datasets/defihacklabs.py is the P4 part-2 deliverable.

import (
	"websec/internal/corpus"
	"websec/internal/evalstore"
	"websec/internal/metrics"
	"websec/internal/trajectory"
	"websec/internal/validation"
)

// evalStoreSeam adapts the evalstore package functions to the two identical
// EvalStore interfaces (trajectory and metrics).
type evalStoreSeam struct{}

func (evalStoreSeam) LoadCase(caseID string) (validation.Value, error) {
	return evalstore.LoadCase(caseID)
}

// wireT33Seams installs the T33 seam targets. Idempotent.
func wireT33Seams() {
	trajectory.SetEvalStore(evalStoreSeam{})
	metrics.SetEvalStore(evalStoreSeam{})
	corpus.SetListEvalCases(func() ([]validation.Value, error) {
		return evalstore.ListCases(nil, nil, nil)
	})
}

// WireT33Seams is wireT33Seams for cmd/webv2's init (Python's import-time
// connections are wired in both the CLI dispatch path and the binary's init,
// exactly like the T26/T28 seams).
func WireT33Seams() { wireT33Seams() }
