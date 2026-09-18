package metrics

import (
	"websec/internal/findings"
	"websec/internal/validation"
)

// STATUS_TO_OUTCOME is the terminal-status -> gold-outcome enum.
var STATUS_TO_OUTCOME = map[string]string{
	"CONFIRMED":     "confirmed-exploitable",
	"CHAIN":         "confirmed-exploitable",
	"DISPROVED":     "disproved",
	"OUT_OF_SCOPE":  "out-of-scope",
	"DUPLICATE":     "duplicate",
	"INFORMATIONAL": "confirmed-not-exploitable",
}

// GOLD_TO_STATUSES is the gold outcome -> the terminal statuses satisfying it.
var GOLD_TO_STATUSES = map[string]map[string]struct{}{
	"confirmed-exploitable":     setOf("CONFIRMED", "CHAIN"),
	"confirmed-not-exploitable": setOf("DISPROVED"),
	"disproved":                 setOf("DISPROVED"),
	"out-of-scope":              setOf("OUT_OF_SCOPE"),
	"duplicate":                 setOf("DUPLICATE"),
	"economic-no-go":            setOf("INFORMATIONAL"),
}

var (
	positiveGolds      = setOf("confirmed-exploitable")
	negativeGolds      = setOf("confirmed-not-exploitable")
	exploitableGolds   = setOf("confirmed-exploitable")
	notExploitableGold = setOf("confirmed-not-exploitable", "disproved")
	predPositive       = setOf("CONFIRMED", "CHAIN")
	predNegative       = setOf("DISPROVED")
	assumptionResolved = setOf("SUPPORTED", "REFUTED")
)

// exportableStatuses is _EXPORTABLE_STATUSES = TERMINAL | {CONFIRMED, CHAIN}.
var exportableStatuses = func() map[string]struct{} {
	out := setOf("CONFIRMED", "CHAIN")
	for k := range findings.TERMINAL {
		out[k] = struct{}{}
	}
	return out
}()

const (
	heldOutReason        = "held-out case — leakage"
	trainingReason       = "training case — leakage"
	unreadableCaseReason = "case partition unreadable (fail closed)"
)

// EvalStore is the eval_store seam (the read-only lens). Absent: every
// case-linked derivation reports a note and fails closed.
type EvalStore interface {
	LoadCase(caseID string) (validation.Value, error)
}

var evalStore EvalStore

// SetEvalStore installs the eval store (nil restores the absent default).
func SetEvalStore(s EvalStore) { evalStore = s }
