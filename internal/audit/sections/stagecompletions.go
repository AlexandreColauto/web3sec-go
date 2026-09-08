// Section 9: stage completion ledger — a MODEL stage the ledger marks done
// while its completion proof fails is a paper-over: a raw set_stage("done")
// can schedule the DAG, but it cannot survive the audit. Advisory proofs
// (deterministic stages) are surfaced separately: a stale report or an open
// ladder there is incompleteness, not tampering. Message-for-message with
// audit.py section 9, including the advisory format and the
// 'checked': len(CP.PROOFS) count.
package sections

import (
	"fmt"
	"strings"

	"websec/internal/completion"
	"websec/internal/state"
	"websec/internal/validation"
)

// StageCompletions is audit.py section 9: {checked, problems, advisory, ok}.
func StageCompletions(c *state.Campaign) (validation.Value, error) {
	problems, err := completion.AuditStageLedger(c)
	if err != nil {
		return validation.Value{}, err
	}
	st, err := c.State()
	if err != nil {
		return validation.Value{}, err
	}
	ledger := objAt(st, "stages")
	all, err := completion.AllProofStatus(c)
	if err != nil {
		return validation.Value{}, err
	}
	var advisory []validation.Value
	for _, kv := range all.O {
		pr := kv.V
		if pr.Kind != validation.Obj || len(pr.O) == 0 {
			continue // Python `if pr`
		}
		if pyTruthy(objAt(pr, "authoritative")) || pyTruthy(objAt(pr, "done")) {
			continue
		}
		entry := orEmptyObj(objAt(ledger, kv.K))
		if objStr(entry, "status") != "done" {
			continue
		}
		advisory = append(advisory, validation.VStr(fmt.Sprintf(
			"stage %s is marked done but its advisory proof is open: %s",
			validation.PyReprStr(kv.K),
			strings.Join(headStrs(strListOf(objAt(pr, "missing")), 3), "; "))))
	}
	return validation.VObj(
		KV("checked", validation.VInt(int64(len(completion.Proofs)))),
		KV("problems", strArrOf(problems)),
		KV("advisory", validation.VArr(advisory...)),
		KV("ok", validation.VBool(len(problems) == 0)),
	), nil
}
