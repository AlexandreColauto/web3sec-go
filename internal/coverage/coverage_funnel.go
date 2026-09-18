// coverage_funnel.go: update_funnel — projecting the candidate funnel from
// findings and the event log into the ledger.
package coverage

import (
	"fmt"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// UpdateFunnel is update_funnel: project the candidate funnel from findings +
// event log.
func UpdateFunnel(c *state.Campaign) (validation.Value, error) {
	found, err := findings.LoadAllFindings(c)
	if err != nil {
		return validation.VNull(), err
	}
	for _, f := range found {
		if _, ok := lookup(f, "status"); !ok {
			// Python's f["status"] raises KeyError before any counter runs.
			return validation.VNull(), fmt.Errorf("%s", validation.PyReprStr("status"))
		}
	}
	funnel := validation.VObj(
		kv("hypotheses_generated", validation.VInt(int64(len(found)))),
		kv("after_dedupe", validation.VInt(countFindings(found, func(f validation.Value) bool {
			return validation.ObjStr(f, "status") != "DUPLICATE"
		}))),
		kv("after_review", validation.VInt(countFindings(found, func(f validation.Value) bool {
			switch validation.ObjStr(f, "status") {
			case "POSSIBLE", "CONFIRMED", "CHAIN":
				return true
			}
			return false
		}))),
		kv("reproduced", validation.VInt(countFindings(found, func(f validation.Value) bool {
			return reproductionStatus(f) == "reproduced"
		}))),
		kv("confirmed", validation.VInt(countFindings(found, func(f validation.Value) bool {
			return validation.ObjStr(f, "status") == "CONFIRMED"
		}))),
		kv("disproved", validation.VInt(countFindings(found, func(f validation.Value) bool {
			return validation.ObjStr(f, "status") == "DISPROVED"
		}))),
		kv("submission_ready", validation.VInt(countFindings(found,
			func(f validation.Value) bool {
				return validation.PyTruthy(validation.ObjAt(validation.ObjAt(f, "bounty"), "submission_ready"))
			}))),
	)
	cov, err := Load(c)
	if err != nil {
		return validation.VNull(), err
	}
	cov.O = validation.SetOrAppend(cov.O, "funnel", funnel)
	if _, err := Save(c, &cov); err != nil {
		return validation.VNull(), err
	}
	return funnel, nil
}

// countFindings is sum(1 for f in findings if pred(f)).
func countFindings(found []validation.Value, pred func(validation.Value) bool) int64 {
	n := int64(0)
	for _, f := range found {
		if pred(f) {
			n++
		}
	}
	return n
}

// reproductionStatus is (f.get("verification") or {}).get("reproduction",
// {}).get("status"): "" when any link is absent or falsy.
func reproductionStatus(f validation.Value) string {
	verification := validation.ObjAt(f, "verification")
	if !validation.PyTruthy(verification) {
		return ""
	}
	repro, ok := lookup(verification, "reproduction")
	if !ok || repro.Kind != validation.Obj {
		return ""
	}
	return validation.ObjStr(repro, "status")
}
