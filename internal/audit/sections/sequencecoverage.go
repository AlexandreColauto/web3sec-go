// Section 12: sequence coverage — every sequence-required finding must have
// a recorded attempt tracing to an exec with verified sequence coverage, the
// standing "structurally under-equipped" signal (spec 2026-07-15 §7). A
// finding is only "applicable" when its gate equivalent
// (onchain_sequence_required = shape AND a fork target on the active
// snapshot) is in effect: a campaign with no fork target cannot produce the
// on-chain multi-tx PoC, so the section records it as not_applicable instead
// of flagging it. Degrades to a problem entry, never raises.
//
// Python's code order puts this section 12th, between
// invariant_verification (11) and probe_surface (13); register.go holds it
// in that slot.
package sections

import (
	"errors"
	"fmt"

	"websec/internal/findings"
	"websec/internal/sequencepoc"
	"websec/internal/state"
	"websec/internal/validation"
)

// SequenceCoverage is audit.py section 12: {required, applicable,
// not_applicable, covered, rows, problems, ok}.
func SequenceCoverage(c *state.Campaign) (validation.Value, error) {
	out, err := sequenceCoverage(c)
	if err != nil {
		// Degraded audit entry (baselines convention).
		return validation.VObj(
			KV("required", validation.VNull()),
			KV("covered", validation.VNull()),
			KV("rows", validation.VArr()),
			KV("applicable", validation.VNull()),
			KV("not_applicable", validation.VNull()),
			KV("ok", validation.VBool(false)),
			KV("problems", validation.VArr(validation.VStr(fmt.Sprintf(
				"sequence coverage section failed: %v", err)))),
		), nil
	}
	return out, nil
}

// sequenceCoverage is the un-degraded body; a Go error maps to Python's
// caught exception.
func sequenceCoverage(c *state.Campaign) (validation.Value, error) {
	execs, err := seqExecIndex(c)
	if err != nil {
		return validation.Value{}, err
	}
	all, err := findings.LoadAllFindings(c)
	if err != nil {
		return validation.Value{}, err
	}
	var rows []validation.Value
	var problems []validation.Value
	applicable, covered := 0, 0
	for _, f := range all {
		if !sequencepoc.IsSequenceRequired(f) {
			continue
		}
		row, problem, app, cov, err := sequenceRow(c, execs, f)
		if err != nil {
			return validation.Value{}, err
		}
		rows = append(rows, row)
		if problem.Kind != validation.Null {
			problems = append(problems, validation.VStr(fmt.Sprintf("%s: %s",
				objStr(row, "finding_id"), problem.S)))
		}
		applicable += app
		covered += cov
	}
	return validation.VObj(
		KV("required", validation.VInt(int64(len(rows)))),
		KV("applicable", validation.VInt(int64(applicable))),
		KV("not_applicable", validation.VInt(int64(len(rows)-applicable))),
		KV("covered", validation.VInt(int64(covered))),
		KV("rows", validation.VArr(rows...)),
		KV("problems", validation.VArr(problems...)),
		KV("ok", validation.VBool(covered == applicable)),
	), nil
}

// seqExecIndex is {exec_id: record} over the ledger.
func seqExecIndex(c *state.Campaign) (map[string]validation.Value, error) {
	recs, err := state.AllExecs(c)
	if err != nil {
		return nil, err
	}
	execs := map[string]validation.Value{}
	for _, r := range recs {
		if eid := objStr(r, "exec_id"); eid != "" {
			execs[eid] = r
		}
	}
	return execs, nil
}

// sequenceRow is one finding's {row, problem, applicable, covered}: the
// not-applicable record when no fork target is pinned, else the
// covered/uncovered row.
func sequenceRow(c *state.Campaign, execs map[string]validation.Value,
	f validation.Value) (validation.Value, validation.Value, int, int, error) {
	fid, err := requiredStr(f, "finding_id")
	if err != nil {
		return validation.Value{}, validation.Value{}, 0, 0, err
	}
	status, err := requiredStr(f, "status")
	if err != nil {
		return validation.Value{}, validation.Value{}, 0, 0, err
	}
	if !sequencepoc.OnchainSequenceRequired(c, f) {
		// Shape-only requirement, but no fork target pinned: the CONFIRMED
		// gate (onchain_sequence_required) agrees this is not applicable
		// on-chain — record, never flag.
		row := validation.VObj(
			KV("finding_id", validation.VStr(fid)),
			KV("status", validation.VStr(status)),
			KV("covered_by", validation.VNull()),
			KV("applicable", validation.VBool(false)),
			KV("problem", validation.VNull()),
			KV("reason", validation.VStr("no fork target on the active "+
				"snapshot — on-chain sequence coverage is not required "+
				"(the CONFIRMED gate agrees)")),
		)
		return row, validation.VNull(), 0, 0, nil
	}
	coveredBy := seqCoveredBy(c, execs, f)
	var problem validation.Value
	covered := 0
	if coveredBy == "" {
		problem = validation.VStr("sequence PoC coverage missing — no " +
			"recorded attempt with verified sequence coverage " +
			"(webv2 sequence run)")
	} else {
		problem = validation.VNull()
		covered = 1
	}
	row := validation.VObj(
		KV("finding_id", validation.VStr(fid)),
		KV("status", validation.VStr(status)),
		KV("covered_by", nullOrStr(coveredBy)),
		KV("applicable", validation.VBool(true)),
		KV("problem", problem),
	)
	return row, problem, 1, covered, nil
}

// seqCoveredBy is the exec_id of the first recorded attempt with verified
// coverage ("" when none). M4: per-entry guards like the gate — one
// malformed attempt entry must not throw the whole section into the
// degraded branch.
func seqCoveredBy(c *state.Campaign, execs map[string]validation.Value,
	f validation.Value) string {
	ver := objAt(f, "verification")
	if ver.Kind != validation.Obj {
		ver = validation.VObj()
	}
	repro := objAt(ver, "reproduction")
	if repro.Kind != validation.Obj {
		repro = validation.VObj()
	}
	for _, a := range attemptsOf(repro) {
		if a.Kind != validation.Obj {
			continue
		}
		rec, ok := execs[objStr(a, "artifact_id")]
		if !ok {
			continue
		}
		if cov, _ := sequencepoc.VerifySequenceCoverage(c, f, rec); cov {
			return objStr(rec, "exec_id")
		}
	}
	return ""
}

// attemptsOf is `raw_attempts if isinstance(raw_attempts, list) else []`
// over `repro.get("attempts") or []`.
func attemptsOf(repro validation.Value) []validation.Value {
	v := objAt(repro, "attempts")
	if !validation.PyTruthy(v) || v.Kind != validation.Arr {
		return nil
	}
	return v.A
}

// requiredStr is Python's d[key] (a missing key raises KeyError).
func requiredStr(v validation.Value, key string) (string, error) {
	for _, kv := range v.O {
		if kv.K == key {
			return pyStrValue(kv.V), nil
		}
	}
	return "", errors.New("'" + key + "'")
}

// nullOrStr renders Python's `covered_by` (None or the exec id).
func nullOrStr(s string) validation.Value {
	if s == "" {
		return validation.VNull()
	}
	return validation.VStr(s)
}
