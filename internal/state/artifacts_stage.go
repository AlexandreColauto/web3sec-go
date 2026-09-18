package state

import (
	"strconv"
	"websec/internal/validation"
)

// --- stage ledger ----------------------------------------------------------

// StageStatus is stage_status: state()["stages"].get(stage,
// {"status": "pending"}).
func (c *Campaign) StageStatus(stage string) (validation.Value, error) {
	st, err := c.State()
	if err != nil {
		return validation.VNull(), err
	}
	if e := validation.ObjAt(validation.ObjAt(st, "stages"), stage); e.Kind != validation.Null {
		return e, nil
	}
	return validation.VObj(kv("status", validation.VStr("pending"))), nil
}

// SetStage is set_stage: the per-stage execution ledger. The entry defaults
// to {"status":"pending","attempts":0,"last_run_at":None,"note":"",
// "executor":None} (exact key order). attempts increments only for
// "needs-model"/"done"/"failed"; note overwrites only when truthy;
// executor only when a non-empty value is passed. No event is logged.
//
// Deviation: Python's optional note/executor parameters are passed
// explicitly — VNull()/nil for the defaults. Python's `executor or ...`
// also treats "" as "keep the old value"; the port matches.
func (c *Campaign) SetStage(stage, status string, note validation.Value, executor *string) error {
	// r15: load->edit->write of campaign_state is one unit;
	// the campaign lock spans the WHOLE window (the entry that
	// used to lock only SaveState still lost updates racing a
	// sibling writer — the processlock law, method-level).
	if err := c.LockProcess(); err != nil {
		return err
	}
	defer c.UnlockProcess()
	st, err := c.State()
	if err != nil {
		return err
	}
	stages := validation.ObjAt(st, "stages")
	entry := validation.ObjAt(stages, stage)
	if entry.Kind == validation.Null {
		entry = validation.VObj(
			kv("status", validation.VStr("pending")),
			kv("attempts", validation.VInt(0)),
			kv("last_run_at", validation.VNull()),
			kv("note", validation.VStr("")),
			kv("executor", validation.VNull()),
		)
	}
	entry.O = validation.SetOrAppend(entry.O, "status", validation.VStr(status))
	attempts := int64(0)
	if a := validation.ObjAt(entry, "attempts"); a.Kind == validation.Int {
		if n, err := strconv.ParseInt(validation.IntText(a), 10, 64); err == nil {
			attempts = n
		}
	}
	if status == "needs-model" || status == "done" || status == "failed" {
		attempts++
	}
	entry.O = validation.SetOrAppend(entry.O, "attempts", validation.VInt(attempts))
	entry.O = validation.SetOrAppend(entry.O, "last_run_at", validation.VStr(nowIso()))
	if validation.PyTruthy(note) {
		entry.O = validation.SetOrAppend(entry.O, "note", validation.VStr(capNote(note)))
	}
	if executor != nil && *executor != "" {
		entry.O = validation.SetOrAppend(entry.O, "executor", validation.VStr(*executor))
	}
	stages.O = validation.SetOrAppend(stages.O, stage, entry)
	st.O = validation.SetOrAppend(st.O, "stages", stages)
	return c.save(st)
}
