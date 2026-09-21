// Package reviewsession records operator review sessions as ledger events
// (framework-plan-v1.6 Part 1): start, end, artifacts covered, LOC. The
// ~60-minute / 400-line budget is a soft target whose effect on catch rate is
// correlatable only if the sessions are measured, so both ends of a session
// are events, never prose.
package reviewsession

import (
	"fmt"

	"websec/internal/state"
	"websec/internal/validation"
)

// projectionKey is the campaign-state key holding the session rows.
const projectionKey = "review_sessions"

// Start opens a session and records review_session.started. One session may be
// open at a time: two concurrent sessions are two contexts, and the whole
// point of the measurement is one operator's attention.
//
// r14 (processlock.go's law): the load-modify-write window of the
// review_sessions projection holds the campaign lock END TO END — the
// one-open-session CHECK included, not just the write. Locking only
// SaveState still lost updates when the State() load happened outside
// (two `review-session start|end` processes racing a `run` that writes
// campaign_state at every stage: both exit 0, one row vanishes). The
// inner SaveState/Log re-enter the lock by depth, exactly as
// floors.SetFloorPolicy relies on.
func Start(c *state.Campaign, actor string, artifacts []string) (validation.Value, error) {
	if err := c.LockProcess(); err != nil {
		return validation.VNull(), err
	}
	defer c.UnlockProcess()
	if _, open := Open(c); open {
		return validation.VNull(), fmt.Errorf("already open: close the current review session first")
	}
	sid := state.NewID("RS", 8)
	row := validation.VObj(
		validation.KV{K: "session_id", V: validation.VStr(sid)},
		validation.KV{K: "actor", V: validation.VStr(orDefault(actor, "operator"))},
		validation.KV{K: "started_at", V: validation.VStr(state.NowIso())},
		validation.KV{K: "artifacts_covered", V: validation.VArr(strValues(artifacts)...)},
		validation.KV{K: "open", V: validation.VBool(true)},
	)
	if err := appendRow(c, row, "review_session.started", sid); err != nil {
		return validation.VNull(), err
	}
	return row, nil
}

// End closes an open session, recording LOC and the artifacts covered.
// The same r14 window as Start: resolve the open row and replace it under
// one lock hold, so a sibling writer cannot land between the two.
func End(c *state.Campaign, sessionID, actor string, loc int64) (validation.Value, error) {
	if err := c.LockProcess(); err != nil {
		return validation.VNull(), err
	}
	defer c.UnlockProcess()
	row, ok := Open(c)
	if !ok || validation.ObjStr(row, "session_id") != sessionID {
		return validation.VNull(), fmt.Errorf("no open review session %s", sessionID)
	}
	if loc < 0 {
		return validation.VNull(), fmt.Errorf("--loc must be >= 0")
	}
	row.O = validation.SetOrAppend(row.O, "open", validation.VBool(false))
	row.O = validation.SetOrAppend(row.O, "ended_at", validation.VStr(state.NowIso()))
	row.O = validation.SetOrAppend(row.O, "loc", validation.VInt(loc))
	row.O = validation.SetOrAppend(row.O, "closed_by", validation.VStr(orDefault(actor, "operator")))
	if err := replaceRow(c, row, "review_session.ended", sessionID); err != nil {
		return validation.VNull(), err
	}
	return row, nil
}

// Open returns the currently open session row, if any.
func Open(c *state.Campaign) (validation.Value, bool) {
	st, err := c.State()
	if err != nil {
		return validation.VNull(), false
	}
	for _, row := range validation.ObjAt(st, projectionKey).A {
		if validation.ObjAt(row, "open").Kind == validation.Bool &&
			validation.ObjAt(row, "open").B {
			return row, true
		}
	}
	return validation.VNull(), false
}

// appendRow adds a row to the projection and logs its event. Callers hold
// the campaign lock (Start/End); the r17 snapshot is taken BEFORE the first
// write so a refused append can put the exact pre-write bytes back.
func appendRow(c *state.Campaign, row validation.Value, eventType, sid string) error {
	priorRaw, hadRaw := c.RawState()
	prior, err := c.State()
	if err != nil {
		return err
	}
	rows := validation.ObjAt(prior, projectionKey).A
	next := make([]validation.Value, 0, len(rows)+1)
	next = append(next, rows...)
	next = append(next, row)
	return saveThenLog(c, withRows(prior, next), eventType, sid, row, priorRaw, hadRaw)
}

// replaceRow replaces the row carrying sid and logs its event, under the
// same lock and with the same pre-write snapshot as appendRow.
func replaceRow(c *state.Campaign, row validation.Value, eventType, sid string) error {
	priorRaw, hadRaw := c.RawState()
	prior, err := c.State()
	if err != nil {
		return err
	}
	rows := validation.ObjAt(prior, projectionKey).A
	next := make([]validation.Value, 0, len(rows))
	for _, r := range rows {
		if validation.ObjStr(r, "session_id") == sid {
			r = row
		}
		next = append(next, r)
	}
	return saveThenLog(c, withRows(prior, next), eventType, sid, row, priorRaw, hadRaw)
}

// withRows returns a copy of st whose projection array is rows. The KV list is
// copied because SetOrAppend writes in place (and SaveState rewrites
// updated_at in place), so the caller's parsed projection is left untouched.
func withRows(st validation.Value, rows []validation.Value) validation.Value {
	kvs := make([]validation.KV, len(st.O))
	copy(kvs, st.O)
	next := st
	next.O = validation.SetOrAppend(kvs, projectionKey, validation.VArr(rows...))
	return next
}

// saveThenLog is the paired-write + unwind door (internal/planner's
// planWindow law, r16/r17): the projection row and its ledger event land
// together or not at all, and a refused append restores the exact pre-write
// BYTES (state.RawState/UnwindState) — a re-save of the parsed prior value
// would bump updated_at and re-validate, i.e. it would not be the state the
// operator had.
func saveThenLog(c *state.Campaign, next validation.Value, eventType, sid string,
	row validation.Value, priorRaw []byte, hadRaw bool) error {
	if err := c.SaveState(next); err != nil {
		return err
	}
	if _, err := c.Log(eventType, &sid, &row); err != nil {
		if rerr := c.UnwindState(priorRaw, hadRaw); rerr != nil {
			return fmt.Errorf("%w (UNWIND ALSO FAILED: %v — the review_sessions "+
				"projection holds post-write rows with no event; repair by hand "+
				"before continuing)", err, rerr)
		}
		return err
	}
	return nil
}

// orDefault is the empty-string default every record row uses (a local copy:
// the four-line helper is deliberately not exported across packages).
func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// strValues is []string -> []validation.Value, local by the same rule.
func strValues(items []string) []validation.Value {
	out := make([]validation.Value, 0, len(items))
	for _, it := range items {
		out = append(out, validation.VStr(it))
	}
	return out
}
