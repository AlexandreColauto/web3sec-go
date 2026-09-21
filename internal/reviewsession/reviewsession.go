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
func Start(c *state.Campaign, actor string, artifacts []string) (validation.Value, error) {
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
func End(c *state.Campaign, sessionID, actor string, loc int64) (validation.Value, error) {
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

// appendRow adds a row to the projection and logs its event.
func appendRow(c *state.Campaign, row validation.Value, eventType, sid string) error {
	prior, err := c.State()
	if err != nil {
		return err
	}
	rows := validation.ObjAt(prior, projectionKey).A
	next := make([]validation.Value, 0, len(rows)+1)
	next = append(next, rows...)
	next = append(next, row)
	return saveThenLog(c, withRows(prior, next), eventType, sid, row, prior)
}

// replaceRow replaces the row carrying sid and logs its event.
func replaceRow(c *state.Campaign, row validation.Value, eventType, sid string) error {
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
	return saveThenLog(c, withRows(prior, next), eventType, sid, row, prior)
}

// withRows returns a copy of st whose projection array is rows. The KV list is
// copied because SetOrAppend writes in place, and the caller still needs the
// untouched prior projection to unwind onto.
func withRows(st validation.Value, rows []validation.Value) validation.Value {
	kvs := make([]validation.KV, len(st.O))
	copy(kvs, st.O)
	next := st
	next.O = validation.SetOrAppend(kvs, projectionKey, validation.VArr(rows...))
	return next
}

// saveThenLog is the paired-write + unwind door (internal/planner's
// planWindow law): the projection row and its ledger event land together or
// not at all, and a refused append restores the pre-write projection.
func saveThenLog(c *state.Campaign, next validation.Value, eventType, sid string,
	row, prior validation.Value) error {
	if err := c.SaveState(next); err != nil {
		return err
	}
	if _, err := c.Log(eventType, &sid, &row); err != nil {
		if rerr := c.SaveState(prior); rerr != nil {
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
