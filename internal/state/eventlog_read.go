// eventlog_read.go: the log readers — next_seq, _last_event, Events, and
// EventsMirrorFromLog (doctor's sanctioned, chain-verified rebuild).
package state

import (
	"fmt"
	"websec/internal/validation"
)

// NextSeq is next_seq: the number of log lines.
func (c *Campaign) NextSeq() (int, error) {
	lines, err := c.logLines()
	if err != nil {
		return 0, err
	}
	return len(lines), nil
}

// lastEvent is _last_event: the final log line parsed, or nil.
func (c *Campaign) lastEvent() (validation.Value, bool, error) {
	lines, err := c.logLines()
	if err != nil {
		return validation.VNull(), false, err
	}
	if len(lines) == 0 {
		return validation.VNull(), false, nil
	}
	ev, err := validation.ParseOrdered([]byte(lines[len(lines)-1]))
	if err != nil {
		return validation.VNull(), false, err
	}
	return ev, true, nil
}

// Events reads the full append-only log (the state file mirrors only the
// last 1000 entries; the log is the complete record).
func (c *Campaign) Events() ([]validation.Value, error) {
	lines, err := c.logLines()
	if err != nil {
		return nil, err
	}
	out := make([]validation.Value, 0, len(lines))
	for i, ln := range lines {
		ev, err := validation.ParseOrdered([]byte(ln))
		if err != nil {
			// r12: a bare json error ("invalid character '{' after
			// object key:value pair") forced the operator to hunt the
			// torn line by hand. Name the line; the hint belongs where
			// EVERY reader gets the error, not one call site.
			return nil, fmt.Errorf("events.jsonl line %d does not parse "+
				"(%v) — repair the torn tail and re-run", i+1, err)
		}
		out = append(out, ev)
	}
	return out, nil
}

// EventsMirrorFromLog is the sanctioned rebuild of the state's events
// mirror: parse the log, keep exactly what a fresh Log would have kept
// (tailEvents over the whole chain). doctor owns calling it; verify owns
// NAMING it. The log is the truth — a projection may be rebuilt from it,
// never the reverse.
// A rebuild is only safe if the log is TRUSTWORTHY: the caller hands
// this function's output to campaign_state, so r14's first cut turned
// doctor into the cheapest corruption path in the tool (r15 P0-2: one
// tampered scalar line + one doctor = a state no verb can load, and
// every later doctor "repaired" it again, rc 0). Law now: the log may
// be treated as truth only when it (a) parses fully, (b) is all JSON
// objects carrying the event contract keys, and (c) its hash chain
// verifies event-by-event (VerifyLog's own machinery, whose mirror
// comparison is skipped here because the mirror is exactly what we are
// rebuilding). A damaged log refuses — loudly, with the reason — and
// hand-repair of events.jsonl is explicitly NOT sanctioned: bring the
// campaign to audit with the damage visible instead of laundering it.
func (c *Campaign) EventsMirrorFromLog() ([]validation.Value, error) {
	lines, err := c.logLines()
	if err != nil {
		return nil, err
	}
	var all []validation.Value
	for i, ln := range lines {
		if blankLine(ln) {
			continue
		}
		v, perr := validation.ParseOrdered([]byte(ln))
		if perr != nil {
			return nil, fmt.Errorf("events.jsonl line %d does not parse (%v) "+
				"— the log is damaged; rebuild refused", i+1, perr)
		}
		if v.Kind != validation.Obj {
			return nil, fmt.Errorf("events.jsonl line %d is not a JSON object "+
				"— tampered or corrupt ledger; rebuild refused", i+1)
		}
		seq := validation.ObjAt(v, "seq")
		if seq.Kind != validation.Int || int64(len(all)) != seq.I {
			return nil, fmt.Errorf("events.jsonl line %d breaks seq "+
				"contiguity (wants %d) — the chain has been cut; rebuild "+
				"refused", i+1, len(all))
		}
		if validation.ObjStr(v, "prev_hash") == "" || validation.ObjStr(v, "event_hash") == "" {
			return nil, fmt.Errorf("events.jsonl line %d lacks the hash "+
				"contract keys; rebuild refused", i+1)
		}
		if len(all) > 0 && validation.ObjStr(v, "prev_hash") != validation.ObjStr(all[len(all)-1], "event_hash") {
			return nil, fmt.Errorf("events.jsonl line %d prev_hash does not "+
				"continue the chain — an event was removed or edited; "+
				"rebuild refused", i+1)
		}
		if recomputed := eventHash(v); recomputed != validation.ObjStr(v, "event_hash") {
			// The line is well-formed AND continues the chain but its
			// own content-hash lies: data was edited under a copied
			// hash. Nothing downstream may vouch for it.
			return nil, fmt.Errorf("events.jsonl line %d event_hash does "+
				"not match its content — edited record; rebuild refused", i+1)
		}
		all = append(all, v)
	}
	if len(all) == 0 {
		return []validation.Value{}, nil
	}
	// Re-run the tail rule over the full history: fold every event
	// through tailEvents exactly as the live mirror did.
	var mirror []validation.Value
	for _, e := range all {
		mirror = tailEvents(mirror, e)
	}
	return mirror, nil
}
