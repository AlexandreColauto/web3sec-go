package state

import (
	"os"
	"strings"

	"fmt"
	"websec/internal/validation"
)

// logLines is _log_lines: the raw non-empty log lines, one read.
func (c *Campaign) logLines() ([]string, error) {
	raw, err := os.ReadFile(c.EventsPath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, ln := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(ln) != "" {
			out = append(out, ln)
		}
	}
	return out, nil
}

// Log appends one hash-chained event to the jsonl log and mirrors it into
// state. The on-disk line is ASCII (ensure_ascii=True via the spaced
// canonical form) so no character in untrusted payloads can break the
// JSONL framing.
func (c *Campaign) Log(eventType string, ref *string, data *validation.Value) (validation.Value, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// r13: the whole read-tail -> append -> mirror-save window must be
	// atomic against OTHER PROCESSES, not just other goroutines — two
	// concurrent loggers used to mint duplicate seqs and drop one
	// event while both exited 0. The lock spans the full window; the
	// inner save() re-enters by depth (processlock.go).
	if err := c.plock.lock(c.lockPath(), c.CampaignID); err != nil {
		return validation.VNull(), err
	}
	defer c.plock.unlock()

	lines, err := c.logLines()
	if err != nil {
		return validation.VNull(), err
	}
	rewoundDropped := 0
	// r12 + r34: writing into a ledger that holds NO RECORDS is genesis —
	// the previous ledger (and whatever the state mirror still carries of
	// it) is gone. The first append must rewind the mirror to the new
	// ledger's own tail; appending onto a stale mirror stranded
	// `verify`/audit's "state event tail" check forever — a heal that
	// could not fully heal. Rewinding before the append keeps the mirror
	// honest from the first event of the new chain.
	//
	// r34 (F2): "holds no records" — NOT "the file is absent" — is the
	// test. The old os.Stat probe healed `rm events.jsonl` and let the
	// SAME loss spelled as a zero-byte file (`: > events.jsonl`, a bad
	// restore, a crash that kept the inode) take the opposite branch: one
	// event appended over the empty log, SUCCESS reported, the mirror left
	// holding the dead tail, `verify` red forever on "state event tail is
	// LONGER than the log", and no ledger_rewound anywhere — so doctor's
	// repair laundered the loss with no record of it. Truncation-to-empty
	// is the ordinary shell shape.
	//
	// A file holding only a newline, or only whitespace, has no records
	// either (logLines and verify both skip blank lines) and heals
	// identically — an explicit decision, not an accident. A TORN tail is
	// NOT genesis: it is refused below with the line attributed, because
	// its last record exists but is incomplete.
	if len(lines) == 0 {
		// r34: read the mirror only to learn what the dead ledger left
		// behind. The rewind itself lands WITH the new event (below), so
		// an append that is refused after this point cannot leave the
		// projection emptied with no ledger_rewound anywhere — the mirror
		// would then be the only record those events ever existed, and
		// the loss would be invisible (verify skips an empty tail).
		st, gerr := c.State()
		if gerr != nil {
			return validation.VNull(), gerr
		}
		rewoundDropped = len(objAt(st, "events").A)
	}
	var last validation.Value
	hasLast := false
	if len(lines) > 0 {
		last, err = validation.ParseOrdered([]byte(lines[len(lines)-1]))
		if err != nil {
			// r15: the last line failing is the whole story a bare
			// "EOF" hides — say which file, which line, and what broke.
			return validation.VNull(), fmt.Errorf(
				"events.jsonl line %d (the chain's head) does not parse "+
					"(%v) — the ledger is damaged; verify/audit name the "+
					"repair path, do not hand-edit this file", len(lines), err)
		}
		hasLast = true
	}
	// r34 (F2), the neighbouring shape: a ledger that still PARSES is not
	// automatically writable. Cutting the log to a prefix of its own bytes
	// at a record boundary (`head -n 1`, a partial restore) leaves a chain
	// that still verifies, so nothing objects until the projection
	// disagrees — and that projection is then the ONLY surviving copy of
	// the events that were cut. The pre-r34 path appended anyway, printed
	// success, and stranded verify on "state event tail is LONGER than the
	// log" with no ledger_rewound anywhere. Adopting that loss is a
	// deliberate operator act, not a side effect of the next write: only
	// `webv2 doctor` may rebuild the mirror FROM the log (it reports the
	// drop and journals it in doctor.json). Refuse here, name the counts,
	// and name the sanctioned repair.
	if hasLast {
		st, serr := c.State()
		if serr != nil {
			return validation.VNull(), serr
		}
		if mirror := objAt(st, "events"); mirror.Kind == validation.Arr &&
			len(mirror.A) > len(lines) {
			return validation.VNull(), fmt.Errorf(
				"events.jsonl holds %d event(s) but the state projection "+
					"mirrors %d — %d mirrored event(s) are GONE from the "+
					"ledger tail, and the projection is the only surviving "+
					"copy of them; the write is refused rather than "+
					"adopting the loss. Copy the campaign dir for evidence, "+
					"then run `webv2 doctor` (it rebuilds the mirror from "+
					"the log and reports exactly what it drops)",
				len(lines), len(mirror.A), len(mirror.A)-len(lines))
		}
	}
	prevHash := GenesisHash
	if hasLast {
		if eh := objAt(last, "event_hash"); eh.Kind == validation.Str {
			prevHash = eh.S
		} else {
			prevHash = legacyAnchor(last)
		}
	}
	refV := validation.VNull()
	if ref != nil {
		refV = validation.VStr(*ref)
	}
	dataV := validation.VObj()
	if data != nil {
		dataV = *data
	}
	if rewoundDropped > 0 {
		// r13: the rewind must be DISCLOSED inside the new chain's first
		// event (hashed, so it cannot be quietly rewritten later):
		// deleting events.jsonl plus any log-writing command was a
		// silent full-history wipe; now the ledger itself says how many
		// mirrored events it lost and when.
		if dataV.Kind != validation.Obj {
			dataV = validation.VObj()
		}
		dataV.O = validation.SetOrAppend(dataV.O, "ledger_rewound",
			validation.VObj(
				kv("dropped_tail", validation.VInt(int64(rewoundDropped))),
				kv("at", validation.VStr(nowIso())),
			))
	}
	event := validation.VObj(
		kv("seq", validation.VInt(int64(len(lines)))),
		kv("at", validation.VStr(nowIso())),
		kv("type", validation.VStr(eventType)),
		kv("ref", refV),
		kv("data", dataV),
		kv("prev_hash", validation.VStr(prevHash)),
	)
	evKvs := append(append([]validation.KV{}, event.O...),
		kv("event_hash", validation.VStr(eventHash(event))))
	event = validation.VObj(evKvs...)

	if err := validation.AppendJsonlAscii(c.EventsPath, validation.CanonSpaced(event)); err != nil {
		return validation.VNull(), err
	}
	st, err := c.State()
	if err != nil {
		return validation.VNull(), err
	}
	existing := objAt(st, "events")
	var have []validation.Value
	if existing.Kind == validation.Arr {
		have = existing.A
	}
	if rewoundDropped > 0 {
		// r34: genesis — the mirror's stale tail is dropped HERE, in the
		// same write that lands the new event, never in a save of its own
		// (a refused append must not empty the projection).
		have = nil
	}
	st.O = validation.SetOrAppend(st.O, "events", validation.Value{Kind: validation.Arr,
		A: tailEvents(have, event)})
	if err := c.save(st); err != nil {
		return validation.VNull(), err
	}
	return event, nil
}

// tailEvents is the state-mirror rule: the state file keeps the last
// 1000 events (prior 999 + the new one); the log keeps everything.
func tailEvents(have []validation.Value, add validation.Value) []validation.Value {
	if len(have) > 999 {
		return append(have[len(have)-999:], add)
	}
	return append(have, add)
}

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

func objAt(v validation.Value, key string) validation.Value {
	if v.Kind != validation.Obj {
		return validation.VNull()
	}
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V
		}
	}
	return validation.VNull()
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
		if strings.TrimSpace(ln) == "" {
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
		seq := objAt(v, "seq")
		if seq.Kind != validation.Int || int64(len(all)) != seq.I {
			return nil, fmt.Errorf("events.jsonl line %d breaks seq "+
				"contiguity (wants %d) — the chain has been cut; rebuild "+
				"refused", i+1, len(all))
		}
		if objStr(v, "prev_hash") == "" || objStr(v, "event_hash") == "" {
			return nil, fmt.Errorf("events.jsonl line %d lacks the hash "+
				"contract keys; rebuild refused", i+1)
		}
		if len(all) > 0 && objStr(v, "prev_hash") != objStr(all[len(all)-1], "event_hash") {
			return nil, fmt.Errorf("events.jsonl line %d prev_hash does not "+
				"continue the chain — an event was removed or edited; "+
				"rebuild refused", i+1)
		}
		if recomputed := eventHash(v); recomputed != objStr(v, "event_hash") {
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
