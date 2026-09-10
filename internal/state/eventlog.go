package state

import (
	"os"
	"strings"

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

	lines, err := c.logLines()
	if err != nil {
		return validation.VNull(), err
	}
	var last validation.Value
	hasLast := false
	if len(lines) > 0 {
		last, err = validation.ParseOrdered([]byte(lines[len(lines)-1]))
		if err != nil {
			return validation.VNull(), err
		}
		hasLast = true
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
	for _, ln := range lines {
		ev, err := validation.ParseOrdered([]byte(ln))
		if err != nil {
			return nil, err
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
