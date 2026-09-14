package state

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"websec/internal/validation"
)

// LogVerdict is the verify_log result: a verdict is ALWAYS produced, even
// for a torn log (the audit/CLI path must not crash on the thing it is
// auditing for).
type LogVerdict struct {
	Events          int
	OK              bool
	Problems        []string
	Chained         int
	LegacyUnchained int
	MalformedLines  int
}

// VerifyLog is verify_log: seq contiguity, the hash chain (every
// prev_hash must equal its predecessor's event_hash and every
// event_hash must recompute), and the state tail vs the log suffix.
// Catches a hand-edited, reordered, inserted, or truncated log ANYWHERE.
//
// A line that is not valid JSON (or not an object) is REPORTED, not
// raised; chain/seq/tail checks are skipped past a malformed line.
//
// Deviation: the "(...)" decoder message inside the malformed-line
// problem is the Go json error text, not CPython's json.JSONDecodeError
// msg. The "not valid JSON" / "not a JSON object" framing is exact.
func (c *Campaign) VerifyLog() (LogVerdict, error) {
	events := []validation.Value{}
	problems := []string{}
	malformed := 0

	if raw, err := os.ReadFile(c.EventsPath); err == nil {
		lineNo := 0
		rest := string(raw)
		for len(rest) > 0 {
			idx := len(rest)
			for i := 0; i < len(rest); i++ {
				if rest[i] == '\n' {
					idx = i
					break
				}
			}
			line := rest[:idx]
			if idx < len(rest) {
				rest = rest[idx+1:]
			} else {
				rest = ""
			}
			lineNo++
			if isBlank(line) {
				continue
			}
			ev, err := validation.ParseOrdered([]byte(line))
			if err != nil {
				malformed++
				problems = append(problems,
					fmt.Sprintf("line %d: not valid JSON (%s) — integrity past this point is unverifiable",
						lineNo, err.Error()))
				continue
			}
			if ev.Kind != validation.Obj {
				malformed++
				problems = append(problems,
					fmt.Sprintf("line %d: event is not a JSON object — integrity past this point is unverifiable",
						lineNo))
				continue
			}
			events = append(events, ev)
		}
	}

	if malformed > 0 {
		return LogVerdict{
			Events:          len(events) + malformed,
			OK:              false,
			Problems:        problems[:min(len(problems), 10)],
			Chained:         0,
			LegacyUnchained: 0,
			MalformedLines:  malformed,
		}, nil
	}

	// Seq contiguity (broken contiguity does NOT stop chain checks).
	for i, e := range events {
		seq := objAt(e, "seq")
		if seq.Kind != validation.Int || seq.I != int64(i) {
			problems = append(problems,
				fmt.Sprintf("event %d has seq=%s", i, pyStr(seq)))
			break
		}
	}

	// The chain.
	expectedPrev := GenesisHash
	chained := 0
	for i, e := range events {
		eh := objAt(e, "event_hash")
		if eh.Kind != validation.Str {
			expectedPrev = legacyAnchor(e)
			continue
		}
		if got := objAt(e, "prev_hash").S; got != expectedPrev {
			problems = append(problems,
				fmt.Sprintf("event %d: prev_hash breaks the chain", i))
		}
		if eventHash(e) != eh.S {
			problems = append(problems,
				fmt.Sprintf("event %d: event_hash does not recompute (content edited?)", i))
		}
		expectedPrev = eh.S
		chained++
	}

	// State tail vs log suffix.
	st, err := c.State()
	if err != nil {
		return LogVerdict{}, err
	}
	stTail := objAt(st, "events")
	if stTail.Kind == validation.Arr && len(stTail.A) > 0 {
		// Python events[-len(st_tail):] with a longer tail is [] —
		// a mismatch, never an out-of-range access.
		var want []validation.Value
		if len(stTail.A) <= len(events) {
			want = events[len(events)-len(stTail.A):]
		}
		if !arraysEq(stTail.A, want) {
			problems = append(problems,
				"state event tail does not match the log "+
					"suffix — the ledger is the truth; run `webv2 doctor` "+
					"on this campaign to rebuild the mirror from it")
		}
	}

	// r12: waivers.jsonl is a PROJECTION like state.events — Waive()
	// writes the row AND logs completion.waived. Deleting the file left
	// `waive` records outside every integrity check ("recorded
	// dispositions, never silent skips" was itself silently skippable).
	// One law now: the waiver file and the ledger's waived events must
	// agree, row for row, per (stage, subject).
	wp := filepath.Join(c.Dir, "waivers.jsonl")
	wrows, werr, wline := readWaiverRowsR12(wp)
	if werr != nil {
		// r13: same line-attribution law the events log got — a bare
		// "unexpected EOF" makes the operator diff the file by eye.
		where := ""
		if wline > 0 {
			where = fmt.Sprintf(" line %d", wline)
		}
		problems = append(problems,
			fmt.Sprintf("waivers.jsonl%s: unreadable (%v) — recorded "+
				"dispositions cannot be trusted", where, werr))
	} else {
		evWaived := map[[2]string]int{}
		for _, e := range events {
			if objAt(e, "type").Kind != validation.Str ||
				objAt(e, "type").S != "completion.waived" {
				continue
			}
			key := [2]string{objStr(e, "ref"),
				objStr(objAt(e, "data"), "subject")}
			evWaived[key]++
		}
		rowWaived := map[[2]string]int{}
		for _, w := range wrows {
			key := [2]string{objStr(w, "stage"), objStr(w, "subject")}
			rowWaived[key]++
		}
		for key, n := range rowWaived {
			if evWaived[key] < n {
				problems = append(problems, fmt.Sprintf(
					"waivers.jsonl: %s/%s recorded %d time(s), the ledger "+
						"%d — a waiver without its event", key[0], key[1],
					n, evWaived[key]))
			}
		}
		for key, n := range evWaived {
			if rowWaived[key] < n {
				problems = append(problems, fmt.Sprintf(
					"waivers.jsonl: the ledger holds %d completion.waived "+
						"event(s) for %s/%s, the file %d — waived rows were "+
						"deleted or never written", n, key[0], key[1],
					rowWaived[key]))
			}
		}
	}
	return LogVerdict{
		Events:          len(events),
		OK:              len(problems) == 0,
		Problems:        problems[:min(len(problems), 10)],
		Chained:         chained,
		LegacyUnchained: len(events) - chained,
		MalformedLines:  0,
	}, nil
}

// readWaiverRowsR12 reads waivers.jsonl (missing file = nil, nil): the
// same one-object-per-line framing, parsed with the ledger's decoder.
func readWaiverRowsR12(path string) ([]validation.Value, error, int) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil, 0
	}
	if err != nil {
		return nil, err, 0
	}
	var out []validation.Value
	for i, ln := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		v, perr := validation.ParseOrdered([]byte(ln))
		if perr != nil {
			return nil, perr, i + 1
		}
		out = append(out, v)
	}
	return out, nil, 0
}

// pyStr is Python's str() over a JSON value, for problem messages:
// None/True/False for null/bools, bare decimals, the string itself (no
// quotes), and repr-style rendering for containers.
func pyStr(v validation.Value) string {
	switch v.Kind {
	case validation.Null:
		return "None"
	case validation.Bool:
		if v.B {
			return "True"
		}
		return "False"
	case validation.Int:
		return validation.IntText(v)
	case validation.Flt:
		return validation.PythonFloat(v.F)
	case validation.Str:
		return v.S
	default:
		return validation.PyRepr(v)
	}
}

func isBlank(line string) bool {
	for _, r := range line {
		if r != ' ' && r != '\t' && r != '\r' && r != '\n' && r != '\v' && r != '\f' {
			return false
		}
	}
	return true
}

// arraysEq is Python list equality (deep, element-wise).
func arraysEq(a, b []validation.Value) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !valueEq(a[i], b[i]) {
			return false
		}
	}
	return true
}

// valueEq is Python dict/list equality: deep and key-ORDER independent
// (json dict == is a set of pairs). Canonical comparison achieves that.
func valueEq(a, b validation.Value) bool {
	return validation.CanonSpaced(a) == validation.CanonSpaced(b)
}
