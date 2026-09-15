package state

import (
	"bytes"
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

// LedgerTail is the framing verdict for a ledger's tail — the ONE
// reader-side answer to the write path's own refusal predicate
// (validation.checkJsonlTail, atomicio.go): a NON-EMPTY ledger whose last
// byte is not '\n' cannot be appended to, because the next append would
// merge two records into one unreadable line.
//
// r42c P3, a false certification: every mutating verb refused such a
// ledger forever — "torn write or external edit ... restore the file from
// a snapshot or truncate" — while verify printed {"ok": true, "problems":
// []} exit 0, doctor billed the campaign clean (exit 0, no warning), and
// audit said PASS. The one corruption class the WRITER refuses was
// invisible to all three readers, so verify affirmatively certified a
// state its own writer calls unusable. The readers answer the writer's
// question now.
//
// The byte shape is genuinely AMBIGUOUS, and the verdict says so rather
// than guessing: "a final record present but not newline-terminated" is
// indistinguishable between (a) an in-flight append that lost the
// terminating byte, (b) a torn write that lost only the newline, and (c)
// an external edit that deleted it. All three are the same bytes and all
// three are equally un-appendable, so the reader refuses all three without
// claiming which one happened. What stays GREEN is exact: any ledger whose
// last byte IS '\n' (whatever its last record is, complete or not) and a
// ledger with no bytes at all (or no file) — the framing guard permits the
// first append to both, and genesis is not damage. A tear that cut INTO
// the final record is already reported by the malformed-line problem (the
// RUNBOOK's torn-log walkthrough names that line and nothing else), so it
// is not re-reported as a tail problem: one damage, one attribution — see
// the finalSegmentMalformed gate in VerifyLog.
type LedgerTail struct {
	// Present is "the ledger file exists on disk".
	Present bool
	// Size is the file's byte length.
	Size int64
	// Torn is "Present && Size > 0 && the last byte is not '\n'".
	Torn bool
	// TailBytes counts the bytes after the last '\n' (the whole file when it
	// holds no newline at all, the blank whitespace tail included). It is 0
	// unless Torn.
	TailBytes int
}

// ledgerTail is THE framing predicate: one pure function of a ledger's
// bytes, so VerifyLog (which already holds them) and doctor
// (LedgerTailFraming) answer from the same code and cannot drift apart.
// The test is the writer's own: the last byte. It is stated in bytes, not
// in lines, because a ledger of "   " is genesis by CONTENT and still
// un-appendable by FRAMING — the write path refuses it, so a reader may
// not call it health.
func ledgerTail(raw []byte) LedgerTail {
	lt := LedgerTail{Present: true, Size: int64(len(raw))}
	if len(raw) == 0 || raw[len(raw)-1] == '\n' {
		return lt
	}
	lt.Torn = true
	if i := bytes.LastIndexByte(raw, '\n'); i >= 0 {
		lt.TailBytes = len(raw) - i - 1
	} else {
		lt.TailBytes = len(raw)
	}
	return lt
}

// LedgerTailFraming is ledgerTail over the campaign's events.jsonl. A
// missing ledger is (Present=false, Torn=false) — the framing guard allows
// the first append to a log that does not exist yet — and a read failure is
// returned as an error so the caller must DISCLOSE it: a reader that could
// not read the ledger has no evidence about it and may not certify it.
func (c *Campaign) LedgerTailFraming() (LedgerTail, error) {
	raw, err := os.ReadFile(c.EventsPath)
	if os.IsNotExist(err) {
		return LedgerTail{}, nil
	}
	if err != nil {
		return LedgerTail{}, err
	}
	return ledgerTail(raw), nil
}

// TornTailProblem is THE problem sentence for a torn ledger tail: one
// definition, three surfaces — verify reports it among its problems, audit
// surfaces verify's problems verbatim (the event_log section), and doctor
// discloses it in log_validation instead of certifying the campaign clean.
// It names the file and the SHAPE (a final record not terminated by a
// newline), the consequence (every mutating verb refuses the file), and the
// only repair (cut back to the last complete record). It does NOT repeat
// the writer's guess that the record is "incomplete": the bytes cannot say
// that (the reader sees a parseable record just as often), so neither does
// this sentence — it says what is observable instead.
func TornTailProblem(file string, tailBytes int) string {
	return fmt.Sprintf("%s: the ledger does not end in a newline — %d "+
		"trailing byte(s) are unterminated, so its final record is not "+
		"terminated by one (torn write or external edit; the bytes cannot "+
		"say which). The framing guard every mutating verb runs refuses to "+
		"append to this file, so the campaign cannot be written to until "+
		"the tail is cut back to the last complete record; nothing here "+
		"may certify a ledger its own writer calls unusable", file, tailBytes)
}

// VerifyLog is verify_log: seq contiguity, the hash chain (every
// prev_hash must equal its predecessor's event_hash and every
// event_hash must recompute), and the state tail vs the log's mirror
// rule — the last min(E, mirrorCap) events, CONTENT AND LENGTH (r38
// P2-4: a mirror that kept only the log's last 3 events matched its own
// tail window and was certified, so the 997 dropped from its head were
// invisible; the length is part of the invariant).
// Catches a hand-edited, reordered, inserted, or truncated log ANYWHERE
// — with one boundary r16 spells out: the chain is an UNKEYED sha256
// over the event's own fields, so it detects ACCIDENTAL and casual
// damage, not a determined rewriter: anyone who can edit events.jsonl
// can recompute the whole chain and produce a log that verifies green
// over fabricated events. Against that adversary the chain is FORMAT,
// not integrity; the real guard is filesystem custody of the campaign
// dir (and out-of-band copies if the campaign must survive its own
// host). doctor's mirror rebuild rides on that honesty: it trusts a
// chain-valid ledger, because a tamperer who recomputed the chain could
// also have written the state directly — the rebuild adds no new
// exposure, but it also cannot detect what it normalizes. Every verify
// red therefore says "repair via doctor", and doctor DISCLOSES the
// content delta it adopts (counts + first divergences), never silently.
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
	tail := LedgerTail{}
	// finalSegmentMalformed records that the unterminated final segment was
	// ALREADY reported as a malformed line: the same damage must not be
	// counted twice, and the RUNBOOK's torn-log walkthrough shows that tear
	// as the line problem alone.
	finalSegmentMalformed := false
	// ledgerReadable gates the mirror rule below: comparing a projection
	// against a ledger that was never read is not a check, it is a guess.
	ledgerReadable := true

	raw, readErr := os.ReadFile(c.EventsPath)
	switch {
	case readErr == nil:
		// r42c P3: the tail framing is judged from the same bytes the
		// records are parsed from.
		tail = ledgerTail(raw)
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
			// unterminated: this segment runs to the end of the file with
			// no newline after it — the shape checkJsonlTail refuses to
			// append behind.
			unterminated := idx >= len(rest)
			if idx < len(rest) {
				rest = rest[idx+1:]
			} else {
				rest = ""
			}
			lineNo++
			// r38 P2-1: the ONE framing predicate, shared with logLines /
			// doctor (blankLine in eventlog.go). Unicode whitespace alone
			// is NOT blank — it is a record this decoder cannot parse,
			// reported below, never skipped.
			if blankLine(line) {
				// A blank unterminated tail is still an unterminated tail
				// (the writer refuses "   " exactly as it refuses a torn
				// record): it is NOT marked malformed here, so the tail
				// problem below reports it.
				continue
			}
			ev, err := validation.ParseOrdered([]byte(line))
			if err != nil {
				malformed++
				if unterminated {
					finalSegmentMalformed = true
				}
				problems = append(problems,
					fmt.Sprintf("line %d: not valid JSON (%s) — integrity past this point is unverifiable",
						lineNo, err.Error()))
				continue
			}
			if ev.Kind != validation.Obj {
				malformed++
				if unterminated {
					finalSegmentMalformed = true
				}
				problems = append(problems,
					fmt.Sprintf("line %d: event is not a JSON object — integrity past this point is unverifiable",
						lineNo))
				continue
			}
			events = append(events, ev)
		}
	case os.IsNotExist(readErr):
		// No ledger at all is genesis, not damage: the framing guard
		// permits the first append to a file that does not exist and the
		// zero-event campaign is honestly green (r39b's genesis case).
	default:
		// r42c P3: an unreadable ledger used to fall through as
		// "zero events" and be certified green whenever the mirror was
		// empty. A reader that could not read the file has no evidence
		// about it, so it says so and judges nothing else.
		ledgerReadable = false
		problems = append(problems, fmt.Sprintf(
			"events.jsonl: unreadable (%v) — the ledger was never read, so "+
				"its records, chain, tail and mirror cannot be judged",
			readErr))
	}

	// r42c P3: the framing law, judged BEFORE the malformed early return so
	// a torn tail is never hidden behind an unrelated malformed line, and
	// PREPENDED so the 10-problem cap cannot drop the one corruption class
	// the write path itself refuses.
	if tail.Torn && !finalSegmentMalformed {
		problems = append([]string{TornTailProblem("events.jsonl",
			tail.TailBytes)}, problems...)
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

	if !ledgerReadable {
		// Nothing past this point is knowable: there is no record list to
		// check the chain against and no log to compare the mirror to.
		return LogVerdict{
			Events:   0,
			OK:       false,
			Problems: problems[:min(len(problems), 10)],
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
	if stTail.Kind == validation.Arr {
		// The mirror rule (tailEvents) keeps exactly min(E, mirrorCap)
		// events, so length is part of the invariant — comparing CONTENT
		// against the tail window of the mirror's own length certified
		// ANY suffix. A mirror holding only the last 3 events of a
		// 1006-event log matched its own window perfectly and passed, so
		// verify/audit certified a projection that had lost the 997
		// events at its head.
		wantLen := len(events)
		if wantLen > mirrorCap {
			wantLen = mirrorCap
		}
		// r39b P3: the invariant is judged for the EMPTY projection too.
		// The old gate (len(stTail.A) > 0) meant a state events array of
		// [] under a live ledger certified ok:true — a projection that
		// lost its WHOLE head. The RUNBOOK calls a projection with a
		// hole in its head "not health"; an empty mirror is the extreme
		// of exactly that shape, so verify says so. The zero-event
		// campaign stays honest: with no events in the ledger at all an
		// empty mirror IS the rule's output (min(0, mirrorCap) = 0).
		if len(stTail.A) == 0 && len(events) > 0 {
			problems = append(problems, fmt.Sprintf(
				"state events projection is EMPTY under a %d-event log — "+
					"the projection rule keeps %d for this log, so a "+
					"projection that lost its whole head is not health "+
					"(its %d mirrored event(s) are all gone). Nothing here "+
					"may certify that projection; run `webv2 doctor` to "+
					"rebuild the mirror from the log (it reports the delta "+
					"it adopts)",
				len(events), wantLen, wantLen))
		} else if len(stTail.A) > 0 {
			// Python events[-len(st_tail):] with a longer tail is [] —
			// a mismatch, never an out-of-range access.
			var want []validation.Value
			if len(stTail.A) <= len(events) {
				want = events[len(events)-len(stTail.A):]
			}
			if !arraysEq(stTail.A, want) {
				// r17: the repair route must not be an unwitting laundering
				// step. A LONGER projection tail than the log has is the
				// truncation signature: doctor trusts the log, so running it
				// ADOPTS the shorter history. Say so at the moment of power.
				msg := "state event tail does not match the log " +
					"suffix — the ledger is the truth; run `webv2 doctor` " +
					"on this campaign to rebuild the mirror from it"
				if len(stTail.A) > len(events) {
					msg = fmt.Sprintf("state event tail is LONGER than the log "+
						"(%d projected vs %d logged) — events are GONE from "+
						"the tail; a truncated log still verifies its chain, "+
						"and doctor rebuilds TO it, adopting the loss. If you "+
						"did not cut it, treat the campaign dir as tampered "+
						"before repairing (investigate, copy the dir); "+
						"`webv2 doctor` then reports exactly what it erases",
						len(stTail.A), len(events))
				}
				problems = append(problems, msg)
			} else if len(stTail.A) != wantLen {
				problems = append(problems, fmt.Sprintf(
					"state event tail holds %d event(s) where the projection "+
						"rule keeps %d for a %d-event log — the content matches "+
						"the log suffix, but the mirror is not the rule's window: "+
						"its HEAD is missing (mirrored events were dropped from "+
						"the front, and the %d survivor(s) are all that is left "+
						"of the projection) or it holds rows beyond the cap. "+
						"Nothing here may certify that projection; run `webv2 "+
						"doctor` to rebuild the mirror from the log (it reports "+
						"the delta it adopts)",
					len(stTail.A), wantLen, len(events), len(stTail.A)))
			}
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
//
// r40c P2-3: this reader and completion.Waivers answer the SAME frame for
// the same bytes — "\n"-delimited physical lines, blankness decided by
// BlankLine. They used to disagree: this one split on "\n" while the
// completion reader used CPython's str.splitlines(), whose boundary set
// includes U+0085/U+2028/U+2029. A waiver reason carrying one of those runes
// raw (json.dumps(ensure_ascii=False) leaves them raw) was ONE green row
// here and TWO fragments there — verify certified a disposition the proof
// never consulted. The writer escapes those three codepoints now
// (completion/pyjson.go), and completion.Waivers frames on the physical
// line, so a legacy raw row reads identically on both sides.
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
		// r38 P2-1: the shared framing predicate — a U+00A0-only waiver
		// line is a parse error below, never silently skipped. Named
		// explicitly as the EXPORTED BlankLine so the pairing with
		// completion.Waivers is visible at the call site.
		if BlankLine(ln) {
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
