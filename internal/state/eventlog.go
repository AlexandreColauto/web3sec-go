package state

import (
	"os"
	"strings"

	"fmt"
	"websec/internal/validation"
)

// blankLine is THE blank-line predicate for the JSONL framing: the one
// answer every consumer of a framed file gives — logLines (the heal
// decision), VerifyLog, EventsMirrorFromLog (doctor's rebuild) and
// readWaiverRowsR12. Before r38 there were two copies that DISAGREED:
// logLines/doctor trimmed with strings.TrimSpace (Unicode IsSpace, which
// strips U+00A0 and friends) while verify's isBlank accepted only ASCII.
//
// The semantics are an explicit decision, not an accident: blank means the
// ASCII framing whitespace this writer may ever emit (' ', '\t', '\r',
// '\n', '\v', '\f') and nothing else. A line made of UNICODE whitespace
// alone — U+00A0 is the ordinary paste/`\u00a0` shape — is a RECORD, not a
// blank: neither validation.ParseOrdered (Go encoding/json, ASCII
// whitespace only) nor the CPython json this port mirrors can parse it, so
// verify/audit must report it and doctor must refuse to rebuild over it.
// The fail-closed law decides the direction: a line verify cannot parse is
// not something the heal may append over. Under the old split a ledger
// holding ONLY a U+00A0 line was "genesis" to the write path — it appended
// a success line over it, and the resulting ledger was malformed forever
// (verify red, chained:0, audit rc 1) while doctor silently skipped the
// same line and certified the mirror.
//
// Byte iteration, not runes: every byte of a multi-byte rune is >= 0x80,
// so any non-ASCII byte answers "not blank" without decoding.
func blankLine(line string) bool { return BlankLine(line) }

// BlankLine is the exported form of THE blank-line predicate, so the other
// JSONL readers in the tree (costs, learning) answer the same way instead
// of carrying their own strings.TrimSpace copy — r38's finding was exactly
// a predicate that agreed with itself in one package and not in another.
func BlankLine(line string) bool {
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case ' ', '\t', '\r', '\n', '\v', '\f':
		default:
			return false
		}
	}
	return true
}

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
		if !blankLine(ln) {
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
	lb := &logBuilder{c: c, lines: lines}
	if err := lb.logProbeGenesis(); err != nil {
		return validation.VNull(), err
	}
	if err := lb.logParseChainHead(); err != nil {
		return validation.VNull(), err
	}
	if err := lb.logClassifyMirrorLag(); err != nil {
		return validation.VNull(), err
	}
	prevHash := lb.logPrevHash()
	refV := validation.VNull()
	if ref != nil {
		refV = validation.VStr(*ref)
	}
	lb.dataV = validation.VObj()
	if data != nil {
		lb.dataV = *data
	}
	lb.logDiscloseRewind()
	lb.logDiscloseLagHeal()
	event := lb.logBuildEvent(eventType, refV, prevHash)
	return lb.logCommit(event)
}

// logBuilder carries the shared context of one Log append across the
// section helpers split out of Log: the genesis probe, the chain-head
// parse, the mirror-lag classification, the hashed disclosures and the
// final append-and-mirror commit.
type logBuilder struct {
	c              *Campaign
	lines          []string
	rewoundDropped int
	rewoundCapped  bool
	last           validation.Value
	hasLast        bool
	lagEvents      []validation.Value
	lagAdopted     int
	dataV          validation.Value
}

// logProbeGenesis is Log's genesis branch.
//
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
// A file holding only a newline, or only ASCII whitespace, has no
// records either (logLines and verify both answer blankLine) and heals
// identically — an explicit decision, not an accident. r38 P2-1: ONLY
// that ASCII set. A line of Unicode whitespace (U+00A0 alone) is a
// record this decoder cannot parse, so it is NOT genesis: it falls
// through to the parse below and the write is REFUSED, naming the line.
// Appending over it (the pre-r38 split) produced a malformed-forever
// ledger that verify/audit red-line and doctor's rebuild must refuse. A
// TORN tail is NOT genesis either: it is refused below with the line
// attributed, because its last record exists but is incomplete.
func (lb *logBuilder) logProbeGenesis() error {
	if len(lb.lines) == 0 {
		// r34: read the mirror only to learn what the dead ledger left
		// behind. The rewind itself lands WITH the new event (below), so
		// an append that is refused after this point cannot leave the
		// projection emptied with no ledger_rewound anywhere — the mirror
		// would then be the only record those events ever existed, and
		// the loss would be invisible (verify skips an empty tail).
		st, gerr := lb.c.State()
		if gerr != nil {
			return gerr
		}
		lb.rewoundDropped = len(validation.ObjAt(st, "events").A)
		// rewoundCapped marks the case where the mirror was AT its cap, so
		// the count below is a lower bound and not the loss (r38 P2-3).
		//
		// r38 P2-3: tailEvents keeps the last mirrorCap events, so a
		// mirror that has EVER been truncated holds EXACTLY mirrorCap
		// events — 1000 mirrored events stand equally for a 1000-event
		// campaign and a 100 000-event one. Below the cap the count is
		// exact (a projection that never reached the cap never dropped
		// anything); at the cap the true total is unknowable from here and
		// the disclosure below says so instead of stating the count as the
		// loss.
		lb.rewoundCapped = lb.rewoundDropped >= mirrorCap
	}
	return nil
}

// logParseChainHead is Log's chain-head read: the ledger's last line
// must parse, or the append is refused with the line named.
func (lb *logBuilder) logParseChainHead() error {
	if len(lb.lines) > 0 {
		last, err := validation.ParseOrdered([]byte(lb.lines[len(lb.lines)-1]))
		if err != nil {
			// r15: the last line failing is the whole story a bare
			// "EOF" hides — say which file, which line, and what broke.
			return fmt.Errorf(
				"events.jsonl line %d (the chain's head) does not parse "+
					"(%v) — the ledger is damaged; verify/audit name the "+
					"repair path, do not hand-edit this file", len(lb.lines), err)
		}
		lb.last = last
		lb.hasLast = true
	}
	return nil
}

// logClassifyMirrorLag is Log's mirror-lag classification.
//
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
// r37b (F4): the crash window was closed in ONE direction only. r13
// made append->mirror-save atomic against other processes; r34 (the
// refusal below) covers a mirror LONGER than the log. The remaining
// direction is a mirror SHORTER than the log — the crash (or SIGKILL)
// between the log append and the mirror save leaves the projection one
// or more events behind, and the pre-r37b write appended onto the
// STALE mirror: the new event landed at the projection's tail while
// the ledger events it had never mirrored stayed unmirrored — a HOLE
// in the middle of the projection ([0,1,2] rolled back to [0,1], the
// next write mirrors [0,1,3]), baked in behind a rc=0 success line and
// found only later by verify's generic tail mismatch. Two shapes live
// in that gap and they take different branches, judged against the
// PARSED ledger (absence of proof here is a refusal, never an
// adoption — classifyLaggingMirror below):
//
//   - a clean LAGGING copy — a proper prefix of the ledger, or the
//     capped tail window of an earlier shorter ledger (the sanctioned
//     crash shape): nothing is lost, every unmirrored event is still
//     IN the ledger, so the write heals by re-deriving the projection
//     tail FROM the log (the same direction doctor's sanctioned
//     rebuild uses, never the reverse) and DISCLOSES the adoption in
//     the new event's hashed data (mirror_lag_healed, below). A heal
//     says what it did: without the disclosure a healed mirror and a
//     tampered one are indistinguishable afterwards.
//   - anything else — a mid-ledger hole (rows that skip a seq while
//     later seqs are present) or edited rows — cannot be repaired by
//     appending, so the write refuses exactly like the truncation
//     case above, naming both counts and the seq the projection
//     skips. The ledger is intact and nothing is dropped: this is a
//     refusal to ADOPT a misalignment, not a record of a loss, and
//     doctor's rebuild (which reports its delta) stays the only
//     sanctioned repair.
func (lb *logBuilder) logClassifyMirrorLag() error {
	if !lb.hasLast {
		return nil
	}
	st, serr := lb.c.State()
	if serr != nil {
		return serr
	}
	if mirror := validation.ObjAt(st, "events"); mirror.Kind == validation.Arr {
		switch mlen := len(mirror.A); {
		case mlen > len(lb.lines):
			return fmt.Errorf(
				"events.jsonl holds %d event(s) but the state projection "+
					"mirrors %d — %d mirrored event(s) are GONE from the "+
					"ledger tail, and the projection is the only surviving "+
					"copy of them; the write is refused rather than "+
					"adopting the loss. Copy the campaign dir for evidence, "+
					"then run `webv2 doctor` (it rebuilds the mirror from "+
					"the log and reports exactly what it drops)",
				len(lb.lines), len(mirror.A), len(mirror.A)-len(lb.lines))
		case mlen < len(lb.lines):
			var lerr error
			lb.lagEvents, lb.lagAdopted, lerr =
				classifyLaggingMirror(lb.lines, mirror.A)
			if lerr != nil {
				return lerr
			}
		}
	}
	return nil
}

// logPrevHash is Log's prev_hash derivation: the last event's
// event_hash, or the legacy anchor for a pre-chain head.
func (lb *logBuilder) logPrevHash() string {
	if lb.hasLast {
		if eh := validation.ObjAt(lb.last, "event_hash"); eh.Kind == validation.Str {
			return eh.S
		}
		return legacyAnchor(lb.last)
	}
	return GenesisHash
}

// logDiscloseRewind folds r13's ledger_rewound disclosure into the new
// event's data.
func (lb *logBuilder) logDiscloseRewind() {
	if lb.rewoundDropped > 0 {
		// r13: the rewind must be DISCLOSED inside the new chain's first
		// event (hashed, so it cannot be quietly rewritten later):
		// deleting events.jsonl plus any log-writing command was a
		// silent full-history wipe; now the ledger itself says how many
		// mirrored events it lost and when.
		if lb.dataV.Kind != validation.Obj {
			lb.dataV = validation.VObj()
		}
		lr := []validation.KV{
			kv("dropped_tail", validation.VInt(int64(lb.rewoundDropped))),
		}
		if lb.rewoundCapped {
			// r38 P2-3: the count is NOT the loss when the mirror was at
			// its cap — it is the MIRRORED TAIL that was dropped, and the
			// true loss is UNKNOWN. The keys are additive so a below-cap
			// disclosure keeps its exact, unchanged shape.
			lr = append(lr,
				kv("mirror_capped", validation.VBool(true)),
				kv("dropped_tail_meaning", validation.VStr(fmt.Sprintf(
					"events dropped from the state mirror's capped tail; "+
						"the mirror was at its %d-event cap, so the total "+
						"number of events the campaign ever held is UNKNOWN "+
						"(dropped_tail is a lower bound, not the loss)",
					mirrorCap))),
			)
		}
		lr = append(lr, kv("at", validation.VStr(nowIso())))
		lb.dataV.O = validation.SetOrAppend(lb.dataV.O, "ledger_rewound",
			validation.VObj(lr...))
	}
}

// logDiscloseLagHeal folds r37b's mirror_lag_healed disclosure into the
// new event's data.
func (lb *logBuilder) logDiscloseLagHeal() {
	if lb.lagAdopted > 0 {
		// r37b (F4): the lag heal is DISCLOSED inside the new event
		// (hashed, like r13's ledger_rewound): the projection jumped
		// forward this write, and the ledger itself now says how many of
		// its own events it adopted into the mirror. A heal discloses
		// what it did — a projection that silently jumps forward leaves
		// the auditor nothing to distinguish heal from tamper.
		if lb.dataV.Kind != validation.Obj {
			lb.dataV = validation.VObj()
		}
		lb.dataV.O = validation.SetOrAppend(lb.dataV.O, "mirror_lag_healed",
			validation.VObj(
				kv("adopted_from_log", validation.VInt(int64(lb.lagAdopted))),
				kv("at", validation.VStr(nowIso())),
			))
	}
}

// logBuildEvent mints the new event object and seals it with its hash.
func (lb *logBuilder) logBuildEvent(eventType string, refV validation.Value,
	prevHash string) validation.Value {
	event := validation.VObj(
		kv("seq", validation.VInt(int64(len(lb.lines)))),
		kv("at", validation.VStr(nowIso())),
		kv("type", validation.VStr(eventType)),
		kv("ref", refV),
		kv("data", lb.dataV),
		kv("prev_hash", validation.VStr(prevHash)),
	)
	evKvs := append(append([]validation.KV{}, event.O...),
		kv("event_hash", validation.VStr(eventHash(event))))
	return validation.VObj(evKvs...)
}

// logCommit appends the sealed event to the jsonl ledger and re-derives
// the state mirror.
func (lb *logBuilder) logCommit(event validation.Value) (validation.Value, error) {
	if err := validation.AppendJsonlAscii(lb.c.EventsPath, validation.CanonSpaced(event)); err != nil {
		return validation.VNull(), err
	}
	st, err := lb.c.State()
	if err != nil {
		return validation.VNull(), err
	}
	existing := validation.ObjAt(st, "events")
	var have []validation.Value
	if existing.Kind == validation.Arr {
		have = existing.A
	}
	if lb.rewoundDropped > 0 {
		// r34: genesis — the mirror's stale tail is dropped HERE, in the
		// same write that lands the new event, never in a save of its own
		// (a refused append must not empty the projection).
		have = nil
	}
	if lb.lagAdopted > 0 {
		// r37b (F4): re-derive the projection tail from the LEDGER (the
		// truth), not from the stale mirror — appending onto the stale
		// mirror is what baked mid-ledger holes. tailEvents below keeps
		// the projection's own 1000-event rule.
		have = lb.lagEvents
	}
	st.O = validation.SetOrAppend(st.O, "events", validation.Value{Kind: validation.Arr,
		A: tailEvents(have, event)})
	if err := lb.c.save(st); err != nil {
		return validation.VNull(), err
	}
	return event, nil
}

// mirrorCap is the state-mirror rule's one number: the projection keeps
// the last mirrorCap events (prior mirrorCap-1 + the new one); the log
// keeps everything. tailEvents, the genesis disclosure and
// classifyLaggingMirror's tail-window branch all read THIS constant — the
// cap used to be spelled "999"/"1000" in three places, so the classifier's
// health branch and the projection rule could drift apart.
const mirrorCap = 1000

// tailEvents is the state-mirror rule: the state file keeps the last
// 1000 events (prior 999 + the new one); the log keeps everything.
func tailEvents(have []validation.Value, add validation.Value) []validation.Value {
	if len(have) >= mirrorCap {
		return append(have[len(have)-(mirrorCap-1):], add)
	}
	return append(have, add)
}

// classifyLaggingMirror judges a state mirror that holds FEWER events
// than the ledger (the r37b F4 crash-window shape). It parses the whole
// ledger — alignment is judged event by event, so a torn line anywhere
// makes the shape INCONCLUSIVE and the write refuses rather than adopting
// (absence is inconclusive) — and returns the parsed events plus how many
// of them the mirror was BEHIND: 0 for a healthy capped mirror aligned
// with the ledger's tail (m == mirrorCap, the only shape the tail-window
// branch may certify — r38 P2-4), > 0 for a sanctioned crash shape the
// caller heals by re-deriving from the ledger. Anything else — a
// mid-ledger hole, a mirror that lost its HEAD, or edited rows — returns
// the refusal, naming both counts and the seq the projection skips.
func classifyLaggingMirror(lines []string, mirror []validation.Value) (
	[]validation.Value, int, error) {
	n, m := len(lines), len(mirror)
	lc := &lagClassifier{lines: lines, mirror: mirror, n: n, m: m}
	if err := lc.lagParseLedger(); err != nil {
		return nil, 0, err
	}
	if adopted, ok := lc.lagScanAlignedShapes(); ok {
		return lc.events, adopted, nil
	}
	return nil, 0, lc.lagRefusal()
}

// lagClassifier carries the classifyLaggingMirror inputs and the parsed
// ledger across its section helpers, together with both lengths.
type lagClassifier struct {
	lines  []string
	mirror []validation.Value
	events []validation.Value
	n, m   int
}

// lagEq is the canonical event equality every alignment check uses.
func (lc *lagClassifier) lagEq(a, b validation.Value) bool {
	return validation.CanonSpaced(a) == validation.CanonSpaced(b)
}

// lagAligned reports whether the mirror matches the parsed ledger
// starting at offset off.
func (lc *lagClassifier) lagAligned(off int) bool {
	for i := 0; i < lc.m; i++ {
		if !lc.lagEq(lc.mirror[i], lc.events[off+i]) {
			return false
		}
	}
	return true
}

// lagParseLedger parses the whole ledger — alignment is judged event by
// event, so a torn line anywhere makes the shape INCONCLUSIVE and the
// write refuses rather than adopting (absence is inconclusive).
func (lc *lagClassifier) lagParseLedger() error {
	lc.events = make([]validation.Value, 0, lc.n)
	for i, ln := range lc.lines {
		ev, perr := validation.ParseOrdered([]byte(ln))
		if perr != nil {
			return fmt.Errorf("events.jsonl line %d does not "+
				"parse (%v) — the projection mirrors %d event(s) but the "+
				"ledger holds %d, and the write cannot confirm the mirror "+
				"is a clean lagging copy of a damaged ledger; repair the "+
				"torn line first (verify names it)", i+1, perr, lc.m, lc.n)
		}
		lc.events = append(lc.events, ev)
	}
	return nil
}

// lagScanAlignedShapes walks classifyLaggingMirror's three sanctioned
// lagging-copy shapes and returns the adopted count when one matches.
//
// Tail-aligned: a healthy campaign whose ledger outgrew the
// projection cap (the mirror IS the ledger's tail window) — appending
// keeps the alignment, nothing to heal.
//
// r38 P2-4: the precondition INCLUDES m == mirrorCap, because this
// branch exists precisely for the cap window — a projection truncated
// by tailEvents always holds exactly mirrorCap events. Without it the
// branch claimed ANY suffix of the ledger as health, so a mirror that
// had lost its HEAD (only the last 3 events of a 1006-event ledger
// survive) was certified tail-aligned: it never reached the mid-hole
// refusal or the cap-window scan BELOW, the next write exited 0 with no
// disclosure, and 997 mirrored events were gone permanently and
// invisibly. Every other suffix-aligned shape falls through to the
// refusal — a mirror missing its head has lost mirrored events the
// write may not adopt.
//
// A proper prefix of the ledger (an empty mirror included): the
// sanctioned crash shape on a ledger within the cap — every
// unmirrored event is still in the ledger, heal by adopting.
//
// The capped window of an earlier, shorter ledger: the sanctioned
// crash shape on a long campaign. The pre-crash projection held the
// last 1000 of a ledger that has since grown, so scan the offsets a
// correct pre-crash mirror could have started at.
func (lc *lagClassifier) lagScanAlignedShapes() (int, bool) {
	if lc.m == mirrorCap && lc.lagAligned(lc.n-lc.m) {
		return 0, true
	}
	if lc.m == 0 || lc.lagAligned(0) {
		return lc.n - lc.m, true
	}
	if lc.m == mirrorCap { // tailEvents' cap: the projection never holds more
		for off := 1; off+lc.m <= lc.n-1; off++ {
			if lc.lagAligned(off) {
				return lc.n - off - lc.m, true
			}
		}
	}
	return 0, false
}

// lagRefusal is classifyLaggingMirror's not-a-lagging-copy verdict: a
// HOLE — the mirror's head is missing, rows were dropped mid-ledger, or
// rows were edited. Name both counts and the first position where the
// mirror stops tracking the ledger.
func (lc *lagClassifier) lagRefusal() error {
	div := lc.m
	for i := 0; i < lc.m && i < lc.n; i++ {
		if !lc.lagEq(lc.mirror[i], lc.events[i]) {
			div = i
			break
		}
	}
	divSeq, wantSeq := int64(-1), int64(-1)
	if div < lc.m {
		if s := validation.ObjAt(lc.mirror[div], "seq"); s.Kind == validation.Int {
			divSeq = s.I
		}
	}
	if div < lc.n {
		if s := validation.ObjAt(lc.events[div], "seq"); s.Kind == validation.Int {
			wantSeq = s.I
		}
	}
	return fmt.Errorf(
		"events.jsonl holds %d event(s) but the state projection mirrors "+
			"%d — and the projection is not a lagging copy of the ledger: "+
			"at mirrored position %d it holds seq %d where the ledger "+
			"holds seq %d, a HOLE in the projection (its head is missing, "+
			"rows were dropped mid-ledger, or rows were edited). Appending "+
			"cannot repair any of those shapes and the old behaviour baked "+
			"it in behind a success line; the ledger itself is intact and "+
			"nothing is lost from IT, so the write is refused rather than "+
			"adopting the misalignment. Copy the campaign dir for evidence, "+
			"then run `webv2 doctor` (it rebuilds the mirror from the log "+
			"and reports exactly what it changes)",
		lc.n, lc.m, div, divSeq, wantSeq)
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
