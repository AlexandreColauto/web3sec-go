// eventlog_mirror.go: the state-mirror tail rule (mirrorCap/tailEvents)
// and the mirror-lag classifier that judges a projection SHORTER than the
// ledger before a write may heal or refuse it.
package state

import (
	"fmt"
	"websec/internal/validation"
)

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
