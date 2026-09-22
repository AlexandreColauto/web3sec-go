// exec_record_anchor.go is the v1.6 exec-record anchor section: the reader
// that recomputes each anchored exec record's digest and compares it with the
// digest the ledger event committed to.
//
// It is the half that makes the anchor load-bearing. A digest nothing
// recomputes is a field with no consumer; this section is what turns "the
// record was edited after the event" into a verdict, and it is the reason
// scripts/verify-full.sh's step 9 stays PASS over the Python-era fixture
// (two unanchored sandbox.exec events, `unanchored: 2`, no problems).
//
// PRESENCE-GATED, deliberately: a campaign with no anchor-carrier event at
// all returns ErrSkip and renders nothing, so the Python parity oracle
// (internal/audit/testdata/p1_audit_vectors.json, whose fixtures contain no
// sandbox.exec events) and the pinned rendered-section lists are unchanged
// for campaigns that never exec. The gate is "no carrier events", never "no
// anchored events": the second form would make the section vanish exactly
// when coverage is zero — the least informative moment.
//
// The EVENT is the driving collection, not execs/. The anchor is a claim an
// EVENT makes about a record, so an exec whose carrier event is gone produces
// no row at all; enumerating execs/ instead would drag the two harness-seeded
// records (which have no event of their own) into the verdict. The stated
// cost — deleting the carrier event plus editing the projection is an
// unclosed residual — is named in docs/gates/v16-exec-record-anchor-scope.md.
package sections

import (
	"fmt"
	"os"
	"path/filepath"

	"websec/internal/sandbox"
	"websec/internal/state"
	"websec/internal/validation"
)

// ExecRecordAnchor is the section: {checked, anchored, unanchored, problems,
// ok}, or ErrSkip when the campaign holds no anchor-carrier event.
//
// Counting rule, pinned: `checked` counts the anchor-carrying EVENTS
// examined, `anchored` counts only digest-VERIFIED matches, and a problem row
// increments `checked` only — never `anchored`. `unanchored` is the separate
// informational list of exec refs whose carriers carry no anchor key at all;
// it is disjoint from `problems` by construction and is not a subset of
// `checked` (an unanchored event carries no anchor to check).
//
// The section has exactly two outcomes: ErrSkip (no carrier event) or a
// report-shaped payload with a nil error. It never aborts the audit — an
// unreadable ledger is folded into a problem row below, exactly as an
// unreadable record is (anchorRecord), because AuditCampaign treats any
// non-ErrSkip error as fatal and one read failure would suppress every other
// section's verdict (internal/audit/audit.go).
func ExecRecordAnchor(c *state.Campaign) (validation.Value, error) {
	events, err := c.Events()
	if err != nil {
		// The ledger cannot be read, so no anchor can be verified. This is a
		// PROBLEM ROW, not a section error: returning it would abort the whole
		// report (audit.go treats any non-ErrSkip error as fatal) and suppress
		// every other section's verdict. Degrading loses nothing — the row
		// names the read failure and `ok` goes false, so the audit is red
		// either way — and it mirrors the event_log section, which folds an
		// unusable ledger into `problems` rather than aborting. (Section 3
		// `execs` refuses the identical read, and in the full audit it aborts
		// first; this arm is defence in depth for a direct call, never a way
		// to hide a damaged ledger.)
		return validation.VObj(
			KV("checked", validation.VInt(0)),
			KV("anchored", validation.VInt(0)),
			KV("unanchored", validation.VArr()),
			KV("problems", validation.VArr(validation.VStr(fmt.Sprintf(
				"the campaign ledger cannot be read, so no exec-record "+
					"anchor can be verified: %v", err)))),
			KV("ok", validation.VBool(false)),
		), nil
	}
	rows := anchorRows(events)
	if len(rows) == 0 {
		return validation.Value{}, ErrSkip
	}
	a := &anchorAudit{}
	for _, row := range rows {
		a.check(c, row)
	}
	return validation.VObj(
		KV("checked", validation.VInt(int64(a.checked))),
		KV("anchored", validation.VInt(int64(a.anchored))),
		KV("unanchored", validation.VArr(a.unanchored...)),
		KV("problems", validation.VArr(a.problems...)),
		KV("ok", validation.VBool(len(a.problems) == 0)),
	), nil
}

// anchorRow is one exec ref's anchor-carrier events, in log order.
type anchorRow struct {
	ref    string
	events []validation.Value
}

// anchorRows groups the campaign's carrier events by ref, in the order each
// ref first appears in the log. A carrier event naming no ref names no exec,
// so it is skipped (it can be checked against nothing).
func anchorRows(events []validation.Value) []anchorRow {
	var rows []anchorRow
	idx := map[string]int{}
	for _, ev := range events {
		if !sandbox.IsAnchorCarrier(validation.ObjStr(ev, "type")) {
			continue
		}
		ref := validation.ObjStr(ev, "ref")
		if ref == "" {
			continue
		}
		i, seen := idx[ref]
		if !seen {
			i = len(rows)
			idx[ref] = i
			rows = append(rows, anchorRow{ref: ref})
		}
		rows[i].events = append(rows[i].events, ev)
	}
	return rows
}

// anchorAudit accumulates the section's verdict in log order.
type anchorAudit struct {
	checked    int
	anchored   int
	unanchored []validation.Value
	problems   []validation.Value
}

// check renders one exec ref's row: unanchored (coverage, never a problem),
// or anchored with unanimity among the carriers and EVERY carrier's own
// verdict from the ONE predicate recomputed against the record on disk.
//
// EVERY anchored carrier is judged, not just the first. A second carrier that
// carries the right digest but no encoding label is exactly the unlabelled
// anchor §3.3 refuses, and it must be refused here too: judging only
// anchored[0] rendered {checked: 2, anchored: 2, ok: true} for that fixture
// while VerifyExecRecordAnchor refused it, so the audit and the mint gate
// disagreed about the same data and `anchored` counted a carrier whose label
// was never checked. Running the SAME predicate (sandbox.AnchorProblem) over
// the SAME carrier walk the mint gate performs is what keeps the two verdicts
// identical; folding label equality into carriersDisagree would leave two
// implementations of one law, which is how they diverged in the first place.
func (a *anchorAudit) check(c *state.Campaign, row anchorRow) {
	anchored := anchoredCarriers(row.events)
	if len(anchored) == 0 {
		a.unanchored = append(a.unanchored,
			validation.VStr(sandbox.AnchorAbsentReason(row.ref)))
		return
	}
	a.checked += len(anchored)
	// §5 state (b) first: two anchored carriers naming different digests get
	// their own row. (The mint side surfaces the same fact as the mismatch on
	// the first carrier that differs from the record — both refuse, so the
	// verdicts still agree.)
	if prob := carriersDisagree(row.ref, anchored); prob != "" {
		a.problems = append(a.problems, validation.VStr(prob))
		return
	}
	rec, prob := anchorRecord(c, row.ref, anchored[0])
	if prob != "" {
		a.problems = append(a.problems, validation.VStr(prob))
		return
	}
	// The ONE predicate, over EVERY anchored carrier, in log order — the
	// same walk the mint gate performs. The first non-empty verdict is the
	// row; no carrier reaches `anchored` without its label AND its digest
	// having been checked.
	for _, ev := range anchored {
		digest, alg, _ := sandbox.EventAnchor(ev)
		if prob := sandbox.AnchorProblem(validation.ObjStr(ev, "type"),
			row.ref, digest, alg, rec); prob != "" {
			a.problems = append(a.problems, validation.VStr(prob))
			return
		}
	}
	a.anchored += len(anchored)
}

// anchoredCarriers is the subset of a ref's carrier events that carries an
// anchor key — the presence of EITHER key makes an event new-style.
func anchoredCarriers(events []validation.Value) []validation.Value {
	var out []validation.Value
	for _, ev := range events {
		if _, _, present := sandbox.EventAnchor(ev); present {
			out = append(out, ev)
		}
	}
	return out
}

// carriersDisagree is §5 state (b): no digest wins by precedence, so two
// anchored carriers for one ref must agree, and a disagreement is itself a
// problem row. (On the mint side the same fact surfaces as the mismatch on
// the first carrier that differs from the record.)
func carriersDisagree(execID string, anchored []validation.Value) string {
	first, _, _ := sandbox.EventAnchor(anchored[0])
	for _, ev := range anchored[1:] {
		if d, _, _ := sandbox.EventAnchor(ev); d != first {
			return fmt.Sprintf("exec %s: the sandbox.exec and "+
				"sandbox.exec.registered events for this exec carry "+
				"different digests (%s vs %s) — the carriers disagree "+
				"about the record", execID, first, d)
		}
	}
	return ""
}

// anchorRecord reads the anchored record, in the ingest gate's own order:
// os.Stat first, then ReadJson, so a MISSING record and an UNPARSEABLE one
// are distinct problem rows. A parse error must never be returned as a
// section error — AuditCampaign treats any non-ErrSkip error as fatal, so one
// unreadable record would suppress every other section's verdict.
func anchorRecord(c *state.Campaign, execID string,
	ev validation.Value) (validation.Value, string) {
	typ := validation.ObjStr(ev, "type")
	path := filepath.Join(c.ExecsDir, execID, "exec_record.json")
	if _, err := os.Stat(path); err != nil {
		return validation.VNull(), fmt.Sprintf("exec %s: the %s event "+
			"anchors a record that is not on disk — the anchor cannot be "+
			"verified", execID, typ)
	}
	rec, err := validation.ReadJson(path)
	if err != nil {
		return validation.VNull(), fmt.Sprintf("exec %s: the %s event "+
			"anchors a record that cannot be parsed — the anchor cannot be "+
			"verified", execID, typ)
	}
	return rec, ""
}
