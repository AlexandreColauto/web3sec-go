// Invariant verification — registry-evidence recheck: the regRecheck walk over the registered artifact, its report, digest, derived fields and provenance (split from invariantverification.go; pure structural move).

package sections

import (
	"fmt"
	"strings"

	"websec/internal/harness"
	"websec/internal/state"
	"websec/internal/validation"
)

func recheckRegistryEvidence(c *state.Campaign, iid string, h,
	last validation.Value, kind harness.Kind, exec string) string {
	r := &regRecheck{c: c, iid: iid, h: h, last: last, kind: kind, exec: exec}
	if msg := r.regPropertyTitleBurn(); msg != "" {
		return msg
	}
	dig, msg := r.regReportDigest()
	if msg != "" {
		return msg
	}
	row, msg := r.regRegistryRow(dig)
	if msg != "" {
		return msg
	}
	rep, msg := r.regReadReport(row, dig)
	if msg != "" {
		return msg
	}
	if msg := r.regCheckDerived(rep); msg != "" {
		return msg
	}
	return r.regProvenance(dig)
}

// regRecheck carries the report-evidence recheck's shared context: the
// campaign, the invariant and harness slot under judgement, the last
// harness_run event's data, and the resolved kind and provenance exec.
type regRecheck struct {
	c    *state.Campaign
	iid  string
	h    validation.Value
	last validation.Value
	kind harness.Kind
	exec string
}

// regPropertyTitleBurn is the r34 F1 attribution check, first in the same
// order the bind's autoprove door asks for it.
func (r *regRecheck) regPropertyTitleBurn() string {
	// r34 F1: the title is the ATTRIBUTION, and the bind's autoprove door
	// asks for it FIRST — cli.verifyAutoprove's opening check refuses an
	// empty one ("verify --autoprove needs --property <exact title the
	// prover gave the property> — attribution is exact-match by design")
	// before it opens the report, loads links or scans the holder ledger. A
	// report rung whose event carries no title therefore names a property NO
	// BIND CAN WRITE, and nothing downstream may resolve it: an empty
	// property_outcomes[""] entry is not evidence of anything, and this arm
	// used to hand it straight to DecideReport's exact lookup (which found
	// the "" key) while reportProofCollisionBurn's `prop == ""` early return
	// switched the one-proof-one-row rail off — so a chain-valid pair
	// claiming "" audited GREEN with an unqualified blessing line over bytes
	// a fresh bind refuses without ever reading them. Absence is not "no
	// claim" on a report rung: the rung is not backed. The check sits FIRST
	// for the same reason the bind's does — this is the verb's own order.
	if prop := validation.ObjStr(r.last, "property"); prop == "" {
		return fmt.Sprintf("%s: the last harness_run event for this report "+
			"rung carries property %s — no bind can write an empty title "+
			"(verify --autoprove refuses one outright: \"needs --property "+
			"<exact title the prover gave the property> — attribution is "+
			"exact-match by design\"), so the rung's proof is attributed to "+
			"no title and it is not backed", r.iid, validation.PyReprStr(prop))
	}
	return ""
}

// regReportDigest extracts the event's report_sha256 pin (r32b F2); it
// returns the digest and, when the pin is missing, the burn message.
func (r *regRecheck) regReportDigest() (string, string) {
	dig := validation.ObjStr(r.last, "report_sha256")
	if dig == "" {
		// r32b F2: r23's report_sha256 is the pin that makes a report rung
		// checkable at all — the digest names the bytes this bind mapped
		// and the campaign store holds them. The old `return ""` here
		// ("pre-r23 autoprove event; refresh will pin it") was a carve-out
		// in NO doc and reachable by deleting ONE field: no registry
		// lookup happened, no re-derivation ran, and the run still
		// displayed as an UNQUALIFIED blessing ("INV-1: PROVEN-BOUNDED
		// (miniprover, k=4, REPORT-…)") with nothing to say those bytes
		// exist nowhere.
		//
		// There is no carve-out left, and none is needed: this arm is
		// reached only when the event's exec is REPORT-<digest> or the
		// slot kind is the report kind (harnessEvidenceRecheck), so every
		// shape arriving here IS a report run, and cli.verifyAutoprove
		// writes report_sha256 on every event it lands — a report
		// provenance without a digest is a shape no bind produced.
		// Absence is inconclusive, never a blessing.
		return "", fmt.Sprintf("%s: the last harness_run event names report "+
			"provenance (%s, rung %s) but pins no report_sha256 — the "+
			"bytes it blessed are named nowhere, so the mapping cannot be "+
			"re-derived from them; the rung is not backed", r.iid,
			validation.PyReprStr(validation.ObjStr(r.last, "exec")),
			validation.PyReprStr(validation.ObjStr(r.last, "rung")))
	}
	return dig, ""
}

// regRegistryRow finds the registry artifact holding the pinned report
// bytes.
func (r *regRecheck) regRegistryRow(dig string) (validation.Value, string) {
	st, err := r.c.State()
	if err != nil {
		return validation.Value{}, fmt.Sprintf("%s: registry unreadable (%v)", r.iid, err)
	}
	var row validation.Value
	for _, a := range validation.ObjAt(st, "artifacts").A {
		if validation.ObjStr(a, "sha256") == dig {
			row = a
			break
		}
	}
	if row.Kind != validation.Obj {
		return validation.Value{}, fmt.Sprintf("%s: no registry artifact holds the report "+
			"bytes the event pins (sha %s) — the evidence named by the "+
			"bind is not in the store (substituted path or quiet "+
			"reconcile)", r.iid, dig[:12])
	}
	return row, ""
}

// regReadReport re-reads and re-parses the pinned report bytes.
func (r *regRecheck) regReadReport(row validation.Value,
	dig string) (validation.Value, string) {
	// r25 F2: OWNERSHIP was paperwork; re-DERIVE the decision from the
	// bytes the row holds, through harness.MapReport — the function the
	// mapper itself now runs. A forged (slot,event) pair naming honest
	// registry bytes still has to match what those bytes say.
	raw, rerr := r.c.ArtifactBytes(row)
	if rerr != nil {
		return validation.Value{}, fmt.Sprintf("%s: pinned report bytes (%s) cannot be "+
			"re-read from the store (%v) — uncheckable is not backed",
			r.iid, dig[:12], rerr)
	}
	rep, perr := validation.ParseOrdered(raw)
	if perr != nil || rep.Kind != validation.Obj {
		return validation.Value{}, fmt.Sprintf("%s: the pinned report bytes no longer parse "+
			"(%v) — the store does not hold what the bind named", r.iid,
			perr)
	}
	return rep, ""
}

// regCheckDerived re-derives the decision from the pinned bytes through
// harness.DecideReport and compares rung, summary and bounded_k.
func (r *regRecheck) regCheckDerived(rep validation.Value) string {
	// r32b F1: the SAME decision entry point the bind runs, over the SAME
	// inputs — the pinned copy's bytes, the property name the event binds,
	// and the flags inside those bytes. harness.DecideReport owns the five
	// run-level gates (publish_problems' shape and emptiness, published,
	// review_error, the review_findings SHAPE, SUSPECT attribution), the
	// EXACT property lookup (ReportProperty — the bind's own rule, no fold
	// fallback) and the typed bound, and it ends in harness.MapReport.
	// Before this the audit re-derived only rung/summary/bounded_k, so a
	// chain-valid report copy whose ONLY difference was a SUSPECT finding
	// (or published:false) audited green over bytes a fresh bind refuses
	// with exit 2.
	dec := harness.DecideReport(rep, validation.ObjStr(r.last, "property"))
	if dec.Gate != harness.GateNone {
		return fmt.Sprintf("%s: the pinned report bytes fail the bind's "+
			"%s gate (%s) — a fresh bind of these very bytes is refused, "+
			"so no mapper produced this event; the rung is not backed",
			r.iid, dec.Gate, strings.TrimRight(dec.Refusal, "\n"))
	}
	rung, summary, bk := dec.Rung, dec.Summary, dec.BoundedK
	if want := validation.ObjStr(r.last, "rung"); want != rung {
		return fmt.Sprintf("%s: the pinned report re-derives to rung "+
			"%s; the event claims %s — the mapping did not come from "+
			"these bytes", r.iid, validation.PyReprStr(rung),
			validation.PyReprStr(want))
	}
	if want := validation.ObjStr(r.last, "summary"); want != summary {
		return fmt.Sprintf("%s: the pinned report re-derives summary "+
			"%s; the event carries %s", r.iid,
			validation.PyReprStr(summary), validation.PyReprStr(want))
	}
	if bk == nil {
		if v := validation.ObjAt(r.last, "bounded_k"); v.Kind == validation.Int {
			return fmt.Sprintf("%s: the pinned report states no bound; "+
				"the event pins bounded_k %d — inflated", r.iid, v.I)
		}
		// r34 F1's ADJACENT ARM: the same off-switch one field over — a
		// BLANK bound. For a property whose rollup is bound UNSTATED
		// (MapReport returns a nil bound) the bind writes bounded_k null and
		// NO proof sidecar, and the arm above found "nothing to compare" in
		// both fields. But the DISPLAY line's k is harnessBoundK(h): the
		// slot's bounded_k when it is an integer, ELSE the slot proof's
		// bounds.loop_bound — the minicertora/scaffold fallback. A chain-valid
		// forgery that adds a proof subtree to the slot and re-lands the
		// matching harness_run event (proof_sha256 over those very bytes,
		// bounded_k still null) therefore printed
		// "INV-3: PROVEN-BOUNDED (miniprover, k=999999, REPORT-…)" over a
		// pinned report that states no bound at all, and audited GREEN: no
		// mapper wrote a bound for these bytes, so the k the line renders is
		// a number the evidence denies. The mirror direction (a derived bound
		// the line does not render) is already closed by the event arm above
		// plus harnessRungBacked's slot/event kind+value comparison.
		if shown, ok := harnessBoundK(r.h); ok {
			return fmt.Sprintf("%s: the pinned report states no bound (the "+
				"rollup is bound UNSTATED) and the event pins none, but the "+
				"stored harness slot renders k=%s from its proof subtree — a "+
				"bound these bytes never stated; the rung is not backed", r.iid,
				shown)
		}
	} else if v := validation.ObjAt(r.last, "bounded_k"); v.Kind != validation.Int ||
		v.I != int64(*bk) {
		return fmt.Sprintf("%s: the pinned report derives bounded_k "+
			"%d; the event carries a different bound", r.iid, *bk)
	}
	return ""
}

// regProvenance checks the rung's own (kind, exec) pair (r33 F4/F5).
func (r *regRecheck) regProvenance(dig string) string {
	// ------------------------------------------------------------------
	// r33 F4/F5: the PROVENANCE the bind would have written for these bytes.
	//
	// Everything above re-derives the MAPPING from the pinned report bytes;
	// none of it reads the rung's own (kind, exec) pair, and three shapes no
	// bind writes rode that gap to a green audit with an unqualified
	// blessing line:
	//
	//	(a) exec = an EXEC- id the campaign does not hold. The bind checks
	//	    every --exec it is handed against the exec ledger
	//	    (cli.verifyAutoprove -> harnessExecRecord) and refuses an unknown
	//	    one with exit 2 ("no exec … in this campaign's exec ledger"); a
	//	    forged slot+event pair carrying "EXEC-99999999-nope" printed that
	//	    label as the witness of a rung whose run does not exist.
	//	(b) exec = a REPORT-<digest12> label that does not name the pinned
	//	    bytes. The bind computes the label FROM the digest it mapped
	//	    (harness.ReportExecLabel), so a label free to disagree with the
	//	    pin is printed provenance no run had — the display line reads
	//	    "…, REPORT-000000000000)" over a rung re-derived from
	//	    89889f8cf360….
	//	(c) a REPORT- provenance wearing an exec-shaped kind (r33 F5): the
	//	    report-bound bind writes harness.ReportKind, and the mapper this
	//	    arm runs is MapReport over the pinned bytes, so a rung claiming
	//	    halmos/forge-fuzz/minicertora while pinned to report bytes names
	//	    a captured stdout that was never read.
	//
	// (b) and (c) are harness.ReportProvenanceReason — the bind's own label
	// rule and its own kind, one home. (a) is the bind's own ledger lookup.
	//
	// The order is deliberate and is what keeps r29b F1(a) honest: the
	// digest/registry/bytes/gate/mapping checks above stay FIRST, so a report
	// row that is missing from the store still burns with the sentence that
	// shape is pinned to ("no registry artifact holds the report bytes the
	// event pins"), even when the rung also wears a scaffold kind.
	// ------------------------------------------------------------------
	if why := harness.ReportProvenanceReason(r.kind, r.exec, dig); why != "" {
		return fmt.Sprintf("%s: %s", r.iid, why)
	}
	if !strings.HasPrefix(r.exec, "REPORT-") {
		recs, lerr := state.AllExecs(r.c)
		if lerr != nil {
			return fmt.Sprintf("%s: the exec ledger cannot be read (%v) — "+
				"the provenance %s it names cannot be checked", r.iid, lerr,
				validation.PyReprStr(r.exec))
		}
		held := false
		for _, e := range recs {
			if validation.ObjStr(e, "exec_id") == r.exec {
				held = true
				break
			}
		}
		if !held {
			return fmt.Sprintf("%s: provenance names %s, which the exec "+
				"ledger does not hold — the bind verifies every --exec it "+
				"writes against that ledger (its own refusal is \"no exec "+
				"… in this campaign's exec ledger\"), so no bind wrote this "+
				"label and the witness it prints does not exist; the rung "+
				"is not backed", r.iid, validation.PyReprStr(r.exec))
		}
	}
	return ""
}
