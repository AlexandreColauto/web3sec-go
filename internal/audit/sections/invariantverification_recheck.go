// Invariant verification — remaining recheck arms: proof-collision burn, map-run evidence recheck and the inconclusive-verdict sweep (split from invariantverification.go; pure structural move).

package sections

import (
	"fmt"
	"strings"

	"path/filepath"
	"websec/internal/harness"
	"websec/internal/state"
	"websec/internal/validation"
)

// reportProofCollisionBurn is r33 F2: ONE PROOF, ONE ROW, for the report
// rungs — the audit's re-derivation of the law the bind enforces in
// cli.verifyAutoprove (autoprovePropertyHolder + the caller's
// `holder != a.autoprove` refusal: "one property's proof binds one
// invariant").
//
// The bind's law, READ OFF ITS OWN CODE AND OBSERVED (not inferred):
// autoprovePropertyHolder scans the harness_run events in sequence for the
// FIRST event whose `property` folds equal to the property being bound
// (cli.autoproveSameName -> harness.SamePropertyName: case and edge
// whitespace fold) and the verb refuses with exit 2 when that event belongs
// to a DIFFERENT invariant:
//
//	verify --autoprove: property 'p1' was already bound to INV-1
//	(REPORT-89889f8cf360) — one property's proof binds one invariant;
//	give the second invariant its OWN property (digest churn is not a new
//	proof)
//
// Note what that scan does NOT look at: the report PIN. It filters on the
// property alone, so the same property title over a DIFFERENT report is
// still "already bound" — measured, not assumed, in
// internal/cli/zz_r33_test.go's TestR33DuplicateControlsStayGreen, where the
// cross-pin bind is refused with the sentence above. An audit rail keyed on
// (pin, property) would therefore bless a duplicate attribution the bind
// refuses: the same forgery as F2's repro with one byte of the report
// changed. So this rail keys on the PROPERTY, exactly as the bind does.
//
// Within that key, the FIRST event (in sequence) keeps its rung; every LATER
// event claiming the same folded property for a DIFFERENT invariant burns,
// naming the collision and the row that bound it first. Three deliberate
// properties of the reading:
//
//   - the fold is harness.SamePropertyName, the bind's own comparison — the
//     two copies of it were collapsed into that one function by this same
//     finding, so a report keyed "p1" whose second row names "P1" collides
//     here exactly as the bind's holder scan collides;
//   - the SAME invariant re-claiming the property is a REFRESH, not a
//     collision: the bind's holder scan returns the first holder and refuses
//     only a DIFFERENT one, so an invariant re-binding its own proof (a
//     newer report for the same property — the re-bind the verb explicitly
//     discloses with a warning — or a byte-identical re-bind) stays green;
//   - an event with no `property` field is not a CLAIMANT — it holds no
//     title, so it can never be named as the row that bound one (the
//     exec-bound payload carries none, and the holder must be a row that
//     actually stated the title);
//   - r34 F1: but a REPORT rung with a blank or absent title is NOT "no
//     claim" — it is a title no bind can write (cli.verifyAutoprove's first
//     check refuses an empty --property before it reads the report), so it
//     is a claim like any other and the rail below runs for it. The opening
//     `prop == ""` early return was an OFF-SWITCH: two rows claiming "" over
//     one pinned proof both displayed an unqualified blessing (and
//     recheckRegistryEvidence then resolved the report's
//     property_outcomes[""] entry, which no bind ever asked for). The
//     blank title's own burn ("no bind can write …", in
//     recheckRegistryEvidence) and this rail therefore both fire, and no
//     pair of rows can both display a blessing. The claimant-side blank stays
//     a non-claimant deliberately: accusing the exec-bound row that has no
//     property field of holding the blank title would put a false
//     attribution in the audit's problems. Anything ELSE is a claim, pin or
//     no pin: the bind's scan reads the property and nothing else.
//
// "" when the first claimant IS this invariant (its own rung is a refresh or
// a collision-free claim).
func reportProofCollisionBurn(events []validation.Value, iid string,
	last validation.Value) string {
	prop := validation.ObjStr(last, "property")
	firstInv, firstExec, firstPin := "", "", ""
	for _, ev := range events {
		if validation.ObjStr(ev, "type") != "harness_run" {
			continue
		}
		d := validation.ObjAt(ev, "data")
		// r34 F1: a claimant must CARRY a title. objStr alone reads an
		// absent/non-string field as "", which would let an exec-bound event
		// (no property field at all) be named as the holder of the blank
		// title — a holder that never claimed it. For every non-blank title
		// this is the same claimant set as before: "" folds equal to no
		// non-blank title.
		if validation.ObjAt(d, "property").Kind != validation.Str {
			continue
		}
		if !harness.SamePropertyName(validation.ObjStr(d, "property"), prop) {
			continue
		}
		inv := validation.ObjStr(d, "invariant")
		if inv == "" {
			continue
		}
		if firstInv == "" {
			firstInv, firstExec = inv, validation.ObjStr(d, "exec")
			firstPin = validation.ObjStr(d, "report_sha256")
		}
	}
	if firstInv == "" || firstInv == iid {
		return ""
	}
	pin := firstPin
	if len(pin) > 12 {
		pin = pin[:12]
	}
	if pin == "" {
		pin = "-"
	}
	return fmt.Sprintf("%s: report property %s is already bound to %s "+
		"(%s, report %s) — one property's proof binds one invariant, and "+
		"the first claimant keeps its rung; this row's rung is not backed",
		iid, validation.PyReprStr(prop), firstInv, firstExec, pin)
}

// autoproveProp was r26 F1's EXACT-first resolution with a single
// fold-equal fallback. r32b F1 deleted it: the fallback is a lookup the
// bind never makes (cli.fieldOf is exact-only), so a forged event naming
// "P1" for a report keyed "p1" re-derived a mapping the bind refuses. The
// one lookup now lives in harness.ReportProperty, called by
// harness.DecideReport, which both the bind and this section run.

// recheckMapRunEvidence extends the read-time law to halmos/forge-fuzz
// (r25 F1: the kind-skip arm was E5's open door — a chain-valid forged
// pair rendered `halmos, k=100` over a stdout whose marker said k=7,
// and `rung=counterexample` over a PASS output, audit-green). Same
// discipline, same entry point: the bind's own decision function
// (harness.DecideBound) over the stored bytes, the record's own
// timedOut/exit status/invocation bound and the scaffold artifact bytes,
// which must reproduce the claimed rung — and a proved-bounded claim must
// reproduce bounded_k. r28b F3 closed the remaining hole here too: this arm
// used to call MapRun directly, so a halmos blessing whose recorded H.t.sol
// hash had since been replaced by a foreign sha (or whose scaffold artifact
// was pruned) re-derived proved-bounded and audited green while the bind
// would have refused it.
func recheckMapRunEvidence(c *state.Campaign, events []validation.Value,
	iid string, entry, last validation.Value, exec string,
	kind harness.Kind) string {
	if kind != harness.Halmos && kind != harness.ForgeFuzz {
		// r29b F1: this was the skip door — `return ""` for every kind that
		// is not halmos/forge-fuzz, with a comment claiming harnessRunLine
		// renders no line for an unknown kind (it renders one for any
		// non-empty kind). Only the two MapRun kinds can legitimately arrive
		// here (harnessEvidenceRecheck resolves the kind first), so anything
		// else is a spelling no mapper implements and must burn by name.
		return fmt.Sprintf("%s: stored harness kind %s is not one of the "+
			"kinds MapRun implements (halmos, forge-fuzz) — no mapper "+
			"produced this rung, so it is not backed", iid,
			validation.PyReprStr(string(kind)))
	}
	recs, err := state.AllExecs(c)
	if err != nil {
		return fmt.Sprintf("%s: the exec ledger cannot be read (%v)",
			iid, err)
	}
	var rec validation.Value
	for _, e := range recs {
		if validation.ObjStr(e, "exec_id") == exec {
			rec = e
			break
		}
	}
	if rec.Kind != validation.Obj {
		return fmt.Sprintf("%s: provenance names %s, which the exec "+
			"ledger does not hold — the witness was deleted or never "+
			"existed; the run is unbacked by its own evidence", iid, exec)
	}
	// r29b F2: the bind's own reader, so both halves map the same bytes at
	// the same length (see recheckExecEvidence).
	raw, rerr := harness.ReadExecStdout(filepath.Join(c.ExecsDir, exec), rec)
	if rerr != nil {
		return stdoutUnreadableBurn(iid, exec, rerr)
	}
	scaffold, scaffoldWhy := harnessScaffoldArtifactBytes(c, events, iid,
		kind)
	if msg := scaffoldUnavailableBurn(iid, exec, scaffoldWhy, rec); msg != "" {
		return msg
	}
	scaffold = scaffoldBytesForUnboundArm(c, events, iid, kind, scaffold,
		scaffoldWhy)
	// r33 F1: the KIND-AWARE bound reader, the same one the bind calls
	// (harness.RecordInvocationBound — see recheckExecEvidence).
	invK := harness.RecordInvocationBound(kind, rec)
	rung, decSummary, _, decBK := harness.DecideBound(kind,
		harness.InvValue(iid, entry), raw, rec, scaffold,
		harness.RecordTimedOut(rec), invK, harness.RecordExitStatus(rec),
		"")
	if want := validation.ObjStr(last, "rung"); rung != want {
		return fmt.Sprintf("%s: exec %s stdout re-derives rung %s; the "+
			"event claims %s — the mapping did not come from this run's "+
			"bytes (re-derived: %s)", iid, exec,
			validation.PyReprStr(rung), validation.PyReprStr(want),
			decSummary)
	}
	if rung == harness.RungProvedBounded {
		if bkV := validation.ObjAt(last, "bounded_k"); bkV.Kind == validation.Int {
			have := int64(-1)
			if decBK != nil {
				have = int64(*decBK)
			}
			if have != bkV.I {
				return fmt.Sprintf("%s: exec %s stdout re-derives "+
					"bounded_k %d; the event pins %d — the bound is "+
					"inflated", iid, exec, have, bkV.I)
			}
		}
	}
	return ""
}

func recheckInconclusive(c *state.Campaign, events []validation.Value,
	iid string, entry, h, last validation.Value, exec string,
	kind harness.Kind) string {
	recs, err := state.AllExecs(c)
	if err != nil {
		// r44a: the silence below ("aged-out witness: nothing to re-derive
		// against") is reserved for a witness that is genuinely ABSENT from a
		// store that WAS listed. A ledger that could not be listed is a
		// refusal, and folding it into the absent case would let this arm
		// pass over evidence it never read. Same text as the sibling arm in
		// recheckExecEvidence: the rung is named and burned.
		return fmt.Sprintf("%s: the exec ledger cannot be read (%v)", iid, err)
	}
	var rec validation.Value
	for _, e := range recs {
		if validation.ObjStr(e, "exec_id") == exec {
			rec = e
			break
		}
	}
	if rec.Kind != validation.Obj {
		return "" // aged-out witness: nothing to re-derive against
	}
	// r29b F2: the bind's own reader (candidate order and 1MB cap included),
	// so a decoration the mapper drew from the capped bytes is not compared
	// against a longer file.
	//
	// r44b P3-b: this arm used to `return ""` on EVERY read failure, while
	// the two sibling arms above refuse with stdoutUnreadableBurn. The
	// aged-out silence belongs to the witness that is genuinely ABSENT from
	// a store that was listed (ErrNoCapturedStdout, or a capture the record
	// names and prunes — the r24 scope law: torching an old, pruned witness
	// dir would punish honesty with noise); a capture that is PRESENT and
	// cannot be READ (EACCES, ENOTDIR, EIO) is a refusal, not absence, and
	// folding the two together let a decorated inconclusive rung stand over
	// bytes this audit never read. Only stdoutAbsent folds.
	raw, rerr := harness.ReadExecStdout(filepath.Join(c.ExecsDir, exec), rec)
	if rerr != nil {
		if !stdoutAbsent(rerr) {
			return stdoutUnreadableBurn(iid, exec, rerr)
		}
		return "" // aged-out witness: nothing to re-derive against
	}
	es := harness.RecordExitStatus(rec)
	// Same entry point as the bind (r27 F1, r28b F3): the decision —
	// invocation floor, recorded-hash arm, Validate re-render, unbound
	// suffix — is harness.DecideBound's, so an inconclusive claim is
	// re-derived from the same bytes through the same arms. A refusal-arm
	// summary ("scaffold-degraded: …", "scaffold-bound violation: …",
	// "aborted: …") is NOT an "inconclusive" mapping, and an inconclusive
	// rung blesses nothing: the guard below skips it (modesty — the
	// scope law above), so missing scaffold bytes can never burn an
	// honest inconclusive bind here.
	// r33 F1: the KIND-AWARE bound reader — this function is reached only
	// for kind == minicertora (recheckExecEvidence's dispatch), and the bind
	// reads the same record with harness.RecordInvocationBound(kind, rec).
	// The kind-free reader this used to call disagreed with the bind about
	// any command naming another tool, which is the F1 divergence.
	invK := harness.RecordInvocationBound(kind, rec)
	scaffold, _ := harnessScaffoldArtifactBytes(c, events, iid,
		harness.MiniCertora)
	_, sum, _, _ := harness.DecideBound(kind,
		harness.InvValue(iid, entry), raw, rec, scaffold,
		harness.RecordTimedOut(rec), invK, es, harness.MspecRuleName(iid))
	if !strings.HasPrefix(sum, "inconclusive") {
		return "" // bytes bless MORE than the claim: modesty, never a
		// lie — the pair under-claims and the ledger stays honest.
	}
	// Compare DISPOSITION CLASSES, not bytes: the mapper legitimately
	// decorates stored summaries (the "(unbound: …)" suffix the unbound arm
	// appends, its own "no clean completion" timeout wording), and those are
	// transport/shape differences, not different advice. Disposition() is
	// the canonical classifier the tally itself reads — comparing classes is
	// the right equality for this rail, and the exact-text version (r25
	// first cut) would have burned honest decorated binds.
	wantCls, _, wantOK := harness.Disposition(validation.ObjStr(last, "summary"))
	gotCls, _, gotOK := harness.Disposition(sum)
	if !wantOK {
		return "" // the pair renders no advice: nothing to fabricate
	}
	if harness.RecordTimedOut(rec) && gotCls == harness.EscalateRuntime &&
		wantCls != harness.EscalateRuntime {
		// A run that never completed, whose bytes re-derive the runtime
		// floor: any OTHER named class is fabricated over a process that
		// was killed (by law its partial bytes map to no verdict).
		//
		// r32 F3: the arm keys on the class the BYTES re-derive, not on
		// the timeout alone. A flooring invocation bound floors on the
		// timeout path too (same predicate as everywhere else), so a
		// timed-out run of a degenerate command re-derives
		// `degenerate-bound` and its stored pair may legitimately carry
		// that class — the old arm burned exactly that honest pair while
		// the generic comparison below already catches any real
		// divergence.
		return fmt.Sprintf("%s: exec %s never completed (exit %d) "+
			"and its bytes re-derive the runtime floor; the bound "+
			"pair claims advice class %q — a disposition no run of "+
			"these bytes can carry", iid, exec, es, wantCls)
	}
	if !gotOK {
		// No named disposition in the bytes (plumbing floor), yet the
		// pair claims one: invented campaign-steering advice.
		return fmt.Sprintf("%s: exec %s stdout re-derives no named "+
			"disposition (%s); the bound pair claims advice class %q "+
			"— fabricated next-step text steers the tally", iid, exec,
			validation.PyReprStr(sum), wantCls)
	}
	if gotCls != wantCls {
		return fmt.Sprintf("%s: exec %s stdout re-derives disposition "+
			"%q; the bound pair claims %q — fabricated next-step text "+
			"steers the tally", iid, exec, gotCls, wantCls)
	}
	return ""
}
