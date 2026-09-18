// Invariant verification — exec-evidence recheck: re-derives the verified verdict from the stored exec capture (split from invariantverification.go; pure structural move).

package sections

import (
	"fmt"

	"path/filepath"
	"websec/internal/harness"
	"websec/internal/state"
	"websec/internal/validation"
)

func recheckExecEvidence(c *state.Campaign, events []validation.Value,
	iid string, entry, h, last validation.Value, exec string,
	kind harness.Kind) string {
	// r24 scope law: re-derivation guards the rungs that RECORD CREDIT
	// (proved-bounded, counterexample). An inconclusive rung blesses
	// nothing, and torching its (often old, often pruned) witness dir
	// would punish honesty with noise.
	rung := validation.ObjStr(last, "rung")
	if rung != harness.RungProvedBounded &&
		rung != harness.RungCounterexample {
		// r25 preemption (critic's sharpest): a forged (slot,event)
		// pair claiming inconclusive with an invented `| next:` advice
		// line feeds the disposition tally — the moment a planner
		// consumes classes, fabricated advice steers the campaign.
		// Re-derive summary+proof digests ONLY when the evidence
		// still exists on disk (an aged-out witness dir stays silent:
		// absence is not proof of a lie), and burn ONLY the
		// over-claim directions (claimed advice the bytes contradict;
		// claimed-absent proof present in the run).
		if kind == harness.MiniCertora {
			return recheckInconclusive(c, events, iid, entry, h, last,
				exec, kind)
		}
		return ""
	}
	if kind != harness.MiniCertora {
		return recheckMapRunEvidence(c, events, iid, entry, last, exec, kind)
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
	// r29b F2: the BIND's own reader (harness.ReadExecStdout) — its
	// candidate order, its 1MB cap and its truncation semantics. The bare
	// os.ReadFile of <execDir>/stdout.log this arm used to make read the
	// whole file, so a capture over the cap whose duplicated verdict line
	// sat past byte 1,048,576 re-derived "inconclusive (duplicate verdict
	// lines for rule)" over a run the bind had honestly mapped as
	// proved-bounded: the audit burned a fresh bind for reading bytes the
	// bind never read.
	raw, rerr := harness.ReadExecStdout(filepath.Join(c.ExecsDir, exec), rec)
	if rerr != nil {
		return stdoutUnreadableBurn(iid, exec, rerr)
	}
	// r28b F3: the audit re-derives through the SAME decision entry point
	// the bind used, with the SAME arguments — the recorded-hash arm, the
	// Validate re-render of the CURRENT claim and the unbound suffix all
	// live in harness.DecideBound. Calling the kind mapper directly (the
	// r24 shape) reproduced only the last step, so a blessing bound before
	// its claim drifted, or bound to a hash the record has since replaced,
	// audited out clean while a re-bind over the same record + claim
	// refused "scaffold-degraded: …" / "scaffold-bound violation: …".
	scaffold, scaffoldWhy := harnessScaffoldArtifactBytes(c, events, iid,
		harness.MiniCertora)
	if msg := scaffoldUnavailableBurn(iid, exec, scaffoldWhy, rec); msg != "" {
		return msg
	}
	scaffold = scaffoldBytesForUnboundArm(c, events, iid,
		harness.MiniCertora, scaffold, scaffoldWhy)
	inv := harness.InvValue(iid, entry)
	// r28b F2: the exit status comes from the BIND's own reader
	// (harness.RecordExitStatus: absent/null/too-wide -> -2). This arm used
	// to read `es := 0` with no guard, so a chain-valid forged pair over a
	// record whose exit_status was absent or null re-derived an honest
	// PROVEN line as proved-bounded and audited green — absence read as a
	// clean exit. Absence is inconclusive, never a blessing.
	//
	// r33 F1: and the invocation bound comes from the BIND's own reader
	// TOO — harness.RecordInvocationBound(kind, rec). This site (like the
	// two siblings below) passed the KIND-FREE reader, so a record whose
	// command names a real tool other than the rung's kind (a `halmos
	// --fuzz-runs 4000` record bound as --kind forge-fuzz: an honest 4000
	// for forge, a foreign-flag floor for the kind-free parse) was read two
	// ways by the two halves. DecideBound only lets a FLOORING kind-aware
	// re-read override the caller, so the audit's floored k survived and it
	// burned a bind that re-binds byte-for-byte.
	invK := harness.RecordInvocationBound(kind, rec)
	decRung, decSummary, decProof, decBK := harness.DecideBound(
		harness.MiniCertora, inv, raw, rec, scaffold,
		harness.RecordTimedOut(rec), invK, harness.RecordExitStatus(rec),
		harness.MspecRuleName(iid))
	if want := validation.ObjStr(last, "rung"); decRung != want {
		return fmt.Sprintf("%s: exec %s stdout re-derives rung %s; the "+
			"event claims %s — the mapping did not come from this run's "+
			"bytes (re-derived: %s)", iid, exec,
			validation.PyReprStr(decRung), validation.PyReprStr(want),
			decSummary)
	}
	proof := decProof
	// The slot proof carries the mapper-appended compiler_pin (host
	// provenance, not tool bytes): strip it before comparing to what
	// re-deriving from stdout alone produces.
	stripPin := func(v validation.Value) validation.Value {
		if v.Kind != validation.Obj {
			return v
		}
		var kvs []validation.KV
		for _, kv := range v.O {
			if kv.K != "compiler_pin" {
				kvs = append(kvs, kv)
			}
		}
		return validation.VObj(kvs...)
	}
	if dig := validation.ObjStr(last, "proof_sha256"); dig != "" {
		slotProof := stripPin(validation.ObjAt(h, "proof"))
		slotDig := proofDigest(slotProof)
		reD := proofDigest(stripPin(proof))
		// A slot that stored LESS proof than the bytes support is
		// under-reporting (hides witness richness, claims no extra
		// credit) — inconclusive-safe territory, not a lie: skip. The
		// burned directions are slot OVER the bytes (fabricated or
		// inflated subtree) and mismatched non-null pairings.
		slotEmpty := slotProof.Kind == validation.Null
		if !slotEmpty && slotDig != reD {
			return fmt.Sprintf("%s: exec %s stdout re-derives proof sha "+
				"%s; the slot carries %s — the proof subtree is not this "+
				"run's bytes (event pinned %s)", iid, exec, reD[:12],
				slotDig[:12], dig[:12])
		}
	}
	if bkV := validation.ObjAt(last, "bounded_k"); bkV.Kind == validation.Int {
		have := int64(-1)
		if decBK != nil {
			have = int64(*decBK)
		}
		if have != bkV.I {
			return fmt.Sprintf("%s: exec %s stdout re-derives bounded_k "+
				"%d; the event pins %d — the bound is inflated", iid, exec,
				have, bkV.I)
		}
	}
	return ""
}
