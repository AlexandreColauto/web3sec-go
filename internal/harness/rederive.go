// rederive.go: the ONE decision entry point for a harness run's rung —
// shared by the bind (cli.harnessMapBound) and by section 11's
// re-derivation (sections.recheckExecEvidence / recheckInconclusive /
// recheckMapRunEvidence).
//
// Law (r28b F3): the audit must re-derive EVERY decision the bind made,
// through the SAME code path with the SAME arguments. Before this file the
// bind's decision lived in package cli while section 11 called the kind
// mappers (MapMinicertoraInvoc / MapRun) DIRECTLY, so the audit reproduced
// only the LAST step. The bind decides the rung in this order — a recorded
// file hash equal to the stored scaffold's sha256 binds the run and then
// Validate re-renders the scaffold from the CURRENT claim ("scaffold-
// degraded: <reason>" when anything outside the body window moved); a
// harness-named hash with a different sha is a "scaffold-bound violation";
// no hash info leaves the run unbound, where Validate still judges the bytes
// on record against the CURRENT claim and a surviving file maps normally
// with the "(unbound: …)" suffix — and only THEN does the kind mapper run.
// DecideBound is that whole decision, once: a blessing whose claim drifted
// or whose recorded hash is foreign now refuses here on BOTH callers, so a
// campaign cannot audit green on a decision the bind would have refused.
//
// What MOVED here (exported so both packages share one implementation,
// never two opinions): InvValue (the claim value Scaffold/Validate render
// from), RecordedHashes (the exec record's file-hash reader),
// ScaffoldDegradedReason (the refusal-reason formatter), RecordExitStatus /
// RecordTimedOut (the exit-status law) and the kind dispatch below the
// decision seam. Package cli keeps thin delegates so its call sites and the
// cross-references in comments elsewhere stay valid.
package harness

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"websec/internal/validation"
)

// unboundSuffix is the honest-limitation clause the unbound arm appends:
// no recorded hash proved WHICH bytes ran, so the mapping is a claim about
// the file on record, not about the run.
const unboundSuffix = " (unbound: harness file hash not recorded)"

// DecideBound runs the bind's whole rung decision — the hash arm, the
// Validate re-render refusal and the kind dispatch — and returns
// (rung, summary, proof, boundedK):
//
//   - a recorded hash (input_hashes or artifact_hashes) equal to the
//     passed scaffold's sha256 binds the run: Validate re-renders the
//     scaffold from the CURRENT invariant claim and refuses with
//     "scaffold-degraded: <reason>" when anything outside the body window
//     moved — otherwise the kind mapper runs;
//   - a harness-named hash entry (H.t.sol / F.t.sol, T17's filenames, or
//     anything harness-named, .mspec included) with a different sha is a
//     scaffold-bound violation: rung inconclusive, the run's output is NOT
//     used;
//   - no hash info at all: the run is unbound, so nothing can be bound to
//     it — Validate still judges the passed bytes against the CURRENT claim
//     (that file is the only artifact left) and drift refuses with the same
//     "scaffold-degraded: <reason>" arm; bytes that still match map normally
//     with the unbound suffix — the honest limitation.
//
// The failure ORDER is deliberate and pinned: the hash check runs first,
// then Validate, on BOTH arms. A hash proves WHICH bytes ran (a foreign
// hash refutes the run outright); Validate proves the bytes still match the
// CURRENT claim (the statement may be edited long after the run). Both are
// needed, they refuse differently, and each refusal names the step that
// stopped it.
//
// scaffold == nil/empty is the AUDIT's "the bytes could not be obtained"
// signal (a pruned artifact, a substituted path, a scaffold event that
// never landed) — the bind never passes it: harnessScaffoldBytes fails with
// exit 2 before this rail is reached. Such a caller still must not bless:
// when the record carries HARNESS-FILE hash evidence — a recorded key naming
// a scaffold file, the only shape whose hash arm cannot be re-derived at all
// — the decision refuses ("scaffold-degraded: scaffold bytes unavailable …").
// The sandbox's own artifact_hashes stdout/stderr digests are NOT that
// evidence (r29b F3: `len(hashes) > 0` was true for every real record, so
// this arm refused runs whose hash comparison was vacuous). With no
// harness-file hash the unbound arm needs no scaffold for the MAPPING (its
// hash comparison is vacuous by definition), and a rung on record proves the
// bind's own Validate passed at bind time — so the mapping decision proceeds
// without the Validate re-render. That is the F3 constraint (3) carve-out:
// burn what cannot be re-derived, keep the honest arm honest.
//
// bounded_k is set only for proved-bounded (parsed k=<n> else the
// invocation k); every other rung carries null.
func DecideBound(kind Kind, inv validation.Value, raw []byte,
	rec validation.Value, scaffold []byte, timedOut bool, k, exitStatus int,
	ruleName string) (rung, summary string, proof validation.Value,
	boundedK *int) {
	// The invocation floor, re-read HERE from the record with the kind
	// (r32 F1/F2/F8). The caller-passed k is what the bind or the audit
	// computed — both now read it with RecordInvocationBound(kind, rec)
	// (r33 F1: the audit's three sites used to pass the KIND-FREE
	// InvocationBound(RecordCommand(rec)), so a command naming a real tool
	// other than the record's kind — `halmos --fuzz-runs 4000` bound as
	// --kind forge-fuzz — got an honest 4000 from the bind and a floor
	// from the audit, and this re-read could not close the gap because
	// only a FLOORING re-read overrides the caller). A command that
	// states a value its tool refuses, names a bound flag another family
	// owns, or is not a string at all floors whichever k arrived. Only a
	// FLOORING re-read overrides the caller — an honest k for a record
	// with no readable command (every pre-r32 test fixture and the
	// report-bound arm) is left exactly as it was.
	invReason := ""
	if rk, why := RecordInvocationBoundReason(kind, rec); BoundFloors(rk) {
		k, invReason = rk, why
	} else if k == BoundUnreadable {
		// A caller-supplied unreadable bound over a command this re-read
		// could read (a kind-free caller's floor): keep the floor and
		// name the construct through the same reader.
		if _, why := InvocationBoundReason(RecordCommand(rec)); why != "" {
			invReason = why
		}
	}
	if len(scaffold) == 0 {
		// r29b F3(a): the question is whether this record carries HARNESS
		// FILE hash evidence — a recorded key naming a scaffold file — not
		// whether it carries any sha at all. Every sandbox record carries
		// the artifact_hashes stdout/stderr digests, so `len(hashes) > 0`
		// was true for EVERY real record and this arm refused mappings it
		// could reproduce, over hash evidence the record never had.
		_, harnessNamed := RecordedHashes(rec)
		if harnessNamed {
			return RungInconclusive, "scaffold-degraded: scaffold bytes " +
					"unavailable (the hash arm cannot be re-derived)",
				validation.VNull(), nil
		}
		return decideMappedKind(kind, raw, timedOut, k, exitStatus,
			ruleName, unboundSuffix, invReason)
	}
	sum := sha256.Sum256(scaffold)
	hexSum := hex.EncodeToString(sum[:])
	hashes, harnessNamed := RecordedHashes(rec)
	for _, h := range hashes {
		if h == hexSum {
			// The run is bound to these bytes; Validate now re-renders
			// the scaffold from the CURRENT claim and compares everything
			// outside the body window. A claim that drifted away from
			// the bytes that ran must never be attributed a rung: the
			// output proved a claim nobody is making any more.
			if err := Validate(kind, inv, scaffold); err != nil {
				return RungInconclusive,
					"scaffold-degraded: " + ScaffoldDegradedReason(err),
					validation.VNull(), nil
			}
			return decideMappedKind(kind, raw, timedOut, k, exitStatus,
				ruleName, "", invReason)
		}
	}
	if harnessNamed {
		return RungInconclusive,
			"scaffold-bound violation: harness file hash differs " +
				"from stored scaffold", validation.VNull(), nil
	}
	// Unbound: no recorded hash proved WHICH bytes ran, so no run can be
	// refuted on its hash — but the passed bytes are still an artifact this
	// rail can judge, and here they are the ONLY one. Validate re-renders
	// them from the CURRENT claim and refuses with the very same
	// "scaffold-degraded:" wording the bound arm uses: bytes that no
	// longer match the claim on record must never be attributed a rung,
	// hash proof or not.
	if err := Validate(kind, inv, scaffold); err != nil {
		return RungInconclusive,
			"scaffold-degraded: " + ScaffoldDegradedReason(err),
			validation.VNull(), nil
	}
	return decideMappedKind(kind, raw, timedOut, k, exitStatus, ruleName,
		unboundSuffix, invReason)
}

// decideMappedKind dispatches one bound run to its kind's mapper: an
// untimed minicertora run through MapMinicertoraInvoc (exit status, rule
// name, the invocation bound k and the unreadable construct when the bound
// parse failed, so neither a degenerate --loop-bound nor an unlexable
// command ever binds), everything else — including a timed-out minicertora
// run, which must never reach the JSONL mapper — through MapRun.
//
// The timed-out minicertora run is the one kind whose MapRun summary would
// lie: MapRun renders the run's rung, but the caller-passed k is the loop
// bound, not a number of seconds. Step 0 gave it its own wording,
// produced here BEFORE the MapRun call: "inconclusive (no clean
// completion; loop bound was N)" when the invocation names a bound, the
// clause-free "inconclusive (no clean completion)" otherwise — a runtime
// floor (EscalateRuntime: re-run with a larger wall-clock).
//
// r32 F3: the FLOOR is asked FIRST on this arm too. "no clean completion"
// is the runtime class, so a run killed under a bound the twin would have
// refused (--loop-bound 0) lost the escalate-bound advice it is owed and
// was told to re-run with a larger timeout instead — advice about a
// command that cannot start at all. Same predicate (BoundFloors), same
// wording home (boundFloorSummary), same class as the untimed arm.
func decideMappedKind(kind Kind, raw []byte, timedOut bool, k,
	exitStatus int, ruleName, suffix, invReason string) (string, string,
	validation.Value, *int) {
	if kind == MiniCertora && timedOut {
		if BoundFloors(k) {
			return RungInconclusive,
				boundFloorSummary(k, invReason) + suffix,
				validation.VNull(), nil
		}
		summary := "inconclusive (no clean completion)"
		if k > 0 {
			summary = fmt.Sprintf(
				"inconclusive (no clean completion; loop bound was %d)",
				k)
		}
		return RungInconclusive, summary + suffix,
			validation.VNull(), nil
	}
	if kind == MiniCertora && !timedOut {
		// r27 F1: the minicertora branch goes through the SAME
		// invocation-level floor as the audit's re-derivation —
		// MapMinicertoraInvoc refuses a command whose own bound flag
		// states a degenerate value (--loop-bound 0), which the twin
		// raises for, and never hands out a bounded_k below 1. r30 P1-1:
		// that floor is BoundFloors, so a command the invocation parse
		// cannot read at all (an unmatched quote, a command list, an
		// expansion in the value) refuses here too, and the construct
		// rides along so the stored summary names it.
		rung, summary, proof, bk := MapMinicertoraInvoc(raw,
			exitStatus, ruleName, k, invReason)
		return rung, summary + suffix, proof, bk
	}
	rung, summary, bk := decideMapped(kind, raw, timedOut, k, suffix,
		invReason)
	return rung, summary, validation.VNull(), bk
}

// decideMapped runs MapRun and attaches bounded_k for proved-bounded. why
// is the invocation's own reason ("" when there is none); MapRun ignores
// it unless the bound floors, but a halmos/forge floor must name the tool
// and the observed refusal exactly like the minicertora arm always has
// (r32 F1/F2 — before this, DecideBound handed the reason only to
// MapMinicertoraInvoc, so a forge floor said only "the invocation states
// no bound >= 1").
func decideMapped(kind Kind, raw []byte, timedOut bool, k int,
	suffix, why string) (string, string, *int) {
	rung, summary := MapRun(kind, raw, timedOut, k, why)
	summary += suffix
	if rung != RungProvedBounded {
		return rung, summary, nil
	}
	// r26 F3 (mirror half): only a STATED bound >= 1 rides the slot. An
	// invocation that never named one used to hand back k=0, which the
	// display then printed as a bound nobody stated — and the paired
	// law above floors a stated-but-degenerate value, so the two arms
	// together say exactly one thing: a number in the slot was stated
	// by the run, or the slot says UNSTATED.
	if bk := BoundK(kind, raw, k); bk >= 1 {
		return rung, summary, &bk
	}
	return rung, summary, nil
}
