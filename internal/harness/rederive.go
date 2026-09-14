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
	"path/filepath"
	"strings"

	"websec/internal/validation"
)

// unboundSuffix is the honest-limitation clause the unbound arm appends:
// no recorded hash proved WHICH bytes ran, so the mapping is a claim about
// the file on record, not about the run.
const unboundSuffix = " (unbound: harness file hash not recorded)"

// recordField is dict.get(key) over an exec record (absent vs null kept
// distinct by the ok flag).
func recordField(rec validation.Value, key string) validation.Value {
	if rec.Kind != validation.Obj {
		return validation.VNull()
	}
	for _, kv := range rec.O {
		if kv.K == key {
			return kv.V
		}
	}
	return validation.VNull()
}

// recordStr is rec[key] as a string; an absent or non-string field reads "".
func recordStr(rec validation.Value, key string) string {
	if v := recordField(rec, key); v.Kind == validation.Str {
		return v.S
	}
	return ""
}

// RecordExitStatus is THE reading of an exec record's exit_status, one home
// for the bind and for the audit (r28b F2). An int exit_status is the run's
// own report; anything else — absent, null, or an integer too wide for
// int64 — is "unknown" (-2), which MapMinicertora's negative floor refuses
// ("inconclusive (exit output unmapped)").
//
// The absent/null default is load-bearing and was the F2 lie: section 11's
// blessing arm read this field with `es := 0` and no guard, so a chain-valid
// forged pair (slot + event + prose all claiming proved-bounded) over a
// record whose exit_status was ABSENT or null re-derived proved-bounded from
// a PROVEN line and audited green — absence read as "the tool exited 0".
// Absence is inconclusive, never a blessing.
func RecordExitStatus(rec validation.Value) int {
	if v := recordField(rec, "exit_status"); v.Kind == validation.Int &&
		v.Big == "" {
		return int(v.I)
	}
	return -2
}

// RecordTimedOut is the MapRun timedOut bit of a record: TimedOutBit over
// RecordExitStatus, so a record with no usable exit status reads as NOT
// timed out while its exit status still floors the mapper at -2. (The two
// are deliberately different questions: -2 is "never reported a clean
// exit", the timeout bit is "the sandbox killed it".)
func RecordTimedOut(rec validation.Value) bool {
	return TimedOutBit(RecordExitStatus(rec))
}

// RecordCommand is the exec record's command string ("" when absent). The
// invocation bound is InvocationBound(RecordCommand(rec)) for both the bind
// and the audit.
func RecordCommand(rec validation.Value) string {
	return recordStr(rec, "command")
}

// InvValue is the invariant value harness.Scaffold renders from: the
// registry entry plus the id the registry carries as its map KEY (Scaffold
// reads "id" off the record, so the key is passed in as that field). The
// scaffold command, the bind's Validate arm and the audit's re-derivation
// all go through here on purpose: if the inputs could drift, every bound run
// would be refused for bytes that never moved.
func InvValue(invID string, entry validation.Value) validation.Value {
	inv := entry
	inv.O = validation.SetOrAppend(
		append([]validation.KV(nil), entry.O...), "id",
		validation.VStr(invID))
	return inv
}

// RecordedHashes collects every recorded file hash from the exec record
// (input_hashes plus artifact_hashes values) and whether any key names the
// harness file (T17's H.t.sol / F.t.sol, the third kind's INV.mspec, or
// anything harness-named — the runs that hashed the file they actually
// executed). The .mspec suffix matters: without it a minicertora run that
// hashed a foreign spec file would read as "no hash info" and map normally,
// which is exactly the bind Decision 2b refuses.
//
// Both the bind and the audit's "can I re-derive this without the scaffold
// bytes?" question read this one function.
func RecordedHashes(rec validation.Value) (hashes []string,
	harnessNamed bool) {
	for _, key := range []string{"input_hashes", "artifact_hashes"} {
		m := recordField(rec, key)
		if m.Kind != validation.Obj {
			continue
		}
		for _, kv := range m.O {
			if kv.V.Kind == validation.Str && kv.V.S != "" {
				hashes = append(hashes, kv.V.S)
			}
			base := strings.ToLower(filepath.Base(kv.K))
			if base == "h.t.sol" || base == "f.t.sol" ||
				strings.HasSuffix(base, ".mspec") ||
				strings.Contains(base, "harness") {
				harnessNamed = true
			}
		}
	}
	return hashes, harnessNamed
}

// ScaffoldDegradedReason reduces a harness.Validate error to the
// scaffold-line reason the refusal text carries. Validate's messages have
// two fixed shapes — lineDiffErr's "harness: scaffold-bound: <reason>
// (<region> line <n>: want <q> got <q>)" and BodyRegion's "harness:
// scaffold-bound: missing BODY start marker" (plus its siblings) — so the
// drift CLASS is what sits between the prefix and the first region detail;
// the quoted want/got bytes are diagnostics, not the refusal. Anything
// unrecognized rides whole: a refusal must never lose its reason.
func ScaffoldDegradedReason(err error) string {
	msg := strings.TrimPrefix(err.Error(), "harness: ")
	msg = strings.TrimPrefix(msg, "scaffold-bound: ")
	for _, anchor := range []string{" (pre-body line ", " (post-body line "} {
		if i := strings.Index(msg, anchor); i >= 0 {
			return msg[:i]
		}
	}
	return msg
}

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
// when the record carries hash evidence the hash arm cannot be re-derived
// at all, so the decision refuses ("scaffold-degraded: scaffold bytes
// unavailable …"). With NO hash info the unbound arm needs no scaffold for
// the MAPPING (its hash comparison is vacuous by definition), and a rung on
// record proves the bind's own Validate passed at bind time — so the
// mapping decision proceeds without the Validate re-render. That is the
// F3 constraint (3) carve-out: burn what cannot be re-derived, keep the
// honest arm honest.
//
// bounded_k is set only for proved-bounded (parsed k=<n> else the
// invocation k); every other rung carries null.
func DecideBound(kind Kind, inv validation.Value, raw []byte,
	rec validation.Value, scaffold []byte, timedOut bool, k, exitStatus int,
	ruleName string) (rung, summary string, proof validation.Value,
	boundedK *int) {
	if len(scaffold) == 0 {
		hashes, harnessNamed := RecordedHashes(rec)
		if len(hashes) > 0 || harnessNamed {
			return RungInconclusive, "scaffold-degraded: scaffold bytes " +
					"unavailable (the hash arm cannot be re-derived)",
				validation.VNull(), nil
		}
		return decideMappedKind(kind, raw, timedOut, k, exitStatus,
			ruleName, unboundSuffix)
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
				ruleName, "")
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
		unboundSuffix)
}

// decideMappedKind dispatches one bound run to its kind's mapper: an
// untimed minicertora run through MapMinicertoraInvoc (exit status, rule
// name and the invocation bound k, so a degenerate --loop-bound never
// binds), everything else — including a timed-out minicertora run, which
// must never reach the JSONL mapper — through MapRun.
//
// The timed-out minicertora run is the one kind whose MapRun summary would
// lie: MapRun renders "timeout after <k>s", but the caller-passed k is the
// loop bound, not a number of seconds. Step 0 gives it its own wording,
// produced here BEFORE the MapRun call: "inconclusive (no clean completion;
// loop bound was N)" when the invocation names a bound, the clause-free
// "inconclusive (no clean completion)" otherwise. halmos/forge-fuzz keep
// MapRun's byte-pinned "timeout after %ds".
func decideMappedKind(kind Kind, raw []byte, timedOut bool, k,
	exitStatus int, ruleName, suffix string) (string, string,
	validation.Value, *int) {
	if kind == MiniCertora && timedOut {
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
		// raises for, and never hands out a bounded_k below 1.
		rung, summary, proof, bk := MapMinicertoraInvoc(raw,
			exitStatus, ruleName, k)
		return rung, summary + suffix, proof, bk
	}
	rung, summary, bk := decideMapped(kind, raw, timedOut, k, suffix)
	return rung, summary, validation.VNull(), bk
}

// decideMapped runs MapRun and attaches bounded_k for proved-bounded.
func decideMapped(kind Kind, raw []byte, timedOut bool, k int,
	suffix string) (string, string, *int) {
	rung, summary := MapRun(kind, raw, timedOut, k)
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
