// Section 11: invariant verification — a CHECKED_AGAINST_CODE entry must be
// LOG-ANCHORED verified: a registered artifact AND a matching
// invariant.verified log event (the shared _is_verified verdict with the
// enforcing halves). A hand-edited registry claiming verification with any
// registered artifact is caught here, exactly like a hand-edited floor
// policy. Message-for-message with audit.py section 11.
//
// G8 harness runs (Task 18) ride along informationally: every invariant
// carrying verification.harness contributes one line to the presence-gated
// "harness_runs" key (uppercase rung label only for proved-bounded), and —
// L-defer T5 — the campaign's stored MiniCertora refusals contribute ONE
// further derived line after those per-invariant lines (the L3 full form:
// a class histogram plus the top reason codes, see proverrefusals.go).
// Campaigns without the field — every golden campaign — serialize
// byte-identically to before (the key is omitted, not emptied).
package sections

import (
	"errors"
	"fmt"
	"os"

	"crypto/sha256"
	"encoding/hex"
	"websec/internal/harness"
	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/validation"
)

// stdoutUnreadableBurn is the ONE refusal for a captured stdout the audit
// could not read: the rung is named, the exec is named, and the errno the
// shared reader observed is carried verbatim. All three rung arms that
// re-derive from stored bytes return exactly this.
func stdoutUnreadableBurn(iid, exec string, err error) string {
	return fmt.Sprintf("%s: exec %s stdout unreadable (%v) — the "+
		"evidence behind the rung cannot be re-checked", iid, exec, err)
}

// stdoutAbsent reports whether a harness.ReadExecStdout failure is the
// documented ABSENCE of the capture — nothing was ever captured
// (ErrNoCapturedStdout), or the file the record names is not there any more
// (a pruned/aged-out witness) — as opposed to a READ failure on a capture
// that IS present. Only the not-exist class is folded into absence; EACCES,
// ENOTDIR and EIO are refusals, the same contract as
// validation.ListPrefixedOptional (r44b P3-b).
func stdoutAbsent(err error) bool {
	if errors.Is(err, harness.ErrNoCapturedStdout) {
		return true
	}
	return errors.Is(err, os.ErrNotExist)
}

// unbackedSuffix qualifies a harness_runs line whose blessing THIS section
// could not back (harnessRungBacked or harnessEvidenceRecheck burned it).
// It closes the line, after every derived clause, and is emitted only on
// that failure — a fully backed rung keeps its historical bytes.
const unbackedSuffix = " (UNBACKED)"

// InvariantVerification is audit.py section 11: {checked, problems, ok}
// plus the presence-gated harness_runs lines: one per invariant carrying a
// well-formed verification.harness object, then — when the campaign stores
// at least one inconclusive MiniCertora record — the one derived refusal
// histogram line (L-defer T5, proverrefusals.go). A line whose own backing
// check burned in this same pass carries the unbackedSuffix.
func InvariantVerification(c *state.Campaign) (validation.Value, error) {
	links, err := invariants.LoadLinks(c)
	if err != nil {
		return validation.Value{}, err
	}
	reg := validation.ObjAt(links, "invariants") // Python .get("invariants", {})
	events, err := c.Events()
	if err != nil {
		return validation.Value{}, err
	}
	var problems []validation.Value
	var runs []validation.Value
	tally := newRefusalTally()
	for _, iid := range sortedObjKeys(reg) {
		e := validation.ObjAt(reg, iid)
		if e.Kind != validation.Obj {
			continue
		}
		line, ok := harnessRunLine(iid, e)
		// r32b F3: harnessRunLine returns ok=false for a slot that STATES
		// a rung while kind or exec is blank — and BOTH backing checks
		// used to live inside `if ok`, so ONE empty string dropped the
		// invariant with no line and NO problem ("audit PASS"). Only a run
		// with no rung at all may be skipped silently; every other
		// required-field blank burns, naming the field.
		if burn := harnessSlotShapeBurn(iid, e); burn != "" {
			problems = append(problems, validation.VStr(burn))
		}
		if ok {
			// r26 D4: the display line and the burn are ONE observation.
			// This section can refuse to back a blessing (a pruned
			// REPORT row, a deleted EXEC) while still printing the
			// unqualified rung — a consumer that reads only
			// harness_runs then sees a blessing the section itself just
			// called unbacked. The qualifier below is driven by the
			// section's OWN two backing checks for THIS invariant
			// (their non-empty return, not a re-grep of problem text),
			// so there is no second derivation to drift.
			unbacked := false
			// r21 F7: the display slot alone used to be beyond reproach —
			// §8's "audit cross-checks claims against events" is NOW
			// true for harness rungs: the CURRENT rung (kind, rung, exec,
			// summary — the summary is the mapper's full rendering, so a
			// hand-edit or an unrecoverable half-land can't match) must
			// appear as the LAST harness_run event for the invariant.
			if msg := harnessRungBacked(events, iid, e); msg != "" {
				problems = append(problems, validation.VStr(msg))
				unbacked = true
			}
			// r24 (sharpest untried idea): the slot↔event rails bind the
			// display to the LEDGER — but a chain-valid forgery edits the
			// events too, and only the EXEC OUTPUT the event names is the
			// original evidence. Re-derive the mapper's numbers from the
			// artifacts at AUDIT time through the BIND'S OWN decision
			// entry point (r28b F3: harness.DecideBound — recorded-hash
			// arm, Validate re-render and unbound suffix included, over
			// the exec stdout, the record's own exit status / timeout bit
			// / invocation bound and the scaffold artifact bytes), while
			// autoprove digests must exist in the registry. A lie then
			// needs the stdout bytes or a registry row to match too —
			// write-time convention becomes an audit-time invariant.
			if msg := harnessEvidenceRecheck(c, events, iid, e); msg != "" {
				problems = append(problems, validation.VStr(msg))
				unbacked = true
			}
			// The qualifier closes the line: after the advice clause
			// (" | next: …") and after the witness label (" | poc: …"),
			// so the rung parenthetical itself stays byte-identical on
			// the happy path.
			if unbacked {
				line += unbackedSuffix
			}
			runs = append(runs, validation.VStr(line))
		}
		tally.add(e)
		if validation.ObjStr(e, "status") != "CHECKED_AGAINST_CODE" {
			continue
		}
		if invariants.IsVerified(e, c, iid, events) {
			continue
		}
		artID := validation.ObjStr(e, "verified_by")
		if artID == "" {
			problems = append(problems, validation.VStr(fmt.Sprintf(
				"%s: CHECKED_AGAINST_CODE without a verified_by artifact", iid)))
			continue
		}
		if _, err := c.Artifact(artID); err != nil {
			problems = append(problems, validation.VStr(fmt.Sprintf(
				"%s: verified_by %s is not a registered artifact",
				iid, validation.PyReprStr(artID))))
			continue
		}
		problems = append(problems, validation.VStr(fmt.Sprintf(
			"%s: verified_by %s has no matching invariant.verified log "+
				"event — hand-edited verification is not verification",
			iid, validation.PyReprStr(artID))))
	}
	out := []validation.KV{
		KV("checked", validation.VInt(int64(len(reg.O)))),
		KV("problems", validation.VArr(problems...)),
		KV("ok", validation.VBool(len(problems) == 0)),
	}
	// The derived refusal histogram closes the run lines: appended AFTER
	// every per-invariant line (one line per invariant, then the tally) and
	// only when an eligible record exists — the per-invariant lines and the
	// key's presence gate are otherwise untouched.
	if line, ok := tally.line(); ok {
		runs = append(runs, validation.VStr(line))
	}
	// Presence-gated: campaigns without a single verification.harness
	// field (every golden campaign) keep the exact historical bytes.
	if len(runs) > 0 {
		out = append(out, KV("harness_runs", validation.VArr(runs...)))
	}
	return validation.VObj(out...), nil
}

// pyKind names a JSON value's shape for drift messages (null != 100 is
// the informative case; "Null vs Int" says it).
func pyKind(v validation.Value) string {
	switch v.Kind {
	case validation.Null:
		return "absent/null"
	case validation.Int:
		return fmt.Sprintf("%d", v.I)
	default:
		return validation.CanonCompact(v)
	}
}

// proofDigest mirrors cli.harnessProofDigest (canonical JSON, sha256):
// two packages, one fingerprint — keep byte-identical.
func proofDigest(proof validation.Value) string {
	sum := sha256.Sum256([]byte(validation.CanonCompact(proof)))
	return hex.EncodeToString(sum[:])
}
