package cli

// supersede_discovery.go: wave N, T5 — supersede DISCOVERABILITY.
//
// WHY: a campaign can hold two rows for one bug (a manual self-duplicate: the
// same root-cause class on the same affected path, filed twice). No dedup tier
// proves those rows equal — tier 1 needs the whole technical signature, tiers
// 2/3 need an LLM-written signature the operator may not have set — so the
// sweep reports "untouched" and the operator's remaining lever looks like an
// adjudication. Adjudicating the copy false-positive is the WRONG lever: it
// writes "the finding is wrong" when the truth is "the row is a second copy of
// a finding I already have", and it drags the campaign's precision down with a
// verdict that was never about the bug. `supersede` already exists and is the
// honest op (the retired row leaves the live set WITH its evidence copied
// forward), so this file's whole job is to make it discoverable at the two
// moments the operator is about to reach for the wrong one:
//
//  1. `dedup` on a zero-action sweep (dedupZeroActionHint) — nothing merged,
//     nothing flagged, and the operator reads "untouched" as "nothing to do".
//  2. the ACCEPTED false-positive adjudication whose target duplicates another
//     LIVE finding (selfDuplicateNudge) — the wrong lever, one keystroke away.
//
// Both are ADVISORY, one line, deterministic, no color. Neither writes
// anything, neither refuses anything, and neither changes a byte of the
// machine-readable report: stdout stays the port-parity JSON/accounting the
// verbs already print, and both lines go to stderr, like every other operator
// notice in this CLI (mint's notice, verify's layout note, ingest's hints).
//
// The controller ruling this file implements (plan
// docs/superpowers/plans/2026-09-13-wave-n-operator-friction.md, T5) is
// explicit that NO basis vocabulary changes: there is no `duplicate`
// adjudication basis. A second exclusion path would hide double-booked rows
// from the precision denominator without retiring them, which silently
// inflates the score — the discovery line points at the ONE path that does the
// bookkeeping honestly.

import (
	"fmt"

	"websec/internal/evalscore"
	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// dedupZeroActionHint is the discovery line for a sweep that touched nothing.
// The wording is pinned VERBATIM by the plan (T5): it names the op, shows the
// argv shape, and says why the tempting alternative costs precision.
const dedupZeroActionHint = "manual self-duplicates: webv2 supersede <C> " +
	"F-new --of F-old retires a copy WITH evidence copied — adjudicating it " +
	"false-positive costs you precision instead"

// dedupActionKeys are the report's four action arrays, in the order
// buildReport emits them. A non-empty ANY of them means the sweep DID
// something, and the discovery line has nothing to add.
var dedupActionKeys = []string{"tier1_merges", "tier2_clusters",
	"tier3_flags", "cross_snapshot_flags"}

// dedupDiscoveryHint returns the one discovery line for a dedup report that
// records NO action, or "" when the sweep touched something (and for a sweep
// over a campaign with no live finding at all: "manual self-duplicates" over
// an empty finding set would name a duplicate that cannot exist).
//
// The predicate reads only the report the command already printed, so it can
// never disagree with what the operator sees, and it is order-free.
func dedupDiscoveryHint(report validation.Value, liveFindings int) string {
	// A self-duplicate needs at least two rows to exist; teaching the op on
	// a lone finding is noise (critic I-7), and the nudge's sibling rule in
	// the adjudicate path already refuses single-finding campaigns.
	if liveFindings < 2 {
		return ""
	}
	for _, k := range dedupActionKeys {
		if len(validation.ObjAt(report, k).A) > 0 {
			return ""
		}
	}
	if objInt(report, "untouched") == 0 {
		return ""
	}
	return dedupZeroActionHint
}

// adjudicateFalsePositive is evalscore's unexported verdictFalsePositive,
// restated here because the nudge is a rendering concern of THIS package
// (evalscore.Verdicts is the exported enum this value must stay a member of).
const adjudicateFalsePositive = "false-positive"

// selfDuplicateKey is the duplication key the nudge matches on:
// (root_cause.class, affected[0].path) — the two anchor keys the eval join and
// the operator's eye both use. It is deliberately NARROWER than dedup's tier-1
// signature (which also folds in the function and the invariant) and wider
// than nothing: the pair names "the same kind of bug in the same file", which
// is exactly the case supersede exists for and exactly the case where an FP
// verdict is ambiguous between "wrong" and "second copy".
//
// "" means the key is unusable (no class, no affected[0].path): two findings
// that both lack a class are NOT duplicates of each other, so they must never
// match — the empty key is refused rather than compared.
func selfDuplicateKey(f validation.Value) string {
	class := validation.ObjStr(validation.ObjAt(f, "root_cause"), "class")
	affected := validation.ObjAt(f, "affected")
	if affected.Kind != validation.Arr || len(affected.A) == 0 {
		return ""
	}
	path := validation.ObjStr(affected.A[0], "path")
	if class == "" || path == "" {
		return ""
	}
	return class + "\x00" + path
}

// selfDuplicateNudge returns the stderr nudge for an ACCEPTED false-positive
// adjudication, or "" when there is nothing to point at.
//
// Contract (plan T5), each clause deliberate:
//
//   - only the false-positive verdict: the other two verdicts never claim the
//     finding is wrong, so no copy-bookkeeping advice applies.
//   - the twin set is the campaign's LIVE findings (findings.LoadLiveFindings
//     — the same predicate evalscore.Record gates the adjudication on, so the
//     nudge can never call a finding live that the verb would refuse), minus
//     the adjudicated finding itself. The row that was just recorded is still
//     live, so a self-match is the one match that must be excluded: it would
//     fire on every single-finding campaign.
//   - the id is the LOWEST matching finding_id (deterministic: LoadLiveFindings
//     is ordered by (created_at, finding_id), but the choice must not depend on
//     file order, and a campaign with three copies must name the same twin on
//     every run).
//   - fail-open: a finding read that errors (or a target whose key cannot be
//     built) yields "" — an advisory must never turn an ACCEPTED adjudication
//     into a failed command.
//
// It writes nothing and refuses nothing: the verdict is recorded before this
// is called, and the message says so ("FP stays recorded either way").
func selfDuplicateNudge(c *state.Campaign, rec evalscore.Adjudication) string {
	if rec.Verdict != adjudicateFalsePositive {
		return ""
	}
	live, err := findings.LoadLiveFindings(c)
	if err != nil {
		return ""
	}
	key := ""
	for _, f := range live {
		if validation.ObjStr(f, "finding_id") == rec.Finding {
			key = selfDuplicateKey(f)
			break
		}
	}
	if key == "" {
		return ""
	}
	twin := ""
	for _, f := range live {
		id := validation.ObjStr(f, "finding_id")
		if id == "" || id == rec.Finding {
			continue
		}
		if selfDuplicateKey(f) != key {
			continue
		}
		if twin == "" || id < twin {
			twin = id
		}
	}
	if twin == "" {
		return ""
	}
	return fmt.Sprintf("this looks like a self-duplicate of %s: webv2 "+
		"supersede may be the honest op — FP stays recorded either way", twin)
}
