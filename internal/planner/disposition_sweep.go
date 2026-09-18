// disposition_sweep.go: the FIX-5 reverse sweep — closures recorded
// before the deferred-consequence gate existed whose reason vocabulary
// implies a failure consequence. It reports, it never mutates.
package planner

import (
	"regexp"
	"slices"
	"websec/internal/state"
	"websec/internal/validation"
)

// ---------------------------------------------------------------------------
// FIX-5, second half: the reverse sweep. Closures recorded before the gate
// existed (or through its override) can still carry the tell: a tier-0
// closure whose reason vocabulary implies a failure consequence — the row
// stays unfinalizable, funds strand, the pool freezes — priced as if the
// consequence were someone else's problem. The sweep lists them and demands
// the re-answer (a finding ref or an --interim statement); it REPORTS, it
// never mutates.
// ---------------------------------------------------------------------------

// DeferredConsequenceTokens is the sweep vocabulary: whole-word tokens that,
// in a high-risk closure's reason, describe what happens if the deferred
// check never runs — the exact tell the G-01 disposition carried.
var DeferredConsequenceTokens = []string{
	"unfinalizable", "strand", "stranded", "freeze", "frozen",
	"revert-forever", "permanently revert", "owner-clears", "owner clears",
}

// deferredTokenRes compiles the vocabulary once: whole-word (a token inside a
// larger word is prose, not the tell), case-insensitive, in table order.
var deferredTokenRes = func() []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(DeferredConsequenceTokens))
	for i, tok := range DeferredConsequenceTokens {
		out[i] = regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(tok) + `\b`)
	}
	return out
}()

// DeferredHits scans a reason for the sweep vocabulary (whole-word,
// case-insensitive) and returns the tokens that hit, in table order
// ([] when clean).
func DeferredHits(reason string) []string {
	hits := []string{}
	for i, re := range deferredTokenRes {
		if re.MatchString(reason) {
			hits = append(hits, DeferredConsequenceTokens[i])
		}
	}
	return hits
}

// DeferredFlag is one flagged closure of the reverse sweep: a high-risk row
// dispositioned on failure-consequence vocabulary with no interim pricing.
type DeferredFlag struct {
	Priority string
	RowID    string
	Tier     int64
	Gap      int64
	Reason   string
	Tokens   []string
}

// DeferredConsequenceReview is the FIX-5 reverse sweep: every dispositioned
// probe row whose closure reason uses the failure-consequence vocabulary on a
// high-risk row and that records no interim pricing (no interim statement, no
// interim_finding — the two exits the gate now demands). It REPORTS — it
// never mutates: the closures it lists were recorded before the gate existed,
// and the fix is a re-answer, which only the operator can make. Rows that
// cannot be resolved against the current surface (the surface was re-emitted
// after the closure) are NOT silently dropped: they come back as the second
// return value (FIX-3), each as "PRIORITY (probe row ROWID)", so the CLI can
// print the skip — the risk rank is the surface's, not the plan's, but the
// reader decides what that is worth.
func DeferredConsequenceReview(campaign *state.Campaign,
	plan validation.Value) ([]DeferredFlag, []string, error) {
	surface, err := PB().CampaignSurface(campaign)
	if err != nil {
		return nil, nil, err
	}
	flags := []DeferredFlag{}
	skipped := []string{}
	for _, p := range listOf(plan, "priorities") {
		prov, hasProv := probeProvenance(p)
		if !hasProv ||
			!slices.Contains(ProbeRowDispositioned, validation.ObjStr(p, "status")) {
			continue
		}
		reason := validation.ObjStr(p, "closed_reason")
		if reason == "" {
			continue
		}
		// already priced: an interim statement or a finding ref recorded on
		// the priority is the fix this sweep asks for
		if hasKey(p, "interim") || hasKey(p, "interim_finding") {
			continue
		}
		tokens := DeferredHits(reason)
		if len(tokens) == 0 {
			continue
		}
		skippedEntry := validation.ObjStr(p, "id") + " (probe row " +
			validation.ObjStr(prov, "row_id") + ")"
		if surface == nil {
			skipped = append(skipped, skippedEntry)
			continue
		}
		row, ok := findRow(*surface, validation.ObjStr(prov, "row_id"))
		if !ok {
			skipped = append(skipped, skippedEntry)
			continue
		}
		if !HighRiskRow(row) {
			continue
		}
		flags = append(flags, DeferredFlag{
			Priority: validation.ObjStr(p, "id"),
			RowID:    validation.ObjStr(prov, "row_id"),
			Tier:     rowInt(row, "tier"),
			Gap:      rowInt(row, "assertion_gap"),
			Reason:   reason,
			Tokens:   tokens,
		})
	}
	return flags, skipped, nil
}
