// Closing report sections: confirmed finding sections, proven and
// unproven chains, the dismissed roster, dismissed-with-reach,
// disposition review and the learning queue.
package report

import (
	"fmt"
	"sort"
	"strings"
	"websec/internal/capabilities"
	"websec/internal/findings"
	"websec/internal/planner"
	"websec/internal/validation"
)

// writeConfirmedSections renders one finding section per CONFIRMED finding,
// ordered by descending risk score.
func (r *reportBuilder) writeConfirmedSections() error {
	sortedConfirmed := append([]validation.Value{}, r.confirmed...)
	sort.SliceStable(sortedConfirmed, func(i, j int) bool {
		return riskScore(sortedConfirmed[i]) > riskScore(sortedConfirmed[j])
	})
	for _, f := range sortedConfirmed {
		sec, err := findingSection(r.campaign, f, "CONFIRMED", r.all)
		if err != nil {
			return err
		}
		r.L = append(r.L, sec...)
	}
	return nil
}

// writeProvenChains renders one CHAIN section per evidence-confirmed chain.
func (r *reportBuilder) writeProvenChains() {
	for _, ch := range r.provenChains {
		var sf validation.Value
		foundSF := false
		for _, f := range r.chainF {
			if validation.ObjStr(validation.ObjAt(f, "dedup_meta"), "chain_id") == validation.ObjStr(ch, "chain_id") {
				sf = f
				foundSF = true
				break
			}
		}
		r.L = append(r.L, fmt.Sprintf("### CHAIN: %s", validation.ObjStr(ch, "title")))
		r.L = append(r.L, "")
		r.L = append(r.L, fmt.Sprintf("- id: `%s` — status %s, evidence floor %s",
			validation.ObjStr(ch, "chain_id"), validation.ObjStr(ch, "status"),
			validation.PyStr(validation.ObjAt(ch, "evidence_floor"))))
		quoted := []string{}
		for _, m := range strList(validation.ObjAt(ch, "members")) {
			quoted = append(quoted, "`"+m+"`")
		}
		r.L = append(r.L, "- members: "+strings.Join(quoted, ", "))
		if validation.ObjStr(ch, "narrative") != "" {
			r.L = append(r.L, "- narrative: "+validation.ObjStr(ch, "narrative"))
		}
		for _, lnk := range listAt(ch, "capability_links") {
			r.L = append(r.L, fmt.Sprintf("- `%s` grants *%s* → `%s` requires it",
				validation.ObjStr(lnk, "from_finding"), validation.ObjStr(lnk, "granted"),
				validation.ObjStr(lnk, "to_finding")))
		}
		if foundSF {
			r.L = append(r.L, fmt.Sprintf("- super-finding: `%s`",
				validation.ObjStr(sf, "finding_id")))
		}
		r.L = append(r.L, "")
	}
}

// writeUnprovenChains renders the B3 unproven (hypothesis-level) chains in
// their own clearly marked section — never the CHAIN: heading, never the
// submission count. Each hop carries its member's evidence level.
// Presence-gated: a campaign without an unproven chain gains no bytes.
func (r *reportBuilder) writeUnprovenChains() {
	if len(r.unprovenChains) > 0 {
		r.L = append(r.L, "## Unproven chains (hypothesis-level)")
		r.L = append(r.L, "")
		r.L = append(r.L, "These are LEADS, not results: at least one member is "+
			"not independently CONFIRMED, so nothing here counts as "+
			"evidence-confirmed and nothing here enters the submission table.")
		r.L = append(r.L, "")
		for _, ch := range r.unprovenChains {
			r.L = append(r.L, fmt.Sprintf("### UNPROVEN CHAIN: %s", validation.ObjStr(ch, "title")))
			r.L = append(r.L, "")
			r.L = append(r.L, fmt.Sprintf("- id: `%s` — provenance %s, evidence floor %s",
				validation.ObjStr(ch, "chain_id"), validation.PyStr(validation.ObjAt(ch, "provenance")),
				validation.PyStr(validation.ObjAt(ch, "evidence_floor"))))
			quoted := []string{}
			for _, m := range strList(validation.ObjAt(ch, "members")) {
				quoted = append(quoted, "`"+m+"`")
			}
			r.L = append(r.L, "- members: "+strings.Join(quoted, ", "))
			if validation.ObjStr(ch, "narrative") != "" {
				r.L = append(r.L, "- narrative: "+validation.ObjStr(ch, "narrative"))
			}
			for _, lnk := range listAt(ch, "capability_links") {
				line := fmt.Sprintf("- `%s` grants *%s* → `%s` requires it",
					validation.ObjStr(lnk, "from_finding"), validation.ObjStr(lnk, "granted"),
					validation.ObjStr(lnk, "to_finding"))
				if lvl := validation.ObjStr(lnk, "link_evidence"); lvl != "" {
					line += " (from-member evidence " + lvl + ")"
				}
				r.L = append(r.L, line)
			}
			if t := validation.AsObj(validation.ObjAt(ch, "terminal")); len(t.O) > 0 {
				// An unproven chain has no super-finding, hence no
				// economic_impact: the terminal is the LEAD's destination.
				// State the price that would apply, and that it is not
				// asserted here — a hypothesis must not carry a number.
				cap := validation.ObjStr(t, "capability")
				note := "UNPROVEN: this is the lead's destination, not a " +
					"priced result — no price or capital figure is asserted " +
					"for a hypothesis-level chain"
				if capabilities.IsLivenessTerminal(cap) {
					note = "UNPROVEN: a liveness freeze would price at the " +
						"blast-radius floor (no USD figure is defensible), " +
						"but this chain is a hypothesis-level lead, so no " +
						"price is asserted"
				}
				r.L = append(r.L, fmt.Sprintf("- terminal: *%s* via `%s` — %s",
					cap, validation.ObjStr(t, "via_finding"), note))
			}
			r.L = append(r.L, "")
		}
	}
}

// writeDismissed renders the dismissed-candidates roster with reasons.
func (r *reportBuilder) writeDismissed() {
	dismissed := []validation.Value{}
	// r6 (critic issue 4): INFORMATIONAL was missing here — an informational
	// row rendered in the tables above but never in "dismissed candidates
	// (with reasons)", so its recorded dismissal reason went unread. This
	// roster is DELIBERATELY not dismissedTerminalStatuses (supersession is
	// correction, not dismissal — but a superseded row's move reason still
	// belongs in the table); the fix is the missing state, not a merge.
	// r12: this roster IS the framework's terminal set (r6's addition
	// completed it) — a hand list that only ever drifts now, so it asks
	// the law itself. SUPERSEDED stays by the law's own definition; the
	// r6 comment above stands.
	for _, f := range r.all {
		if findings.IsTerminal(validation.ObjStr(f, "status")) {
			dismissed = append(dismissed, f)
		}
	}
	if len(dismissed) > 0 {
		r.L = append(r.L, "## Dismissed candidates (with reasons)")
		r.L = append(r.L, "")
		for _, f := range dismissed {
			hist := listAt(f, "history")
			last := validation.VObj()
			if len(hist) > 0 {
				last = validation.AsObj(hist[len(hist)-1])
			}
			r.L = append(r.L, fmt.Sprintf("- `%s` **%s** — %s",
				validation.ObjStr(f, "finding_id"), validation.ObjStr(f, "status"), validation.ObjStr(f, "title")))
			reason := "n/a"
			if v := validation.ObjAt(last, "reason"); v.Kind != validation.Null {
				reason = validation.PyStr(v)
			}
			r.L = append(r.L, "  - reason: "+reason)
		}
		r.L = append(r.L, "")
	}
}

// writeDismissedWithReach appends the dismissed-with-strong-reaching
// subsection: the false-negative direction of the dismissal area. A
// dismissed finding a high-risk probe row still reaches is the queue
// nobody asked for: the row says "look here" and the finding says "never
// mind". Presence-gated (the additive convention): renders only when (a)
// at least one finding carries a terminal-dismissal status and (b) at
// least one high-risk probe row reaches a dismissed finding — otherwise
// the campaign gains no bytes.
func (r *reportBuilder) writeDismissedWithReach() {
	if reach := dismissedWithReach(r.campaign, r.all); len(reach) > 0 {
		r.L = append(r.L, reach...)
	}
}

// writeDispositionReview renders the B4 disposition review: high-risk probe
// rows dismissed with dismissal vocabulary, plus the explicit overrides of
// that gate. Presence-gated (the additive convention): it renders only when
// something was flagged or overridden, so a campaign with clean closures
// gains no bytes.
func (r *reportBuilder) writeDispositionReview() {
	var flags []planner.DismissalFlag
	var dispErr error
	if planV, perr := planner.LoadPlanReadonly(r.campaign); perr == nil {
		flags, dispErr = planner.DispositionReview(r.campaign, planV)
	}
	overrides := []validation.Value{}
	if evts, eerr := r.campaign.Events(); eerr == nil {
		for _, e := range evts {
			if validation.ObjStr(e, "type") == "probe.dismissal_overridden" {
				overrides = append(overrides, e)
			}
		}
	}
	if dispErr == nil && (len(flags) > 0 || len(overrides) > 0) {
		r.L = append(r.L, "## Disposition review")
		r.L = append(r.L, "")
		for _, f := range flags {
			r.L = append(r.L, fmt.Sprintf("- `%s` (row %s, tier %d, gap %d): %s — dismissal vocabulary: %s",
				f.Priority, f.RowID, f.Tier, f.Gap, f.Reason,
				strings.Join(f.Phrases, ", ")))
		}
		for _, e := range overrides {
			data := validation.ObjAt(e, "data")
			r.L = append(r.L, fmt.Sprintf("- OVERRIDDEN `%s` (row %s) by %s: %s",
				validation.ObjStr(e, "ref"), validation.ObjStr(data, "row_id"),
				validation.ObjStr(data, "actor"),
				validation.ObjStr(data, "override_reason")))
		}
		r.L = append(r.L, "")
	}
}

// writeLearningQueue renders the learning-memory table and the pending
// approval note, presence-gated on any memory entries.
func (r *reportBuilder) writeLearningQueue() {
	if len(r.mem) > 0 {
		r.L = append(r.L, "## Learning queue")
		r.L = append(r.L, "")
		r.L = append(r.L, "| id | kind | status | promotion |")
		r.L = append(r.L, "|---|---|---|---|")
		for _, m := range r.mem {
			r.L = append(r.L, fmt.Sprintf("| `%s` | %s | %s | %s |",
				validation.ObjStr(m, "memory_id"), validation.ObjStr(m, "kind"), validation.ObjStr(m, "status"),
				validation.ObjStr(m, "promotion_status")))
		}
		pending := 0
		for _, m := range r.mem {
			if validation.ObjStr(m, "promotion_status") == "pending" {
				pending++
			}
		}
		if pending > 0 {
			r.L = append(r.L, "")
			r.L = append(r.L, fmt.Sprintf("> %d candidate(s) awaiting human "+
				"approval — nothing enters long-term memory without it.",
				pending))
		}
		r.L = append(r.L, "")
	}
}
