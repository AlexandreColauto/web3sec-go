// gate_probe_anchor.go: the B10(a) CONFIRMED-path forcing function — the
// anchor blind-spot check (docs/feedback-triage-morph-r2.md §B10(a)).
//
// WHY IT EXISTS. The round-1 replay's verdict was throughput, not information:
// both gold shapes sat on tier-0 probe-surface rows that were never
// dispositioned, and the bootstrap's own rule ("any undispositioned row keeps
// the lens OPEN") first bites at end-of-pass LENS closure — a pass that stops
// before the end never meets it. So the teeth go on the CONFIRMED path, where
// the false-positive budget already bites: a finding may not CONFIRM past a
// machine question about the SAME code its own affected[] entries name. The
// HYPOTHESIS side is untouched (NOT-doing #3: discovery volume stays
// unthrottled), and the check is per-finding, so an unrelated blind axis never
// blocks a promotion.
//
// PRESENCE-GATED (byte discipline). The rule needs three artifacts: the
// protocol model (the name→path index anchorlink builds), the probe surface
// (the rows), and the campaign plan (the rows' dispositions). A campaign
// missing ANY of them — or a model anchorlink.Open rejects — SKIPS the check
// ENTIRELY: no clause is appended, so the clause count, the checklist bytes,
// the refusal text and the recorded check_ids are all exactly what they were
// before. That is what keeps existing campaigns (and every findings/cli test
// fixture, none of which carries a probe surface) byte-identical; the pin is
// TestProbeAnchorAbsentArtifactsLeavesClauseSetIdentical.
//
// THE JOIN IS ANCHORLINK'S (B7, shipped and consumed here, never modified).
// FindingTargets resolves this finding's affected[] files onto canonical
// snapshot-relative model paths; RowTargets resolves a surface row onto the
// same key space (its contract plus its siblings[] contracts, with the
// documented basename fan-out). "The SAME code anchor" is therefore an EXACT
// canonical-path intersection — never a basename guess, never a substring, and
// the collision rule is the one B7 documented: a row that cites an ambiguous
// NAME reaches every candidate path, and a finding that pins the path by full
// path is exactly what lets that row join it. Disposition is anchorlink's too
// (Query's RowMatch), which reads the FIRST plan priority that claims the row
// through probe.row_id — the same provenance the planner's own closure gate
// uses, so the gate and the closure sentence can never disagree about which
// rows are open.
//
// RISK COORDINATES ARE THE PLANNER'S. gateHighRiskRow is planner.HighRiskRow
// (the B4 predicate: tier 0 or assertion_gap >= 3, a missing tier reading as
// 0) copied rather than imported — planner imports bounty imports findings, so
// importing planner from here is an import cycle — and pinned against it by
// TestProbeAnchorHighRiskRowMatchesPlanner, so drift fails the build instead of
// silently re-labelling rows. This is the same copy-and-pin the anchorlink
// package uses for planner.ProbeRowDispositioned.
//
// FAIL-OPEN ON A BROKEN ARTIFACT. A present-but-unreadable model/surface/plan
// skips the check too, the same fail-open the planner's own model loader takes
// ("the protocol model, or an empty object when it is absent/unreadable").
// This check is a forcing function, not an integrity check: a corrupt artifact
// must not become a new way for a CONFIRMED transition to fail with an error
// the operator cannot act on. The cost is a silent false negative, recorded
// here deliberately.
package findings

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"websec/internal/anchorlink"
	"websec/internal/state"
	"websec/internal/validation"
)

// ProbeAnchorCheckID is the check id B10(a) adds to the CONFIRMED gate. One
// clause is emitted PER undispositioned row, qualified by the row id as its
// subject — the shape invariant-unverified uses for its per-invariant clauses.
const ProbeAnchorCheckID = "probe-surface-undispositioned"

// AnchorBlindSpot is one undispositioned high-risk probe-surface row that
// cites a code anchor this finding's own affected[] entries name.
type AnchorBlindSpot struct {
	// RowID is the surface row's row_id, and the clause's subject.
	RowID string
	// Path is the canonical model path the row and this finding both name.
	Path string
	// Tier and AssertionGap are the row's own risk coordinates, as stored.
	Tier         int
	AssertionGap int
	// PriorityID is the plan priority that claims the row through
	// probe.row_id; "" when the surface row was never emitted as a priority
	// (the morph handoff's common case: 40 rows, 0 dispositioned).
	PriorityID string
	// Disposition is that priority's status, or "undispositioned" when no
	// priority claims the row.
	Disposition string
}

// Heal is the exact command that clears this row's clause: the probe-row
// disposition form `answered <campaign> <priority> <status> --reason …
// --anchor …` (planner.checkAnchorless: a probe row's closure must name the
// field it claims is safe, so --anchor is not optional). A row no priority
// claims cannot be answered yet — there is no Q-* id to name — so the heal
// starts with the emit that mints one.
func (s AnchorBlindSpot) Heal(campaignID string) string {
	prio := s.PriorityID
	if prio == "" {
		prio = "<Q-id>"
	}
	answer := "webv2 answered " + campaignID + " " + prio + " answered " +
		"--reason '<why row " + s.RowID + " is safe — cite the row's own " +
		"code>' --anchor <field>"
	if s.PriorityID != "" {
		return answer
	}
	return "webv2 probes " + campaignID + " run --emit   (mint the Q-* " +
		"priority that claims row " + s.RowID + ") then " + answer
}

// Message is the diagnosis: which row, how risky it is, and the anchor it
// shares with this finding. The remediation is Heal's command; the two are
// split so the gate renders them in its usual "✗ <id>: <why>" + "fix: <cmd>"
// shape.
func (s AnchorBlindSpot) Message() string {
	return fmt.Sprintf("undispositioned probe-surface row %s (tier %d, "+
		"assertion_gap %d) cites this finding's own anchor %s — the machine "+
		"question about the same code is unanswered, so CONFIRMED would be "+
		"claimed past an open row", s.RowID, s.Tier, s.AssertionGap, s.Path)
}

// ProbeAnchorBlindSpots is the ONE checker: `webv2 gate <C> <F>` renders it
// (through ConfirmationGateClauses) and the enforcing `move … CONFIRMED` path
// reads the same clauses, so the dry run and the refusal can never disagree.
//
// ok == false means the check is SKIPPED ENTIRELY — the campaign carries no
// protocol model, no probe surface, or no campaign plan, or the model does not
// index. ok == true with an empty slice means the check RAN and found nothing
// to answer, which is a satisfied clause, not a skip.
func ProbeAnchorBlindSpots(campaign *state.Campaign,
	finding validation.Value) ([]AnchorBlindSpot, bool) {
	if campaign == nil {
		return nil, false
	}
	model, present := readGateArtifact(campaign, "protocol_model.json")
	if !present {
		return nil, false
	}
	surface, present := readGateArtifact(campaign, "probe_surface.json")
	if !present {
		return nil, false
	}
	plan, present := readGateArtifact(campaign, "campaign_plan.json")
	if !present {
		return nil, false
	}
	store, err := anchorlink.Open(model)
	if err != nil {
		return nil, false
	}
	rows := gateObjList(surface, "rows")
	// The finding in hand is the findings store this join needs: B10(a) asks
	// only about THIS finding's own affected[] anchors.
	store.Index(rows, gateObjList(plan, "priorities"),
		[]validation.Value{finding})
	targets := map[string]bool{}
	for _, p := range store.FindingTargets(finding) {
		targets[p] = true
	}
	if len(targets) == 0 {
		// The artifacts are all here, but this finding anchors nothing the
		// model knows: there is no shared anchor to be blind about.
		return nil, true
	}
	byRowID := map[string]validation.Value{}
	for _, row := range rows {
		id := validation.ObjStr(row, "row_id")
		if id == "" {
			continue
		}
		if _, dup := byRowID[id]; !dup {
			byRowID[id] = row
		}
	}
	paths := make([]string, 0, len(targets))
	for p := range targets {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	seen := map[string]bool{}
	out := []AnchorBlindSpot{}
	for _, path := range paths {
		for _, m := range store.Query(path).Rows {
			if seen[m.RowID] {
				continue
			}
			row, known := byRowID[m.RowID]
			if !known {
				// A row the surface carries but the id table does not:
				// nothing to cite, so nothing to ask about.
				continue
			}
			if !gateRowCitesTarget(store, row, targets) {
				// Query's path rule is deliberately looser than the join
				// (a search widens; an anchor must not), so the exact
				// canonical-path intersection decides.
				continue
			}
			seen[m.RowID] = true
			if m.Dispositioned || !gateHighRiskRow(row) {
				continue
			}
			out = append(out, AnchorBlindSpot{
				RowID:        m.RowID,
				Path:         path,
				Tier:         gateObjInt(row, "tier"),
				AssertionGap: gateObjInt(row, "assertion_gap"),
				PriorityID:   gateRowPriorityID(plan, m.RowID),
				Disposition:  m.Disposition,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RowID != out[j].RowID {
			return out[i].RowID < out[j].RowID
		}
		return out[i].Path < out[j].Path
	})
	return out, true
}

// gateRowCitesTarget reports whether the row resolves onto one of the
// finding's canonical anchors. This is the EXACT intersection the collision
// rule requires: RowTargets already fanned an ambiguous contract name out to
// every candidate path, and a finding that pinned one of those paths by full
// path is what makes the join real.
func gateRowCitesTarget(store *anchorlink.Store, row validation.Value,
	targets map[string]bool) bool {
	paths, _ := store.RowTargets(row)
	for _, p := range paths {
		if targets[p] {
			return true
		}
	}
	return false
}

// gateRowPriorityID is the id of the first plan priority that claims the row
// through probe.row_id — anchorlink's disposition rule, repeated here only to
// name the id in the heal (anchorlink exposes the disposition, not its
// source). "" when no priority claims the row.
func gateRowPriorityID(plan validation.Value, rowID string) string {
	for _, p := range gateObjList(plan, "priorities") {
		prov := validation.ObjAt(p, "probe")
		if prov.Kind != validation.Obj || validation.ObjStr(prov, "row_id") != rowID {
			continue
		}
		return validation.ObjStr(p, "id")
	}
	return ""
}

// readGateArtifact reads one campaign artifact and reports whether it is
// there to read. An absent OR unreadable artifact reads as not-present: the
// check is presence-gated on the artifact, and a corrupt file must not turn a
// forcing function into a new refusal (see the file header).
func readGateArtifact(c *state.Campaign, name string) (validation.Value, bool) {
	path := filepath.Join(c.ArtifactsDir, name)
	if _, err := os.Stat(path); err != nil {
		return validation.VNull(), false
	}
	v, err := validation.ReadJson(path)
	if err != nil {
		return validation.VNull(), false
	}
	return v, true
}

// gateObjList is obj[key] as a list (empty when absent or not an array).
func gateObjList(obj validation.Value, key string) []validation.Value {
	v := validation.ObjAt(obj, key)
	if v.Kind != validation.Arr {
		return nil
	}
	return v.A
}

// gateObjInt reads an integer field (0 when absent), for the two coordinates
// the message quotes.
func gateObjInt(obj validation.Value, key string) int {
	v := validation.ObjAt(obj, key)
	switch v.Kind {
	case validation.Int:
		return int(v.I)
	case validation.Flt:
		return int(v.F)
	}
	return 0
}

// gateHighRiskRow is planner.HighRiskRow (B4): tier 0 — the probe's most
// serious claim — or assertion_gap >= 3 — the row asserts far beyond its
// evidence. A missing tier reads as tier 0, the linter erring toward caution.
// Copied, not imported: planner -> bounty -> findings is an import cycle. The
// copy is pinned by TestProbeAnchorHighRiskRowMatchesPlanner.
func gateHighRiskRow(row validation.Value) bool {
	return gateObjInt(row, "tier") == 0 || gateObjInt(row, "assertion_gap") >= 3
}
