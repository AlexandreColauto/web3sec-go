package briefing

import (
	"fmt"
	"sort"
	"strings"

	"websec/internal/completion"
	"websec/internal/planner"
	"websec/internal/probes"
	"websec/internal/validation"
)

// nextActionsClosed renders the closed-pass branch: the integrity-first
// doctor line, the completion summary and the open completion proofs. It
// reports whether the pass was closed — the action list is then final.
func (n *nextActionsCtx) nextActionsClosed() (bool, error) {
	if objBool(n.cb, "closed") {
		cid := n.campaign.CampaignID
		if validation.ObjAt(n.integ, "ok").Kind == validation.Bool && !validation.ObjAt(n.integ, "ok").B {
			n.actions = append(n.actions, webv2Action("webv2 doctor "+cid,
				"FIX INTEGRITY FIRST — trust issue, fix even though the "+
					"pass is closed: "+integrityDetail(n.integ)))
		}
		st, err := n.campaign.State()
		if err != nil {
			return false, err
		}
		who := validation.ObjStr(st, "completed_by")
		if who == "" {
			who = "operator"
		}
		why := validation.ObjStr(st, "completed_reason")
		if why == "" {
			why = "no reason recorded"
		}
		n.actions = append(n.actions, webv2Action("webv2 status "+cid,
			fmt.Sprintf("pass marked COMPLETE by %s — %s; the pass is "+
				"closed by decision — resume by running a stage command, "+
				"e.g. webv2 run", who, why)))
		proofs, err := completion.AllProofStatus(n.campaign)
		if err != nil {
			return false, err
		}
		openProofs := []string{}
		for _, pr := range proofs.O {
			if pr.V.Kind != validation.Obj {
				continue
			}
			if !objBool(pr.V, "authoritative") || objBool(pr.V, "done") {
				continue
			}
			openProofs = append(openProofs, pr.K)
		}
		limit := len(openProofs)
		if limit > 6 {
			limit = 6
		}
		for _, stage := range openProofs[:limit] {
			// the per-proof missing-item prose the old line inlined is
			// exactly what `prove --stage` prints (Task 7's trade-off)
			n.actions = append(n.actions, webv2Action(
				"webv2 prove "+cid+" --stage "+stage,
				"open completion proof — noted, NOT blocking"))
		}
		return true, nil
	}
	return false, nil
}

// nextActionsColdProbe appends the Task 11 cold-probe-surface line.
func (n *nextActionsCtx) nextActionsColdProbe() {
	// Task 11: the cold probe surface. DISCOVERY is the phase whose whole
	// point is a mechanical pass over the probe surface, and every later
	// gate reads what that pass emitted — a campaign running DISCOVERY with
	// no `probes run --emit` on record is working an unprobed surface. The
	// line is standing and advisory: it names the exact command and clears
	// the moment the emit is on record. It gates nothing.
	if n.campaign != nil && validation.ObjStr(n.cb, "phase") == "DISCOVERY" {
		if emitted, err := probes.Emitted(n.campaign); err == nil && !emitted {
			n.actions = append(n.actions, webv2Action(
				"webv2 probes "+n.cid+" run --emit",
				"cold probe surface — DISCOVERY is running with no probe "+
					"emit on record, so the mechanical surface is unprobed"))
		}
	}
}

// nextActionsReachability appends the Task 3 evidence-reachability line.
func (n *nextActionsCtx) nextActionsReachability() error {
	// Task 3 (defect 5): evidence reachability. G-01's accepted classes floor
	// at E4 (dos-griefing, logic-error) and this box reaches E4 locally — the
	// cockpit never said so, so CONFIRMED read as out of reach when it was
	// not. Rendered immediately after the cold-probe warning; advisory only
	// (no gate, proof or phase transition reads it) and silent when no open
	// finding carries a class.
	if n.campaign != nil {
		classes, err := openFindingClasses(n.campaign)
		if err != nil {
			return err
		}
		if line := ReachabilityLine(classes, boxLocalCap); line != "" {
			n.actions = append(n.actions, line)
		}
	}
	return nil
}

// nextActionsProbeRows renders the probe-surface section: the ranked open
// rows lead, promoted rows mint an `answered` obligation, the rest mint an
// emit.
func (n *nextActionsCtx) nextActionsProbeRows() {
	// probe surface: the ranked open rows lead
	if ps := validation.ObjAt(n.brief, "probe_surface"); ps.Kind == validation.Obj {
		rows := listAt(ps, "open_rows")
		sorted := append([]validation.Value{}, rows...)
		sort.SliceStable(sorted, func(i, j int) bool {
			return probes.RankKeyOf(sorted[i]).Less(probes.RankKeyOf(sorted[j]))
		})
		for _, r := range sorted {
			rid := validation.ObjStr(r, "row_id")
			where := orQuestion(validation.ObjStr(r, "lens")) + " " +
				orQuestion(validation.ObjStr(r, "axis"))
			name := validation.ObjStr(r, "name")
			if name == "" {
				name = validation.ObjStr(r, "probe")
			}
			if validation.ObjAt(r, "priority_id").Kind == validation.Str &&
				validation.ObjAt(r, "priority_id").S != "" {
				why := strings.Join(strings.Fields(validation.ObjStr(r, "why")), " ")
				if len([]rune(why)) > 80 {
					why = string([]rune(why)[:77]) + "…"
				}
				// a promoted row IS a plan priority: the attention queue
				// works its oldest untouched question with the same verb
				n.actions = append(n.actions, webv2Action("webv2 answered "+n.cid+
					" "+validation.ObjStr(r, "priority_id")+
					" answered --reason <reason> --actor <actor>",
					fmt.Sprintf("work probe row %s — %s: %s — %s",
						rid, where, name, why)))
			} else {
				n.actions = append(n.actions, webv2Action(
					"webv2 probes "+n.cid+" run --emit",
					fmt.Sprintf("emit probe row %s — %s: %s — emitting it "+
						"turns it into a plan obligation", rid, where, name)))
			}
		}
	}
}

// nextActionsLensRouting renders the M6 per-lens routing lines.
func (n *nextActionsCtx) nextActionsLensRouting() {
	// M6 (framework eval): an untouched lens names its mechanical table.
	// The G-01 miss showed the failure mode — the brief nagged "questions
	// worked 0/48" but never said L-03 was the unworked street nor that
	// `enforce prevStateRoot` walks it. Per-lens probe closure already
	// rides the brief's divergence block, so a lens with open rows and
	// zero dispositions gets one routing line to the table that reads the
	// structural index directly (no surface needed). L-02 has no table
	// verb — its trust rows are already listed per-row above.
	if div := validation.ObjAt(n.brief, "divergence"); div.Kind == validation.Obj {
		for _, l := range listAt(div, "lenses") {
			lid := validation.ObjStr(l, "id")
			table, ok := lensMechanicalTable[lid]
			if !ok || lensDispositioned(validation.ObjStr(l, "status")) {
				continue
			}
			probe := validation.ObjAt(l, "probe")
			if probe.Kind != validation.Obj {
				// A surface exists but carries none of this lens's
				// axes — the reduced-quota shape. The --emit refresh is
				// already named by the divergence missing entries;
				// route to the table instead.
				if ps := validation.ObjAt(n.brief, "probe_surface"); ps.Kind == validation.Obj {
					n.actions = append(n.actions, webv2Action(
						fmt.Sprintf(table, n.cid),
						lid+" has no probe surface for its axes — "+
							"work it directly off the index"))
				}
				continue
			}
			if objBool(probe, "closed") {
				continue
			}
			disp := intField(probe, "dispositioned")
			open := intField(probe, "open")
			if disp != 0 || open == 0 {
				continue
			}
			n.actions = append(n.actions, webv2Action(fmt.Sprintf(table, n.cid),
				fmt.Sprintf("%s open with 0/%d rows dispositioned, %d "+
					"open — run the mechanical table before theorizing",
					lid, intField(probe, "rows"), open)))
		}
	}
}

// nextActionsSkew appends the DEFECT-2 framework-skew line.
func (n *nextActionsCtx) nextActionsSkew() {
	// DEFECT-2 follow-up: framework skew. The snapshot's pin event records
	// the build that produced it; a different running build may carry
	// different probe semantics (the eval's stale-binary case: the defect
	// was fixed in checkout while the binary still crashed). Both sides
	// known and different is the only loud case — old campaigns without
	// the key and unstamped builds stay silent (the grandfather rule).
	if n.campaign != nil {
		if line := skewAction(n.brief, n.campaign); line != "" {
			n.actions = append(n.actions, line)
		}
	}
}

// nextActionsCriticality renders the criticality-coverage section.
func (n *nextActionsCtx) nextActionsCriticality() {
	// criticality coverage
	if crit := validation.ObjAt(n.brief, "criticality"); crit.Kind == validation.Obj {
		for _, name := range listAt(crit, "uncovered_consensus_critical") {
			n.actions = append(n.actions, webv2Action("webv2 run "+n.cid,
				fmt.Sprintf("open %s — consensus-critical, untouched by "+
					"any priority/finding/exec", valueText(name))))
		}
	}
}

// nextActionsPlanPriorities renders the plan-priority section: the Task 10
// open-question rows and the open SIBLING priorities, off one readonly load.
func (n *nextActionsCtx) nextActionsPlanPriorities() {
	// The plan's own priorities carry two open-work families that must reach
	// the cockpit: the open-question rows Task 10 mints, and open SIBLING
	// priorities (the disproof-sibling rule: a DISPROVED lifecycle finding
	// names its adjacent unchecked property, which spawns an OPEN priority
	// carrying sibling_of — the neighborhood stays open until the sibling is
	// worked). One readonly load serves both. Guarded like the criticality
	// block: plan-less/model-less campaigns get zero new lines.
	if n.campaign != nil {
		if plan, err := planner.LoadPlanReadonly(n.campaign); err == nil {
			// Task 10's Law ends "brief shows it" (independent Phase C
			// review, docs/sdd/task-10-12-review.md, Task 10 finding 1):
			// the minted `resolve open question Q-…: <text>` row was visible
			// only through `webv2 plan --json` and the queue-debt counts, so
			// the question's own text never reached the brief. It now renders
			// its own line — the id and the text, command-first per the
			// Task 7 law, pointing at the plan JSON that shows the row and
			// its rank. `status` is the clear condition: answering the
			// priority closes it, and the line goes with it.
			for _, p := range listAt(plan, "priorities") {
				text := validation.ObjStr(p, "question")
				if validation.ObjStr(p, "status") != "open" ||
					!strings.HasPrefix(text, "resolve open question ") {
					continue
				}
				if id := validation.ObjStr(p, "id"); id != "" &&
					!strings.Contains(text, id) {
					text = "resolve open question " + id + ": " + text
				}
				n.actions = append(n.actions, webv2Action(
					"webv2 plan "+n.cid+" --json", text))
			}
			for _, p := range listAt(plan, "priorities") {
				if validation.ObjStr(p, "status") == "open" &&
					validation.ObjStr(p, "sibling_of") != "" {
					pid := validation.ObjStr(p, "id")
					cmd := "webv2 run " + n.cid
					if pid != "" {
						cmd = "webv2 answered " + n.cid + " " + pid +
							" answered --reason <reason> --actor <actor>"
					}
					n.actions = append(n.actions, webv2Action(cmd, fmt.Sprintf(
						"work sibling of %s: %s", validation.ObjStr(p, "sibling_of"),
						validation.ObjStr(p, "question"))))
				}
			}
		}
	}
}

// nextActionsAttention renders the attention-ledger section: the top-ranked
// commands lead, then remaining queue rows not already led.
func (n *nextActionsCtx) nextActionsAttention() {
	if att := validation.ObjAt(n.brief, "attention"); att.Kind == validation.Obj {
		ranked := listAt(att, "ranked")
		lead := ranked
		if len(lead) > 2 {
			lead = lead[:2]
		}
		for _, item := range lead {
			if cmd := validation.ObjStr(item, "command"); cmd != "" {
				n.actions = append(n.actions, cmd)
				n.attentionLines[cmd] = true
			}
			ident := validation.ObjStr(item, "priority_id")
			if ident == "" {
				ident = validation.ObjStr(item, "invariant_id")
			}
			n.attentionLead[ident] = true
		}
		for _, item := range ranked[minInt(2, len(ranked)):] {
			if validation.ObjStr(item, "kind") == "queue" &&
				validation.ObjStr(item, "command") != "" &&
				!n.attentionLead[validation.ObjStr(item, "priority_id")] {
				cmd := validation.ObjStr(item, "command")
				n.actions = append(n.actions, cmd)
				n.attentionLines[cmd] = true
			}
		}
	}
}

// nextActionsDivergenceGate renders the divergence-gate section.
func (n *nextActionsCtx) nextActionsDivergenceGate() {
	// the divergence gate
	if div := validation.ObjAt(n.brief, "divergence"); div.Kind == validation.Obj &&
		!objBool(div, "closed") {
		missing := listAt(div, "missing")
		if len(missing) > 3 {
			missing = missing[:3]
		}
		for _, m := range missing {
			what := []rune(validation.ObjStr(m, "what"))
			if len(what) > 80 {
				what = what[:80]
			}
			n.actions = append(n.actions, webv2Action(
				"webv2 probes "+n.cid+" run --emit",
				fmt.Sprintf("divergence gate open — %s: %s",
					validation.ObjStr(m, "subject"), string(what))))
		}
	}
}

// nextActionsInvariantDebt renders the remaining high-consequence
// invariant-debt section.
func (n *nextActionsCtx) nextActionsInvariantDebt() {
	// remaining high-consequence invariant debt
	if att := validation.ObjAt(n.brief, "attention"); att.Kind == validation.Obj {
		items := listAt(validation.AsObj(validation.ObjAt(att, "invariants")), "items")
		for _, item := range items {
			if objBool(item, "high_consequence") &&
				validation.ObjStr(item, "command") != "" &&
				!n.attentionLead[validation.ObjStr(item, "invariant_id")] {
				cmd := validation.ObjStr(item, "command")
				n.actions = append(n.actions, cmd)
				n.attentionLines[cmd] = true
			}
		}
	}
}
