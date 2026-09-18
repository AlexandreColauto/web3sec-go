package briefing

import (
	"fmt"
	"strings"

	"websec/internal/bounty"
	"websec/internal/orchestrator"
	"websec/internal/validation"
	"websec/internal/wilson"
)

// nextActionsIntegrity appends the doctor line for unchecked-deep integrity.
func (n *nextActionsCtx) nextActionsIntegrity() {
	// integrity, if not checked deep
	if validation.ObjAt(n.integ, "ok").Kind == validation.Bool && !validation.ObjAt(n.integ, "ok").B {
		n.actions = append(n.actions, webv2Action("webv2 doctor "+n.cid,
			"FIX INTEGRITY FIRST: "+integrityDetail(n.integ)))
	}
}

// nextActionsCostCeiling renders the cost-ceiling section.
func (n *nextActionsCtx) nextActionsCostCeiling() {
	// cost ceiling
	if econ := validation.ObjAt(n.brief, "economics"); econ.Kind == validation.Obj {
		b := validation.AsObj(validation.ObjAt(econ, "budget"))
		spent := validation.ObjAt(b, "spent_usd")
		limit := validation.ObjAt(b, "max_total_cost_usd")
		if spent.Kind != validation.Null && limit.Kind != validation.Null &&
			floatOf(spent) > floatOf(limit) {
			n.actions = append(n.actions, webv2Action(
				"webv2 budget "+n.cid+" --set <max-usd> --actor <actor>",
				fmt.Sprintf("cost ceiling exceeded: $%s spent vs $%s "+
					"limit — raise max_total_cost_usd or stop; the "+
					"pipeline will not run past the ceiling",
					pyCommaFloat(floatOf(spent), 2),
					pyCommaFloat(floatOf(limit), 2))))
		}
	}
}

// nextActionsChains renders the materializable-chains section.
func (n *nextActionsCtx) nextActionsChains() {
	// chains ready to materialize
	for _, ch := range listAt(validation.ObjAt(n.brief, "findings"), "materializable_chains") {
		members := strListOf(validation.ObjAt(ch, "members"))
		cmd := "webv2 run " + n.cid
		if len(members) >= 2 {
			cmd = "webv2 chain " + n.cid + " " + strings.Join(members, " ")
		}
		n.actions = append(n.actions, webv2Action(cmd,
			"materialize chain — all members confirmed, not yet a chain"))
	}
}

// nextActionsE6Queue renders the independent-verification (E6) queue.
func (n *nextActionsCtx) nextActionsE6Queue() {
	// the E6 queue
	for _, q := range listAt(n.brief, "independent_verification_queue") {
		need := "E6"
		if v := validation.ObjAt(q, "effective_floor"); v.Kind == validation.Str {
			need = v.S
		} else if v.Kind == validation.Null {
			need = "None"
		}
		tag := "defence in depth"
		if objBool(q, "mandatory") {
			tag = "MANDATORY, effective floor " + need
		}
		fid := validation.ObjStr(q, "finding_id")
		n.actions = append(n.actions, webv2Action("webv2 verify "+n.cid+
			" --finding "+fid+" --exec <EXEC-id> --verifier <verifier>"+
			" --description <description>",
			fmt.Sprintf("independently verify %s at %s, needs %s — %s",
				fid, validation.ObjStr(q, "evidence_level"), need, tag)))
	}
}

// nextActionsMemoryRecall renders the pending memory-recall section.
func (n *nextActionsCtx) nextActionsMemoryRecall() {
	// memory recall
	for _, fid := range listAt(validation.ObjAt(n.brief, "findings"), "memory_recall_pending") {
		n.actions = append(n.actions, webv2Action("webv2 recall "+n.cid+
			" --finding "+valueText(fid),
			"memory recall pending — critic + repro already in place"))
	}
}

// nextActionsCorpusRecall renders the B3/D2 corpus-recall disclosure.
func (n *nextActionsCtx) nextActionsCorpusRecall() {
	// corpus recall (B3/D2): a recorded check that cites no structurally-
	// overlapping row still closes the gate clause, so the operator is told.
	cr := validation.ObjAt(n.brief, "corpus_recall")
	if cr.Kind == validation.Obj && objInt(cr, "irrelevant_checks") != 0 {
		irrelevant := objInt(cr, "irrelevant_checks")
		fids := strListOf(validation.ObjAt(cr, "findings"))
		first := "?"
		if len(fids) > 0 {
			first = fids[0]
		}
		more := ""
		if len(fids) > 1 {
			more = fmt.Sprintf(" — %d more findings", len(fids)-1)
		}
		detail := ""
		labelOnly := objInt(cr, "label_only_checks")
		if labelOnly != 0 {
			labels := strings.Join(aliasSuffixLabels(
				strListOf(validation.ObjAt(cr, "discounted"))), ", ")
			if labels == "" {
				labels = "-"
			}
			verb := "share"
			if labelOnly == 1 {
				verb = "shares"
			}
			detail = fmt.Sprintf(" — %d %s only a non-discriminative class "+
				"label %s: the corpus has rows in that class, the label "+
				"alone is not lineage overlap", labelOnly, verb, labels)
		}
		noun, verb := "checks", "cite"
		if irrelevant == 1 {
			noun, verb = "check", "cites"
		}
		n.actions = append(n.actions, webv2Action("webv2 recall "+n.cid+
			" --finding "+first,
			fmt.Sprintf("corpus: %d memory %s %s no overlapping row%s%s",
				irrelevant, noun, verb, detail, more)))
	}
}

// nextActionsUnreachable renders the structurally-unreachable section.
func (n *nextActionsCtx) nextActionsUnreachable() {
	// structurally unreachable findings
	for _, r := range listAt(validation.ObjAt(n.brief, "findings"), "structurally_unreachable") {
		floor := validation.ObjStr(r, "floor")
		floorArg := floor
		if floorArg == "" || floorArg == "None" {
			floorArg = "<E4-E7>"
		}
		n.actions = append(n.actions, webv2Action("webv2 floors "+n.cid+
			" set --actor <actor> --reason <reason> <class_> "+floorArg,
			fmt.Sprintf("%s is structurally stuck at %s, effective floor %s"+
				": %s — pin the target or record the decision",
				validation.ObjStr(r, "finding_id"), validation.ObjStr(r, "level"),
				orQuestion(floor),
				strings.Join(strListOf(validation.ObjAt(r, "missing")), "; "))))
	}
}

// nextActionsBountyGate renders the bounty-gate section.
func (n *nextActionsCtx) nextActionsBountyGate() {
	// bounty gate
	if bv := validation.ObjAt(n.brief, "bounty"); bv.Kind == validation.Obj {
		for _, x := range listAt(bv, "evaluated") {
			fid := validation.ObjStr(x, "finding_id")
			if objBool(x, "submission_ready") {
				// submission itself happens off-CLI; the report is the
				// command step that precedes it
				n.actions = append(n.actions, webv2Action("webv2 report "+n.cid,
					"submit "+fid+" — gate passed, submission ready"))
				continue
			}
			if objBool(x, "eligible") {
				n.actions = append(n.actions, webv2Action("webv2 run "+n.cid,
					fmt.Sprintf("finish %s for submission: %s", fid,
						strings.Join(strListOf(validation.ObjAt(x, "blocking_reasons")),
							"; "))))
			}
		}
	}
}

// nextActionsGateDeficits renders the gate-deficits section.
func (n *nextActionsCtx) nextActionsGateDeficits() {
	// gate deficits
	for _, d := range listAt(validation.ObjAt(n.brief, "findings"), "gate_deficits") {
		n.actions = append(n.actions, webv2Action("webv2 run "+n.cid, fmt.Sprintf(
			"advance %s — %s, %s: %s", validation.ObjStr(d, "finding_id"),
			validation.ObjStr(d, "status"), validation.ObjStr(d, "level"), validation.ObjStr(d, "deficit"))))
	}
}

// nextActionsPendingMemory renders the pending-memory-promotion section.
func (n *nextActionsCtx) nextActionsPendingMemory() {
	// pending memory promotion
	for _, m := range listAt(n.brief, "pending_memory") {
		n.actions = append(n.actions, webv2Action("webv2 memory "+n.cid+
			" --approve "+validation.ObjStr(m, "memory_id"),
			fmt.Sprintf("human decision on %s — %s/%s: approve or reject",
				validation.ObjStr(m, "memory_id"), validation.ObjStr(m, "kind"),
				validation.ObjStr(m, "status"))))
	}
}

// nextActionsTerminals renders the terminal-states section.
func (n *nextActionsCtx) nextActionsTerminals() {
	// terminal states
	for _, t := range listAt(n.brief, "terminals") {
		path := strListOf(validation.ObjAt(t, "path"))
		cmd := "webv2 terminals " + n.cid
		if len(path) > 0 {
			// the work command: demonstrate the terminal capability on the
			// last finding of the path
			cmd = "webv2 exploit " + n.cid + " " + path[len(path)-1] + " --paid"
		}
		n.actions = append(n.actions, webv2Action(cmd, fmt.Sprintf(
			"terminal state reachable: -> %s via %s — capital $%s",
			validation.ObjStr(t, "terminal_capability"), strings.Join(path, " -> "),
			pyCommaFloat(floatOf(validation.ObjAt(t, "capital_usd")), 0))))
	}
}

// nextActionsGenericFallback filters out the section-specific lines and, when
// nothing generic remains, falls back to the orchestrator's next actions.
func (n *nextActionsCtx) nextActionsGenericFallback() error {
	generic := []string{}
	for _, a := range n.actions {
		// M6 lens-routing lines ("L-03 open with ...", "L-04 has no probe
		// surface ...") are surface-derived mechanical work, same family
		// as the probe-row actions — they must not count as "something
		// else to do", or they would suppress the phase-guidance fallback
		// on exactly the untouched-surface campaigns they route. The
		// markers ride the `# reason` suffix now that every minted line
		// leads with its command (I-2); attention-ledger lines carry no
		// reason — they are excluded by identity.
		if n.attentionLines[a] {
			continue
		}
		reason := ""
		if i := strings.Index(a, "  # "); i >= 0 {
			reason = a[i+4:]
		}
		if !hasAnyPrefix(reason, "work probe row ", "emit probe row ",
			"L-01 ", "L-03 ", "L-04 ",
			"divergence gate open — ") {
			generic = append(generic, a)
		}
	}
	surfacePresent := validation.ObjAt(n.brief, "probe_surface").Kind != validation.Null
	if len(generic) == 0 &&
		(len(n.actions) == 0 || surfacePresent) {
		extra, err := orchestrator.NextActions(n.campaign)
		if err != nil {
			return err
		}
		for _, a := range extra.A {
			if a.Kind == validation.Str {
				n.actions = append(n.actions, a.S)
			}
		}
	}
	return nil
}

// nextActionsLensYield appends the G17 per-lens batting-average lines.
func (n *nextActionsCtx) nextActionsLensYield() {
	// G17 tactic batting average (advisory render, policy-gated OFF plus
	// presence-gated): one line per lens with verdict-resolved data. The
	// rows come from the brief's own economics.lens_yield block — the
	// same T22 join the queue gate consumes — so the gate, the table,
	// and this line can never disagree. Presence gate: a real lens
	// (never "unattributed") with n_planned>0 renders; anything thinner
	// has no average to report. Appended last: advisory lines never
	// suppress or reorder the standing actions. Renders only — gates
	// nothing.
	if bounty.AutoTuneForCampaign(n.campaign) {
		if econ := validation.ObjAt(n.brief, "economics"); econ.Kind == validation.Obj {
			for _, r := range listAt(econ, "lens_yield") {
				lens := validation.ObjStr(r, "lens")
				if lens == "" || lens == "unattributed" {
					continue
				}
				planned := objInt(r, "n_planned")
				confirmed := objInt(r, "n_confirmed")
				if planned <= 0 {
					continue
				}
				// the advisory stat rides the lens's mechanical-table
				// command where one exists — a weak average is worked by
				// walking the table, exactly like the M6 routing
				cmd := "webv2 run " + n.cid
				if table, ok := lensMechanicalTable[lens]; ok {
					cmd = fmt.Sprintf(table, n.cid)
				}
				n.actions = append(n.actions, webv2Action(cmd, "lens "+lens+
					" batting average — "+
					wilson.Format(int(confirmed), int(planned),
						"precision")))
			}
		}
	}
}
