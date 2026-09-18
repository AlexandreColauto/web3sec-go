// Results-section renderers: finding classification, the confirmed
// summary and precision block, cost attribution, the all-findings
// table, answer quality, root-cause clusters, hypothesis lenses and
// the liveness findings subsection.
package report

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"websec/internal/classweights"
	"websec/internal/costs"
	"websec/internal/findings"
	"websec/internal/planner"
	"websec/internal/relations"
	"websec/internal/validation"
)

// classifyFindings buckets the findings by status and collects the
// submission-ready set for the Results section.
func (r *reportBuilder) classifyFindings() {
	r.confirmed = []validation.Value{}
	r.chainF = []validation.Value{}
	r.ready = []validation.Value{}
	r.disproved, r.duplicates, r.outOfScope = 0, 0, 0
	for _, f := range r.all {
		switch validation.ObjStr(f, "status") {
		case "CONFIRMED":
			r.confirmed = append(r.confirmed, f)
		case "CHAIN":
			r.chainF = append(r.chainF, f)
		case "DISPROVED":
			r.disproved++
		case "DUPLICATE":
			r.duplicates++
		case "OUT_OF_SCOPE":
			r.outOfScope++
		}
		if pyTruthyInt64Only(validation.ObjAt(validation.AsObj(validation.ObjAt(f, "bounty")), "submission_ready")) {
			r.ready = append(r.ready, f)
		}
	}
}

// writeResults renders the Results section: the confirmed summary line,
// the chain counts, the precision block and the submission-ready line.
func (r *reportBuilder) writeResults() {
	r.L = append(r.L, "## Results")
	r.L = append(r.L, "")
	if len(r.confirmed) > 0 {
		type clsCount struct {
			cls string
			n   int
		}
		order := []string{}
		counts := map[string]int{}
		for _, f := range r.confirmed {
			cls := validation.ObjStr(validation.ObjAt(f, "root_cause"), "class")
			if cls == "" {
				cls = "unclassified"
			}
			if _, ok := counts[cls]; !ok {
				order = append(order, cls)
			}
			counts[cls]++
		}
		rows := []clsCount{}
		for _, c := range order {
			rows = append(rows, clsCount{c, counts[c]})
		}
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].n > rows[j].n })
		parts := []string{}
		for _, rr := range rows {
			// G12: a mapped class names its pinned OWASP id; an unmapped
			// class renders bare (presence-gated, zero byte move).
			if sfx := classweights.ClassAliasSuffix(rr.cls); sfx != "" {
				parts = append(parts, fmt.Sprintf("%d %s %s", rr.n, rr.cls, sfx))
			} else {
				parts = append(parts, fmt.Sprintf("%d %s", rr.n, rr.cls))
			}
		}
		r.L = append(r.L, fmt.Sprintf("- **confirmed: %d** — %s", len(r.confirmed),
			strings.Join(parts, ", ")))
	} else {
		r.L = append(r.L, "- **confirmed: 0**")
	}
	r.L = append(r.L, fmt.Sprintf("- chains materialized: **%d**", len(r.provenChains)))
	// B3: presence-gated — an unproven chain is a lead, and the count line
	// above must never absorb it.
	if len(r.unprovenChains) > 0 {
		r.L = append(r.L, fmt.Sprintf("- unproven chains (hypothesis-level): %d — "+
			"leads only, never counted as confirmed", len(r.unprovenChains)))
	}
	r.L = append(r.L, fmt.Sprintf("- disproved: %d  - duplicates: %d  "+
		"- out-of-scope: %d", r.disproved, r.duplicates, r.outOfScope))
	r.L = append(r.L, "")
	r.L = append(r.L, precisionBlock(r.campaign, r.all, r.policy)...)
	if r.policy.Kind == validation.Obj && len(r.policy.O) > 0 {
		r.L = append(r.L, fmt.Sprintf("- submission (bounty gate): **%d** of %d "+
			"confirmed are submission-ready — the gate measures submission "+
			"packaging (patch immunization, program policy), not finding severity",
			len(r.ready), len(r.confirmed)))
		r.L = append(r.L, "")
	}
}

// G13 cost attribution, presence-gated (the additive convention): a
// campaign with zero lens-carrying cost rows and no plan lens data
// renders no bytes here at all — no header, no table.
func (r *reportBuilder) writeCostAttribution() {
	if ly, err := costs.LensYield(r.campaign); err == nil && len(ly) > 0 {
		r.L = append(r.L, lensYieldBlock(r.campaign, ly)...)
	}
}

// D1 (2026-09-10): the operator's single view of EVERY finding. The
// precision block above is capped by the submission budget, skips
// DUPLICATE/OUT_OF_SCOPE, and renders only when scores exist — so a
// 23-finding campaign could be counted in one line and otherwise invisible
// (the post-mortem's report showed `confirmed: 0` while 23 findings were
// critic-confirmed). This table has no gate beyond "there are findings":
// the point is that nothing is hidden. Deterministic: sorted by acceptance
// score descending, then by finding id.
func (r *reportBuilder) writeAllFindingsTable() {
	if len(r.all) > 0 {
		r.L = append(r.L, allFindingsTable(r.all)...)
	}
}

// writeAnswerQuality renders the plan's answer-quality section,
// presence-gated on the campaign_plan.json artifact carrying priorities.
func (r *reportBuilder) writeAnswerQuality() {
	planPath := filepath.Join(r.campaign.ArtifactsDir, "campaign_plan.json")
	if fileExists(planPath) {
		plan, err := validation.ReadJson(planPath)
		if err != nil {
			plan = validation.VObj()
		}
		priorities := listAt(plan, "priorities")
		if len(priorities) > 0 {
			r.L = append(r.L, "## Answer quality")
			r.L = append(r.L, "")
			flagged := []string{}
			answered, na, openN := 0, 0, 0
			for _, p := range priorities {
				status := validation.ObjStr(p, "status")
				ref := validation.ObjAt(p, "closed_ref")
				reason := validation.ObjStr(p, "closed_reason")
				sib := ""
				if validation.ObjStr(p, "sibling_of") != "" {
					sib = " (sibling of " + validation.ObjStr(p, "sibling_of") + ")"
				}
				question := []rune(validation.ObjStr(p, "question"))
				if len(question) > 100 {
					question = question[:100]
				}
				// An empty-string closed_ref is "no usable ref" too, not just
				// an absent (null) one.
				noRef := ref.Kind == validation.Null ||
					(ref.Kind == validation.Str && ref.S == "")
				if status == "answered" && noRef {
					why := "no reason recorded"
					if reason != "" {
						why = "reason recorded, but no exec/finding/artifact " +
							"ref links it"
					}
					flagged = append(flagged, fmt.Sprintf("- **%s** (answered, "+
						"no evidence ref)%s: %s — %s", validation.ObjStr(p, "id"), sib,
						string(question), why))
				} else if (status == "not-applicable" ||
					status == "deprioritized") && reason == "" {
					flagged = append(flagged, fmt.Sprintf("- **%s** (%s, no "+
						"reason)%s: %s", validation.ObjStr(p, "id"), status, sib,
						string(question)))
				}
				switch status {
				case "answered":
					answered++
				case "not-applicable":
					na++
				case "open":
					openN++
				}
			}
			r.L = append(r.L, fmt.Sprintf("- plan: %d priorities — %d answered, "+
				"%d not-applicable, %d still open", len(priorities), answered,
				na, openN))
			for _, p := range priorities {
				if validation.ObjStr(p, "status") == "open" && validation.ObjStr(p, "sibling_of") != "" {
					question := []rune(validation.ObjStr(p, "question"))
					if len(question) > 100 {
						question = question[:100]
					}
					r.L = append(r.L, fmt.Sprintf("- **%s** (open, sibling of %s): %s",
						validation.ObjStr(p, "id"), validation.ObjStr(p, "sibling_of"), string(question)))
				}
			}
			if len(flagged) > 0 {
				r.L = append(r.L, fmt.Sprintf("- **%d closure(s) lack evidence** "+
					"(flagged):", len(flagged)))
				r.L = append(r.L, flagged...)
			} else {
				r.L = append(r.L, "- all closed priorities carry a reason; every "+
					"'answered' priority is linked to evidence (ref or finding)")
			}
			r.L = append(r.L, "")
		}
	}
}

// writeRootCauseClusters renders the root-cause cluster section from the
// relations view, presence-gated on at least one cluster.
func (r *reportBuilder) writeRootCauseClusters() error {
	clusterView, err := relations.RootCauseClusters(r.campaign)
	if err != nil {
		return err
	}
	if clusters := listAt(clusterView, "clusters"); len(clusters) > 0 {
		r.L = append(r.L, "## Root-cause clusters")
		r.L = append(r.L, "")
		for _, cl := range clusters {
			members := listAt(cl, "members")
			r.L = append(r.L, fmt.Sprintf("### `%s` — %d findings share this "+
				"root cause", validation.ObjStr(cl, "class"), len(members)))
			r.L = append(r.L, "")
			if validation.ObjStr(cl, "description") != "" {
				r.L = append(r.L, "- root cause: "+validation.ObjStr(cl, "description"))
			}
			subs := listAt(cl, "subclusters")
			if len(subs) >= 2 {
				r.L = append(r.L, "- **one bug, several gates** — a fix at one "+
					"attack surface does NOT close the others; each surface "+
					"below needs its own fix (and its own verification)")
			}
			for _, sc := range subs {
				locs := []string{}
				for _, p := range strList(validation.ObjAt(sc, "locations")) {
					locs = append(locs, "`"+p+"`")
				}
				fids := []string{}
				for _, m := range strList(validation.ObjAt(sc, "finding_ids")) {
					fids = append(fids, "`"+m+"`")
				}
				line := fmt.Sprintf("- a fix at %s closes %s",
					strings.Join(locs, ", "), strings.Join(fids, ", "))
				if imm := strList(validation.ObjAt(sc, "immunized")); len(imm) > 0 {
					quoted := []string{}
					for _, i := range imm {
						quoted = append(quoted, "`"+i+"`")
					}
					line += " (immunized: " + strings.Join(quoted, ", ") + ")"
				}
				r.L = append(r.L, line)
			}
			for _, e := range listAt(cl, "attested_causation") {
				r.L = append(r.L, fmt.Sprintf("- attested causation: `%s` "+
					"caused_by `%s` (attested by %s)", validation.ObjStr(e, "src"),
					validation.ObjStr(e, "dst"), validation.ObjStr(e, "actor")))
			}
			r.L = append(r.L, "")
		}
	}
	return nil
}

// writeHypothesisLenses renders the plan's hypothesis-lens section,
// presence-gated on the plan carrying lenses.
func (r *reportBuilder) writeHypothesisLenses() error {
	var planPtr *validation.Value
	if plan, err := planner.LoadPlanReadonly(r.campaign); err == nil {
		planPtr = &plan
	}
	if planPtr != nil && len(listAt(*planPtr, "lenses")) > 0 {
		plan := *planPtr
		div, err := planner.DivergenceStatusFor(r.campaign, plan, nil)
		if err != nil {
			return err
		}
		lines := []string{"", "## Hypothesis lenses", ""}
		named := strList(validation.ObjAt(div, "named_classes"))
		namedTxt := strings.Join(named, ", ")
		if namedTxt == "" {
			namedTxt = "none"
		}
		lines = append(lines, fmt.Sprintf("Bug classes named: %d (min %d): %s",
			len(named), planner.MinDistinctClasses, namedTxt))
		lines = append(lines, "")
		for _, l := range listAt(plan, "lenses") {
			reason := strings.TrimSpace(validation.ObjStr(l, "closed_reason"))
			tail := ""
			if reason != "" {
				rr := []rune(reason)
				if len(rr) > 120 {
					rr = rr[:120]
				}
				tail = " — " + string(rr)
			}
			ref := ""
			if validation.ObjStr(l, "closed_ref") != "" {
				ref = " [ref: " + validation.ObjStr(l, "closed_ref") + "]"
			}
			fam := fmt.Sprintf(" [families: %s; attested: %s]",
				strings.Join(strList(validation.ObjAt(l, "families")), ", "),
				strings.Join(strList(validation.ObjAt(l, "families_checked")), ", "))
			reopen := ""
			if validation.ObjStr(l, "reopen_reason") != "" {
				reopen = " (REOPENED: " + validation.ObjStr(l, "reopen_reason") + ")"
			}
			lines = append(lines, fmt.Sprintf("- %s %s (%s): %s%s%s%s%s",
				validation.ObjStr(l, "id"), validation.ObjStr(l, "lens"), validation.ObjStr(l, "surface"),
				validation.ObjStr(l, "status"), tail, ref, fam, reopen))
			for _, s := range listAt(l, "symmetry") {
				lines = append(lines, fmt.Sprintf("    - %s -> %s",
					validation.ObjStr(s, "family"),
					strings.Join(strList(validation.ObjAt(s, "primitives")), ", ")))
			}
		}
		r.L = append(r.L, strings.Join(lines, "\n"))
	}
	return nil
}

// writeLivenessFindings renders the B2 liveness-findings subsection — one
// row per liveness finding (any status), with the incentive answer
// (who_profits) at a glance so a freeze finding cannot sit at HYPOTHESIS
// without its adversarial-game clause being visible. Presence-gated: no
// liveness finding, no section.
func (r *reportBuilder) writeLivenessFindings() {
	livenessRows := []validation.Value{}
	for _, f := range r.all {
		if findings.IsLivenessFinding(f) {
			livenessRows = append(livenessRows, f)
		}
	}
	if len(livenessRows) > 0 {
		sort.SliceStable(livenessRows, func(i, j int) bool {
			return validation.ObjStr(livenessRows[i], "finding_id") <
				validation.ObjStr(livenessRows[j], "finding_id")
		})
		r.L = append(r.L, "### LIVENESS FINDINGS — who profits from the freeze")
		r.L = append(r.L, "")
		for _, f := range livenessRows {
			ag := validation.AsObj(validation.ObjAt(f, "adversarial_game"))
			who := "UNANSWERED (gate check15)"
			if len(ag.O) > 0 {
				if wp := validation.ObjStr(ag, "who_profits"); wp != "" {
					who = wp
				}
			}
			r.L = append(r.L, fmt.Sprintf("- `%s` (%s): %s",
				validation.ObjStr(f, "finding_id"), validation.ObjStr(f, "status"), who))
		}
		r.L = append(r.L, "")
	}
}
