// The per-finding section renderer (report.generate's finding_section):
// the heading block, the risk/economics/gate bullets, the claim,
// mechanism and sequence, the evidence ladder, the variant ladder, the
// fork-PoC and patch-verification verdicts and the price basis — split
// into one helper per bullet group, appended in the original order.
package report

import (
	"fmt"
	"sort"
	"strings"

	"websec/internal/completion"
	"websec/internal/findings"
	"websec/internal/forkpoc"
	"websec/internal/immunize"
	"websec/internal/maximization"
	"websec/internal/pricing"
	"websec/internal/state"
	"websec/internal/validation"
)

// findingSection is report.generate's finding_section closure.
func findingSection(campaign *state.Campaign, f validation.Value, heading string,
	all []validation.Value) ([]string, error) {
	out := []string{}
	rc := validation.AsObj(validation.ObjAt(f, "root_cause"))
	out = appendFindingSectionHead(out, f, rc, heading)
	out = appendFindingSectionRisk(out, f)
	out = appendFindingSectionEconomics(out, f)
	out = appendFindingSectionGate(out, campaign, f)
	out = appendFindingSectionClaim(out, rc, f)
	out, err := appendFindingSectionEvidence(out, f)
	if err != nil {
		return nil, err
	}
	out, err = appendFindingSectionLadder(out, campaign, f)
	if err != nil {
		return nil, err
	}
	status := validation.ObjStr(f, "status")
	if status == "CONFIRMED" || status == "CHAIN" {
		out, err = appendFindingSectionForkPoc(out, campaign, f)
		if err != nil {
			return nil, err
		}
		out = appendFindingSectionPatchVerify(out, campaign, f)
		out = appendFindingSectionImmunizationScope(out, f, rc, all)
	}
	out, err = appendFindingSectionPriceBasis(out, campaign, f)
	if err != nil {
		return nil, err
	}
	out = append(out, "")
	return out, nil
}

// appendFindingSectionHead renders the section heading, the id/status
// line, the bug class (with its G12 alias suffix) and the violated
// invariant.
func appendFindingSectionHead(out []string, f validation.Value,
	rc validation.Value, heading string) []string {
	out = append(out, fmt.Sprintf("### %s: %s", heading, validation.ObjStr(f, "title")))
	out = append(out, "")
	out = append(out, fmt.Sprintf("- id: `%s` — status **%s** (trajectory: %s)",
		validation.ObjStr(f, "finding_id"), validation.ObjStr(f, "status"),
		validation.PyStr(validation.ObjAt(f, "trajectory"))))
	cwe := ""
	if validation.ObjStr(rc, "cwe") != "" {
		cwe = "CWE " + validation.ObjStr(rc, "cwe")
	}
	out = append(out, fmt.Sprintf("- bug class: `%s`%s %s", validation.PyStr(validation.ObjAt(rc, "class")),
		classAliasSuffixSpaced(validation.ObjStr(rc, "class")), cwe))
	inv := validation.AsObj(validation.ObjAt(f, "invariant"))
	if validation.ObjStr(inv, "statement") != "" {
		out = append(out, "- violated invariant: "+validation.ObjStr(inv, "statement"))
	}
	return out
}

// appendFindingSectionRisk renders the attacker-profile bullet and the
// validated-risk group: score/band, reversibility, impact vector and the
// reported-vs-computed severity line.
func appendFindingSectionRisk(out []string, f validation.Value) []string {
	att := validation.AsObj(validation.ObjAt(f, "attacker"))
	if validation.ObjStr(att, "profile") != "" {
		capital := ""
		if pyTruthyInt64Only(validation.ObjAt(att, "required_capital_usd")) {
			capital = " (capital: $" + pyCommaAuto(validation.ObjAt(att, "required_capital_usd")) + ")"
		}
		out = append(out, "- attacker: "+validation.ObjStr(att, "profile")+capital)
	}
	risk := validation.AsObj(validation.ObjAt(f, "risk"))
	v := validation.AsObj(validation.ObjAt(risk, "validated"))
	if len(v.O) > 0 {
		out = append(out, fmt.Sprintf("- validated risk: **%s/10 (%s)**",
			validation.PyStr(validation.ObjAt(v, "score")), validation.PyStr(validation.ObjAt(v, "band"))))
	}
	if rv := validation.ObjStr(risk, "reversibility"); rv != "" {
		out = append(out, "- reversibility: **"+rv+"** (validated_risk component)")
	}
	iv := validation.AsObj(validation.ObjAt(risk, "impact_vector"))
	if len(iv.O) > 0 {
		out = append(out, fmt.Sprintf("- impact vector: %s/%s/%s/%s (score %s)",
			validation.PyStr(validation.ObjAt(iv, "asset_exposure")),
			validation.PyStr(validation.ObjAt(iv, "privilege_class")),
			validation.PyStr(validation.ObjAt(iv, "recoverability")),
			validation.PyStr(validation.ObjAt(iv, "insolvency_risk")), validation.PyStr(validation.ObjAt(iv, "score"))))
	}
	if reported := validation.ObjAt(f, "reported_severity"); pyTruthyInt64Only(reported) {
		band := "n/a"
		if b := validation.ObjAt(validation.AsObj(validation.ObjAt(f, "risk")), "validated"); b.Kind == validation.Obj {
			if bv := validation.ObjAt(b, "band"); bv.Kind != validation.Null {
				band = validation.PyStr(bv)
			}
		}
		out = append(out, fmt.Sprintf("- reported severity: **%s** — computed "+
			"band: **%s**", validation.PyStr(reported), band))
	}
	return out
}

// appendFindingSectionEconomics renders the extraction bullet (the
// unpriceable decision or the extractable USD figure), the paid
// exploitability argument and the B2 adversarial-game clause.
func appendFindingSectionEconomics(out []string, f validation.Value) []string {
	econ := validation.AsObj(validation.ObjAt(validation.AsObj(validation.ObjAt(f, "risk")), "economic"))
	if decision := findings.UnpriceableDecision(f); decision != nil {
		out = append(out, fmt.Sprintf("- economically extractable: "+
			"UNPRICEABLE (ceiling: %s)", validation.PyStr(validation.ObjAt(*decision, "ceiling"))))
	} else if ex := validation.ObjAt(econ, "extractable_usd"); ex.Kind != validation.Null {
		out = append(out, fmt.Sprintf("- economically extractable: $%s",
			pyCommaAuto(ex)))
	}
	if exp := validation.AsObj(validation.ObjAt(f, "exploitability")); len(exp.O) > 0 {
		if paid := validation.ObjAt(exp, "paid"); paid.Kind == validation.Bool {
			if paid.B {
				out = append(out, fmt.Sprintf(
					"- paid exploitability: **yes** — who pays, and why: "+
						"%s", validation.PyStr(validation.ObjAt(exp, "argument"))))
			} else {
				line := "- paid exploitability: **no**"
				if a := validation.ObjStr(exp, "argument"); a != "" {
					line += " — " + a
				}
				out = append(out, line)
			}
		}
	}
	// B2: the adversarial-game clause (liveness findings) — who profits,
	// how, why the challenge path does not undo it, and whether that
	// interplay answer survives the strongest attacker variant (morph
	// §7.2). Presence-gated: findings without the clause render nothing
	// here.
	if ag := validation.AsObj(validation.ObjAt(f, "adversarial_game")); len(ag.O) > 0 {
		out = append(out, fmt.Sprintf("- adversarial game: who profits — %s",
			validation.PyStr(validation.ObjAt(ag, "who_profits"))))
		out = append(out, fmt.Sprintf("-   mechanism: %s",
			validation.PyStr(validation.ObjAt(ag, "profit_mechanism"))))
		out = append(out, fmt.Sprintf("-   challenge interplay: %s",
			validation.PyStr(validation.ObjAt(ag, "challenge_interplay"))))
		out = append(out, fmt.Sprintf("-   strongest attacker: %s",
			validation.PyStr(validation.ObjAt(ag, "strongest_attacker"))))
	}
	return out
}

// appendFindingSectionGate renders the verification bullets: the in-code
// acknowledgement (with its source quote), the G5 soundness layer, the
// bounty-gate verdict with advisories and the accepted-risk disclosure.
func appendFindingSectionGate(out []string, campaign *state.Campaign,
	f validation.Value) []string {
	if ack := validation.AsObj(validation.ObjAt(validation.ObjAt(f, "dedup_meta"), "in_code_ack")); len(ack.O) > 0 {
		line := fmt.Sprintf("- in-code ack: %s:%s — phrase %q (window %s)",
			validation.PyStr(validation.ObjAt(ack, "file")), validation.PyStr(validation.ObjAt(ack, "line")),
			validation.PyStr(validation.ObjAt(ack, "phrase")), validation.PyStr(validation.ObjAt(ack, "window")))
		if q, ok := reportAckQuote(campaign, f, ack); ok {
			line += " — " + q
		} else {
			line += " — source unavailable for quote"
		}
		out = append(out, line)
	}
	// G5 soundness layer: the structural defense covering the flagged
	// code. Sibling of the in-code-ack bullet in this correctness group —
	// score-only, never a dismissal. Presence-gated: findings without a
	// parseable mitigation_present render nothing here. The POLICY layer
	// (accepted risk below) never reads this field.
	if ms := validation.ObjAt(validation.ObjAt(f, "dedup_meta"), "mitigation_present"); ms.Kind ==
		validation.Str && ms.S != "" {
		if pattern, file, line, _, ok :=
			findings.ParseMitigationPresent(ms.S); ok {
			out = append(out, fmt.Sprintf(
				"- soundness layer demotes: %s (%s:%s)",
				pattern, file, line))
		}
	}
	b := validation.AsObj(validation.ObjAt(f, "bounty"))
	if len(b.O) > 0 {
		line := fmt.Sprintf("- bounty gate: eligible=%s, submission_ready=%s",
			validation.PyStr(validation.ObjAt(b, "eligible")), validation.PyStr(validation.ObjAt(b, "submission_ready")))
		if blockers := listAt(b, "blocking_reasons"); len(blockers) > 0 {
			line += ", blockers: " + strings.Join(strList(validation.ObjAt(b,
				"blocking_reasons")), "; ")
		}
		out = append(out, line)
		// Advisories never gate (A2's in-code acknowledgement, D8's
		// boundary-mutation note under a prose/none patch clause) — but they
		// exist to be READ, so the report carries them next to the verdict.
		// Emitted only when present: a finding without advisories renders
		// byte-for-byte as before.
		if adv := strList(validation.ObjAt(b, "advisories")); len(adv) > 0 {
			out = append(out, "  - advisory: "+strings.Join(adv, "; "))
		}
	}
	if ar := validation.AsObj(validation.ObjAt(b, "accepted_risk")); len(ar.O) > 0 {
		kind := validation.ObjStr(ar, "kind")
		line := fmt.Sprintf("- accepted risk: **%s**", validation.PyStr(validation.ObjAt(ar,
			"pattern")))
		if kind != "" {
			line += " (" + kind + ")"
		}
		if ref := validation.ObjStr(ar, "reference"); ref != "" {
			line += " — " + ref
		}
		if note := validation.ObjStr(ar, "note"); note != "" {
			line += " — " + note
		}
		// G7 hygiene (Task 15): a policy claim without a reference is
		// still valid, but the report stamps it. Golden-safe by evidence:
		// no golden policy carries accepted_risks and no golden tree
		// renders an accepted-risk bullet (see task-15-report.md), so the
		// absent-branch suffix moves zero golden bytes.
		if refURL := validation.ObjStr(ar, "reference_url"); refURL != "" {
			line += " — cites " + refURL
		} else {
			line += " — no reference cited"
		}
		line += " (documented by the program; not submittable as written)"
		out = append(out, line)
	}
	return out
}

// appendFindingSectionClaim renders the claim statement, the mechanism
// paragraph and the exploit sequence (sorted by step).
func appendFindingSectionClaim(out []string, rc validation.Value,
	f validation.Value) []string {
	out = append(out, "")
	out = append(out, "**Claim:** "+getOr(rc, "description", ""))
	if validation.ObjStr(rc, "mechanism") != "" {
		out = append(out, "")
		out = append(out, "**Mechanism:** "+validation.ObjStr(rc, "mechanism"))
	}
	seq := listAt(f, "exploit_sequence")
	if len(seq) > 0 {
		out = append(out, "")
		out = append(out, "**Sequence:**")
		sortedSeq := append([]validation.Value{}, seq...)
		sort.SliceStable(sortedSeq, func(i, j int) bool {
			return intAt(sortedSeq[i], "step") < intAt(sortedSeq[j], "step")
		})
		for _, s := range sortedSeq {
			line := fmt.Sprintf("%s. %s", validation.PyStr(validation.ObjAt(s, "step")),
				validation.PyStr(validation.ObjAt(s, "action")))
			if validation.ObjStr(s, "state_effect") != "" {
				line += " → " + validation.ObjStr(s, "state_effect")
			}
			out = append(out, line)
		}
	}
	return out
}

// appendFindingSectionEvidence renders the evidence ladder, sorted by
// evidence level, and validates every level up front: a bad level in a
// single-item evidence array would never trip the sort comparator.
func appendFindingSectionEvidence(out []string, f validation.Value) ([]string, error) {
	ev := listAt(f, "evidence")
	if len(ev) > 0 {
		out = append(out, "")
		out = append(out, "**Evidence (ladder):**")
		// Validate every level up front: a bad level in a single-item
		// evidence array would never trip the sort comparator below.
		for _, e := range ev {
			if evidenceIndex(validation.ObjStr(e, "level")) < 0 {
				return nil, fmt.Errorf("unknown evidence level")
			}
		}
		sortedEv := append([]validation.Value{}, ev...)
		sort.SliceStable(sortedEv, func(i, j int) bool {
			return evidenceIndex(validation.ObjStr(sortedEv[i], "level")) <
				evidenceIndex(validation.ObjStr(sortedEv[j], "level"))
		})
		for _, e := range sortedEv {
			line := fmt.Sprintf("- %s [%s] %s", validation.ObjStr(e, "level"),
				validation.ObjStr(e, "type"), validation.PyStr(validation.ObjAt(e, "description")))
			if validation.ObjStr(e, "sandbox_profile") != "" {
				line += " (sandbox: " + validation.ObjStr(e, "sandbox_profile") + ")"
			}
			// G15 advisories ride the line presence-gated: a fresh /
			// un-rerun item renders exactly as before.
			if validation.ObjStr(e, "reruns") != "" {
				line += " [reruns " + validation.ObjStr(e, "reruns") + "]"
			}
			if validation.ObjStr(e, "fork_stale") != "" {
				line += " [fork stale]"
			}
			out = append(out, line)
		}
	}
	return out, nil
}

// appendFindingSectionLadder renders the maximization variant ladder for a
// confirmed/chain finding that carries one: its disposition, the rung
// table and the base→maximal claim delta.
func appendFindingSectionLadder(out []string, campaign *state.Campaign,
	f validation.Value) ([]string, error) {
	if validation.ObjStr(validation.AsObj(validation.ObjAt(f, "maximization")), "ladder_id") == "" {
		return out, nil
	}
	status := validation.ObjStr(f, "status")
	if status != "CONFIRMED" && status != "CHAIN" {
		return out, nil
	}
	rep, err := maximization.LadderReport(campaign, validation.ObjStr(f, "finding_id"))
	if err != nil {
		return nil, err
	}
	lad := validation.ObjAt(rep, "ladder")
	if lad.Kind != validation.Obj {
		return out, nil
	}
	out = append(out, "")
	disp := validation.AsObj(validation.ObjAt(lad, "disposition"))
	line := fmt.Sprintf("**Variant ladder** `%s` — disposition: "+
		"**%s**", validation.ObjStr(lad, "ladder_id"), validation.ObjStr(disp, "state"))
	if validation.ObjStr(disp, "state") == "waived" && validation.ObjStr(disp, "reason") != "" {
		r := []rune(validation.ObjStr(disp, "reason"))
		if len(r) > 120 {
			r = r[:120]
		}
		line += " (waived: " + string(r) + ")"
	}
	out = append(out, line)
	out = append(out, "")
	out = appendFindingSectionLadderTable(out, rep, lad)
	if unexplored := strList(validation.ObjAt(rep, "unexplored_axes")); len(unexplored) > 0 {
		out = append(out, "")
		out = append(out, "> unexplored axes: "+
			strings.Join(unexplored, ", ")+" — the search is not "+
			"complete; the maximal rung is provisional")
	}
	out = appendFindingSectionLadderDelta(out, rep)
	return out, nil
}

// appendFindingSectionLadderTable renders the rung table: one row per
// rung with the maximal rung marked.
func appendFindingSectionLadderTable(out []string, rep validation.Value,
	lad validation.Value) []string {
	out = append(out, "| rung | name | axes | capital | extract | "+
		"status | exec |")
	out = append(out, "|---|---|---|---|---|---|---|")
	for _, r := range listAt(rep, "rungs") {
		ratio := "—"
		if v := validation.ObjAt(r, "extraction_ratio"); v.Kind != validation.Null {
			ratio = pyPercent0(floatVal(v))
		}
		cap := "—"
		if v := validation.ObjAt(r, "capital_usd"); v.Kind != validation.Null {
			cap = "$" + pyCommaAuto(v)
		}
		axes := strings.Join(strList(validation.ObjAt(r, "axes")), ", ")
		if axes == "" {
			axes = "—"
		}
		row := fmt.Sprintf("| `%s` | %s ", validation.ObjStr(r, "rung_id"),
			validation.ObjStr(r, "name"))
		if validation.ObjStr(r, "rung_id") == validation.ObjStr(lad, "maximal_rung_id") {
			row += "**(maximal)** "
		}
		row += fmt.Sprintf("| %s | %s | %s | %s", axes, cap, ratio,
			validation.ObjStr(r, "status"))
		if validation.ObjStr(r, "reason") != "" {
			rr := []rune(validation.ObjStr(r, "reason"))
			if len(rr) > 60 {
				rr = rr[:60]
			}
			row += " (reason: " + string(rr) + ")"
		}
		execID := validation.ObjStr(r, "exec_id")
		if execID == "" {
			execID = "—"
		}
		row += fmt.Sprintf(" | `%s` |", execID)
		out = append(out, row)
	}
	return out
}

// appendFindingSectionLadderDelta renders the claim delta between the
// base rung and the maximal rung when they differ.
func appendFindingSectionLadderDelta(out []string, rep validation.Value) []string {
	rungs := listAt(rep, "rungs")
	if len(rungs) > 0 {
		base := rungs[0]
		mx := validation.AsObj(validation.ObjAt(rep, "maximal"))
		if len(mx.O) > 0 &&
			validation.ObjStr(mx, "rung_id") != validation.ObjStr(base, "rung_id") &&
			validation.ObjAt(mx, "extraction_delta").Kind != validation.Null {
			delta := fmt.Sprintf("> claim delta base→maximal: "+
				"extraction %s → %s", pyPercent0(ratioOf(base)),
				pyPercent0(ratioOf(mx)))
			if validation.ObjAt(base, "capital_usd").Kind != validation.Null &&
				validation.ObjAt(mx, "capital_usd").Kind != validation.Null {
				delta += fmt.Sprintf(", capital $%s → $%s",
					pyCommaAuto(validation.ObjAt(base, "capital_usd")),
					pyCommaAuto(validation.ObjAt(mx, "capital_usd")))
			}
			out = append(out, "")
			out = append(out, delta)
		}
	}
	return out
}

// appendFindingSectionForkPoc renders the mainnet fork PoC verdict for a
// confirmed/chain finding: proven, waived, or not proven with its reason.
func appendFindingSectionForkPoc(out []string, campaign *state.Campaign,
	f validation.Value) ([]string, error) {
	item, reasonPtr, err := forkpoc.ForkPocEvidence(campaign, f)
	if err != nil {
		return nil, err
	}
	reason := ""
	if reasonPtr != nil {
		reason = *reasonPtr
	}
	out = append(out, "")
	if item.Kind == validation.Obj {
		out = append(out, fmt.Sprintf("- mainnet fork PoC: **proven** — "+
			"%s `%s` from `%s` (fork-runner, exit 0)", validation.ObjStr(item, "level"),
			validation.ObjStr(item, "type"), validation.PyStr(validation.ObjAt(item, "artifact_id"))))
	} else {
		waivers, err := completion.Waivers(campaign, "mainnet-fork-poc")
		if err != nil {
			return nil, err
		}
		waived := false
		for _, w := range waivers {
			subj := validation.ObjStr(w, "subject")
			if subj == "*" || subj == validation.ObjStr(f, "finding_id") {
				waived = true
				break
			}
		}
		if waived {
			out = append(out, "- mainnet fork PoC: **WAIVED** (waiver on "+
				"the record)")
		} else {
			out = append(out, "- mainnet fork PoC: **NOT PROVEN** — "+reason)
		}
	}
	return out, nil
}

// appendFindingSectionPatchVerify renders the patch-verification verdict
// (with the B1 waiver caveat) and the G11 post-patch regression record.
func appendFindingSectionPatchVerify(out []string, campaign *state.Campaign,
	f validation.Value) []string {
	immState, immDetail := immunize.ImmunizationDetail(f)
	marks := map[string]string{"immunized": "**IMMUNIZED**",
		"bypass": "**BYPASS FOUND**", "partial": "**PARTIAL**",
		"missing": "**NOT VERIFIED**"}
	mark, immRendered := marks[immState], immDetail
	if immState != "immunized" && immunizationWaived(campaign, f) {
		// B1: an explicit immunization waiver renders as a caveat,
		// matching how the fork-PoC waiver renders above.
		mark, immRendered = "**WAIVED**", "waiver on the record"
	}
	out = append(out, fmt.Sprintf("- patch verification: %s — %s",
		mark, immRendered))
	// G11 post-patch verdict (Task 8): presence-gated on the
	// verification.patch_regression record verify --post-patch
	// lands. Fail-open metadata — it never moves finding status.
	if pr := validation.ObjAt(validation.AsObj(validation.ObjAt(f, "verification")),
		"patch_regression"); pr.Kind == validation.Obj {
		out = append(out, fmt.Sprintf("- patch regression: %s (%s → %s)",
			patchRegressionMark(validation.ObjStr(pr, "verdict")),
			validation.ObjStr(pr, "base_exec"), validation.ObjStr(pr, "exec")))
		if d := validation.ObjStr(pr, "detail"); d != "" {
			out = append(out, "- "+d)
		}
	}
	return out
}

// appendFindingSectionImmunizationScope renders the immunization-credit
// scope caveat when an immunized finding leaves same-class siblings
// unimmunized.
func appendFindingSectionImmunizationScope(out []string, f validation.Value,
	rc validation.Value, all []validation.Value) []string {
	immState, _ := immunize.ImmunizationDetail(f)
	if immState != "immunized" {
		return out
	}
	cls := validation.ObjStr(rc, "class")
	siblings := []validation.Value{}
	for _, g := range all {
		if validation.ObjStr(g, "finding_id") == validation.ObjStr(f, "finding_id") {
			continue
		}
		gs := validation.ObjStr(g, "status")
		if gs != "CONFIRMED" && gs != "CHAIN" {
			continue
		}
		if validation.ObjStr(validation.ObjAt(g, "root_cause"), "class") != cls {
			continue
		}
		if immunize.IsImmunized(g) {
			continue
		}
		siblings = append(siblings, g)
	}
	if len(siblings) > 0 {
		sort.SliceStable(siblings, func(i, j int) bool {
			return validation.ObjStr(siblings[i], "finding_id") <
				validation.ObjStr(siblings[j], "finding_id")
		})
		ids := []string{}
		for _, g := range siblings {
			ids = append(ids, "`"+validation.ObjStr(g, "finding_id")+"`")
		}
		out = append(out, fmt.Sprintf("- immunization credit scope: "+
			"this patch immunizes `%s` ONLY — %d same-class sibling(s) "+
			"are NOT immunized by it (%s); they are separate attack "+
			"surfaces of the same root cause", validation.ObjStr(f, "finding_id"),
			len(siblings), strings.Join(ids, ", ")))
	}
	return out
}

// appendFindingSectionPriceBasis renders the economic-impact price basis
// line: the resolved price-table row, or the unattributed-USD note.
func appendFindingSectionPriceBasis(out []string, campaign *state.Campaign,
	f validation.Value) ([]string, error) {
	ei := validation.AsObj(validation.ObjAt(f, "economic_impact"))
	usdKeys := []string{}
	for _, k := range ei.O {
		if strings.HasSuffix(k.K, "_usd") && k.V.Kind != validation.Null {
			usdKeys = append(usdKeys, k.K)
		}
	}
	if len(usdKeys) > 0 {
		basis := validation.ObjStr(ei, "price_basis")
		out = append(out, "")
		if basis != "" {
			rowPtr, err := pricing.PriceRow(campaign, basis)
			if err != nil {
				return nil, err
			}
			if rowPtr != nil {
				src := []rune(validation.ObjStr(*rowPtr, "source"))
				if len(src) > 60 {
					src = src[:60]
				}
				out = append(out, fmt.Sprintf("- price basis: `%s` — %s @ $%s "+
					"(%s, as of %s)", basis, validation.ObjStr(*rowPtr, "asset"),
					pyCommaAuto(validation.ObjAt(*rowPtr, "usd")), string(src),
					validation.PyStr(validation.ObjAt(*rowPtr, "as_of"))))
			} else {
				out = append(out, fmt.Sprintf("- price basis: `%s` — "+
					"**UNRESOLVED** (no row in the price table)", basis))
			}
		} else {
			out = append(out, "- price basis: **NONE** — USD figures "+
				strings.Join(usdKeys, ", ")+" are unattributed")
		}
	}
	return out, nil
}
