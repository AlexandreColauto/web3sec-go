// Package report is webv2.report: the deterministic markdown report — a
// VIEW over the finding IR. The report is generated FROM the finding
// objects, never the reverse: edit findings, regenerate the report.
//
// I1: the ONE sanctioned mutation is generate() re-running the bounty gate
// (a stale submission_ready flag is a stale claim) and registering the
// report artifact + logging report.generated. Everything else reads.
package report

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"websec/internal/bounty"
	"websec/internal/capabilities"
	"websec/internal/classweights"
	"websec/internal/completion"
	"websec/internal/costs"
	"websec/internal/coverage"
	"websec/internal/economics"
	"websec/internal/findings"
	"websec/internal/forkpoc"
	"websec/internal/immunize"
	"websec/internal/learning"
	"websec/internal/maximization"
	"websec/internal/planner"
	"websec/internal/pricing"
	"websec/internal/privileged"
	"websec/internal/probes"
	"websec/internal/protocolgraph"
	"websec/internal/relations"
	"websec/internal/risk"
	"websec/internal/state"
	"websec/internal/validation"
)

func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

func hasKey(v validation.Value, key string) bool {
	for _, pair := range v.O {
		if pair.K == key {
			return true
		}
	}
	return false
}

func listAt(v validation.Value, key string) []validation.Value {
	f := validation.ObjAt(v, key)
	if f.Kind != validation.Arr {
		return nil
	}
	return f.A
}

func asObj(v validation.Value) validation.Value {
	if v.Kind != validation.Obj {
		return validation.VObj()
	}
	return v
}

// pyTruthyInt64Only is a DIVERGENT pyTruthy variant (Wave J Task 7), NOT the
// canonical form; it is named so the divergence is visible.
// Rule: exactly validation.PyTruthy, except that an Int reads only the int64
// field I and ignores Big — so an integer that overflowed int64 (Big set,
// I == 0) reads FALSE where validation.PyTruthy reads it true.
func pyTruthyInt64Only(v validation.Value) bool {
	switch v.Kind {
	case validation.Null:
		return false
	case validation.Bool:
		return v.B
	case validation.Int:
		return v.I != 0
	case validation.Flt:
		return v.F != 0
	case validation.Str:
		return v.S != ""
	case validation.Arr:
		return len(v.A) > 0
	case validation.Obj:
		return len(v.O) > 0
	}
	return false
}

func pyStr(v validation.Value) string {
	if v.Kind == validation.Str {
		return v.S
	}
	return validation.PyRepr(v)
}

func strList(v validation.Value) []string {
	out := []string{}
	for _, e := range v.A {
		out = append(out, pyStr(e))
	}
	return out
}

// constraintNote is _constraint_note: one recorded privilege entry,
// annotated with the constraints it states. Reported, never inferred.
func constraintNote(c validation.Value) string {
	text := validation.ObjStr(c, "capability")
	if text == "" {
		text = validation.ObjStr(c, "mechanism")
	}
	if text == "" {
		text = "unspecified privilege"
	}
	notes := []string{}
	if validation.ObjAt(c, "timelocked").Kind == validation.Bool &&
		validation.ObjAt(c, "timelocked").B {
		notes = append(notes, "timelocked")
	}
	t := validation.ObjAt(c, "multisig_threshold")
	if t.Kind == validation.Int {
		notes = append(notes, strconv.FormatInt(t.I, 10)+"-of-n multisig")
	}
	if validation.ObjAt(c, "can_drain").Kind == validation.Bool &&
		validation.ObjAt(c, "can_drain").B {
		notes = append(notes, "model claims can_drain")
	}
	if len(notes) > 0 {
		return text + " (" + strings.Join(notes, ", ") + ")"
	}
	return text
}

// count is _count: "{n} {singular}" with plain English pluralization.
func count(n int, singular string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, singular)
	}
	return fmt.Sprintf("%d %ss", n, singular)
}

// PrivilegedSection is privileged_section: the 3.1 privileged-actor track as
// a report section. MUST STAY READ-ONLY over campaign state.
func PrivilegedSection(campaign *state.Campaign) ([]string, error) {
	modelPtr := privileged.LoadProtocolModel(campaign)
	if modelPtr == nil || modelPtr.Kind != validation.Obj ||
		!pyTruthyInt64Only(validation.ObjAt(*modelPtr, "privileges")) {
		return nil, nil
	}
	if len(privileged.PrivilegedRoles(*modelPtr)) == 0 {
		return nil, nil
	}
	ex, err := privileged.PrivilegedExposure(campaign)
	if err != nil {
		return nil, err
	}
	L := []string{"## Privileged-actor exposure", "",
		"Separate attacker track: bounded privileged roles as explicit baselines;",
		"the unprivileged-EOA results above are unaffected by this section.", ""}
	for _, r := range listAt(ex, "roles") {
		head := fmt.Sprintf("- **%s** (`%s`) — band: `%s`", validation.ObjStr(r, "role"),
			validation.ObjStr(r, "role_label"), validation.ObjStr(r, "exposure_band"))
		direct := listAt(r, "direct")
		chains := listAt(r, "terminal_chains")
		if len(direct) == 0 && len(chains) == 0 {
			L = append(L, head+"; no terminal paths recorded")
			continue
		}
		notes := []string{}
		for _, c := range listAt(r, "constraints") {
			notes = append(notes, constraintNote(c))
		}
		L = append(L, head+"; constraints: "+strings.Join(notes, ", "))
		if len(direct) > 0 {
			best := direct[0]
			L = append(L, fmt.Sprintf("  - direct: %s, best: %s -> %s",
				count(len(direct), "path"),
				strings.Join(strList(validation.ObjAt(best, "path")), " -> "),
				validation.ObjStr(best, "terminal_capability")))
		}
		if len(chains) > 0 {
			best := chains[0]
			L = append(L, fmt.Sprintf("  - chains: %s, best: %s -> %s",
				count(len(chains), "multi-step path"),
				strings.Join(strList(validation.ObjAt(best, "path")), " -> "),
				validation.ObjStr(best, "terminal_capability")))
		} else {
			L = append(L, "  - chains: 0 multi-step paths")
		}
	}
	L = append(L, "")
	return L, nil
}

// ProbeSurfaceSection is probe_surface_section: the mechanical candidate
// plane, rendered. Empty when the campaign never ran `webv2 probes`.
func ProbeSurfaceSection(campaign *state.Campaign) ([]string, error) {
	surfacePtr, err := probes.CampaignSurface(campaign)
	if err != nil {
		return nil, err
	}
	if surfacePtr == nil {
		return nil, nil
	}
	surface := *surfacePtr
	summaryPtr, err := probes.SurfaceSummary(campaign, nil)
	if err != nil {
		return nil, err
	}
	if summaryPtr == nil {
		return nil, nil
	}
	summary := *summaryPtr
	var planPtr *validation.Value
	if plan, err := planner.LoadPlanReadonly(campaign); err == nil {
		planPtr = &plan
	}
	disp := probes.RowDispositions(planPtr, surface)
	indexPtr, err := probes.CampaignIndex(campaign)
	if err != nil {
		return nil, err
	}
	var index validation.Value = validation.VNull()
	if indexPtr != nil {
		index = *indexPtr
	}
	blanks := probes.BlankEntries(campaign)
	L := []string{"## Mechanical candidate surface", ""}
	L = append(L, fmt.Sprintf("- ranked candidate rows: **%d** (%d "+
		"dispositioned, %d open)", intAt(summary, "rows"),
		intAt(summary, "dispositioned"), intAt(summary, "open")))
	staleNote := ""
	if pyTruthyInt64Only(validation.ObjAt(summary, "stale")) {
		staleNote = " — **STALE**: the structural index has moved since this " +
			"surface was built; re-run `webv2 probes " + campaign.CampaignID +
			" run` and re-disposition what moved"
	}
	L = append(L, fmt.Sprintf("- surface `index_sha`: `%s`%s",
		pyStr(validation.ObjAt(surface, "index_sha")), staleNote))
	L = append(L, "")
	for _, row := range listAt(surface, "rows") {
		rid := validation.ObjStr(row, "row_id")
		d := asObj(validation.ObjAt(disp, rid))
		anchors := "—"
		if pairs := probes.RowAnchorPairs(row, &index); len(pairs) > 0 {
			anchors = strings.Join(pairs, ", ")
		}
		var state string
		switch {
		case pyTruthyInt64Only(validation.ObjAt(d, "dispositioned")):
			state = "**" + validation.ObjStr(d, "status") + "**"
			if validation.ObjStr(d, "reason") != "" {
				state += ": " + validation.ObjStr(d, "reason")
			}
			a := asObj(validation.ObjAt(d, "anchor"))
			if len(a.O) > 0 {
				state += fmt.Sprintf(" (anchor `%s` = %s)",
					validation.ObjStr(a, "field"), pyStr(validation.ObjAt(a, "ref")))
			}
		case validation.ObjStr(d, "status") != "" && validation.ObjStr(d, "status") != "open":
			state = "open (" + validation.ObjStr(d, "status") + ")"
		case validation.ObjStr(d, "priority_id") != "":
			state = "open"
		default:
			state = "open (not emitted)"
		}
		L = append(L, fmt.Sprintf("- `%s` %s (%s %s) tier %s, gap %s, "+
			"anchors %s — %s", rid, validation.ObjStr(row, "probe"), validation.ObjStr(row, "axis"),
			validation.ObjStr(row, "lens"), pyStr(validation.ObjAt(row, "tier")),
			pyStr(validation.ObjAt(row, "assertion_gap")), anchors, state))
	}
	L = append(L, "")
	for _, entry := range blanks {
		L = append(L, fmt.Sprintf("- blank attested: %s cites `%s` — %s (%s)",
			validation.ObjStr(entry, "axis"), validation.ObjStr(entry, "anchor_blind"),
			validation.ObjStr(entry, "reason"), validation.ObjStr(entry, "actor")))
	}
	if len(blanks) > 0 {
		L = append(L, "")
	}
	return L, nil
}

func intAt(v validation.Value, key string) int64 {
	f := validation.ObjAt(v, key)
	if f.Kind == validation.Int {
		return f.I
	}
	return 0
}

// unscoredNotice is the one line a policy-less campaign must print: without a
// policy the report is a technical inventory, not a submission recommendation.
func unscoredNotice(campaign *state.Campaign) []string {
	return []string{"- **scope:** NO POLICY LOADED — this report is unscored: " +
		"no acceptance ranking, no submission budget, no accepted-risks check " +
		"and no paid-exploitability gate ran. Every finding below is a " +
		"technical claim, not a submission recommendation. Load a policy " +
		"(`webv2 scope " + campaign.CampaignID + " --policy FILE`) and re-run " +
		"`webv2 run` before submitting anything."}
}

// precisionBlock is the A3 "which findings matter" block in Results: the
// dual critic/evidence counts, the false-positive ratio (the share of
// critic-confirmed live findings that fail the evidence floor) and
// the top-K acceptance table — the operator's ranked answer over every LIVE
// finding (the production live predicate, findings.LoadLiveFindings:
// DUPLICATE / OUT_OF_SCOPE / SUPERSEDED excluded; a DISPROVED finding stays
// visible, disqualified at the bottom, so a critic/pipeline disagreement is
// legible). The score is recomputed live (risk.AcceptanceScore), never read
// from the stored field, so the table is current even before the next gate
// run.
//
// Budget: submission_budget.max_findings caps K (0/absent = top 10);
// rank_by flips the key from acceptance score to severity band. A reached
// cap prints a note; disqualified (critic-disproved) findings drop out of
// the table and are named below it.
//
// Presence gate (the additive convention — a new section must not change
// an existing campaign's bytes): the block renders only when an A3 field
// is present — the gate stored risk.acceptance_score on at least one
// finding, or the policy opted in with submission_budget. A campaign with
// neither renders no block at all.
func precisionBlock(campaign *state.Campaign, all []validation.Value,
	policy validation.Value) []string {
	// A campaign with no policy is UNSCORED: the acceptance scores, the
	// submission budget and the accepted-risks check all come from the policy,
	// so without one nothing separates "the program will pay" from "real but
	// accepted". Saying nothing here is what let a 23-finding campaign look
	// complete next to a 2-finding gold. Presence-gated: a scoped campaign
	// never prints the notice.
	unscored := policy.Kind != validation.Obj || len(policy.O) == 0
	if unscored && validation.ObjAt(policy, "submission_budget").Kind != validation.Obj {
		stored := false
		for _, f := range all {
			v := validation.ObjAt(validation.ObjAt(f, "risk"), "acceptance_score")
			if v.Kind == validation.Flt || v.Kind == validation.Int {
				stored = true
				break
			}
		}
		if !stored {
			return append(unscoredNotice(campaign), "")
		}
	}
	var live []validation.Value
	criticN, evidenceN, criticNoEvidenceN := 0, 0, 0
	for _, f := range all {
		if s := validation.ObjStr(f, "status"); s == "DUPLICATE" || s == "OUT_OF_SCOPE" ||
			s == "SUPERSEDED" {
			continue
		}
		live = append(live, f)
		if criticVerdictOf(f) == "confirmed" {
			criticN++
			// The ratio's numerator, counted in the same pass and over the
			// same set as its denominator: of the critic-confirmed
			// findings, the ones the evidence floor does NOT clear. The
			// old subtraction compared this count against the disjoint
			// evidence-confirmed count, so a finding the critic confirmed
			// but did not evidence (or vice versa) could drive the ratio
			// negative — the campaign printed -25.0% for 4 vs 5.
			if findings.EvidenceDeficit(f, "CONFIRMED", campaign) != nil {
				criticNoEvidenceN++
			}
		}
		if findings.EvidenceDeficit(f, "CONFIRMED", campaign) == nil {
			evidenceN++
		}
	}
	L := []string{}
	if unscored {
		L = append(L, unscoredNotice(campaign)...)
	}
	if len(live) == 0 {
		L = append(L, "- **precision:** no live findings to rank")
		L = append(L, "")
		return L
	}
	ratio := "n/a (no critic-confirmed findings)"
	if criticN > 0 {
		ratio = fmt.Sprintf("%.1f%%", float64(criticNoEvidenceN)/
			float64(criticN)*100)
	}
	L = append(L, fmt.Sprintf(
		"- **precision:** critic-confirmed: %d  - evidence-confirmed: %d  "+
			"- false-positive ratio: %s", criticN, evidenceN, ratio))

	k, rankBy := 0, "acceptance"
	if sb := validation.ObjAt(policy, "submission_budget"); sb.Kind == validation.Obj {
		if mf := intAt(sb, "max_findings"); mf > 0 {
			k = int(mf)
		}
		if rb := validation.ObjStr(sb, "rank_by"); rb == "severity" {
			rankBy = "severity"
		}
	}
	keyName := "acceptance"
	if rankBy == "severity" {
		keyName = "severity"
	}
	entries := risk.AcceptanceRanking(live, rankBy)
	if bounty.PriorsEnabled(policy) {
		// G3 wPrior, policy-gated OFF by default: a store failure
		// resolves to nil priors, which rank bit-identically to the
		// plain path above — the flag degrades to today's order, never
		// to an error.
		priors, global, _ := risk.AcceptancePriors(risk.DefaultMinN)
		entries = risk.AcceptanceRankingWithPriors(live, rankBy,
			priors, global)
	}
	top, capped := risk.AcceptanceTopK(entries, k)
	if k > 0 {
		L = append(L, fmt.Sprintf(
			"- **top %d by %s:** (submission budget)", k, keyName))
	} else {
		L = append(L, fmt.Sprintf("- **top %d by %s:**", len(top), keyName))
	}
	L = append(L, "  | # | finding | band | evidence | critic | score |")
	L = append(L, "  |---|---------|------|----------|--------|-------|")
	for i, e := range top {
		L = append(L, fmt.Sprintf("  | %d | %s | %s | %s | %s | %s |",
			i+1, rankCell(e), bandCell(e), evidenceCell(e),
			criticCell(e), scoreCell(e)))
	}
	if capped {
		L = append(L, fmt.Sprintf(
			"  - capped at %d by the submission budget: %d more qualified "+
				"finding(s) not shown",
			k, countQualified(entries)-len(top)))
	}
	var dq []string
	for _, e := range entries {
		if e.Disqualified {
			dq = append(dq, findingIDOf(e.Finding))
		}
	}
	if len(dq) > 0 {
		L = append(L, fmt.Sprintf(
			"- disqualified (critic disproved): %s — excluded from the table",
			strings.Join(dq, ", ")))
	}
	L = append(L, "")
	return L
}

// lensYieldBlock is the G13 cost-attribution table in Results: spend per
// lens against the confirmations that lens produced, plus the framework's
// own unit economics (cost per critic-confirmed / per evidence-confirmed
// finding). Advisory only — it ranks spend, it gates nothing, and the
// caller presence-gates it: no lens data, no bytes. Deterministic: rows
// arrive L-id ascending with "unattributed" last (costs.LensYield), money
// renders to 2 decimals, null quotients render n/a (never inf).
func lensYieldBlock(campaign *state.Campaign,
	ly []validation.Value) []string {
	perCritic, perEvidence := "n/a", "n/a"
	if rep, err := costs.YieldReport(campaign); err == nil {
		totals := validation.ObjAt(rep, "totals")
		if v := validation.ObjAt(totals,
			"cost_per_critic_confirmed_usd"); v.Kind != validation.Null {
			perCritic = "$" + lensMoney(v)
		}
		if v := validation.ObjAt(totals,
			"cost_per_evidence_confirmed_usd"); v.Kind != validation.Null {
			perEvidence = "$" + lensMoney(v)
		}
	}
	L := []string{"- **lens yield (advisory — never gates):** cost per " +
		"critic-confirmed " + perCritic + " / per evidence-confirmed " +
		perEvidence}
	L = append(L, "  | lens | planned | confirmed | cost_usd |")
	L = append(L, "  |---|---|---|---|")
	for _, r := range ly {
		L = append(L, fmt.Sprintf("  | %s | %d | %d | $%s |",
			validation.ObjStr(r, "lens"), lensInt(r, "n_planned"),
			lensInt(r, "n_confirmed"), lensMoney(validation.ObjAt(r, "cost_usd"))))
	}
	L = append(L, "")
	return L
}

// lensMoney is Python's f"${x:.2f}" for the number shapes the rollup
// holds (int 0 included — the unattributed bucket starts at zero).
func lensMoney(v validation.Value) string {
	switch v.Kind {
	case validation.Flt:
		return strconv.FormatFloat(v.F, 'f', 2, 64)
	case validation.Int:
		if v.Big != "" {
			if f, err := strconv.ParseFloat(v.Big, 64); err == nil {
				return strconv.FormatFloat(f, 'f', 2, 64)
			}
		}
		return strconv.FormatFloat(float64(v.I), 'f', 2, 64)
	}
	return "0.00"
}

// lensInt is int(r.get(key, 0)) for the rollup's count shapes.
func lensInt(r validation.Value, key string) int64 {
	if v := validation.ObjAt(r, key); v.Kind == validation.Int {
		return v.I
	}
	return 0
}

// allFindingsTable is the D1 "All findings" table: one row per finding. Order
// is STATUS FIRST (confirmed/chain, then hypothesis, then dismissed), and only
// then the live acceptance score descending with the finding id as tie-break.
//
// Status must lead because the score is not comparable across statuses, and the
// golden campaign proved it: a HYPOTHESIS whose band was stamped outranked three
// CONFIRMED findings that had no validated band yet, because an absent band
// contributes zero to the live score — so the inventory opened with an unproven
// claim above the confirmed ones. Within a status group the key is the same one
// risk.AcceptanceRanking uses (the precision table, `webv2 rank`), with the
// critic-disproved last: a disproved finding can keep a high score because the
// band survives the verdict in the arithmetic, and it must never head a group as
// if it were a candidate. Every cell degrades to "—" rather than failing the
// report — this is the view an operator reads when something already looks
// wrong, so it must render even for a half-populated finding.
func allFindingsTable(all []validation.Value) []string {
	sorted := append([]validation.Value{}, all...)
	sort.SliceStable(sorted, func(i, j int) bool {
		ri, rj := allFindingStatusRank(sorted[i]), allFindingStatusRank(sorted[j])
		if ri != rj {
			return ri < rj
		}
		si, di := risk.AcceptanceScore(sorted[i])
		sj, dj := risk.AcceptanceScore(sorted[j])
		if di != dj {
			return !di
		}
		if si != sj {
			return si > sj
		}
		return findingIDOf(sorted[i]) < findingIDOf(sorted[j])
	})
	L := []string{fmt.Sprintf("### All findings (%d)", len(sorted)), ""}
	L = append(L, "  | finding | status | evidence | critic | risk | accept "+
		"| submit | chain |")
	L = append(L, "  |---------|--------|----------|--------|------|--------"+
		"|--------|-------|")
	for _, f := range sorted {
		L = append(L, fmt.Sprintf("  | %s | %s | %s | %s | %s | %s | %s | %s |",
			allFindingCell(f), validation.ObjStr(f, "status"), allFindingEvidence(f),
			allFindingCritic(f), allFindingRisk(f), allFindingAccept(f),
			allFindingSubmit(f), allFindingChain(f)))
	}
	dq := 0
	for _, f := range sorted {
		if _, d := risk.AcceptanceScore(f); d {
			dq++
		}
	}
	note := "  - ordered by status (confirmed/chain → hypothesis → " +
		"dismissed), then live acceptance score"
	if dq > 0 {
		note += fmt.Sprintf("; %d critic-disproved finding(s) sorted last "+
			"within their status (shown for completeness, never as "+
			"candidates)", dq)
	}
	L = append(L, note)
	L = append(L, "")
	return L
}

// allFindingStatusRank orders the inventory by what the campaign currently
// believes: 0 for the findings it stands behind (CONFIRMED, or a member of a
// materialized chain), 1 for the unproven claims, 2 for everything it has
// dismissed (duplicates, out-of-scope, intended behaviour, unreachable,
// non-economic, test-harness-only, and the critic-disproved). An unknown status
// is treated as a claim, not as a dismissal — the table shows what it does not
// recognize rather than burying it.
func allFindingStatusRank(f validation.Value) int {
	switch validation.ObjStr(f, "status") {
	case "CONFIRMED", "CHAIN":
		return 0
	case "HYPOTHESIS", "":
		return 1
	default:
		return 2
	}
}

// allFindingCell is the id plus a readable title, the same shape the precision
// table uses.
func allFindingCell(f validation.Value) string {
	id := findingIDOf(f)
	title := validation.ObjStr(f, "title")
	if len(title) > 40 {
		title = title[:40] + "…"
	}
	if title != "" {
		return id + " " + title
	}
	return id
}

func allFindingEvidence(f validation.Value) string {
	l, err := findings.FindingLevel(f)
	if err != nil || l == "" {
		return "—"
	}
	return l
}

func allFindingCritic(f validation.Value) string {
	if v := criticVerdictOf(f); v != "" {
		return v
	}
	return "—"
}

// allFindingRisk is score + validated band, the risk-calibration pair.
func allFindingRisk(f validation.Value) string {
	riskObj := asObj(validation.ObjAt(f, "risk"))
	band := validation.ObjStr(asObj(validation.ObjAt(riskObj, "validated")), "band")
	score := ""
	if x, ok := risk.AcceptanceScore(f); ok {
		score = risk.ScoreText(x)
	}
	switch {
	case score != "" && band != "":
		return score + " " + band
	case score != "":
		return score
	case band != "":
		return band
	}
	return "—"
}

// allFindingAccept is the stored A3 acceptance score, empty unless the gate
// ran (the live value is the risk column's first half).
func allFindingAccept(f validation.Value) string {
	v := validation.ObjAt(validation.ObjAt(f, "risk"), "acceptance_score")
	switch v.Kind {
	case validation.Flt:
		return risk.ScoreText(v.F)
	case validation.Int:
		return risk.ScoreText(float64(v.I))
	}
	return "—"
}

func allFindingSubmit(f validation.Value) string {
	if pyTruthyInt64Only(validation.ObjAt(asObj(validation.ObjAt(f, "bounty")), "submission_ready")) {
		return "yes"
	}
	return "—"
}

// allFindingChain is the chain membership: a per-finding chain id when the
// finding carries one, otherwise a marker for the CHAIN status.
func allFindingChain(f validation.Value) string {
	if id := validation.ObjStr(f, "chain_id"); id != "" {
		return id
	}
	if validation.ObjStr(f, "status") == "CHAIN" {
		return "chain"
	}
	return "—"
}

func countQualified(entries []risk.AcceptanceEntry) int {
	n := 0
	for _, e := range entries {
		if !e.Disqualified {
			n++
		}
	}
	return n
}

// rankCell is the finding cell: id + truncated title (the table is the
// operator's "which 5 of 23" answer, so the title must be readable there).
func rankCell(e risk.AcceptanceEntry) string {
	id := findingIDOf(e.Finding)
	title := validation.ObjStr(e.Finding, "title")
	if len(title) > 40 {
		title = title[:40] + "…"
	}
	if title != "" {
		return id + " " + title
	}
	return id
}

func bandCell(e risk.AcceptanceEntry) string {
	riskObj := asObj(validation.ObjAt(e.Finding, "risk"))
	b := validation.ObjStr(asObj(validation.ObjAt(riskObj, "validated")), "band")
	if b == "" {
		return "—"
	}
	return b
}

// evidenceCell is the finding's highest evidence level (FindingLevel is
// E0 when the finding holds none — shown as E0, not hidden).
func evidenceCell(e risk.AcceptanceEntry) string {
	l, err := findings.FindingLevel(e.Finding)
	if err != nil {
		return "—"
	}
	return l
}

func criticCell(e risk.AcceptanceEntry) string {
	v := criticVerdictOf(e.Finding)
	if v == "" {
		return "—"
	}
	return v
}

// scoreCell is the two-decimal score with its demotion markers (A2 ack, A1
// accepted risk, G5 soundness mitigation) — the markers are what make a
// demoted number legible.
// The G3 prior marker rides the same presence pattern: absent when the
// term is zero, so policy-off tables never move.
func scoreCell(e risk.AcceptanceEntry) string {
	s := risk.ScoreText(e.Score)
	if e.AckDemoted {
		s += " -ack"
	}
	if e.RiskDemoted {
		s += " -risk"
	}
	if e.MitigationDemoted {
		s += " -mitigation"
	}
	if e.PriorFactor != 0 {
		s += " +prior"
	}
	return s
}

func findingIDOf(f validation.Value) string {
	return validation.ObjStr(f, "finding_id")
}

func criticVerdictOf(f validation.Value) string {
	return validation.ObjStr(validation.ObjAt(f, "verification"), "critic_verdict")
}

// componentSurfacesBlock is the G9 tracked-but-opaque surfaces block: one
// line per protocol-model component (`- <kind> <path|url>:
// <in_scope|out-of-scope><, paid>`, via protocolgraph.ComponentSurfaceLines).
// Presence-gated (the additive convention): nil unless the campaign's
// model file exists AND carries a non-empty components list, so a
// component-free campaign gains no bytes. Findings may anchor on these
// surfaces; structidx never indexes them.
func componentSurfacesBlock(campaign *state.Campaign) []string {
	modelPath := filepath.Join(campaign.ArtifactsDir, "protocol_model.json")
	if !fileExists(modelPath) {
		return nil
	}
	model, err := validation.ReadJson(modelPath)
	if err != nil {
		return nil
	}
	lines := protocolgraph.ComponentSurfaceLines(model)
	if len(lines) == 0 {
		return nil
	}
	L := []string{"## Tracked-but-opaque surfaces", "",
		"> These surfaces are tracked for findings but opaque to " +
			"structidx: never indexed, never prescreened.", ""}
	L = append(L, lines...)
	L = append(L, "")
	return L
}

// chainAssumptionsBlock is the G10 per-hop assumption table: one line per
// AssumptionTable row plus one per gap, via the shared
// protocolgraph.RenderAssumptionLines builder (the same bytes the brief
// renders, so the two can never drift apart).
//
// Presence-gated (the Task 4 law, the additive convention): nil unless
// len(rows) > 0 AND (any row carries a non-null detail OR len(gaps) > 0),
// so a chains-only legacy campaign gains no bytes. A row carries detail
// when any non-chain field is non-null.
func chainAssumptionsBlock(campaign *state.Campaign) []string {
	modelPath := filepath.Join(campaign.ArtifactsDir, "protocol_model.json")
	if !fileExists(modelPath) {
		return nil
	}
	model, err := validation.ReadJson(modelPath)
	if err != nil {
		return nil
	}
	rows, gaps := protocolgraph.AssumptionTable(model)
	if len(rows) == 0 {
		return nil
	}
	hasDetail := false
	for _, r := range rows {
		for _, pair := range r.O {
			if pair.K == "chain" {
				continue
			}
			if pair.V.Kind != validation.Null {
				hasDetail = true
				break
			}
		}
		if hasDetail {
			break
		}
	}
	if !hasDetail && len(gaps) == 0 {
		return nil
	}
	lines := protocolgraph.RenderAssumptionLines(rows, gaps)
	if len(lines) == 0 {
		return nil
	}
	L := []string{"## Chain assumptions", "",
		"> Declared per-hop assumptions; gaps mark hops whose endpoints " +
			"declare nothing.", ""}
	L = append(L, lines...)
	L = append(L, "")
	return L
}

// Generate is generate(): write report.md, register/refresh the artifact and
// log report.generated. Returns the report path.
func Generate(campaign *state.Campaign) (string, error) {
	st, err := campaign.State()
	if err != nil {
		return "", err
	}
	policyPath := validation.ObjStr(st, "policy_path")
	// policy is hoisted out of the if-block: the Results section's precision
	// block (A3) reads its submission_budget even when the gate re-run above
	// had nothing to do.
	var policy validation.Value
	if policyPath != "" && fileExists(policyPath) {
		p, err := bounty.LoadPolicy(policyPath)
		if err != nil {
			return "", err
		}
		policy = p
		all, err := findings.LoadAllFindings(campaign)
		if err != nil {
			return "", err
		}
		for _, f := range all {
			status := validation.ObjStr(f, "status")
			if status != "CONFIRMED" && status != "CHAIN" {
				continue
			}
			if _, err := bounty.EvaluateBountyGate(campaign,
				validation.ObjStr(f, "finding_id"), policy, true); err != nil {
				return "", err
			}
		}
	}
	all, err := findings.LoadAllFindings(campaign)
	if err != nil {
		return "", err
	}
	// r43a: a report renders "no materialized chains" only when the chain
	// store really is empty; an unreadable store refuses, naming the path.
	chainPaths, err := validation.ListPrefixedOptional(campaign.ChainsDir,
		"CHAIN-", ".json")
	if err != nil {
		return "", fmt.Errorf("the chain store %s cannot be listed: %v",
			campaign.ChainsDir, err)
	}
	sort.Strings(chainPaths)
	chains := []validation.Value{}
	for _, p := range chainPaths {
		doc, err := validation.ReadJson(p)
		if err != nil {
			return "", err
		}
		chains = append(chains, doc)
	}
	// B3: a chain doc is either evidence-confirmed (the materialization hard
	// gate) or hypothesis-level ("unproven"). The split is by field
	// presence: pre-B3 docs carry no provenance key at all and stay proven.
	provenChains, unprovenChains := splitChainsByProvenance(chains)
	mem, err := learning.AllMemory(campaign)
	if err != nil {
		return "", err
	}

	evts, err := campaign.Events()
	if err != nil {
		return "", err
	}
	var headHash validation.Value = validation.VNull()
	if len(evts) > 0 {
		if h := validation.ObjAt(evts[len(evts)-1], "event_hash"); h.Kind != validation.Null {
			headHash = h
		}
	}

	L := []string{}
	L = append(L, "<!-- state-head: "+pyStr(headHash)+" -->")
	L = append(L, "# Security Research Report — "+validation.ObjStr(st, "program"))
	L = append(L, "")
	L = append(L, fmt.Sprintf("- campaign: `%s`", validation.ObjStr(st, "campaign_id")))
	L = append(L, fmt.Sprintf("- phase: **%s** (pass %s)", validation.ObjStr(st, "phase"),
		pyStr(validation.ObjAt(asObj(validation.ObjAt(st, "budget")), "pass"))))
	L = append(L, fmt.Sprintf("- active snapshot: `%s`",
		pyStr(validation.ObjAt(st, "active_snapshot_id"))))
	L = append(L, fmt.Sprintf("- generated: %s", state.NowIso()))
	L = append(L, "")

	modelPath := filepath.Join(campaign.ArtifactsDir, "protocol_model.json")
	if fileExists(modelPath) {
		model, err := validation.ReadJson(modelPath)
		if err != nil {
			return "", err
		}
		econ := economics.EconomicSummary(model)
		L = append(L, "## Protocol economics")
		L = append(L, "")
		if gaps := listAt(econ, "equation_gaps"); len(gaps) > 0 {
			L = append(L, "| equation | missing |")
			L = append(L, "|---|---|")
			shown := gaps
			if len(shown) > 12 {
				shown = shown[:12]
			}
			for _, g := range shown {
				eq := []rune(validation.ObjStr(g, "equation"))
				if len(eq) > 60 {
					eq = eq[:60]
				}
				L = append(L, fmt.Sprintf("| `%s` | %s |", string(eq),
					strings.Join(strList(validation.ObjAt(g, "missing")), ", ")))
			}
			L = append(L, "")
		}
		if risky := listAt(econ, "risky_assets"); len(risky) > 0 {
			names := []string{}
			shown := risky
			if len(shown) > 6 {
				shown = shown[:6]
			}
			for _, a := range shown {
				names = append(names, validation.ObjStr(a, "asset"))
			}
			L = append(L, fmt.Sprintf("- risky assets "+
				"(fee-on-transfer/rebasing/odd-decimals): %d — %s", len(risky),
				strings.Join(names, ", ")))
		}
		gaps := len(listAt(econ, "equation_gaps"))
		L = append(L, fmt.Sprintf("> %d equation(s) with no enforcement or "+
			"no known break path — the economic model is unfinished, not safe",
			gaps))
		L = append(L, "")
	}

	// G10 assumption table (Task 4): the per-hop declared table plus
	// ASSUMPTION GAP lines, beside the economics model section.
	// Presence-gated (the additive convention) — a chains-only legacy
	// campaign gains no bytes.
	L = append(L, chainAssumptionsBlock(campaign)...)

	covPath := filepath.Join(campaign.ArtifactsDir, "coverage.json")
	if fileExists(covPath) {
		cov, err := validation.ReadJson(covPath)
		if err != nil {
			return "", err
		}
		s := asObj(validation.ObjAt(cov, "summary"))
		if len(s.O) > 0 {
			L = append(L, "## Coverage")
			L = append(L, "")
			L = append(L, "| metric | value |")
			L = append(L, "|---|---|")
			for _, k := range s.O {
				if k.K == "unknown_note" {
					continue
				}
				L = append(L, fmt.Sprintf("| %s | %s |",
					strings.ReplaceAll(k.K, "_", " "), pyStr(k.V)))
			}
			L = append(L, "")
			note := "unknown ≠ secure"
			if v := validation.ObjAt(s, "unknown_note"); v.Kind != validation.Null {
				note = pyStr(v)
			}
			L = append(L, "> "+note)
			L = append(L, "")
			thin, err := coverage.ThinCoverage(campaign, 2)
			if err != nil {
				return "", err
			}
			if len(thin) > 0 {
				L = append(L, "### Thin coverage (fewer than 2 trajectories)")
				L = append(L, "")
				shown := thin
				if len(shown) > 20 {
					shown = shown[:20]
				}
				for _, t := range shown {
					trajs := strings.Join(strList(validation.ObjAt(t, "trajectories")), ", ")
					if trajs == "" {
						trajs = "none"
					}
					L = append(L, fmt.Sprintf("- `%s` — status %s, "+
						"trajectories: %s", validation.ObjStr(t, "path"),
						validation.ObjStr(t, "status"), trajs))
				}
				L = append(L, "")
			}
		}
	}

	// G9 opaque surfaces (Task 6): the tracked-but-opaque component
	// block, beside the Coverage scope section. Presence-gated (the
	// additive convention) — a component-free campaign gains no bytes.
	L = append(L, componentSurfacesBlock(campaign)...)
	priv, err := PrivilegedSection(campaign)
	if err != nil {
		return "", err
	}
	L = append(L, priv...)
	ps, err := ProbeSurfaceSection(campaign)
	if err != nil {
		return "", err
	}
	L = append(L, ps...)

	confirmed := []validation.Value{}
	chainF := []validation.Value{}
	ready := []validation.Value{}
	disproved, duplicates, outOfScope := 0, 0, 0
	for _, f := range all {
		switch validation.ObjStr(f, "status") {
		case "CONFIRMED":
			confirmed = append(confirmed, f)
		case "CHAIN":
			chainF = append(chainF, f)
		case "DISPROVED":
			disproved++
		case "DUPLICATE":
			duplicates++
		case "OUT_OF_SCOPE":
			outOfScope++
		}
		if pyTruthyInt64Only(validation.ObjAt(asObj(validation.ObjAt(f, "bounty")), "submission_ready")) {
			ready = append(ready, f)
		}
	}

	L = append(L, "## Results")
	L = append(L, "")
	if len(confirmed) > 0 {
		type clsCount struct {
			cls string
			n   int
		}
		order := []string{}
		counts := map[string]int{}
		for _, f := range confirmed {
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
		for _, r := range rows {
			// G12: a mapped class names its pinned OWASP id; an unmapped
			// class renders bare (presence-gated, zero byte move).
			if sfx := classweights.ClassAliasSuffix(r.cls); sfx != "" {
				parts = append(parts, fmt.Sprintf("%d %s %s", r.n, r.cls, sfx))
			} else {
				parts = append(parts, fmt.Sprintf("%d %s", r.n, r.cls))
			}
		}
		L = append(L, fmt.Sprintf("- **confirmed: %d** — %s", len(confirmed),
			strings.Join(parts, ", ")))
	} else {
		L = append(L, "- **confirmed: 0**")
	}
	L = append(L, fmt.Sprintf("- chains materialized: **%d**", len(provenChains)))
	// B3: presence-gated — an unproven chain is a lead, and the count line
	// above must never absorb it.
	if len(unprovenChains) > 0 {
		L = append(L, fmt.Sprintf("- unproven chains (hypothesis-level): %d — "+
			"leads only, never counted as confirmed", len(unprovenChains)))
	}
	L = append(L, fmt.Sprintf("- disproved: %d  - duplicates: %d  "+
		"- out-of-scope: %d", disproved, duplicates, outOfScope))
	L = append(L, "")
	L = append(L, precisionBlock(campaign, all, policy)...)
	if policy.Kind == validation.Obj && len(policy.O) > 0 {
		L = append(L, fmt.Sprintf("- submission (bounty gate): **%d** of %d "+
			"confirmed are submission-ready — the gate measures submission "+
			"packaging (patch immunization, program policy), not finding severity",
			len(ready), len(confirmed)))
		L = append(L, "")
	}

	// G13 cost attribution, presence-gated (the additive convention): a
	// campaign with zero lens-carrying cost rows and no plan lens data
	// renders no bytes here at all — no header, no table.
	if ly, err := costs.LensYield(campaign); err == nil && len(ly) > 0 {
		L = append(L, lensYieldBlock(campaign, ly)...)
	}

	// D1 (2026-09-10): the operator's single view of EVERY finding. The
	// precision block above is capped by the submission budget, skips
	// DUPLICATE/OUT_OF_SCOPE, and renders only when scores exist — so a
	// 23-finding campaign could be counted in one line and otherwise invisible
	// (the post-mortem's report showed `confirmed: 0` while 23 findings were
	// critic-confirmed). This table has no gate beyond "there are findings":
	// the point is that nothing is hidden. Deterministic: sorted by acceptance
	// score descending, then by finding id.
	if len(all) > 0 {
		L = append(L, allFindingsTable(all)...)
	}

	planPath := filepath.Join(campaign.ArtifactsDir, "campaign_plan.json")
	if fileExists(planPath) {
		plan, err := validation.ReadJson(planPath)
		if err != nil {
			plan = validation.VObj()
		}
		priorities := listAt(plan, "priorities")
		if len(priorities) > 0 {
			L = append(L, "## Answer quality")
			L = append(L, "")
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
			L = append(L, fmt.Sprintf("- plan: %d priorities — %d answered, "+
				"%d not-applicable, %d still open", len(priorities), answered,
				na, openN))
			for _, p := range priorities {
				if validation.ObjStr(p, "status") == "open" && validation.ObjStr(p, "sibling_of") != "" {
					question := []rune(validation.ObjStr(p, "question"))
					if len(question) > 100 {
						question = question[:100]
					}
					L = append(L, fmt.Sprintf("- **%s** (open, sibling of %s): %s",
						validation.ObjStr(p, "id"), validation.ObjStr(p, "sibling_of"), string(question)))
				}
			}
			if len(flagged) > 0 {
				L = append(L, fmt.Sprintf("- **%d closure(s) lack evidence** "+
					"(flagged):", len(flagged)))
				L = append(L, flagged...)
			} else {
				L = append(L, "- all closed priorities carry a reason; every "+
					"'answered' priority is linked to evidence (ref or finding)")
			}
			L = append(L, "")
		}
	}

	clusterView, err := relations.RootCauseClusters(campaign)
	if err != nil {
		return "", err
	}
	if clusters := listAt(clusterView, "clusters"); len(clusters) > 0 {
		L = append(L, "## Root-cause clusters")
		L = append(L, "")
		for _, cl := range clusters {
			members := listAt(cl, "members")
			L = append(L, fmt.Sprintf("### `%s` — %d findings share this "+
				"root cause", validation.ObjStr(cl, "class"), len(members)))
			L = append(L, "")
			if validation.ObjStr(cl, "description") != "" {
				L = append(L, "- root cause: "+validation.ObjStr(cl, "description"))
			}
			subs := listAt(cl, "subclusters")
			if len(subs) >= 2 {
				L = append(L, "- **one bug, several gates** — a fix at one "+
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
				L = append(L, line)
			}
			for _, e := range listAt(cl, "attested_causation") {
				L = append(L, fmt.Sprintf("- attested causation: `%s` "+
					"caused_by `%s` (attested by %s)", validation.ObjStr(e, "src"),
					validation.ObjStr(e, "dst"), validation.ObjStr(e, "actor")))
			}
			L = append(L, "")
		}
	}

	var planPtr *validation.Value
	if plan, err := planner.LoadPlanReadonly(campaign); err == nil {
		planPtr = &plan
	}
	if planPtr != nil && len(listAt(*planPtr, "lenses")) > 0 {
		plan := *planPtr
		div, err := planner.DivergenceStatusFor(campaign, plan, nil)
		if err != nil {
			return "", err
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
				r := []rune(reason)
				if len(r) > 120 {
					r = r[:120]
				}
				tail = " — " + string(r)
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
		L = append(L, strings.Join(lines, "\n"))
	}

	// B2: the liveness-findings subsection — one row per liveness finding
	// (any status), with the incentive answer (who_profits) at a glance so
	// a freeze finding cannot sit at HYPOTHESIS without its adversarial-game
	// clause being visible. Presence-gated: no liveness finding, no section.
	livenessRows := []validation.Value{}
	for _, f := range all {
		if findings.IsLivenessFinding(f) {
			livenessRows = append(livenessRows, f)
		}
	}
	if len(livenessRows) > 0 {
		sort.SliceStable(livenessRows, func(i, j int) bool {
			return validation.ObjStr(livenessRows[i], "finding_id") <
				validation.ObjStr(livenessRows[j], "finding_id")
		})
		L = append(L, "### LIVENESS FINDINGS — who profits from the freeze")
		L = append(L, "")
		for _, f := range livenessRows {
			ag := asObj(validation.ObjAt(f, "adversarial_game"))
			who := "UNANSWERED (gate check15)"
			if len(ag.O) > 0 {
				if wp := validation.ObjStr(ag, "who_profits"); wp != "" {
					who = wp
				}
			}
			L = append(L, fmt.Sprintf("- `%s` (%s): %s",
				validation.ObjStr(f, "finding_id"), validation.ObjStr(f, "status"), who))
		}
		L = append(L, "")
	}

	sortedConfirmed := append([]validation.Value{}, confirmed...)
	sort.SliceStable(sortedConfirmed, func(i, j int) bool {
		return riskScore(sortedConfirmed[i]) > riskScore(sortedConfirmed[j])
	})
	for _, f := range sortedConfirmed {
		sec, err := findingSection(campaign, f, "CONFIRMED", all)
		if err != nil {
			return "", err
		}
		L = append(L, sec...)
	}

	for _, ch := range provenChains {
		var sf validation.Value
		foundSF := false
		for _, f := range chainF {
			if validation.ObjStr(validation.ObjAt(f, "dedup_meta"), "chain_id") == validation.ObjStr(ch, "chain_id") {
				sf = f
				foundSF = true
				break
			}
		}
		L = append(L, fmt.Sprintf("### CHAIN: %s", validation.ObjStr(ch, "title")))
		L = append(L, "")
		L = append(L, fmt.Sprintf("- id: `%s` — status %s, evidence floor %s",
			validation.ObjStr(ch, "chain_id"), validation.ObjStr(ch, "status"),
			pyStr(validation.ObjAt(ch, "evidence_floor"))))
		quoted := []string{}
		for _, m := range strList(validation.ObjAt(ch, "members")) {
			quoted = append(quoted, "`"+m+"`")
		}
		L = append(L, "- members: "+strings.Join(quoted, ", "))
		if validation.ObjStr(ch, "narrative") != "" {
			L = append(L, "- narrative: "+validation.ObjStr(ch, "narrative"))
		}
		for _, lnk := range listAt(ch, "capability_links") {
			L = append(L, fmt.Sprintf("- `%s` grants *%s* → `%s` requires it",
				validation.ObjStr(lnk, "from_finding"), validation.ObjStr(lnk, "granted"),
				validation.ObjStr(lnk, "to_finding")))
		}
		if foundSF {
			L = append(L, fmt.Sprintf("- super-finding: `%s`",
				validation.ObjStr(sf, "finding_id")))
		}
		L = append(L, "")
	}

	// B3: the unproven (hypothesis-level) chains get their own clearly marked
	// section — never the CHAIN: heading, never the submission count. Each
	// hop carries its member's evidence level. Presence-gated: a campaign
	// without an unproven chain gains no bytes.
	if len(unprovenChains) > 0 {
		L = append(L, "## Unproven chains (hypothesis-level)")
		L = append(L, "")
		L = append(L, "These are LEADS, not results: at least one member is "+
			"not independently CONFIRMED, so nothing here counts as "+
			"evidence-confirmed and nothing here enters the submission table.")
		L = append(L, "")
		for _, ch := range unprovenChains {
			L = append(L, fmt.Sprintf("### UNPROVEN CHAIN: %s", validation.ObjStr(ch, "title")))
			L = append(L, "")
			L = append(L, fmt.Sprintf("- id: `%s` — provenance %s, evidence floor %s",
				validation.ObjStr(ch, "chain_id"), pyStr(validation.ObjAt(ch, "provenance")),
				pyStr(validation.ObjAt(ch, "evidence_floor"))))
			quoted := []string{}
			for _, m := range strList(validation.ObjAt(ch, "members")) {
				quoted = append(quoted, "`"+m+"`")
			}
			L = append(L, "- members: "+strings.Join(quoted, ", "))
			if validation.ObjStr(ch, "narrative") != "" {
				L = append(L, "- narrative: "+validation.ObjStr(ch, "narrative"))
			}
			for _, lnk := range listAt(ch, "capability_links") {
				line := fmt.Sprintf("- `%s` grants *%s* → `%s` requires it",
					validation.ObjStr(lnk, "from_finding"), validation.ObjStr(lnk, "granted"),
					validation.ObjStr(lnk, "to_finding"))
				if lvl := validation.ObjStr(lnk, "link_evidence"); lvl != "" {
					line += " (from-member evidence " + lvl + ")"
				}
				L = append(L, line)
			}
			if t := asObj(validation.ObjAt(ch, "terminal")); len(t.O) > 0 {
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
				L = append(L, fmt.Sprintf("- terminal: *%s* via `%s` — %s",
					cap, validation.ObjStr(t, "via_finding"), note))
			}
			L = append(L, "")
		}
	}

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
	for _, f := range all {
		if findings.IsTerminal(validation.ObjStr(f, "status")) {
			dismissed = append(dismissed, f)
		}
	}
	if len(dismissed) > 0 {
		L = append(L, "## Dismissed candidates (with reasons)")
		L = append(L, "")
		for _, f := range dismissed {
			hist := listAt(f, "history")
			last := validation.VObj()
			if len(hist) > 0 {
				last = asObj(hist[len(hist)-1])
			}
			L = append(L, fmt.Sprintf("- `%s` **%s** — %s",
				validation.ObjStr(f, "finding_id"), validation.ObjStr(f, "status"), validation.ObjStr(f, "title")))
			reason := "n/a"
			if v := validation.ObjAt(last, "reason"); v.Kind != validation.Null {
				reason = pyStr(v)
			}
			L = append(L, "  - reason: "+reason)
		}
		L = append(L, "")
	}

	// dismissed-with-strong-reaching: the false-negative direction of the
	// dismissal area. A dismissed finding a high-risk probe row still
	// reaches is the queue nobody asked for: the row says "look here" and
	// the finding says "never mind". Presence-gated (the additive
	// convention): renders only when (a) at least one finding carries a
	// terminal-dismissal status and (b) at least one high-risk probe row
	// reaches a dismissed finding — otherwise the campaign gains no bytes.
	if reach := dismissedWithReach(campaign, all); len(reach) > 0 {
		L = append(L, reach...)
	}

	// B4 disposition review: high-risk probe rows dismissed with dismissal
	// vocabulary, plus the explicit overrides of that gate. Presence-gated
	// (the additive convention): it renders only when something was flagged
	// or overridden, so a campaign with clean closures gains no bytes.
	var flags []planner.DismissalFlag
	var dispErr error
	if planV, perr := planner.LoadPlanReadonly(campaign); perr == nil {
		flags, dispErr = planner.DispositionReview(campaign, planV)
	}
	overrides := []validation.Value{}
	if evts, eerr := campaign.Events(); eerr == nil {
		for _, e := range evts {
			if validation.ObjStr(e, "type") == "probe.dismissal_overridden" {
				overrides = append(overrides, e)
			}
		}
	}
	if dispErr == nil && (len(flags) > 0 || len(overrides) > 0) {
		L = append(L, "## Disposition review")
		L = append(L, "")
		for _, f := range flags {
			L = append(L, fmt.Sprintf("- `%s` (row %s, tier %d, gap %d): %s — dismissal vocabulary: %s",
				f.Priority, f.RowID, f.Tier, f.Gap, f.Reason,
				strings.Join(f.Phrases, ", ")))
		}
		for _, e := range overrides {
			data := validation.ObjAt(e, "data")
			L = append(L, fmt.Sprintf("- OVERRIDDEN `%s` (row %s) by %s: %s",
				validation.ObjStr(e, "ref"), validation.ObjStr(data, "row_id"),
				validation.ObjStr(data, "actor"),
				validation.ObjStr(data, "override_reason")))
		}
		L = append(L, "")
	}

	if len(mem) > 0 {
		L = append(L, "## Learning queue")
		L = append(L, "")
		L = append(L, "| id | kind | status | promotion |")
		L = append(L, "|---|---|---|---|")
		for _, m := range mem {
			L = append(L, fmt.Sprintf("| `%s` | %s | %s | %s |",
				validation.ObjStr(m, "memory_id"), validation.ObjStr(m, "kind"), validation.ObjStr(m, "status"),
				validation.ObjStr(m, "promotion_status")))
		}
		pending := 0
		for _, m := range mem {
			if validation.ObjStr(m, "promotion_status") == "pending" {
				pending++
			}
		}
		if pending > 0 {
			L = append(L, "")
			L = append(L, fmt.Sprintf("> %d candidate(s) awaiting human "+
				"approval — nothing enters long-term memory without it.",
				pending))
		}
		L = append(L, "")
	}

	out := filepath.Join(campaign.Dir, "report.md")
	if err := os.WriteFile(out, []byte(strings.Join(L, "\n")+"\n"), 0o644); err != nil {
		return "", err
	}
	if _, err := campaign.RegisterOrRefresh("report", out, "", nil,
		"report regenerated (view over current findings)"); err != nil {
		return "", err
	}
	data := validation.VObj(kv("path", validation.VStr(out)))
	if _, err := campaign.Log("report.generated", nil, &data); err != nil {
		return "", err
	}
	return out, nil
}

// dismissedTerminalStatuses are the dismissal-side terminal states: the
// finding was looked at and set aside. SUPERSEDED is deliberately absent —
// supersession is correction, not dismissal, so it never arms gate (a).
var dismissedTerminalStatuses = []string{"DISPROVED", "OUT_OF_SCOPE",
	"INFORMATIONAL", "DUPLICATE"}

// dismissedWithReach renders the "Dismissed with strong reaching"
// subsection: every terminal-dismissal finding a high-risk probe row
// reaches, sorted by finding id then row ref (the determinism law: every
// map iteration output is sorted). It returns nil when the presence gate is
// closed — no terminal dismissals, no surface, no high-risk rows, or no
// reach — so the campaign gains no bytes.
func dismissedWithReach(campaign *state.Campaign,
	all []validation.Value) []string {
	dismissed := []validation.Value{}
	for _, f := range all {
		if dismissalTerminal(validation.ObjStr(f, "status")) {
			dismissed = append(dismissed, f)
		}
	}
	if len(dismissed) == 0 {
		return nil
	}
	surfacePtr, err := probes.CampaignSurface(campaign)
	if err != nil || surfacePtr == nil {
		return nil
	}
	indexPtr, err := probes.CampaignIndex(campaign)
	if err != nil {
		return nil
	}
	type hit struct {
		fid, status, class, row string
		tier, gap               int64
	}
	hits := []hit{}
	for _, row := range listAt(*surfacePtr, "rows") {
		if !planner.HighRiskRow(row) {
			continue
		}
		files := reachRowFiles(row, indexPtr)
		if len(files) == 0 {
			continue
		}
		rid := validation.ObjStr(row, "row_id")
		for _, f := range dismissed {
			ff := reachFindingFiles(f)
			overlap := false
			for name := range files {
				if _, ok := ff[name]; ok {
					overlap = true
					break
				}
			}
			if !overlap {
				continue
			}
			hits = append(hits, hit{fid: validation.ObjStr(f, "finding_id"),
				status: validation.ObjStr(f, "status"),
				class:  reachFindingClass(f), row: rid,
				tier: reachInt(row, "tier"),
				gap:  reachInt(row, "assertion_gap")})
		}
	}
	if len(hits) == 0 {
		return nil
	}
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].fid != hits[j].fid {
			return hits[i].fid < hits[j].fid
		}
		return hits[i].row < hits[j].row
	})
	L := []string{"### Dismissed with strong reaching", ""}
	for _, h := range hits {
		L = append(L, fmt.Sprintf("- `%s` (%s, class %s): reached by "+
			"high-risk row `%s` (tier %d, assertion_gap %d)",
			h.fid, h.status, h.class, h.row, h.tier, h.gap))
	}
	L = append(L, "reach joined by file overlap (no id-level link exists).")
	L = append(L, "")
	return L
}

// dismissalTerminal reports whether a finding status arms gate (a) of
// the dismissed-with-reach section.
func dismissalTerminal(status string) bool {
	for _, s := range dismissedTerminalStatuses {
		if status == s {
			return true
		}
	}
	return false
}

// reachRowFiles is the row side of the file-overlap join: the basenames of
// the row's anchor files (RowAnchorPairs resolves contracts through the
// index, falling back to bare contract names without one), plus the row's
// own contract names for findings whose affected entry carries no path.
func reachRowFiles(row validation.Value,
	index *validation.Value) map[string]struct{} {
	out := map[string]struct{}{}
	for _, pair := range probes.RowAnchorPairs(row, index) {
		file := pair
		if i := strings.LastIndex(file, "#L"); i >= 0 {
			file = file[:i]
		}
		if b := pathBase(file); b != "" {
			out[b] = struct{}{}
		}
	}
	for _, key := range []string{"contract", "base"} {
		if v := validation.ObjStr(row, key); v != "" {
			out[v] = struct{}{}
		}
	}
	for _, s := range listAt(row, "siblings") {
		if v := validation.ObjStr(s, "contract"); v != "" {
			out[v] = struct{}{}
		}
	}
	return out
}

// reachFindingFiles is the finding side of the join: the basenames of the
// affected paths (or files), plus contract names for entries without one.
func reachFindingFiles(f validation.Value) map[string]struct{} {
	out := map[string]struct{}{}
	for _, a := range listAt(f, "affected") {
		p := validation.ObjStr(a, "path")
		if p == "" {
			p = validation.ObjStr(a, "file")
		}
		if p != "" {
			if b := pathBase(p); b != "" {
				out[b] = struct{}{}
			}
		}
		if c := validation.ObjStr(a, "contract"); c != "" {
			out[c] = struct{}{}
		}
	}
	return out
}

// reachFindingClass is the finding's root-cause class (bug_class, then
// unclassified when neither is set).
func reachFindingClass(f validation.Value) string {
	if c := validation.ObjStr(validation.ObjAt(f, "root_cause"), "class"); c != "" {
		return c
	}
	if c := validation.ObjStr(f, "bug_class"); c != "" {
		return c
	}
	return "unclassified"
}

// classAliasSuffixSpaced is the G12 display suffix with its leading space
// (" [OWASP SC05]") or "" when the class carries no alias — the empty string
// keeps unmapped render sites byte-identical.
func classAliasSuffixSpaced(class string) string {
	if sfx := classweights.ClassAliasSuffix(class); sfx != "" {
		return " " + sfx
	}
	return ""
}

// reachInt reads an integer row field across the Int/Flt shapes (0 when
// absent — the HighRiskRow caution reads the same way).
func reachInt(row validation.Value, key string) int64 {
	switch v := validation.ObjAt(row, key); v.Kind {
	case validation.Int:
		return v.I
	case validation.Flt:
		return int64(v.F)
	}
	return 0
}

// pathBase is path.Base without importing path at the call sites.
func pathBase(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// immunizationWaived reports whether an explicit immunization waiver covers
// this finding (subject '*' waives the whole stage). B1: mirrors the
// fork-PoC waiver check so a waived immunization renders as a caveat.
func immunizationWaived(campaign *state.Campaign, f validation.Value) bool {
	waivers, err := completion.Waivers(campaign, "immunization")
	if err != nil {
		return false
	}
	for _, w := range waivers {
		subj := validation.ObjStr(w, "subject")
		if subj == "*" || subj == validation.ObjStr(f, "finding_id") {
			return true
		}
	}
	return false
}

// patchRegressionMark renders the G11 post-patch verdict label. Unknown
// verdicts fail open to INDETERMINATE, never to a fix claim.
func patchRegressionMark(verdict string) string {
	switch verdict {
	case "fixed":
		return "**FIXED**"
	case "still_reproducible":
		return "**STILL REPRODUCIBLE**"
	default:
		return "**INDETERMINATE**"
	}
}

func riskScore(f validation.Value) float64 {
	v := asObj(validation.ObjAt(asObj(validation.ObjAt(f, "risk")), "validated"))
	s := validation.ObjAt(v, "score")
	switch s.Kind {
	case validation.Int:
		return float64(s.I)
	case validation.Flt:
		return s.F
	}
	return 0
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// getOr is Python's d.get(key, default) as a string render.
func getOr(v validation.Value, key, def string) string {
	if !hasKey(v, key) {
		return def
	}
	return pyStr(validation.ObjAt(v, key))
}

// pyCommaAuto is Python's f"{v:,}": thousands separators, no forced decimals.
func pyCommaAuto(v validation.Value) string {
	switch v.Kind {
	case validation.Int:
		return commaInt(validation.IntText(v))
	case validation.Flt:
		s := validation.PythonFloat(v.F)
		return commaFloatText(s)
	}
	return pyStr(v)
}

func commaInt(digits string) string {
	neg := strings.HasPrefix(digits, "-")
	if neg {
		digits = digits[1:]
	}
	out := commaGroups(digits)
	if neg {
		return "-" + out
	}
	return out
}

func commaFloatText(s string) string {
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	intPart, frac := s, ""
	if i := strings.IndexByte(s, '.'); i >= 0 {
		intPart, frac = s[:i], s[i:]
	} else if i := strings.IndexAny(s, "eE"); i >= 0 {
		intPart, frac = s[:i], s[i:]
	}
	out := commaGroups(intPart) + frac
	if neg {
		return "-" + out
	}
	return out
}

func commaGroups(digits string) string {
	var b strings.Builder
	for i, c := range digits {
		if i > 0 && (len(digits)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	return b.String()
}

// pyPercent0 is Python's f"{x:.0%}".
func pyPercent0(x float64) string {
	return strconv.FormatFloat(x*100, 'f', 0, 64) + "%"
}

var evidenceOrder = []string{"E0", "E1", "E2", "E3", "E4", "E5", "E6", "E7"}

func evidenceIndex(level string) int {
	for i, l := range evidenceOrder {
		if l == level {
			return i
		}
	}
	return -1
}

// findingSection is report.generate's finding_section closure.
func findingSection(campaign *state.Campaign, f validation.Value, heading string,
	all []validation.Value) ([]string, error) {
	out := []string{}
	rc := asObj(validation.ObjAt(f, "root_cause"))
	out = append(out, fmt.Sprintf("### %s: %s", heading, validation.ObjStr(f, "title")))
	out = append(out, "")
	out = append(out, fmt.Sprintf("- id: `%s` — status **%s** (trajectory: %s)",
		validation.ObjStr(f, "finding_id"), validation.ObjStr(f, "status"),
		pyStr(validation.ObjAt(f, "trajectory"))))
	cwe := ""
	if validation.ObjStr(rc, "cwe") != "" {
		cwe = "CWE " + validation.ObjStr(rc, "cwe")
	}
	out = append(out, fmt.Sprintf("- bug class: `%s`%s %s", pyStr(validation.ObjAt(rc, "class")),
		classAliasSuffixSpaced(validation.ObjStr(rc, "class")), cwe))
	inv := asObj(validation.ObjAt(f, "invariant"))
	if validation.ObjStr(inv, "statement") != "" {
		out = append(out, "- violated invariant: "+validation.ObjStr(inv, "statement"))
	}
	att := asObj(validation.ObjAt(f, "attacker"))
	if validation.ObjStr(att, "profile") != "" {
		capital := ""
		if pyTruthyInt64Only(validation.ObjAt(att, "required_capital_usd")) {
			capital = " (capital: $" + pyCommaAuto(validation.ObjAt(att, "required_capital_usd")) + ")"
		}
		out = append(out, "- attacker: "+validation.ObjStr(att, "profile")+capital)
	}
	risk := asObj(validation.ObjAt(f, "risk"))
	v := asObj(validation.ObjAt(risk, "validated"))
	if len(v.O) > 0 {
		out = append(out, fmt.Sprintf("- validated risk: **%s/10 (%s)**",
			pyStr(validation.ObjAt(v, "score")), pyStr(validation.ObjAt(v, "band"))))
	}
	if rv := validation.ObjStr(risk, "reversibility"); rv != "" {
		out = append(out, "- reversibility: **"+rv+"** (validated_risk component)")
	}
	iv := asObj(validation.ObjAt(risk, "impact_vector"))
	if len(iv.O) > 0 {
		out = append(out, fmt.Sprintf("- impact vector: %s/%s/%s/%s (score %s)",
			pyStr(validation.ObjAt(iv, "asset_exposure")),
			pyStr(validation.ObjAt(iv, "privilege_class")),
			pyStr(validation.ObjAt(iv, "recoverability")),
			pyStr(validation.ObjAt(iv, "insolvency_risk")), pyStr(validation.ObjAt(iv, "score"))))
	}
	if reported := validation.ObjAt(f, "reported_severity"); pyTruthyInt64Only(reported) {
		band := "n/a"
		if b := validation.ObjAt(asObj(validation.ObjAt(f, "risk")), "validated"); b.Kind == validation.Obj {
			if bv := validation.ObjAt(b, "band"); bv.Kind != validation.Null {
				band = pyStr(bv)
			}
		}
		out = append(out, fmt.Sprintf("- reported severity: **%s** — computed "+
			"band: **%s**", pyStr(reported), band))
	}
	econ := asObj(validation.ObjAt(risk, "economic"))
	if decision := findings.UnpriceableDecision(f); decision != nil {
		out = append(out, fmt.Sprintf("- economically extractable: "+
			"UNPRICEABLE (ceiling: %s)", pyStr(validation.ObjAt(*decision, "ceiling"))))
	} else if ex := validation.ObjAt(econ, "extractable_usd"); ex.Kind != validation.Null {
		out = append(out, fmt.Sprintf("- economically extractable: $%s",
			pyCommaAuto(ex)))
	}
	if exp := asObj(validation.ObjAt(f, "exploitability")); len(exp.O) > 0 {
		if paid := validation.ObjAt(exp, "paid"); paid.Kind == validation.Bool {
			if paid.B {
				out = append(out, fmt.Sprintf(
					"- paid exploitability: **yes** — who pays, and why: "+
						"%s", pyStr(validation.ObjAt(exp, "argument"))))
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
	// how, and why the challenge path does not undo it. Presence-gated:
	// findings without the clause render nothing here.
	if ag := asObj(validation.ObjAt(f, "adversarial_game")); len(ag.O) > 0 {
		out = append(out, fmt.Sprintf("- adversarial game: who profits — %s",
			pyStr(validation.ObjAt(ag, "who_profits"))))
		out = append(out, fmt.Sprintf("-   mechanism: %s",
			pyStr(validation.ObjAt(ag, "profit_mechanism"))))
		out = append(out, fmt.Sprintf("-   challenge interplay: %s",
			pyStr(validation.ObjAt(ag, "challenge_interplay"))))
	}
	if ack := asObj(validation.ObjAt(validation.ObjAt(f, "dedup_meta"), "in_code_ack")); len(ack.O) > 0 {
		line := fmt.Sprintf("- in-code ack: %s:%s — phrase %q (window %s)",
			pyStr(validation.ObjAt(ack, "file")), pyStr(validation.ObjAt(ack, "line")),
			pyStr(validation.ObjAt(ack, "phrase")), pyStr(validation.ObjAt(ack, "window")))
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
	b := asObj(validation.ObjAt(f, "bounty"))
	if len(b.O) > 0 {
		line := fmt.Sprintf("- bounty gate: eligible=%s, submission_ready=%s",
			pyStr(validation.ObjAt(b, "eligible")), pyStr(validation.ObjAt(b, "submission_ready")))
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
	if ar := asObj(validation.ObjAt(b, "accepted_risk")); len(ar.O) > 0 {
		kind := validation.ObjStr(ar, "kind")
		line := fmt.Sprintf("- accepted risk: **%s**", pyStr(validation.ObjAt(ar,
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
			line := fmt.Sprintf("%s. %s", pyStr(validation.ObjAt(s, "step")),
				pyStr(validation.ObjAt(s, "action")))
			if validation.ObjStr(s, "state_effect") != "" {
				line += " → " + validation.ObjStr(s, "state_effect")
			}
			out = append(out, line)
		}
	}
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
				validation.ObjStr(e, "type"), pyStr(validation.ObjAt(e, "description")))
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

	if validation.ObjStr(asObj(validation.ObjAt(f, "maximization")), "ladder_id") != "" {
		status := validation.ObjStr(f, "status")
		if status == "CONFIRMED" || status == "CHAIN" {
			rep, err := maximization.LadderReport(campaign, validation.ObjStr(f, "finding_id"))
			if err != nil {
				return nil, err
			}
			lad := validation.ObjAt(rep, "ladder")
			if lad.Kind == validation.Obj {
				out = append(out, "")
				disp := asObj(validation.ObjAt(lad, "disposition"))
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
				if unexplored := strList(validation.ObjAt(rep, "unexplored_axes")); len(unexplored) > 0 {
					out = append(out, "")
					out = append(out, "> unexplored axes: "+
						strings.Join(unexplored, ", ")+" — the search is not "+
						"complete; the maximal rung is provisional")
				}
				rungs := listAt(rep, "rungs")
				if len(rungs) > 0 {
					base := rungs[0]
					mx := asObj(validation.ObjAt(rep, "maximal"))
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
			}
		}
	}

	status := validation.ObjStr(f, "status")
	if status == "CONFIRMED" || status == "CHAIN" {
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
				validation.ObjStr(item, "type"), pyStr(validation.ObjAt(item, "artifact_id"))))
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
		if pr := validation.ObjAt(asObj(validation.ObjAt(f, "verification")),
			"patch_regression"); pr.Kind == validation.Obj {
			out = append(out, fmt.Sprintf("- patch regression: %s (%s → %s)",
				patchRegressionMark(validation.ObjStr(pr, "verdict")),
				validation.ObjStr(pr, "base_exec"), validation.ObjStr(pr, "exec")))
			if d := validation.ObjStr(pr, "detail"); d != "" {
				out = append(out, "- "+d)
			}
		}
		if immState == "immunized" {
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
		}
	}

	ei := asObj(validation.ObjAt(f, "economic_impact"))
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
					pyStr(validation.ObjAt(*rowPtr, "as_of"))))
			} else {
				out = append(out, fmt.Sprintf("- price basis: `%s` — "+
					"**UNRESOLVED** (no row in the price table)", basis))
			}
		} else {
			out = append(out, "- price basis: **NONE** — USD figures "+
				strings.Join(usdKeys, ", ")+" are unattributed")
		}
	}
	out = append(out, "")
	return out, nil
}

// reportAckQuote re-reads the acknowledged source line for the report quote:
// the record stores the file relative to the finding's source pin root. The
// quote is the trimmed line; any failure to resolve the pin, the file or the
// line yields (empty, false) and the caller prints the record without a quote.
func reportAckQuote(campaign *state.Campaign, f validation.Value,
	ack validation.Value) (string, bool) {
	sid := validation.ObjStr(validation.ObjAt(f, "snapshot_ids"), "source")
	if sid == "" || sid == "unpinned" {
		return "", false
	}
	snap, err := validation.ReadJson(filepath.Join(campaign.Dir, "snapshots",
		sid, "snapshot.json"))
	if err != nil {
		return "", false
	}
	root := validation.ObjStr(validation.ObjAt(snap, "source"), "root")
	file := validation.ObjStr(ack, "file")
	p := file
	if !filepath.IsAbs(p) {
		p = filepath.Join(root, p)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return "", false
	}
	lines := strings.Split(string(raw), "\n")
	n := int(validation.ObjAt(ack, "line").I)
	if n < 1 || n > len(lines) {
		return "", false
	}
	q := strings.TrimRight(strings.TrimLeft(lines[n-1], " \t"), " \t")
	if q == "" {
		return "", false
	}
	return `"` + q + `"`, true
}

func ratioOf(rung validation.Value) float64 {
	return floatVal(validation.ObjAt(rung, "extraction_ratio"))
}

func floatVal(v validation.Value) float64 {
	switch v.Kind {
	case validation.Int:
		return float64(v.I)
	case validation.Flt:
		return v.F
	}
	return 0
}

// splitChainsByProvenance is the B3 split: a chain doc whose provenance is
// "unproven" is a hypothesis-level lead, everything else (including every
// pre-B3 doc, which carries no provenance key at all) is evidence-confirmed.
func splitChainsByProvenance(chains []validation.Value) (proven,
	unproven []validation.Value) {
	for _, ch := range chains {
		if validation.ObjStr(ch, "provenance") == "unproven" {
			unproven = append(unproven, ch)
		} else {
			proven = append(proven, ch)
		}
	}
	return proven, unproven
}
