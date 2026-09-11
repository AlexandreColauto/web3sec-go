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
	"websec/internal/relations"
	"websec/internal/risk"
	"websec/internal/state"
	"websec/internal/validation"
)

func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

func objAt(v validation.Value, key string) validation.Value {
	if v.Kind != validation.Obj {
		return validation.VNull()
	}
	for _, pair := range v.O {
		if pair.K == key {
			return pair.V
		}
	}
	return validation.VNull()
}

func hasKey(v validation.Value, key string) bool {
	for _, pair := range v.O {
		if pair.K == key {
			return true
		}
	}
	return false
}

func objStr(v validation.Value, key string) string {
	f := objAt(v, key)
	if f.Kind == validation.Str {
		return f.S
	}
	return ""
}

func listAt(v validation.Value, key string) []validation.Value {
	f := objAt(v, key)
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

func pyTruthy(v validation.Value) bool {
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
	text := objStr(c, "capability")
	if text == "" {
		text = objStr(c, "mechanism")
	}
	if text == "" {
		text = "unspecified privilege"
	}
	notes := []string{}
	if objAt(c, "timelocked").Kind == validation.Bool &&
		objAt(c, "timelocked").B {
		notes = append(notes, "timelocked")
	}
	t := objAt(c, "multisig_threshold")
	if t.Kind == validation.Int {
		notes = append(notes, strconv.FormatInt(t.I, 10)+"-of-n multisig")
	}
	if objAt(c, "can_drain").Kind == validation.Bool &&
		objAt(c, "can_drain").B {
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
		!pyTruthy(objAt(*modelPtr, "privileges")) {
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
		head := fmt.Sprintf("- **%s** (`%s`) — band: `%s`", objStr(r, "role"),
			objStr(r, "role_label"), objStr(r, "exposure_band"))
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
				strings.Join(strList(objAt(best, "path")), " -> "),
				objStr(best, "terminal_capability")))
		}
		if len(chains) > 0 {
			best := chains[0]
			L = append(L, fmt.Sprintf("  - chains: %s, best: %s -> %s",
				count(len(chains), "multi-step path"),
				strings.Join(strList(objAt(best, "path")), " -> "),
				objStr(best, "terminal_capability")))
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
	if pyTruthy(objAt(summary, "stale")) {
		staleNote = " — **STALE**: the structural index has moved since this " +
			"surface was built; re-run `webv2 probes " + campaign.CampaignID +
			" run` and re-disposition what moved"
	}
	L = append(L, fmt.Sprintf("- surface `index_sha`: `%s`%s",
		pyStr(objAt(surface, "index_sha")), staleNote))
	L = append(L, "")
	for _, row := range listAt(surface, "rows") {
		rid := objStr(row, "row_id")
		d := asObj(objAt(disp, rid))
		anchors := "—"
		if pairs := probes.RowAnchorPairs(row, &index); len(pairs) > 0 {
			anchors = strings.Join(pairs, ", ")
		}
		var state string
		switch {
		case pyTruthy(objAt(d, "dispositioned")):
			state = "**" + objStr(d, "status") + "**"
			if objStr(d, "reason") != "" {
				state += ": " + objStr(d, "reason")
			}
			a := asObj(objAt(d, "anchor"))
			if len(a.O) > 0 {
				state += fmt.Sprintf(" (anchor `%s` = %s)",
					objStr(a, "field"), pyStr(objAt(a, "ref")))
			}
		case objStr(d, "status") != "" && objStr(d, "status") != "open":
			state = "open (" + objStr(d, "status") + ")"
		case objStr(d, "priority_id") != "":
			state = "open"
		default:
			state = "open (not emitted)"
		}
		L = append(L, fmt.Sprintf("- `%s` %s (%s %s) tier %s, gap %s, "+
			"anchors %s — %s", rid, objStr(row, "probe"), objStr(row, "axis"),
			objStr(row, "lens"), pyStr(objAt(row, "tier")),
			pyStr(objAt(row, "assertion_gap")), anchors, state))
	}
	L = append(L, "")
	for _, entry := range blanks {
		L = append(L, fmt.Sprintf("- blank attested: %s cites `%s` — %s (%s)",
			objStr(entry, "axis"), objStr(entry, "anchor_blind"),
			objStr(entry, "reason"), objStr(entry, "actor")))
	}
	if len(blanks) > 0 {
		L = append(L, "")
	}
	return L, nil
}

func intAt(v validation.Value, key string) int64 {
	f := objAt(v, key)
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
	if unscored && objAt(policy, "submission_budget").Kind != validation.Obj {
		stored := false
		for _, f := range all {
			v := objAt(objAt(f, "risk"), "acceptance_score")
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
		if s := objStr(f, "status"); s == "DUPLICATE" || s == "OUT_OF_SCOPE" ||
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
	if sb := objAt(policy, "submission_budget"); sb.Kind == validation.Obj {
		if mf := intAt(sb, "max_findings"); mf > 0 {
			k = int(mf)
		}
		if rb := objStr(sb, "rank_by"); rb == "severity" {
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
		totals := objAt(rep, "totals")
		if v := objAt(totals,
			"cost_per_critic_confirmed_usd"); v.Kind != validation.Null {
			perCritic = "$" + lensMoney(v)
		}
		if v := objAt(totals,
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
			objStr(r, "lens"), lensInt(r, "n_planned"),
			lensInt(r, "n_confirmed"), lensMoney(objAt(r, "cost_usd"))))
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
	if v := objAt(r, key); v.Kind == validation.Int {
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
			allFindingCell(f), objStr(f, "status"), allFindingEvidence(f),
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
	switch objStr(f, "status") {
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
	title := objStr(f, "title")
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
	riskObj := asObj(objAt(f, "risk"))
	band := objStr(asObj(objAt(riskObj, "validated")), "band")
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
	v := objAt(objAt(f, "risk"), "acceptance_score")
	switch v.Kind {
	case validation.Flt:
		return risk.ScoreText(v.F)
	case validation.Int:
		return risk.ScoreText(float64(v.I))
	}
	return "—"
}

func allFindingSubmit(f validation.Value) string {
	if pyTruthy(objAt(asObj(objAt(f, "bounty")), "submission_ready")) {
		return "yes"
	}
	return "—"
}

// allFindingChain is the chain membership: a per-finding chain id when the
// finding carries one, otherwise a marker for the CHAIN status.
func allFindingChain(f validation.Value) string {
	if id := objStr(f, "chain_id"); id != "" {
		return id
	}
	if objStr(f, "status") == "CHAIN" {
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
	title := objStr(e.Finding, "title")
	if len(title) > 40 {
		title = title[:40] + "…"
	}
	if title != "" {
		return id + " " + title
	}
	return id
}

func bandCell(e risk.AcceptanceEntry) string {
	riskObj := asObj(objAt(e.Finding, "risk"))
	b := objStr(asObj(objAt(riskObj, "validated")), "band")
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
	return objStr(f, "finding_id")
}

func criticVerdictOf(f validation.Value) string {
	return objStr(objAt(f, "verification"), "critic_verdict")
}

// Generate is generate(): write report.md, register/refresh the artifact and
// log report.generated. Returns the report path.
func Generate(campaign *state.Campaign) (string, error) {
	st, err := campaign.State()
	if err != nil {
		return "", err
	}
	policyPath := objStr(st, "policy_path")
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
			status := objStr(f, "status")
			if status != "CONFIRMED" && status != "CHAIN" {
				continue
			}
			if _, err := bounty.EvaluateBountyGate(campaign,
				objStr(f, "finding_id"), policy, true); err != nil {
				return "", err
			}
		}
	}
	all, err := findings.LoadAllFindings(campaign)
	if err != nil {
		return "", err
	}
	chainPaths := validation.ListPrefixed(campaign.ChainsDir, "CHAIN-", ".json")
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
		if h := objAt(evts[len(evts)-1], "event_hash"); h.Kind != validation.Null {
			headHash = h
		}
	}

	L := []string{}
	L = append(L, "<!-- state-head: "+pyStr(headHash)+" -->")
	L = append(L, "# Security Research Report — "+objStr(st, "program"))
	L = append(L, "")
	L = append(L, fmt.Sprintf("- campaign: `%s`", objStr(st, "campaign_id")))
	L = append(L, fmt.Sprintf("- phase: **%s** (pass %s)", objStr(st, "phase"),
		pyStr(objAt(asObj(objAt(st, "budget")), "pass"))))
	L = append(L, fmt.Sprintf("- active snapshot: `%s`",
		pyStr(objAt(st, "active_snapshot_id"))))
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
				eq := []rune(objStr(g, "equation"))
				if len(eq) > 60 {
					eq = eq[:60]
				}
				L = append(L, fmt.Sprintf("| `%s` | %s |", string(eq),
					strings.Join(strList(objAt(g, "missing")), ", ")))
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
				names = append(names, objStr(a, "asset"))
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

	covPath := filepath.Join(campaign.ArtifactsDir, "coverage.json")
	if fileExists(covPath) {
		cov, err := validation.ReadJson(covPath)
		if err != nil {
			return "", err
		}
		s := asObj(objAt(cov, "summary"))
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
			if v := objAt(s, "unknown_note"); v.Kind != validation.Null {
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
					trajs := strings.Join(strList(objAt(t, "trajectories")), ", ")
					if trajs == "" {
						trajs = "none"
					}
					L = append(L, fmt.Sprintf("- `%s` — status %s, "+
						"trajectories: %s", objStr(t, "path"),
						objStr(t, "status"), trajs))
				}
				L = append(L, "")
			}
		}
	}

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
		switch objStr(f, "status") {
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
		if pyTruthy(objAt(asObj(objAt(f, "bounty")), "submission_ready")) {
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
			cls := objStr(objAt(f, "root_cause"), "class")
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
				status := objStr(p, "status")
				ref := objAt(p, "closed_ref")
				reason := objStr(p, "closed_reason")
				sib := ""
				if objStr(p, "sibling_of") != "" {
					sib = " (sibling of " + objStr(p, "sibling_of") + ")"
				}
				question := []rune(objStr(p, "question"))
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
						"no evidence ref)%s: %s — %s", objStr(p, "id"), sib,
						string(question), why))
				} else if (status == "not-applicable" ||
					status == "deprioritized") && reason == "" {
					flagged = append(flagged, fmt.Sprintf("- **%s** (%s, no "+
						"reason)%s: %s", objStr(p, "id"), status, sib,
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
				if objStr(p, "status") == "open" && objStr(p, "sibling_of") != "" {
					question := []rune(objStr(p, "question"))
					if len(question) > 100 {
						question = question[:100]
					}
					L = append(L, fmt.Sprintf("- **%s** (open, sibling of %s): %s",
						objStr(p, "id"), objStr(p, "sibling_of"), string(question)))
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
				"root cause", objStr(cl, "class"), len(members)))
			L = append(L, "")
			if objStr(cl, "description") != "" {
				L = append(L, "- root cause: "+objStr(cl, "description"))
			}
			subs := listAt(cl, "subclusters")
			if len(subs) >= 2 {
				L = append(L, "- **one bug, several gates** — a fix at one "+
					"attack surface does NOT close the others; each surface "+
					"below needs its own fix (and its own verification)")
			}
			for _, sc := range subs {
				locs := []string{}
				for _, p := range strList(objAt(sc, "locations")) {
					locs = append(locs, "`"+p+"`")
				}
				fids := []string{}
				for _, m := range strList(objAt(sc, "finding_ids")) {
					fids = append(fids, "`"+m+"`")
				}
				line := fmt.Sprintf("- a fix at %s closes %s",
					strings.Join(locs, ", "), strings.Join(fids, ", "))
				if imm := strList(objAt(sc, "immunized")); len(imm) > 0 {
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
					"caused_by `%s` (attested by %s)", objStr(e, "src"),
					objStr(e, "dst"), objStr(e, "actor")))
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
		named := strList(objAt(div, "named_classes"))
		namedTxt := strings.Join(named, ", ")
		if namedTxt == "" {
			namedTxt = "none"
		}
		lines = append(lines, fmt.Sprintf("Bug classes named: %d (min %d): %s",
			len(named), planner.MinDistinctClasses, namedTxt))
		lines = append(lines, "")
		for _, l := range listAt(plan, "lenses") {
			reason := strings.TrimSpace(objStr(l, "closed_reason"))
			tail := ""
			if reason != "" {
				r := []rune(reason)
				if len(r) > 120 {
					r = r[:120]
				}
				tail = " — " + string(r)
			}
			ref := ""
			if objStr(l, "closed_ref") != "" {
				ref = " [ref: " + objStr(l, "closed_ref") + "]"
			}
			fam := fmt.Sprintf(" [families: %s; attested: %s]",
				strings.Join(strList(objAt(l, "families")), ", "),
				strings.Join(strList(objAt(l, "families_checked")), ", "))
			reopen := ""
			if objStr(l, "reopen_reason") != "" {
				reopen = " (REOPENED: " + objStr(l, "reopen_reason") + ")"
			}
			lines = append(lines, fmt.Sprintf("- %s %s (%s): %s%s%s%s%s",
				objStr(l, "id"), objStr(l, "lens"), objStr(l, "surface"),
				objStr(l, "status"), tail, ref, fam, reopen))
			for _, s := range listAt(l, "symmetry") {
				lines = append(lines, fmt.Sprintf("    - %s -> %s",
					objStr(s, "family"),
					strings.Join(strList(objAt(s, "primitives")), ", ")))
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
			return objStr(livenessRows[i], "finding_id") <
				objStr(livenessRows[j], "finding_id")
		})
		L = append(L, "### LIVENESS FINDINGS — who profits from the freeze")
		L = append(L, "")
		for _, f := range livenessRows {
			ag := asObj(objAt(f, "adversarial_game"))
			who := "UNANSWERED (gate check15)"
			if len(ag.O) > 0 {
				if wp := objStr(ag, "who_profits"); wp != "" {
					who = wp
				}
			}
			L = append(L, fmt.Sprintf("- `%s` (%s): %s",
				objStr(f, "finding_id"), objStr(f, "status"), who))
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
			if objStr(objAt(f, "dedup_meta"), "chain_id") == objStr(ch, "chain_id") {
				sf = f
				foundSF = true
				break
			}
		}
		L = append(L, fmt.Sprintf("### CHAIN: %s", objStr(ch, "title")))
		L = append(L, "")
		L = append(L, fmt.Sprintf("- id: `%s` — status %s, evidence floor %s",
			objStr(ch, "chain_id"), objStr(ch, "status"),
			pyStr(objAt(ch, "evidence_floor"))))
		quoted := []string{}
		for _, m := range strList(objAt(ch, "members")) {
			quoted = append(quoted, "`"+m+"`")
		}
		L = append(L, "- members: "+strings.Join(quoted, ", "))
		if objStr(ch, "narrative") != "" {
			L = append(L, "- narrative: "+objStr(ch, "narrative"))
		}
		for _, lnk := range listAt(ch, "capability_links") {
			L = append(L, fmt.Sprintf("- `%s` grants *%s* → `%s` requires it",
				objStr(lnk, "from_finding"), objStr(lnk, "granted"),
				objStr(lnk, "to_finding")))
		}
		if foundSF {
			L = append(L, fmt.Sprintf("- super-finding: `%s`",
				objStr(sf, "finding_id")))
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
			L = append(L, fmt.Sprintf("### UNPROVEN CHAIN: %s", objStr(ch, "title")))
			L = append(L, "")
			L = append(L, fmt.Sprintf("- id: `%s` — provenance %s, evidence floor %s",
				objStr(ch, "chain_id"), pyStr(objAt(ch, "provenance")),
				pyStr(objAt(ch, "evidence_floor"))))
			quoted := []string{}
			for _, m := range strList(objAt(ch, "members")) {
				quoted = append(quoted, "`"+m+"`")
			}
			L = append(L, "- members: "+strings.Join(quoted, ", "))
			if objStr(ch, "narrative") != "" {
				L = append(L, "- narrative: "+objStr(ch, "narrative"))
			}
			for _, lnk := range listAt(ch, "capability_links") {
				line := fmt.Sprintf("- `%s` grants *%s* → `%s` requires it",
					objStr(lnk, "from_finding"), objStr(lnk, "granted"),
					objStr(lnk, "to_finding"))
				if lvl := objStr(lnk, "link_evidence"); lvl != "" {
					line += " (from-member evidence " + lvl + ")"
				}
				L = append(L, line)
			}
			if t := asObj(objAt(ch, "terminal")); len(t.O) > 0 {
				// An unproven chain has no super-finding, hence no
				// economic_impact: the terminal is the LEAD's destination.
				// State the price that would apply, and that it is not
				// asserted here — a hypothesis must not carry a number.
				cap := objStr(t, "capability")
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
					cap, objStr(t, "via_finding"), note))
			}
			L = append(L, "")
		}
	}

	dismissed := []validation.Value{}
	for _, f := range all {
		switch objStr(f, "status") {
		case "DISPROVED", "OUT_OF_SCOPE", "DUPLICATE", "SUPERSEDED":
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
				objStr(f, "finding_id"), objStr(f, "status"), objStr(f, "title")))
			reason := "n/a"
			if v := objAt(last, "reason"); v.Kind != validation.Null {
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
			if objStr(e, "type") == "probe.dismissal_overridden" {
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
			data := objAt(e, "data")
			L = append(L, fmt.Sprintf("- OVERRIDDEN `%s` (row %s) by %s: %s",
				objStr(e, "ref"), objStr(data, "row_id"),
				objStr(data, "actor"),
				objStr(data, "override_reason")))
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
				objStr(m, "memory_id"), objStr(m, "kind"), objStr(m, "status"),
				objStr(m, "promotion_status")))
		}
		pending := 0
		for _, m := range mem {
			if objStr(m, "promotion_status") == "pending" {
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
		if dismissalTerminal(objStr(f, "status")) {
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
		rid := objStr(row, "row_id")
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
			hits = append(hits, hit{fid: objStr(f, "finding_id"),
				status: objStr(f, "status"),
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
		if v := objStr(row, key); v != "" {
			out[v] = struct{}{}
		}
	}
	for _, s := range listAt(row, "siblings") {
		if v := objStr(s, "contract"); v != "" {
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
		p := objStr(a, "path")
		if p == "" {
			p = objStr(a, "file")
		}
		if p != "" {
			if b := pathBase(p); b != "" {
				out[b] = struct{}{}
			}
		}
		if c := objStr(a, "contract"); c != "" {
			out[c] = struct{}{}
		}
	}
	return out
}

// reachFindingClass is the finding's root-cause class (bug_class, then
// unclassified when neither is set).
func reachFindingClass(f validation.Value) string {
	if c := objStr(objAt(f, "root_cause"), "class"); c != "" {
		return c
	}
	if c := objStr(f, "bug_class"); c != "" {
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
	switch v := objAt(row, key); v.Kind {
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
		subj := objStr(w, "subject")
		if subj == "*" || subj == objStr(f, "finding_id") {
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
	v := asObj(objAt(asObj(objAt(f, "risk")), "validated"))
	s := objAt(v, "score")
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
	return pyStr(objAt(v, key))
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
	rc := asObj(objAt(f, "root_cause"))
	out = append(out, fmt.Sprintf("### %s: %s", heading, objStr(f, "title")))
	out = append(out, "")
	out = append(out, fmt.Sprintf("- id: `%s` — status **%s** (trajectory: %s)",
		objStr(f, "finding_id"), objStr(f, "status"),
		pyStr(objAt(f, "trajectory"))))
	cwe := ""
	if objStr(rc, "cwe") != "" {
		cwe = "CWE " + objStr(rc, "cwe")
	}
	out = append(out, fmt.Sprintf("- bug class: `%s`%s %s", pyStr(objAt(rc, "class")),
		classAliasSuffixSpaced(objStr(rc, "class")), cwe))
	inv := asObj(objAt(f, "invariant"))
	if objStr(inv, "statement") != "" {
		out = append(out, "- violated invariant: "+objStr(inv, "statement"))
	}
	att := asObj(objAt(f, "attacker"))
	if objStr(att, "profile") != "" {
		capital := ""
		if pyTruthy(objAt(att, "required_capital_usd")) {
			capital = " (capital: $" + pyCommaAuto(objAt(att, "required_capital_usd")) + ")"
		}
		out = append(out, "- attacker: "+objStr(att, "profile")+capital)
	}
	risk := asObj(objAt(f, "risk"))
	v := asObj(objAt(risk, "validated"))
	if len(v.O) > 0 {
		out = append(out, fmt.Sprintf("- validated risk: **%s/10 (%s)**",
			pyStr(objAt(v, "score")), pyStr(objAt(v, "band"))))
	}
	if rv := objStr(risk, "reversibility"); rv != "" {
		out = append(out, "- reversibility: **"+rv+"** (validated_risk component)")
	}
	iv := asObj(objAt(risk, "impact_vector"))
	if len(iv.O) > 0 {
		out = append(out, fmt.Sprintf("- impact vector: %s/%s/%s/%s (score %s)",
			pyStr(objAt(iv, "asset_exposure")),
			pyStr(objAt(iv, "privilege_class")),
			pyStr(objAt(iv, "recoverability")),
			pyStr(objAt(iv, "insolvency_risk")), pyStr(objAt(iv, "score"))))
	}
	if reported := objAt(f, "reported_severity"); pyTruthy(reported) {
		band := "n/a"
		if b := objAt(asObj(objAt(f, "risk")), "validated"); b.Kind == validation.Obj {
			if bv := objAt(b, "band"); bv.Kind != validation.Null {
				band = pyStr(bv)
			}
		}
		out = append(out, fmt.Sprintf("- reported severity: **%s** — computed "+
			"band: **%s**", pyStr(reported), band))
	}
	econ := asObj(objAt(risk, "economic"))
	if decision := findings.UnpriceableDecision(f); decision != nil {
		out = append(out, fmt.Sprintf("- economically extractable: "+
			"UNPRICEABLE (ceiling: %s)", pyStr(objAt(*decision, "ceiling"))))
	} else if ex := objAt(econ, "extractable_usd"); ex.Kind != validation.Null {
		out = append(out, fmt.Sprintf("- economically extractable: $%s",
			pyCommaAuto(ex)))
	}
	if exp := asObj(objAt(f, "exploitability")); len(exp.O) > 0 {
		if paid := objAt(exp, "paid"); paid.Kind == validation.Bool {
			if paid.B {
				out = append(out, fmt.Sprintf(
					"- paid exploitability: **yes** — who pays, and why: "+
						"%s", pyStr(objAt(exp, "argument"))))
			} else {
				line := "- paid exploitability: **no**"
				if a := objStr(exp, "argument"); a != "" {
					line += " — " + a
				}
				out = append(out, line)
			}
		}
	}
	// B2: the adversarial-game clause (liveness findings) — who profits,
	// how, and why the challenge path does not undo it. Presence-gated:
	// findings without the clause render nothing here.
	if ag := asObj(objAt(f, "adversarial_game")); len(ag.O) > 0 {
		out = append(out, fmt.Sprintf("- adversarial game: who profits — %s",
			pyStr(objAt(ag, "who_profits"))))
		out = append(out, fmt.Sprintf("-   mechanism: %s",
			pyStr(objAt(ag, "profit_mechanism"))))
		out = append(out, fmt.Sprintf("-   challenge interplay: %s",
			pyStr(objAt(ag, "challenge_interplay"))))
	}
	if ack := asObj(objAt(objAt(f, "dedup_meta"), "in_code_ack")); len(ack.O) > 0 {
		line := fmt.Sprintf("- in-code ack: %s:%s — phrase %q (window %s)",
			pyStr(objAt(ack, "file")), pyStr(objAt(ack, "line")),
			pyStr(objAt(ack, "phrase")), pyStr(objAt(ack, "window")))
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
	if ms := objAt(objAt(f, "dedup_meta"), "mitigation_present"); ms.Kind ==
		validation.Str && ms.S != "" {
		if pattern, file, line, _, ok :=
			findings.ParseMitigationPresent(ms.S); ok {
			out = append(out, fmt.Sprintf(
				"- soundness layer demotes: %s (%s:%s)",
				pattern, file, line))
		}
	}
	b := asObj(objAt(f, "bounty"))
	if len(b.O) > 0 {
		line := fmt.Sprintf("- bounty gate: eligible=%s, submission_ready=%s",
			pyStr(objAt(b, "eligible")), pyStr(objAt(b, "submission_ready")))
		if blockers := listAt(b, "blocking_reasons"); len(blockers) > 0 {
			line += ", blockers: " + strings.Join(strList(objAt(b,
				"blocking_reasons")), "; ")
		}
		out = append(out, line)
		// Advisories never gate (A2's in-code acknowledgement, D8's
		// boundary-mutation note under a prose/none patch clause) — but they
		// exist to be READ, so the report carries them next to the verdict.
		// Emitted only when present: a finding without advisories renders
		// byte-for-byte as before.
		if adv := strList(objAt(b, "advisories")); len(adv) > 0 {
			out = append(out, "  - advisory: "+strings.Join(adv, "; "))
		}
	}
	if ar := asObj(objAt(b, "accepted_risk")); len(ar.O) > 0 {
		kind := objStr(ar, "kind")
		line := fmt.Sprintf("- accepted risk: **%s**", pyStr(objAt(ar,
			"pattern")))
		if kind != "" {
			line += " (" + kind + ")"
		}
		if ref := objStr(ar, "reference"); ref != "" {
			line += " — " + ref
		}
		if note := objStr(ar, "note"); note != "" {
			line += " — " + note
		}
		// G7 hygiene (Task 15): a policy claim without a reference is
		// still valid, but the report stamps it. Golden-safe by evidence:
		// no golden policy carries accepted_risks and no golden tree
		// renders an accepted-risk bullet (see task-15-report.md), so the
		// absent-branch suffix moves zero golden bytes.
		if refURL := objStr(ar, "reference_url"); refURL != "" {
			line += " — cites " + refURL
		} else {
			line += " — no reference cited"
		}
		line += " (documented by the program; not submittable as written)"
		out = append(out, line)
	}
	out = append(out, "")
	out = append(out, "**Claim:** "+getOr(rc, "description", ""))
	if objStr(rc, "mechanism") != "" {
		out = append(out, "")
		out = append(out, "**Mechanism:** "+objStr(rc, "mechanism"))
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
			line := fmt.Sprintf("%s. %s", pyStr(objAt(s, "step")),
				pyStr(objAt(s, "action")))
			if objStr(s, "state_effect") != "" {
				line += " → " + objStr(s, "state_effect")
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
			if evidenceIndex(objStr(e, "level")) < 0 {
				return nil, fmt.Errorf("unknown evidence level")
			}
		}
		sortedEv := append([]validation.Value{}, ev...)
		sort.SliceStable(sortedEv, func(i, j int) bool {
			return evidenceIndex(objStr(sortedEv[i], "level")) <
				evidenceIndex(objStr(sortedEv[j], "level"))
		})
		for _, e := range sortedEv {
			line := fmt.Sprintf("- %s [%s] %s", objStr(e, "level"),
				objStr(e, "type"), pyStr(objAt(e, "description")))
			if objStr(e, "sandbox_profile") != "" {
				line += " (sandbox: " + objStr(e, "sandbox_profile") + ")"
			}
			// G15 advisories ride the line presence-gated: a fresh /
			// un-rerun item renders exactly as before.
			if objStr(e, "reruns") != "" {
				line += " [reruns " + objStr(e, "reruns") + "]"
			}
			if objStr(e, "fork_stale") != "" {
				line += " [fork stale]"
			}
			out = append(out, line)
		}
	}

	if objStr(asObj(objAt(f, "maximization")), "ladder_id") != "" {
		status := objStr(f, "status")
		if status == "CONFIRMED" || status == "CHAIN" {
			rep, err := maximization.LadderReport(campaign, objStr(f, "finding_id"))
			if err != nil {
				return nil, err
			}
			lad := objAt(rep, "ladder")
			if lad.Kind == validation.Obj {
				out = append(out, "")
				disp := asObj(objAt(lad, "disposition"))
				line := fmt.Sprintf("**Variant ladder** `%s` — disposition: "+
					"**%s**", objStr(lad, "ladder_id"), objStr(disp, "state"))
				if objStr(disp, "state") == "waived" && objStr(disp, "reason") != "" {
					r := []rune(objStr(disp, "reason"))
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
					if v := objAt(r, "extraction_ratio"); v.Kind != validation.Null {
						ratio = pyPercent0(floatVal(v))
					}
					cap := "—"
					if v := objAt(r, "capital_usd"); v.Kind != validation.Null {
						cap = "$" + pyCommaAuto(v)
					}
					axes := strings.Join(strList(objAt(r, "axes")), ", ")
					if axes == "" {
						axes = "—"
					}
					row := fmt.Sprintf("| `%s` | %s ", objStr(r, "rung_id"),
						objStr(r, "name"))
					if objStr(r, "rung_id") == objStr(lad, "maximal_rung_id") {
						row += "**(maximal)** "
					}
					row += fmt.Sprintf("| %s | %s | %s | %s", axes, cap, ratio,
						objStr(r, "status"))
					if objStr(r, "reason") != "" {
						rr := []rune(objStr(r, "reason"))
						if len(rr) > 60 {
							rr = rr[:60]
						}
						row += " (reason: " + string(rr) + ")"
					}
					execID := objStr(r, "exec_id")
					if execID == "" {
						execID = "—"
					}
					row += fmt.Sprintf(" | `%s` |", execID)
					out = append(out, row)
				}
				if unexplored := strList(objAt(rep, "unexplored_axes")); len(unexplored) > 0 {
					out = append(out, "")
					out = append(out, "> unexplored axes: "+
						strings.Join(unexplored, ", ")+" — the search is not "+
						"complete; the maximal rung is provisional")
				}
				rungs := listAt(rep, "rungs")
				if len(rungs) > 0 {
					base := rungs[0]
					mx := asObj(objAt(rep, "maximal"))
					if len(mx.O) > 0 &&
						objStr(mx, "rung_id") != objStr(base, "rung_id") &&
						objAt(mx, "extraction_delta").Kind != validation.Null {
						delta := fmt.Sprintf("> claim delta base→maximal: "+
							"extraction %s → %s", pyPercent0(ratioOf(base)),
							pyPercent0(ratioOf(mx)))
						if objAt(base, "capital_usd").Kind != validation.Null &&
							objAt(mx, "capital_usd").Kind != validation.Null {
							delta += fmt.Sprintf(", capital $%s → $%s",
								pyCommaAuto(objAt(base, "capital_usd")),
								pyCommaAuto(objAt(mx, "capital_usd")))
						}
						out = append(out, "")
						out = append(out, delta)
					}
				}
			}
		}
	}

	status := objStr(f, "status")
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
				"%s `%s` from `%s` (fork-runner, exit 0)", objStr(item, "level"),
				objStr(item, "type"), pyStr(objAt(item, "artifact_id"))))
		} else {
			waivers, err := completion.Waivers(campaign, "mainnet-fork-poc")
			if err != nil {
				return nil, err
			}
			waived := false
			for _, w := range waivers {
				subj := objStr(w, "subject")
				if subj == "*" || subj == objStr(f, "finding_id") {
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
		if pr := objAt(asObj(objAt(f, "verification")),
			"patch_regression"); pr.Kind == validation.Obj {
			out = append(out, fmt.Sprintf("- patch regression: %s (%s → %s)",
				patchRegressionMark(objStr(pr, "verdict")),
				objStr(pr, "base_exec"), objStr(pr, "exec")))
			if d := objStr(pr, "detail"); d != "" {
				out = append(out, "- "+d)
			}
		}
		if immState == "immunized" {
			cls := objStr(rc, "class")
			siblings := []validation.Value{}
			for _, g := range all {
				if objStr(g, "finding_id") == objStr(f, "finding_id") {
					continue
				}
				gs := objStr(g, "status")
				if gs != "CONFIRMED" && gs != "CHAIN" {
					continue
				}
				if objStr(objAt(g, "root_cause"), "class") != cls {
					continue
				}
				if immunize.IsImmunized(g) {
					continue
				}
				siblings = append(siblings, g)
			}
			if len(siblings) > 0 {
				sort.SliceStable(siblings, func(i, j int) bool {
					return objStr(siblings[i], "finding_id") <
						objStr(siblings[j], "finding_id")
				})
				ids := []string{}
				for _, g := range siblings {
					ids = append(ids, "`"+objStr(g, "finding_id")+"`")
				}
				out = append(out, fmt.Sprintf("- immunization credit scope: "+
					"this patch immunizes `%s` ONLY — %d same-class sibling(s) "+
					"are NOT immunized by it (%s); they are separate attack "+
					"surfaces of the same root cause", objStr(f, "finding_id"),
					len(siblings), strings.Join(ids, ", ")))
			}
		}
	}

	ei := asObj(objAt(f, "economic_impact"))
	usdKeys := []string{}
	for _, k := range ei.O {
		if strings.HasSuffix(k.K, "_usd") && k.V.Kind != validation.Null {
			usdKeys = append(usdKeys, k.K)
		}
	}
	if len(usdKeys) > 0 {
		basis := objStr(ei, "price_basis")
		out = append(out, "")
		if basis != "" {
			rowPtr, err := pricing.PriceRow(campaign, basis)
			if err != nil {
				return nil, err
			}
			if rowPtr != nil {
				src := []rune(objStr(*rowPtr, "source"))
				if len(src) > 60 {
					src = src[:60]
				}
				out = append(out, fmt.Sprintf("- price basis: `%s` — %s @ $%s "+
					"(%s, as of %s)", basis, objStr(*rowPtr, "asset"),
					pyCommaAuto(objAt(*rowPtr, "usd")), string(src),
					pyStr(objAt(*rowPtr, "as_of"))))
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
	sid := objStr(objAt(f, "snapshot_ids"), "source")
	if sid == "" || sid == "unpinned" {
		return "", false
	}
	snap, err := validation.ReadJson(filepath.Join(campaign.Dir, "snapshots",
		sid, "snapshot.json"))
	if err != nil {
		return "", false
	}
	root := objStr(objAt(snap, "source"), "root")
	file := objStr(ack, "file")
	p := file
	if !filepath.IsAbs(p) {
		p = filepath.Join(root, p)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return "", false
	}
	lines := strings.Split(string(raw), "\n")
	n := int(objAt(ack, "line").I)
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
	return floatVal(objAt(rung, "extraction_ratio"))
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
		if objStr(ch, "provenance") == "unproven" {
			unproven = append(unproven, ch)
		} else {
			proven = append(proven, ch)
		}
	}
	return proven, unproven
}
