// Standalone report sections rendered directly over the campaign:
// the privileged-actor track (3.1) and the mechanical probe-surface
// section, plus their row/constraint annotation helpers.
package report

import (
	"fmt"
	"strconv"
	"strings"
	"websec/internal/planner"
	"websec/internal/privileged"
	"websec/internal/probes"
	"websec/internal/state"
	"websec/internal/validation"
)

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
		validation.PyStr(validation.ObjAt(surface, "index_sha")), staleNote))
	L = append(L, "")
	for _, row := range listAt(surface, "rows") {
		L = append(L, probeSurfaceRow(row, disp, index))
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

// probeSurfaceRow renders one mechanical-candidate row line: its anchor
// pairs and its disposition state — dispositioned (with reason and
// anchor), open with a recorded status, plain open, or not yet emitted.
func probeSurfaceRow(row validation.Value, disp validation.Value,
	index validation.Value) string {
	rid := validation.ObjStr(row, "row_id")
	d := validation.AsObj(validation.ObjAt(disp, rid))
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
		a := validation.AsObj(validation.ObjAt(d, "anchor"))
		if len(a.O) > 0 {
			state += fmt.Sprintf(" (anchor `%s` = %s)",
				validation.ObjStr(a, "field"), validation.PyStr(validation.ObjAt(a, "ref")))
		}
	case validation.ObjStr(d, "status") != "" && validation.ObjStr(d, "status") != "open":
		state = "open (" + validation.ObjStr(d, "status") + ")"
	case validation.ObjStr(d, "priority_id") != "":
		state = "open"
	default:
		state = "open (not emitted)"
	}
	return fmt.Sprintf("- `%s` %s (%s %s) tier %s, gap %s, "+
		"anchors %s — %s", rid, validation.ObjStr(row, "probe"), validation.ObjStr(row, "axis"),
		validation.ObjStr(row, "lens"), validation.PyStr(validation.ObjAt(row, "tier")),
		validation.PyStr(validation.ObjAt(row, "assertion_gap")), anchors, state)
}
