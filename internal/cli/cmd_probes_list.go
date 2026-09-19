// cmd_probes_list: `probes <c> list` — the operator view and the
// --json projection, plus the shared closure printer.
package cli

import (
	"fmt"
	"io"
	"strings"

	"websec/internal/planner"
	"websec/internal/probes"
	"websec/internal/state"
	"websec/internal/validation"
)

// probeAxisLines is _probe_axis_lines.
func probeAxisLines(surface validation.Value, axisFilter *probes.AxisScope,
	showAll bool) []string {
	lines := []string{}
	for _, a := range t14List(surface, "axes").A {
		if axisFilter != nil && !t14InList(validation.ObjStr(a, "axis"), axisFilter.Axes) {
			continue
		}
		if !showAll && objInt(a, "emitted") == 0 {
			continue
		}
		lines = append(lines, fmt.Sprintf("  %s (%s, %s): sites %d, rows %d, "+
			"emitted %d, tail %d — %s", validation.ObjStr(a, "axis"), validation.ObjStr(a, "lens"),
			validation.ObjStr(a, "probe"), objInt(a, "sites"), objInt(a, "rows"),
			objInt(a, "emitted"), objInt(a, "tail"), validation.ObjStr(a, "status")))
		if showAll {
			lines = append(lines, probeBlindLines(a)...)
		}
	}
	return lines
}

// probeBlindLines is the --all blind-key block for ONE axis: the published
// key, its near-miss context and the probe's own reason. Shared by the row
// view (probeAxisLines) and the B5(a) summary so the two cannot drift.
func probeBlindLines(a validation.Value) []string {
	lines := []string{}
	for _, b := range t14List(a, "blind").A {
		near := ""
		if nearVal := validation.ObjAt(b, "near"); nearVal.Kind == validation.Str {
			near = " (near " + nearVal.S + ")"
		}
		lines = append(lines, fmt.Sprintf("      blind: %s%s — %s",
			scalarStr(validation.ObjAt(b, "key")), near,
			scalarStr(validation.ObjAt(b, "reason"))))
	}
	return lines
}

// probeWarningLines is _probe_warning_lines.
func probeWarningLines(surface validation.Value) []string {
	lines := []string{}
	for _, w := range t14List(surface, "warnings").A {
		if msg := validation.ObjStr(w, "message"); msg != "" {
			lines = append(lines, "  warning: "+msg)
		}
	}
	return lines
}

// probesListView carries the shared probesList context: the parsed flags,
// the campaign, the runner and the loaded surface artifacts.
type probesListView struct {
	a            *probesArgs
	c            *state.Campaign
	r            *Runner
	surface      *validation.Value
	axisFilter   *probes.AxisScope
	summary      *validation.Value
	index        *validation.Value
	planPtr      *validation.Value
	dispositions validation.Value
}

// probesList is cli.py _probes_list.
func probesList(a *probesArgs, c *state.Campaign, r *Runner) error {
	lv := &probesListView{a: a, c: c, r: r}
	if err := probesListLoad(lv); err != nil {
		return err
	}
	if err := probesListAxisFilter(lv); err != nil {
		return err
	}
	if err := probesListContext(lv); err != nil {
		return err
	}
	if lv.a.asJSON {
		return probesListJSON(lv)
	}
	if lv.a.summary {
		probesListSummary(lv)
		return nil
	}
	probesListTable(lv)
	t29PrintProbeClosure(lv.c, lv.planPtr, nil, false, lv.r.Out)
	return nil
}

// probesListLoad reads the recorded probe surface, refusing to continue
// without one.
func probesListLoad(lv *probesListView) error {
	surface, err := probes.CampaignSurface(lv.c)
	if err != nil {
		return err
	}
	if surface == nil {
		return t14ExitErr(2, "probes: no probe surface for %s — run "+
			"`webv2 probes %s run` first\n", lv.c.CampaignID, lv.c.CampaignID)
	}
	lv.surface = surface
	return nil
}

// probesListAxisFilter resolves the --axis flag into a scope, refusing an
// unregistered axis.
func probesListAxisFilter(lv *probesListView) error {
	if lv.a.axis == nil {
		return nil
	}
	axisFilter := probes.AxisScopeOf(*lv.a.axis)
	if axisFilter == nil {
		return t14ExitErr(2, "probes: unknown axis %s; registered: %s "+
			"(or their lens ids %s)\n", validation.PyReprStr(*lv.a.axis),
			strings.Join(t29AxisNames(), ", "),
			strings.Join(t29LensIDs(), ", "))
	}
	lv.axisFilter = axisFilter
	return nil
}

// probesListContext loads the summary, the structural index, the readonly
// plan (its absence is tolerated) and the row dispositions.
func probesListContext(lv *probesListView) error {
	summary, err := probes.SurfaceSummary(lv.c, nil)
	if err != nil {
		return err
	}
	if summary == nil {
		return t14ExitErr(2, "probes: no probe surface for %s — run "+
			"`webv2 probes %s run` first\n", lv.c.CampaignID, lv.c.CampaignID)
	}
	lv.summary = summary
	index, err := probes.CampaignIndex(lv.c)
	if err != nil {
		return err
	}
	lv.index = index
	plan, err := planner.LoadPlanReadonly(lv.c)
	var planPtr *validation.Value
	if err == nil {
		planPtr = &plan
	}
	lv.planPtr = planPtr
	lv.dispositions = probes.RowDispositions(planPtr, *lv.surface)
	return nil
}

// probesListJSON is the --json branch: the machine-readable table.
func probesListJSON(lv *probesListView) error {
	surface, axisFilter, index := lv.surface, lv.axisFilter, lv.index
	rows := []validation.Value{}
	for _, row := range t14List(*surface, "rows").A {
		if axisFilter != nil && !t14InList(validation.ObjStr(row, "axis"), axisFilter.Axes) {
			continue
		}
		d := validation.ObjAt(lv.dispositions, validation.ObjStr(row, "row_id"))
		rows = append(rows, validation.VObj(
			validation.KV{K: "row_id", V: validation.ObjAt(row, "row_id")},
			validation.KV{K: "probe", V: validation.ObjAt(row, "probe")},
			validation.KV{K: "axis", V: validation.ObjAt(row, "axis")},
			validation.KV{K: "lens", V: validation.ObjAt(row, "lens")},
			validation.KV{K: "tier", V: validation.ObjAt(row, "tier")},
			validation.KV{K: "rank", V: validation.ObjAt(row, "rank")},
			validation.KV{K: "assertion_gap", V: validation.ObjAt(row, "assertion_gap")},
			validation.KV{K: "anchors", V: strListValue(probes.RowAnchorPairs(row, index))},
			validation.KV{K: "priority_id", V: validation.ObjAt(d, "priority_id")},
			validation.KV{K: "status", V: validation.ObjAt(d, "status")},
			validation.KV{K: "dispositioned", V: validation.VBool(objBool(d, "dispositioned"))},
			validation.KV{K: "reason", V: validation.ObjAt(d, "reason")},
			validation.KV{K: "anchor", V: validation.ObjAt(d, "anchor")}))
	}
	axes := []validation.Value{}
	for _, ax := range t14List(*surface, "axes").A {
		if axisFilter != nil && !t14InList(validation.ObjStr(ax, "axis"), axisFilter.Axes) {
			continue
		}
		axes = append(axes, ax)
	}
	t14PrintJSON(lv.r.Out, validation.VObj(
		validation.KV{K: "campaign_id", V: validation.ObjAt(*surface, "campaign_id")},
		validation.KV{K: "index_sha", V: validation.ObjAt(*surface, "index_sha")},
		validation.KV{K: "current_index_sha", V: validation.ObjAt(*lv.summary, "current_index_sha")},
		validation.KV{K: "stale", V: validation.ObjAt(*lv.summary, "stale")},
		validation.KV{K: "rows", V: validation.ObjAt(*lv.summary, "rows")},
		validation.KV{K: "dispositioned", V: validation.ObjAt(*lv.summary, "dispositioned")},
		validation.KV{K: "open", V: validation.ObjAt(*lv.summary, "open")},
		validation.KV{K: "axes", V: validation.VArr(axes...)},
		validation.KV{K: "surface_rows", V: validation.VArr(rows...)}))
	return nil
}

// probesListTable is the console branch: the summary line, the per-axis
// lines and the (capped) row table.
func probesListTable(lv *probesListView) {
	out := lv.r.Out
	surface, axisFilter := lv.surface, lv.axisFilter
	stale := ""
	if objBool(*lv.summary, "stale") {
		stale = " — stale?"
	}
	fmt.Fprintf(out, "probe surface: %d rows (%d dispositioned, %d open)%s\n",
		objInt(*lv.summary, "rows"), objInt(*lv.summary, "dispositioned"),
		objInt(*lv.summary, "open"), stale)
	for _, line := range probeAxisLines(*surface, axisFilter, lv.a.all) {
		fmt.Fprintln(out, line)
	}
	// B5(b) / r35 F1 convention (the kept-ghost disclosure,
	// cmd_artifact_register.go): the quota disclosures are warnings, so
	// they ride stderr and stdout keeps the
	// summary, the axis lines and the row table alone. Byte-identical per
	// line — only the destination stream moved.
	for _, line := range probeWarningLines(*surface) {
		fmt.Fprintln(lv.r.Err, line)
	}
	// The console table is capped: a surface is an obligation list, not a
	// transcript. The summary line points at the complete machine-readable
	// table (`--json`), and the count is the number actually selected by the
	// axis filter (not the raw artifact size).
	selected := make([]validation.Value, 0, len(t14List(*surface, "rows").A))
	for _, row := range t14List(*surface, "rows").A {
		if axisFilter != nil && !t14InList(validation.ObjStr(row, "axis"), axisFilter.Axes) {
			continue
		}
		selected = append(selected, row)
	}
	for i, row := range selected {
		if i == consoleRowCap {
			fmt.Fprintf(out,
				"  … +%d more rows — use --json for the full table\n",
				len(selected)-consoleRowCap)
			break
		}
		d := validation.ObjAt(lv.dispositions, validation.ObjStr(row, "row_id"))
		stateStr := "open (not emitted)"
		switch {
		case objBool(d, "dispositioned"):
			stateStr = "dispositioned"
		case validation.ObjStr(d, "status") != "" && validation.ObjStr(d, "status") != "open":
			stateStr = "open (" + validation.ObjStr(d, "status") + ")"
		case validation.ObjStr(d, "priority_id") != "":
			stateStr = "open"
		}
		prio := validation.ObjStr(d, "priority_id")
		if prio == "" {
			prio = "—"
		}
		anchors := strings.Join(probes.RowAnchorPairs(row, lv.index), ", ")
		if anchors == "" {
			anchors = "—"
		}
		fmt.Fprintf(out, "    %s rank %d tier %d gap %d %s — %s %s\n",
			validation.ObjStr(row, "row_id"), objInt(row, "rank"), objInt(row, "tier"),
			objInt(row, "assertion_gap"), anchors, prio, stateStr)
		if reason := validation.ObjStr(d, "reason"); reason != "" {
			fmt.Fprintf(out, "        reason: %s\n", reason)
		}
	}
}

// probesListSummary is the B5(a) `list --summary` branch: the cockpit, not the
// table. The header (reused verbatim from the row view), one line per axis with
// its row count, its UNDISPOSITIONED count and its risky count, the quota
// disclosures (warnings and missing[], both on stderr — the r35 F1 / B5(b)
// convention), then ONE pointer line: the pending count and the command that
// drains it, or an all-clear. No row table, no per-row lines.
//
// WHERE THE COUNTS COME FROM. Rows, dispositions and the open set are
// probes.SurfaceSummary's (`summary.open_rows`) — the seam already carries the
// per-row tier and assertion_gap, so the risk count is
// planner.HighRiskRow applied to the SAME open rows, never a re-derivation.
// The risky count is over the undispositioned rows only: a cockpit asks "how
// many dangerous rows are still open", and a dispositioned row is no longer
// work. The header and the pointer stay campaign-wide (exactly as the row
// view's header and `probes pending` are), while the per-axis lines honour
// --axis like every other list view.
//
// --summary always prints one line per axis IN THE SURFACE, including the
// no-sites/blind axes the row view hides (a count view that hides the axes
// with nothing to show is not a count view); --all still adds each axis's
// published blind keys underneath. `--json --summary` is the plain --json view
// (see probesListJSON): one machine shape, not two.
func probesListSummary(lv *probesListView) {
	out := lv.r.Out
	stale := ""
	if objBool(*lv.summary, "stale") {
		stale = " — stale?"
	}
	fmt.Fprintf(out, "probe surface: %d rows (%d dispositioned, %d open)%s\n",
		objInt(*lv.summary, "rows"), objInt(*lv.summary, "dispositioned"),
		objInt(*lv.summary, "open"), stale)
	undispositioned := map[string]int{}
	risky := map[string]int{}
	for _, row := range t14List(*lv.summary, "open_rows").A {
		axis := validation.ObjStr(row, "axis")
		undispositioned[axis]++
		if planner.HighRiskRow(row) {
			risky[axis]++
		}
	}
	for _, a := range t14List(*lv.surface, "axes").A {
		axis := validation.ObjStr(a, "axis")
		if lv.axisFilter != nil && !t14InList(axis, lv.axisFilter.Axes) {
			continue
		}
		fmt.Fprintf(out, "  %s (%s): rows %d, undispositioned %d, "+
			"risky(tier 0/gap>=3) %d\n", axis,
			validation.ObjStr(a, "lens"), objInt(a, "rows"),
			undispositioned[axis], risky[axis])
		if lv.a.all {
			for _, line := range probeBlindLines(a) {
				fmt.Fprintln(out, line)
			}
		}
	}
	// The quota disclosures: the same two byte-exact line shapes `probes run`
	// renders, on stderr — the summary's stdout is the count view alone.
	for _, line := range probeWarningLines(*lv.surface) {
		fmt.Fprintln(lv.r.Err, line)
	}
	for _, m := range t14List(*lv.surface, "missing").A {
		fmt.Fprintf(lv.r.Err, "  missing: %s\n", validation.ObjStr(m, "reason"))
	}
	open := objInt(*lv.summary, "open")
	if open == 0 {
		fmt.Fprintln(out, "all clear: 0 pending — every surface row is "+
			"dispositioned")
		return
	}
	fmt.Fprintf(out, "%d pending — see webv2 probes %s pending\n", open,
		lv.c.CampaignID)
}

// t29PrintProbeClosure is _print_probe_closure (cmd_answered.go owns the
// only_closed=True call site; `probes list` needs only_closed=False).
func t29PrintProbeClosure(c *state.Campaign, plan *validation.Value,
	lensNames map[string]struct{}, onlyClosed bool, w io.Writer) {
	planVal := validation.VNull()
	if plan != nil {
		planVal = *plan
	}
	div, err := planner.DivergenceStatusFor(c, planVal, nil)
	if err != nil {
		return // never break a disposition on this
	}
	for _, entry := range t14List(div, "lenses").A {
		probe := validation.ObjAt(entry, "probe")
		if probe.Kind != validation.Obj || validation.ObjStr(probe, "message") == "" {
			continue
		}
		if lensNames != nil {
			_, a := lensNames[validation.ObjStr(entry, "lens")]
			_, b := lensNames[validation.ObjStr(entry, "id")]
			if !a && !b {
				continue
			}
		}
		if onlyClosed && !t14Truthy(validation.ObjAt(probe, "closed")) {
			continue
		}
		fmt.Fprintf(w, "%s\n", validation.ObjStr(probe, "message"))
	}
}
