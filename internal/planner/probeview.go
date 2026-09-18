package planner

import (
	"slices"
	"sort"
	"strings"

	"websec/internal/validation"
)

// lensProbeClosure is the internal lens_probe_closure (callers have already
// established that a surface exists).
func lensProbeClosure(plan validation.Value, lid string,
	opts DivergenceOpts) *validation.Value {
	return probeLensView(plan, lid, opts).counts
}

// probeLensView is _probe_lens_view: the probe clause of ONE lens — its
// closure issues AND its counts.
//
// I2: the closure moment is a sentence, so the numbers behind it must come
// from the same code path as the gate — otherwise the message could say
// "closed" while divergence_status still blocks. `rows` is the ranked total
// across the lens's axes, so `dispositioned/rows` cannot be inflated by a
// shrunken `--per-axis`: rows the quota left in the tail stay in the
// denominator and are reported as `tail`. A disposition counts only when the
// stored `probe.shape_sha` still matches the row, exactly like the gate. A
// registered axis the surface does not carry is a `missing_axes` entry and
// contributes nothing to the counts.
func probeLensView(plan validation.Value, lid string,
	opts DivergenceOpts) probeView {
	surface := *opts.Surface
	axes, rowsByAxis := surfaceIndex(surface)
	byRow := provenanceByRow(plan)
	cid := campaignIDForPlan(plan, opts)
	refresh := "run `webv2 probes " + cid + " run --emit`"
	mine, present, missingAxes := lensAxes(lid, axes)
	issues := []string{}
	if len(present) == 0 {
		return probeView{axes: mine, present: present, missingAxes: missingAxes,
			issues: issues}
	}
	issues = append(issues, probeIndexIssues(surface, opts, cid, refresh)...)
	dispositioned, openRowsN, staleN := 0, 0, 0
	for _, ax := range present {
		var blankPtr *validation.Value
		if blank := opts.Blanks[ax]; blank.Kind != validation.Null {
			blankPtr = &blank
		}
		if b := PB().AxisSurfaceBlocker(axes[ax], blankPtr); b != "" {
			issues = append(issues, b)
		}
		d, o, s, extra := axisRowIssues(rowsByAxis[ax], byRow, refresh)
		dispositioned += d
		openRowsN += o
		staleN += s
		issues = append(issues, extra...)
	}
	return probeView{axes: mine, present: present, missingAxes: missingAxes,
		issues: issues,
		counts: probeCounts(surface, opts, lid, present, dispositioned,
			openRowsN, staleN, issues)}
}

// surfaceIndex splits a probe surface into its axis table and its rows grouped
// by axis.
func surfaceIndex(surface validation.Value) (map[string]validation.Value,
	map[string][]validation.Value) {
	axes := map[string]validation.Value{}
	for _, a := range listOf(surface, "axes") {
		if a.Kind == validation.Obj {
			axes[pyStr(validation.ObjAt(a, "axis"))] = a
		}
	}
	rowsByAxis := map[string][]validation.Value{}
	for _, r := range listOf(surface, "rows") {
		if r.Kind != validation.Obj {
			continue
		}
		if ax := validation.ObjAt(r, "axis"); pyTruthyBigNonEmpty(ax) {
			rowsByAxis[pyStr(ax)] = append(rowsByAxis[pyStr(ax)], r)
		}
	}
	return axes, rowsByAxis
}

// provenanceByRow maps a probe row_id to the first priority that claims it.
func provenanceByRow(plan validation.Value) map[string]validation.Value {
	byRow := map[string]validation.Value{}
	for _, p := range listOf(plan, "priorities") {
		prov, ok := probeProvenance(p)
		if !ok || !pyTruthyBigNonEmpty(validation.ObjAt(prov, "row_id")) {
			continue
		}
		key := pyStr(validation.ObjAt(prov, "row_id"))
		if _, dup := byRow[key]; !dup {
			byRow[key] = p
		}
	}
	return byRow
}

// lensAxes is the registered-axis split: all axes of the lens, those the
// surface carries, and those it does not.
func lensAxes(lid string, axes map[string]validation.Value) ([]string,
	[]string, []string) {
	registered := registeredAxes()
	mine := []string{}
	for _, ax := range sortedMapKeys(registered) {
		if registered[ax].Lens == lid {
			mine = append(mine, ax)
		}
	}
	missingAxes, present := []string{}, []string{}
	for _, ax := range mine {
		if _, ok := axes[ax]; ok {
			present = append(present, ax)
		} else {
			missingAxes = append(missingAxes, ax)
		}
	}
	return mine, present, missingAxes
}

// axisRowIssues walks one axis's ranked rows and classifies them: unemitted,
// still-open, stale (the stored shape_sha no longer matches the row), or
// dispositioned. It returns the counts plus the rendered issue lines.
func axisRowIssues(rows []validation.Value, byRow map[string]validation.Value,
	refresh string) (int, int, int, []string) {
	dispositioned := 0
	unemitted, openRows, staleRows := []string{}, []string{}, []string{}
	for _, row := range sortRowsByID(rows) {
		rid := pyStr(validation.ObjAt(row, "row_id"))
		p, emitted := byRow[rid]
		switch {
		case !emitted:
			unemitted = append(unemitted, rid)
		case !slices.Contains(ProbeRowDispositioned, validation.ObjStr(p, "status")):
			openRows = append(openRows, validation.ObjStr(p, "id")+" ("+rid+": "+
				validation.ObjStr(p, "status")+")")
		case validation.ObjStr(validation.ObjAt(p, "probe"), "shape_sha") != PB().RowShapeSha(row):
			// The disposition was stamped against a different shape: the row
			// moved (or gained/lost a sibling) and `probes run` ran without
			// `--emit`, so the stored closure is stale.
			staleRows = append(staleRows, validation.ObjStr(p, "id")+" ("+rid+
				": disposition is stale — the row's anchors moved since it "+
				"was closed)")
		default:
			dispositioned++
		}
	}
	issues := rowIssues(unemitted, openRows, staleRows, refresh)
	return dispositioned, len(unemitted) + len(openRows), len(staleRows),
		issues
}

// probeIndexIssues is the index-sha half of the closure clause.
func probeIndexIssues(surface validation.Value, opts DivergenceOpts, cid,
	refresh string) []string {
	surfaceSha := validation.ObjAt(surface, "index_sha")
	if opts.CurrentIndexSha == nil {
		return []string{"no current structural index to check the probe " +
			"surface against — run `webv2 index " + cid + " --src <target>`"}
	}
	if pyStr(surfaceSha) != *opts.CurrentIndexSha {
		return []string{"probe surface is stale (surface index_sha " +
			trunc12(pyStr(surfaceSha)) + "… != current " +
			trunc12(*opts.CurrentIndexSha) + "…) — " + refresh}
	}
	return nil
}

// rowIssues is the three per-axis issue lines, in Python's order.
func rowIssues(unemitted, openRows, staleRows []string,
	refresh string) []string {
	out := []string{}
	if len(unemitted) > 0 {
		out = append(out, itoa(len(unemitted))+" surface row(s) not emitted "+
			"as priorities ("+strings.Join(head5(unemitted), ", ")+") — "+
			refresh)
	}
	if len(openRows) > 0 {
		out = append(out, itoa(len(openRows))+" probe row(s) not "+
			"dispositioned ("+strings.Join(head5(openRows), ", ")+")")
	}
	if len(staleRows) > 0 {
		out = append(out, itoa(len(staleRows))+" probe row(s) whose "+
			"disposition is stale ("+strings.Join(head5(staleRows), ", ")+
			") — "+refresh)
	}
	return out
}

// probeCounts is the `counts` dict, keys in Python's insertion order.
func probeCounts(surface validation.Value, opts DivergenceOpts, lid string,
	present []string, dispositioned, openRowsN, staleN int,
	issues []string) *validation.Value {
	rows, emitted, tail, blind, attested := 0, 0, 0, 0, 0
	for _, ax := range present {
		axis := surfaceAxis(surface, ax)
		rows += int(numAt(axis, "rows"))
		emitted += int(numAt(axis, "emitted"))
		tail += int(numAt(axis, "tail"))
		if bt := validation.ObjAt(axis, "blind_total"); bt.Kind != validation.Null {
			blind += int(numAt(axis, "blind_total"))
		} else {
			blind += len(listOf(axis, "blind"))
		}
		blank := opts.Blanks[ax]
		if blank.Kind == validation.Null {
			continue
		}
		for _, b := range listOf(axis, "blind") {
			if pyStr(validation.ObjAt(b, "key")) == pyStr(validation.ObjAt(blank, "anchor_blind")) {
				attested++
				break
			}
		}
	}
	verb := "open"
	if len(issues) == 0 {
		verb = "closed"
	}
	msg := lid + " " + verb + " — " + itoa(dispositioned) + "/" + itoa(rows) +
		" rows dispositioned, " + itoa(tail) + " in tail, " + itoa(blind) +
		" blind keys disclosed"
	counts := validation.VObj(
		kv("axes", validation.StrArr(present)),
		kv("rows", validation.VInt(int64(rows))),
		kv("emitted", validation.VInt(int64(emitted))),
		kv("dispositioned", validation.VInt(int64(dispositioned))),
		kv("open", validation.VInt(int64(openRowsN))),
		kv("stale", validation.VInt(int64(staleN))),
		kv("tail", validation.VInt(int64(tail))),
		kv("blind", validation.VInt(int64(blind))),
		kv("blind_attested", validation.VInt(int64(attested))),
		kv("closed", validation.VBool(len(issues) == 0)),
		kv("message", validation.VStr(msg)),
	)
	return &counts
}

// surfaceAxis is `{a.get("axis"): a for a in surface.get("axes") or []}[ax]`.
func surfaceAxis(surface validation.Value, ax string) validation.Value {
	for _, a := range listOf(surface, "axes") {
		if a.Kind == validation.Obj && pyStr(validation.ObjAt(a, "axis")) == ax {
			return a
		}
	}
	return validation.VObj()
}

// sortRowsByID is `sorted(rows, key=lambda r: str(r.get("row_id")))` — a
// stable sort, so rows sharing a row_id keep surface order.
func sortRowsByID(rows []validation.Value) []validation.Value {
	out := make([]validation.Value, len(rows))
	copy(out, rows)
	sort.SliceStable(out, func(i, j int) bool {
		return pyStr(validation.ObjAt(out[i], "row_id")) < pyStr(validation.ObjAt(out[j], "row_id"))
	})
	return out
}

// head5 is `rows[:5]`.
func head5(items []string) []string {
	if len(items) > 5 {
		return items[:5]
	}
	return items
}

// trunc12 is `str(x)[:12]`.
func trunc12(s string) string {
	r := []rune(s)
	if len(r) > 12 {
		return string(r[:12])
	}
	return s
}
