package probes

import (
	"regexp"
	"slices"
	"sort"
	"strconv"

	"websec/internal/planner"
	"websec/internal/state"
	"websec/internal/validation"
)

// closedPriority is _CLOSED_PRIORITY.
var closedPriority = map[string]struct{}{"answered": {}, "not-applicable": {},
	"deprioritized": {}, "blocked": {}}

var priorityIDRe = regexp.MustCompile(`^Q-\d{3,}$`)

// nextPrioritySeq is _next_priority_seq.
func nextPrioritySeq(plan validation.Value) int {
	top := 0
	for _, p := range vList(plan, "priorities") {
		id := validation.PyStr(vGet(p, "id"))
		if !priorityIDRe.MatchString(id) {
			continue
		}
		n, err := strconv.Atoi(id[2:])
		if err == nil && n > top {
			top = n
		}
	}
	return top
}

// probePriority is _probe_priority.
func probePriority(pid string, row validation.Value, surfaceSha string,
	index *validation.Value) validation.Value {
	band, risk := ProbeRisk(row)
	question, _ := RowQuestion(row, index)
	return validation.VObj(
		kv("id", validation.VStr(pid)),
		kv("question", validation.VStr(question)),
		kv("risk", validation.VFloat(risk)),
		kv("required_context", validation.StrArr([]string{"structural_index",
			"protocol_model"})),
		kv("trajectories", validation.StrArr([]string{"lifecycle"})),
		kv("status", validation.VStr("open")),
		kv("probe", validation.VObj(
			kv("row_id", vGet(row, "row_id")),
			kv("probe_id", vGet(row, "probe")),
			kv("axis", vGet(row, "axis")),
			kv("surface_sha", validation.VStr(surfaceSha)),
			kv("shape_sha", validation.VStr(RowShapeSha(row))),
			kv("risk_band", validation.VStr(band)))))
}

// EmitRows is emit_rows: turn the surface's emitted rows into plan priorities
// and save the plan. Idempotent by `row_id`.
func EmitRows(c *state.Campaign, plan validation.Value, surface validation.Value,
	index *validation.Value) (validation.Value, error) {
	surfaceSha := vStr(surface, "index_sha")
	if surfaceSha == "" && index != nil {
		surfaceSha = IndexSha(*index)
	}
	prios := vList(plan, "priorities")
	byRow := map[string]int{}
	for i, p := range prios {
		prov := vGet(p, "probe")
		if prov.Kind == validation.Obj && vStr(prov, "row_id") != "" {
			if _, seen := byRow[vStr(prov, "row_id")]; !seen {
				byRow[vStr(prov, "row_id")] = i
			}
		}
	}
	created, updated, reopened, kept := []string{}, []string{}, []string{}, []string{}
	seq := nextPrioritySeq(plan)
	emitted := map[string]struct{}{}
	for _, row := range vList(surface, "rows") {
		rid := vStr(row, "row_id")
		if rid == "" {
			continue
		}
		emitted[rid] = struct{}{}
		shape := RowShapeSha(row)
		idx, exists := byRow[rid]
		if !exists {
			seq++
			pid := sprintf("Q-%03d", seq)
			prios = append(prios, probePriority(pid, row, surfaceSha, index))
			byRow[rid] = len(prios) - 1 // a repeated row is one obligation
			created = append(created, pid)
			continue
		}
		existing := prios[idx]
		prov := vGet(existing, "probe")
		provObj := copyObj(prov)
		if _, closed := closedPriority[vStr(existing, "status")]; closed {
			if vStr(provObj, "shape_sha") == shape {
				vSet(&provObj, "surface_sha", validation.VStr(surfaceSha))
				vSet(&existing, "probe", provObj)
				prios[idx] = existing
				kept = append(kept, validation.PyStr(vGet(existing, "id")))
				continue
			}
			vSet(&existing, "status", validation.VStr("open"))
			for _, k := range []string{"closed_reason", "closed_ref", "closed_at",
				"closed_by"} {
				vDel(&existing, k)
			}
			vDel(&provObj, "anchor")
			reopened = append(reopened, validation.PyStr(vGet(existing, "id")))
			data := validation.VObj(
				kv("row_id", validation.VStr(rid)),
				kv("old_shape_sha", vGet(provObj, "shape_sha")),
				kv("new_shape_sha", validation.VStr(shape)),
				kv("actor", validation.VStr("probes.emit")))
			ref := validation.PyStr(vGet(existing, "id"))
			if _, err := c.Log("probes.reopen", &ref, &data); err != nil {
				return validation.VNull(), err
			}
		} else {
			updated = append(updated, validation.PyStr(vGet(existing, "id")))
		}
		band, risk := ProbeRisk(row)
		question, _ := RowQuestion(row, index)
		vSet(&existing, "question", validation.VStr(question))
		vSet(&existing, "risk", validation.VFloat(risk))
		vSet(&existing, "trajectories", validation.StrArr([]string{"lifecycle"}))
		vSet(&provObj, "probe_id", vGet(row, "probe"))
		vSet(&provObj, "axis", vGet(row, "axis"))
		vSet(&provObj, "surface_sha", validation.VStr(surfaceSha))
		vSet(&provObj, "shape_sha", validation.VStr(shape))
		vSet(&provObj, "risk_band", validation.VStr(band))
		vSet(&existing, "probe", provObj)
		prios[idx] = existing
	}
	orphaned := []string{}
	for _, p := range prios {
		prov := vGet(p, "probe")
		if prov.Kind != validation.Obj {
			continue
		}
		if _, ok := emitted[vStr(prov, "row_id")]; !ok {
			orphaned = append(orphaned, validation.PyStr(vGet(p, "id")))
		}
	}
	sort.Strings(orphaned)
	vSet(&plan, "priorities", validation.VArr(prios...))
	if _, err := planner.SavePlan(c, plan); err != nil {
		return validation.VNull(), err
	}
	summary := validation.VObj(
		kv("surface_sha", validation.VStr(surfaceSha)),
		kv("created", validation.StrArr(created)),
		kv("updated", validation.StrArr(updated)),
		kv("reopened", validation.StrArr(reopened)),
		kv("kept", validation.StrArr(kept)),
		kv("orphaned", validation.StrArr(orphaned)))
	if _, err := c.Log("probes.emit", nil, &summary); err != nil {
		return validation.VNull(), err
	}
	return summary, nil
}

// RowDispositions is row_dispositions: `row_id` -> the plan's disposition of
// that row, judged exactly as the divergence clause judges it.
func RowDispositions(plan *validation.Value, surface validation.Value) validation.Value {
	byRow := map[string]validation.Value{}
	var prios []validation.Value
	if plan != nil {
		prios = vList(*plan, "priorities")
	}
	for _, p := range prios {
		prov := vGet(p, "probe")
		if prov.Kind == validation.Obj && vStr(prov, "row_id") != "" {
			rid := vStr(prov, "row_id")
			if _, seen := byRow[rid]; !seen {
				byRow[rid] = p
			}
		}
	}
	out := validation.VObj()
	for _, row := range vList(surface, "rows") {
		rid := vStr(row, "row_id")
		p, found := byRow[rid]
		prov := validation.VNull()
		status := validation.VNull()
		if found {
			prov = vGet(p, "probe")
			status = vGet(p, "status")
		}
		provObj := validation.VObj()
		if prov.Kind == validation.Obj {
			provObj = prov
		}
		stale := found && vStr(provObj, "shape_sha") != RowShapeSha(row)
		dispositioned := found && slices.Contains(planner.ProbeRowDispositioned, vStr(p, "status")) && !stale
		vSet(&out, rid, validation.VObj(
			kv("row_id", validation.VStr(rid)),
			kv("priority_id", nullableStr(found, vGet(p, "id"))),
			kv("status", status),
			kv("reason", nullableStr(found, vGet(p, "closed_reason"))),
			kv("anchor", vGet(provObj, "anchor")),
			kv("dispositioned", validation.VBool(dispositioned)),
			kv("stale", validation.VBool(stale))))
	}
	return out
}

// nullableStr is `(p or {}).get(k)`.
func nullableStr(found bool, v validation.Value) validation.Value {
	if !found {
		return validation.VNull()
	}
	return v
}

// SurfaceSummary is surface_summary: the cockpit view of the campaign's
// surface. nil when the campaign has no surface artifact.
func SurfaceSummary(c *state.Campaign,
	plan *validation.Value) (*validation.Value, error) {
	surface, err := CampaignSurface(c)
	if err != nil {
		return nil, err
	}
	if surface == nil {
		return nil, nil
	}
	if plan == nil {
		p, err := planner.LoadPlanReadonly(c)
		if err == nil {
			plan = &p
		}
	}
	disp := RowDispositions(plan, *surface)
	rows := vObjList(*surface, "rows")
	openRows := []validation.Value{}
	dispositioned := 0
	for _, row := range rows {
		d := vGet(disp, vStr(row, "row_id"))
		if vBool(d, "dispositioned") {
			dispositioned++
			continue
		}
		openRows = append(openRows, validation.VObj(
			kv("row_id", vGet(row, "row_id")),
			kv("priority_id", vGet(d, "priority_id")),
			kv("probe", vGet(row, "probe")),
			kv("axis", vGet(row, "axis")),
			kv("lens", vGet(row, "lens")),
			kv("tier", vGet(row, "tier")),
			kv("assertion_gap", vGet(row, "assertion_gap")),
			kv("siblings", validation.VInt(int64(NSiblings(row)))),
			kv("name", validation.VStr(rowName(row))),
			kv("why", vGet(row, "why"))))
	}
	sort.SliceStable(openRows, func(i, j int) bool {
		return RankKeyOf(openRows[i]).Less(RankKeyOf(openRows[j]))
	})
	current := CampaignIndexSha(c)
	currentVal := validation.VNull()
	if current != nil {
		currentVal = validation.VStr(*current)
	}
	stale := false
	if current == nil {
		stale = vGet(*surface, "index_sha").Kind != validation.Null
	} else {
		stale = vStr(*surface, "index_sha") != *current
	}
	summary := validation.VObj(
		kv("rows", validation.VInt(int64(len(rows)))),
		kv("dispositioned", validation.VInt(int64(dispositioned))),
		kv("open", validation.VInt(int64(len(rows)-dispositioned))),
		kv("index_sha", vGet(*surface, "index_sha")),
		kv("current_index_sha", currentVal),
		kv("stale", validation.VBool(stale)),
		kv("open_rows", validation.VArr(openRows...)))
	return &summary, nil
}
