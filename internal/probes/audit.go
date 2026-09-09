package probes

import (
	"path/filepath"

	"websec/internal/planner"
	"websec/internal/state"
	"websec/internal/validation"
)

// AuditSurface is audit.py section 13: the four probe-surface checks, all
// re-derived from the artifacts. Implements
// audit/sections.ProbeSurfaceAuditAPI.
type AuditSurface struct{}

// NewProbeSurfaceAudit returns the seam value installed by Wire.
func NewProbeSurfaceAudit() AuditSurface { return AuditSurface{} }

// AuditSurface is the section body: the no-surface dict, or the four checks.
func (AuditSurface) AuditSurface(c *state.Campaign) (validation.Value, error) {
	surface, err := CampaignSurface(c)
	if err != nil {
		return validation.VNull(), err
	}
	if surface == nil {
		return validation.VObj(
			kv("checked", validation.VInt(0)),
			kv("problems", validation.VArr()),
			kv("ok", validation.VBool(true)),
			kv("note", validation.VStr("no probe surface artifact (campaign "+
				"predates or has not run `webv2 probes`)"))), nil
	}
	return auditSurface(c, *surface)
}

// auditSurface is the populated branch.
func auditSurface(c *state.Campaign, surface validation.Value) (validation.Value, error) {
	problems := []string{}
	currentSha := CampaignIndexSha(c)
	if vStr(surface, "index_sha") != strOrNil(currentSha) {
		problems = append(problems, sprintf("probe surface is stale: built "+
			"against index_sha %s, current index is %s — every row anchor "+
			"describes the old tree; re-run `webv2 probes %s run --emit`",
			vStr(surface, "index_sha"), strOrNil(currentSha), c.CampaignID))
	}
	plan, err := planner.LoadPlanReadonly(c)
	var planPtr *validation.Value
	if err == nil {
		planPtr = &plan
	}
	planRows := map[string]string{}
	if planPtr != nil {
		for _, p := range vList(*planPtr, "priorities") {
			prov := vGet(p, "probe")
			if prov.Kind == validation.Obj && vStr(prov, "row_id") != "" {
				// Python: plan_rows[prov["row_id"]] = p.get("id") — last wins.
				planRows[vStr(prov, "row_id")] = vStr(p, "id")
			}
		}
	}
	surfaceRows := []string{}
	surfaceSet := map[string]struct{}{}
	for _, r := range vList(surface, "rows") {
		rid := vStr(r, "row_id")
		if _, seen := surfaceSet[rid]; !seen {
			surfaceSet[rid] = struct{}{}
			surfaceRows = append(surfaceRows, rid)
		}
	}
	if len(planRows) > 0 {
		for _, rid := range sortedKeys(planRows) {
			if _, ok := surfaceSet[rid]; !ok {
				problems = append(problems, sprintf("plan priority %s cites "+
					"probe row %s, which the current surface does not carry — "+
					"the surface was rebuilt without it (re-run `webv2 probes "+
					"<campaign> run --emit`)", planRows[rid],
					validation.PyReprStr(rid)))
			}
		}
		for _, rid := range sortedStrings(surfaceRows) {
			if _, ok := planRows[rid]; !ok {
				problems = append(problems, sprintf("probe row %s is in the "+
					"surface but was never emitted as a plan priority — "+
					"`webv2 probes %s run --emit`", validation.PyReprStr(rid),
					c.CampaignID))
			}
		}
	} else if len(surfaceRows) > 0 {
		problems = append(problems, sprintf("the probe surface carries %d "+
			"row(s) but no plan priority was emitted from it — `webv2 probes "+
			"%s run --emit`", len(surfaceSet), c.CampaignID))
	}
	rederived, reProblems := rederiveSurface(c, surface, currentSha)
	problems = append(problems, reProblems...)
	if rederived != nil {
		problems = append(problems, rederiveProblems(c, surface, *rederived,
			planPtr)...)
	}
	// Python reads campaign.state() once: a raise degrades the whole section.
	st, err := c.State()
	if err != nil {
		return validation.VNull(), err
	}
	blanks := vObjList(st, "probe_blanks")
	problems = append(problems, blankProblems(c, surface, blanks)...)
	return validation.VObj(
		kv("checked", validation.VInt(int64(len(surfaceSet)+len(planRows)+
			len(blanks)))),
		kv("rederived_rows", validation.VInt(int64(rederivedRowCount(rederived)))),
		kv("problems", strArr(problems)),
		kv("ok", validation.VBool(len(problems) == 0))), nil
}

// rederiveSurface is the I3 re-derivation from the CURRENT index + model.
func rederiveSurface(c *state.Campaign, surface validation.Value,
	currentSha *string) (*validation.Value, []string) {
	if vStr(surface, "index_sha") != strOrNil(currentSha) {
		return nil, nil
	}
	idx, err := CampaignIndex(c)
	if err != nil || idx == nil {
		return nil, []string{"probe surface is current but there is no " +
			"structural index to re-derive its rows from — run `webv2 index " +
			c.CampaignID + " --src <target>`"}
	}
	model := validation.VNull()
	mp := filepath.Join(c.ArtifactsDir, "protocol_model.json")
	if fileExists(mp) {
		if m, err := validation.ReadJson(mp); err == nil {
			model = m
		}
	}
	perAxis := knob(surface, "per_axis", 12)
	total := knob(surface, "total", 40)
	floor := knob(surface, "floor", 3)
	built, err := BuildSurface(*idx, model, perAxis, total, floor, "")
	if err != nil {
		return nil, []string{sprintf("could not re-derive the probe surface "+
			"from the current index + model (%s) — the row anchors cannot be "+
			"checked against the tree", err)}
	}
	return &built, nil
}

// knob is surface.get(k) with build_surface's default when absent.
func knob(surface validation.Value, key string, def int) int {
	v := vGet(surface, key)
	if v.Kind != validation.Int {
		return def
	}
	return int(v.I)
}

// rederiveProblems is the row-set + shape + disposition-stamp comparison.
func rederiveProblems(c *state.Campaign, surface, fresh validation.Value,
	plan *validation.Value) []string {
	problems := []string{}
	freshByID := map[string]validation.Value{}
	for _, r := range vList(fresh, "rows") {
		if _, seen := freshByID[vStr(r, "row_id")]; !seen {
			freshByID[vStr(r, "row_id")] = r
		}
	}
	storedByID := map[string]validation.Value{}
	for _, r := range vList(surface, "rows") {
		if _, seen := storedByID[vStr(r, "row_id")]; !seen {
			storedByID[vStr(r, "row_id")] = r
		}
	}
	rerun := "re-run `webv2 probes " + c.CampaignID + " run --emit`"
	for _, rid := range sortedKeys(freshByID) {
		if _, ok := storedByID[rid]; !ok {
			problems = append(problems, sprintf("re-deriving the surface "+
				"produces row %s, which probe_surface.json does not carry — "+
				"the artifact was edited; %s", validation.PyReprStr(rid), rerun))
		}
	}
	for _, rid := range sortedKeys(storedByID) {
		if _, ok := freshByID[rid]; !ok {
			problems = append(problems, sprintf("probe_surface.json carries "+
				"row %s, which the current index + model do not produce — the "+
				"artifact was edited; %s", validation.PyReprStr(rid), rerun))
		}
	}
	for _, rid := range sortedKeys(storedByID) {
		if _, ok := freshByID[rid]; !ok {
			continue
		}
		was := RowShapeSha(storedByID[rid])
		now := RowShapeSha(freshByID[rid])
		if was != now {
			problems = append(problems, sprintf("probe row %s does not "+
				"re-derive: its anchors in probe_surface.json describe "+
				"different code (shape %s… != re-derived %s…) — the artifact "+
				"was edited; %s", validation.PyReprStr(rid), truncRunes(was, 12),
				truncRunes(now, 12), rerun))
		}
	}
	if plan == nil {
		return problems
	}
	for _, p := range vList(*plan, "priorities") {
		prov := vGet(p, "probe")
		if prov.Kind != validation.Obj {
			continue
		}
		rid := vStr(prov, "row_id")
		stamp := vStr(prov, "shape_sha")
		if rid == "" || stamp == "" {
			continue
		}
		row, ok := freshByID[rid]
		if !ok {
			continue
		}
		now := RowShapeSha(row)
		if stamp != now {
			problems = append(problems, sprintf("plan priority %s "+
				"dispositioned probe row %s against shape %s…, which the "+
				"current index + model do not produce (re-derived %s…) — %s",
				pyStr(vGet(p, "id")), validation.PyReprStr(rid),
				truncRunes(stamp, 12), truncRunes(now, 12), rerun))
		}
	}
	return problems
}

// blankProblems is check (c): every persisted attestation must have the
// `probes.blank` event that put it there AND still cite a published key.
func blankProblems(c *state.Campaign, surface validation.Value,
	blanks []validation.Value) []string {
	problems := []string{}
	events, err := c.Events()
	if err != nil {
		events = nil
	}
	blankEvents := []validation.Value{}
	for _, e := range events {
		if vStr(e, "type") == "probes.blank" {
			blankEvents = append(blankEvents, e)
		}
	}
	byLens := map[string]string{}
	{
		reg := RegisteredAxes()
		for _, axis := range sortedKeys(reg) {
			byLens[reg[axis].Lens] = axis
		}
	}
	for _, entry := range blanks {
		lens := vStr(entry, "axis")
		token := vStr(entry, "probe_axis")
		hasToken := vHas(entry, "probe_axis")
		ev := []validation.Value{}
		for _, e := range blankEvents {
			if vStr(e, "ref") != lens {
				continue
			}
			if hasToken && vStr(vGet(e, "data"), "probe_axis") != token {
				continue
			}
			ev = append(ev, e)
		}
		if len(ev) == 0 {
			problems = append(problems, sprintf("blank attestation for %s "+
				"cites %s with no probes.blank event — the attestation was "+
				"hand-edited", validation.PyReprStr(lens),
				validation.PyReprStr(vStr(entry, "anchor_blind"))))
			continue
		}
		if vStr(vGet(ev[len(ev)-1], "data"), "anchor_blind") !=
			vStr(entry, "anchor_blind") {
			problems = append(problems, sprintf("blank attestation for %s "+
				"cites %s but the log's last probes.blank event cites %s — "+
				"projection drifted from the log", validation.PyReprStr(lens),
				validation.PyReprStr(vStr(entry, "anchor_blind")),
				validation.PyReprStr(vStr(vGet(ev[len(ev)-1], "data"),
					"anchor_blind"))))
		}
		axisName := token
		if axisName == "" {
			axisName = byLens[lens]
		}
		ax := surfaceAxis(surface, axisName)
		if ax == nil {
			problems = append(problems, sprintf("blank attestation for %s "+
				"but the surface carries no such axis — re-run `webv2 probes "+
				"%s run`", validation.PyReprStr(lens), c.CampaignID))
			continue
		}
		if vStr(*ax, "status") != "blind" {
			problems = append(problems, sprintf("blank attestation for %s "+
				"but its axis %s is %s, not blind — a blank says the probe "+
				"rejected every site it saw; this axis has rows to work",
				validation.PyReprStr(lens), validation.PyReprStr(axisName),
				validation.PyReprStr(vStr(*ax, "status"))))
		}
		keys := axisBlindKeys(surface, axisName)
		if !containsStr(keys, vStr(entry, "anchor_blind")) {
			problems = append(problems, sprintf("blank attestation for %s "+
				"cites %s, which the surface no longer publishes (blind: %s)",
				validation.PyReprStr(lens),
				validation.PyReprStr(vStr(entry, "anchor_blind")),
				validation.PyRepr(strArr(keys))))
		}
	}
	return problems
}

// strOrNil renders an optional sha the way Python's f-string renders None.
func strOrNil(s *string) string {
	if s == nil {
		return "None"
	}
	return *s
}

func rederivedRowCount(v *validation.Value) int {
	if v == nil {
		return 0
	}
	return len(vList(*v, "rows"))
}
