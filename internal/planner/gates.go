package planner

import (
	"sort"
	"strings"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// DivergenceOpts is the optional tail of divergence_status (Python:
// surface=None, current_index_sha=None, blanks=None). A nil Surface is the
// grandfather case; a nil CurrentIndexSha is "no current structural index";
// a nil Blanks map is no persisted attestation.
type DivergenceOpts struct {
	Surface         *validation.Value
	CurrentIndexSha *string
	Blanks          map[string]validation.Value
	// CampaignID names the campaign in operator-facing repair hints when the
	// plan JSON itself carries no campaign_id (a hand-loaded plan). It is
	// required for a named hint on this exported path: the only production
	// caller is DivergenceStatusFor, which sets it. A direct call with
	// neither id prints the documented metavariable — a command with an
	// empty hole where the campaign belongs is worse than the obvious
	// placeholder.
	CampaignID string
	// CampaignClasses carries the canonical bug classes the campaign's own
	// findings already name. The diversity clause unions them with the
	// plan's priorities: a shape the model dispositioned by filing a finding
	// was named whether or not the planner stamped the priority. nil (the
	// pure function) keeps the plan-only behavior byte-identical.
	CampaignClasses []string
}

// campaignIDForPlan is the campaign id an operator-facing repair hint names:
// the plan's own campaign_id, else the campaign the caller supplied. A direct
// call with neither has no id to name — no production path reaches that (the
// CLI always goes through DivergenceStatusFor) — so the documented
// metavariable stands in rather than an empty string, which would render a
// command with a hole where the campaign belongs.
func campaignIDForPlan(plan validation.Value,
	opts DivergenceOpts) string {
	if cid := validation.ObjStr(plan, "campaign_id"); cid != "" {
		return cid
	}
	if opts.CampaignID != "" {
		return opts.CampaignID
	}
	return "<campaign>"
}

// DivergenceStatus is divergence_status: the divergence gate as DATA. A lens
// is closed only when status is answered/not-applicable AND a written reason
// (>=10 chars) AND a named actor are on record. Diversity: distinct canonical
// bug_class values across ALL priorities (any status — a deprioritized shape
// was still named and dispositioned).
//
// When a surface is supplied, every registered probe axis adds its own
// closure clause: emitted rows must be dispositioned and the surface must
// still match CurrentIndexSha. When it is nil the campaign has no probe
// artifact and the pre-A3 gate is returned byte-identical — old campaigns do
// not regress.
func DivergenceStatus(plan validation.Value, opts DivergenceOpts) validation.Value {
	missing := []validation.Value{}
	lenses := listOf(plan, "lenses")
	rows := []validation.Value{}
	for _, l := range lenses {
		entry := lensGateEntry(plan, l, opts)
		rows = append(rows, entry.row)
		missing = append(missing, entry.missing...)
	}
	if opts.Surface != nil {
		missing = append(missing, probeMissing(plan, opts)...)
	}
	if len(lenses) == 0 {
		missing = append(missing, validation.VObj(
			kv("subject", validation.VStr("lenses")),
			kv("what", validation.VStr("plan predates the lens era — "+
				"re-save it (webv2 plan C plan.json --rebuild; the outgoing "+
				"plan is archived as plan.superseded) to seed L-01..L-04"))))
	}
	named := namedClasses(plan, opts.CampaignClasses)
	if len(named) < MinDistinctClasses {
		what := itoa(len(named)) + " distinct bug class(es) named (" +
			joinOrNone(named) + "); min " + itoa(MinDistinctClasses) +
			" — set priorities[].bug_class"
		// The findings exit is offered only when the caller actually
		// counted the campaign's classes: a pure DivergenceStatus call
		// (nil/empty CampaignClasses) does not, so naming that exit would
		// point at a command that cannot move this gate — and the
		// pre-campaign hint stays byte-identical for those callers.
		if len(opts.CampaignClasses) > 0 {
			what += " or file findings naming them"
		}
		missing = append(missing, validation.VObj(
			kv("subject", validation.VStr("diversity")),
			kv("what", validation.VStr(what))))
	}
	return validation.VObj(
		kv("closed", validation.VBool(len(missing) == 0)),
		kv("missing", validation.VArr(missing...)),
		kv("named_classes", validation.StrArr(named)),
		kv("lenses", validation.VArr(rows...)),
	)
}

// gateEntry is one lens's output row plus its missing[] entries.
type gateEntry struct {
	row     validation.Value
	missing []validation.Value
}

// lensGateEntry is the divergence_status loop body for one lens.
func lensGateEntry(plan, l validation.Value, opts DivergenceOpts) gateEntry {
	lid := validation.ObjStr(l, "id")
	lens := pyStr(validation.ObjAt(l, "lens"))
	seeded := familyList(l)
	checked := stringSet(listOf(l, "families_checked"))
	symmetry, hasSymmetry := fieldAt(l, "symmetry")
	symBranch := lens == "primitive-symmetry" && len(seeded) > 0 &&
		!(len(seeded) == 1 && seeded[0] == "protocol") && hasSymmetry
	familiesOK, uncovered := lensFamiliesOK(symBranch, seeded, checked, symmetry)
	closed := lensClosed(l, familiesOK)
	row := validation.VObj(
		kv("id", validation.ObjAt(l, "id")),
		kv("lens", validation.ObjAt(l, "lens")),
		kv("status", validation.ObjAt(l, "status")),
	)
	if opts.Surface != nil {
		counts := lensProbeClosure(plan, lid, opts)
		if counts == nil {
			row.O = validation.SetOrAppend(row.O, "probe", validation.VNull())
		} else {
			row.O = validation.SetOrAppend(row.O, "probe", *counts)
		}
	}
	if closed {
		return gateEntry{row: row}
	}
	return gateEntry{row: row, missing: []validation.Value{lensMissing(l, lid,
		lens, seeded, uncovered, symBranch)}}
}

// familyList is `l.get("families") or []` rendered as strings.
func familyList(l validation.Value) []string {
	out := []string{}
	for _, f := range listOf(l, "families") {
		out = append(out, pyStr(f))
	}
	return out
}

// stringSet is set(items) for string-valued items.
func stringSet(items []validation.Value) map[string]struct{} {
	out := map[string]struct{}{}
	for _, it := range items {
		out[pyStr(it)] = struct{}{}
	}
	return out
}

// lensFamiliesOK is the family-attestation half of the closure test plus the
// uncovered families the message names. symBranch selects the symmetry
// variant of the rule.
func lensFamiliesOK(symBranch bool, seeded []string,
	checked map[string]struct{}, symmetry validation.Value) (bool, []string) {
	if symBranch {
		sym := symmetryPrimitives(symmetry)
		var uncovered []string
		for _, f := range seeded {
			if len(sym[f]) == 0 {
				uncovered = append(uncovered, f)
			}
		}
		return len(uncovered) == 0, uncovered
	}
	if len(seeded) == 0 {
		return true, nil
	}
	protocolOnly := len(seeded) == 1 && seeded[0] == "protocol"
	if _, na := checked["none-applicable"]; protocolOnly && na {
		return true, nil
	}
	var uncovered []string
	for _, f := range seeded {
		if _, ok := checked[f]; !ok {
			uncovered = append(uncovered, f)
		}
	}
	sort.Strings(uncovered)
	return len(uncovered) == 0, uncovered
}

// symmetryPrimitives is `{s.get("family"): [p for p in (s.get("primitives")
// or []) if str(p).strip()] for s in (l.get("symmetry") or [])}`.
func symmetryPrimitives(symmetry validation.Value) map[string][]string {
	out := map[string][]string{}
	for _, s := range symmetry.A {
		prims := []string{}
		for _, p := range listOf(s, "primitives") {
			if pyStrip(pyStr(p)) != "" {
				prims = append(prims, pyStr(p))
			}
		}
		out[pyStr(validation.ObjAt(s, "family"))] = prims
	}
	return out
}

// lensClosed is the closure predicate: a written reason (>= 10 stripped
// chars), an actor, and the family attestation.
func lensClosed(l validation.Value, familiesOK bool) bool {
	status := validation.ObjStr(l, "status")
	if status != "answered" && status != "not-applicable" {
		return false
	}
	reason := validation.ObjAt(l, "closed_reason")
	if reason.Kind != validation.Str || len(pyStrip(reason.S)) < 10 {
		return false
	}
	if !pyTruthyBigNonEmpty(validation.ObjAt(l, "closed_by")) {
		return false
	}
	return familiesOK
}

// lensMissing is the what-text for one unresolved lens.
func lensMissing(l validation.Value, lid, lens string, seeded,
	uncovered []string, symBranch bool) validation.Value {
	status := validation.ObjStr(l, "status")
	resolved := status == "answered" || status == "not-applicable"
	var what string
	switch {
	case symBranch && len(uncovered) > 0 && resolved:
		what = "lens primitive-symmetry closed but families lack a quoted " +
			"primitive (missing: " + strings.Join(uncovered, ", ") +
			") — webv2 answered C " + lid + " " + status + " --symmetry '" +
			strings.Join(symmetryStub(uncovered), ";") +
			"' --reason R --actor A"
	case len(seeded) > 0 && len(uncovered) > 0 && resolved:
		what = "lens " + lens + " closed but families not attested " +
			"(missing: " + strings.Join(uncovered, ", ") + ") — webv2 " +
			"answered C " + lid + " " + status + " --families " +
			strings.Join(uncovered, ",") + " --reason R --actor A"
	default:
		what = "lens " + lens + " (" + pyStr(validation.ObjAt(l, "surface")) +
			") not resolved — webv2 answered C " + lid +
			" answered|not-applicable --families ... --reason R --actor A"
	}
	return validation.VObj(
		kv("subject", validation.VStr(lid)),
		kv("what", validation.VStr(what)),
	)
}

// symmetryStub is `f + '=' + 'prim'` per uncovered family.
func symmetryStub(uncovered []string) []string {
	out := make([]string, 0, len(uncovered))
	for _, f := range uncovered {
		out = append(out, f+"=prim")
	}
	return out
}

// namedClasses is `sorted({p["bug_class"] for p in plan.get("priorities", [])
// if p.get("bug_class")} | set(campaign))`: the plan's own classes unioned with
// the canonical classes the campaign's findings name (empty strings dropped,
// deduped, sorted).
func namedClasses(plan validation.Value, campaign []string) []string {
	seen := map[string]struct{}{}
	for _, p := range listOf(plan, "priorities") {
		if bc := validation.ObjAt(p, "bug_class"); pyTruthyBigNonEmpty(bc) {
			seen[pyStr(bc)] = struct{}{}
		}
	}
	for _, c := range campaign {
		if c != "" {
			seen[c] = struct{}{}
		}
	}
	return validation.SortedKeys(seen)
}

// joinOrNone is `', '.join(named) or 'none'`.
func joinOrNone(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	return strings.Join(items, ", ")
}

// DivergenceStatusFor is divergence_status_for: the campaign-aware wrapper the
// CLI/briefing/report call. A nil blanks map reads the persisted attestation
// store (pass an empty non-nil map to assert "no attestations").
//
// It is also where the diversity clause learns what the campaign itself
// already named: the classes come from the campaign's stored findings, so a
// plan whose priorities carry no bug_class is still satisfiable when the
// findings name four canonical classes.
func DivergenceStatusFor(campaign *state.Campaign, plan validation.Value,
	blanks map[string]validation.Value) (validation.Value, error) {
	if blanks == nil {
		got, err := PB().CampaignBlanks(campaign)
		if err != nil {
			return validation.VNull(), err
		}
		blanks = got
	}
	surface, err := PB().CampaignSurface(campaign)
	if err != nil {
		return validation.VNull(), err
	}
	classes, err := PB().CampaignBugClasses(campaign)
	if err != nil {
		return validation.VNull(), err
	}
	return DivergenceStatus(plan, DivergenceOpts{Surface: surface,
		CurrentIndexSha: PB().CampaignIndexSha(campaign), Blanks: blanks,
		CampaignID: campaign.CampaignID, CampaignClasses: classes}), nil
}

// campaignBugClasses is PB().CampaignBugClasses: the canonical bug classes the
// campaign's own findings name — every stored finding's root_cause.class that
// passes isCanonicalClass, deduped and sorted. root_cause.class is schema-free
// form (advisory taxonomy mapping), exactly like the class copied into an
// anchor priority, so a non-canonical value is not a class a plan could carry
// and must not count toward the diversity clause. Findings are read in the
// store's deterministic (created_at, finding_id) order.
func campaignBugClasses(campaign *state.Campaign) ([]string, error) {
	all, err := findings.LoadAllFindings(campaign)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	for _, f := range all {
		cls, ok := fieldAt(validation.ObjAt(f, "root_cause"), "class")
		if !ok || cls.Kind != validation.Str || !isCanonicalClass(cls.S) {
			continue
		}
		seen[cls.S] = struct{}{}
	}
	return validation.SortedKeys(seen), nil
}

// LensProbeClosure is lens_probe_closure: the one-line probe closure statement
// for a lens, or nil when the lens owns no registered axis / the campaign has
// no surface (grandfather).
func LensProbeClosure(plan validation.Value, lensID string,
	opts DivergenceOpts) *validation.Value {
	if opts.Surface == nil {
		return nil
	}
	return probeLensView(plan, lensID, opts).counts
}

// probeMissing is _probe_missing: the A3 probe clause as missing[] entries.
//
// For every registered probe axis belonging to a lens, when the surface HAS
// that axis the lens may close only when (a) every emitted row of the axis is
// dispositioned (answered/not-applicable/deprioritized) against the shape the
// plan actually stored (`probe.shape_sha`) and (b) the surface still matches
// the current index; the axis's own four-state blocker (blind without a blank
// attestation, under-filled quota) is folded in. `probes run` is valid without
// `--emit`, so a surface whose row anchors moved leaves every stored
// disposition stale — such a row is NOT dispositioned and the entry names the
// re-emit command. A registered axis the surface does NOT carry gets exactly
// one entry naming the refresh command.
func probeMissing(plan validation.Value, opts DivergenceOpts) []validation.Value {
	registered := registeredAxes()
	out := []validation.Value{}
	cid := campaignIDForPlan(plan, opts)
	for _, l := range listOf(plan, "lenses") {
		lid := validation.ObjStr(l, "id")
		view := probeLensView(plan, lid, opts)
		if len(view.axes) == 0 {
			continue
		}
		for _, ax := range view.missingAxes {
			meta := registered[ax]
			out = append(out, validation.VObj(
				kv("subject", validation.VStr(ax)),
				kv("what", validation.VStr("probe axis "+ax+" ("+meta.Probe+
					", lens "+lid+") has no surface in probe_surface.json "+
					"— run `webv2 probes "+cid+" run --emit`")),
			))
		}
		if len(view.issues) > 0 {
			out = append(out, validation.VObj(
				kv("subject", validation.VStr(lid)),
				kv("what", validation.VStr(strings.Join(view.issues, "; "))),
			))
		}
	}
	return out
}

// probeView is the Python dict _probe_lens_view returns.
type probeView struct {
	axes        []string
	present     []string
	missingAxes []string
	issues      []string
	counts      *validation.Value
}
