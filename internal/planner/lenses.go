package planner

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"websec/internal/capabilities"
	"websec/internal/economics"
	"websec/internal/state"
	"websec/internal/validation"
)

// ModelOrEmpty is _model_or_empty: the campaign's protocol_model artifact, or
// an empty object when it is absent or unreadable.
func ModelOrEmpty(campaign *state.Campaign) validation.Value {
	p := filepath.Join(campaign.ArtifactsDir, "protocol_model.json")
	if _, err := statFile(p); err != nil {
		return validation.VObj()
	}
	model, err := validation.ReadJson(p)
	if err != nil {
		return validation.VObj()
	}
	return model
}

// entryPointName is `ep if isinstance(ep, str) else (ep.get("name") or "")`.
func entryPointName(ep validation.Value) string {
	if ep.Kind == validation.Str {
		return ep.S
	}
	if ep.Kind == validation.Obj {
		if nm := objAt(ep, "name"); nm.Kind == validation.Str {
			return nm.S
		}
	}
	return ""
}

// contractToken is `c.get("name") or c.get("path") or "?"`.
func contractToken(c validation.Value) string {
	if nm := objAt(c, "name"); nm.Kind == validation.Str && nm.S != "" {
		return nm.S
	}
	if pa := objAt(c, "path"); pa.Kind == validation.Str && pa.S != "" {
		return pa.S
	}
	return "?"
}

// LensFamilies is lens_families: deterministic candidate families per lens,
// derived from the protocol model — the checklist a lens closure must attest
// against. The teeth that turn a one-shot lens into an exhaustive one.
func LensFamilies(model validation.Value) validation.Value {
	var sms []string
	for _, sm := range listOf(model, "state_machines") {
		if nm := objAt(sm, "name"); nm.Kind == validation.Str && nm.S != "" {
			sms = append(sms, nm.S)
		}
	}
	var actors []string
	for _, a := range listOf(model, "actors") {
		if id := objAt(a, "id"); id.Kind == validation.Str && id.S != "" {
			actors = append(actors, id.S)
		}
	}
	verbContracts := map[string]map[string]struct{}{}
	for _, c := range listOf(model, "contracts") {
		cname := contractToken(c)
		for _, ep := range listOf(c, "entry_points") {
			low := strings.ToLower(entryPointName(ep))
			for _, v := range lifecycleVerbs {
				if strings.Contains(low, v) {
					if verbContracts[v] == nil {
						verbContracts[v] = map[string]struct{}{}
					}
					verbContracts[v][cname] = struct{}{}
				}
			}
		}
	}
	var sym []string
	for v, cs := range verbContracts {
		if len(cs) >= 2 {
			sym = append(sym, v)
		}
	}
	sort.Strings(sym)
	return validation.VObj(
		kv("liveness", strArr(orDefault(sms, []string{"protocol"}))),
		kv("incentive-inversion", strArr(orDefault(actors, orDefault(sms,
			[]string{"protocol"})))),
		kv("enforcement-timing", strArr(orDefault(sms, []string{"protocol"}))),
		kv("primitive-symmetry", strArr(orDefault(sym, orDefault(sms,
			[]string{"protocol"})))),
	)
}

// orDefault is Python's `a or b` for string slices.
func orDefault(a, b []string) []string {
	if len(a) == 0 {
		return b
	}
	return a
}

// modelKey is the dict key a Python lookup would use: strings as-is, None as
// the None key, everything else via str().
func modelKey(v validation.Value) string {
	if v.Kind == validation.Str {
		return v.S
	}
	return "\x00" + pyStr(v)
}

// FamiliesForFinding is families_for_finding: family tokens a finding
// implicates — lifecycle verbs present in its affected contracts' entry
// points, plus any state machine named in the finding. Used to decide which
// exhausted lens a CONFIRMED finding re-opens.
func FamiliesForFinding(model, finding validation.Value) map[string]struct{} {
	contracts := map[string]validation.Value{}
	for _, c := range listOf(model, "contracts") {
		nm := objAt(c, "name")
		pa := objAt(c, "path")
		var key string
		switch {
		case pyTruthyBigNonEmpty(nm):
			key = modelKey(nm)
		case pyTruthyBigNonEmpty(pa):
			key = modelKey(pa)
		default:
			key = modelKey(validation.VNull())
		}
		contracts[key] = c
	}
	toks := map[string]struct{}{}
	affected := listOf(finding, "affected")
	for _, a := range affected {
		c, ok := contracts[modelKey(objAt(a, "contract"))]
		if !ok {
			continue
		}
		for _, ep := range listOf(c, "entry_points") {
			low := strings.ToLower(entryPointName(ep))
			for _, v := range lifecycleVerbs {
				if strings.Contains(low, v) {
					toks[v] = struct{}{}
				}
			}
		}
	}
	for _, sm := range listOf(model, "state_machines") {
		nm := objAt(sm, "name")
		if !pyTruthyBigNonEmpty(nm) || nm.Kind != validation.Str {
			continue
		}
		for _, a := range affected {
			if strings.Contains(strings.ToLower(pyStr(a)),
				strings.ToLower(nm.S)) {
				toks[nm.S] = struct{}{}
				break
			}
		}
	}
	return toks
}

// SeedLenses is seed_lenses: idempotently add the missing canonical lens
// entries (L-01..L-04). Returns the entries ADDED (empty when the plan is
// already current) and the plan (callers must use the returned value).
func SeedLenses(plan, model validation.Value) ([]validation.Value,
	validation.Value) {
	machines := machinesLabel(model)
	have := map[string]struct{}{}
	byID := map[string]validation.Value{}
	for _, l := range listOf(plan, "lenses") {
		if l.Kind != validation.Obj {
			continue
		}
		id := objStr(l, "id")
		have[id] = struct{}{}
		byID[id] = l
	}
	fams := LensFamilies(model)
	added := []validation.Value{}
	lenses := objAt(plan, "lenses")
	if lenses.Kind != validation.Arr {
		lenses = validation.VArr()
	}
	for i, lens := range LensIDs {
		lid := fmt.Sprintf("L-%02d", i+1)
		if _, ok := have[lid]; ok {
			// Grandfather rule: already-closed lenses were sealed under the
			// old reason+actor contract — never retroactively demand a family
			// attestation they never gave. Only open lenses get backfilled.
			entry := byID[lid]
			if objStr(entry, "status") == "open" && !hasKey(entry, "families") {
				entry.O = validation.SetOrAppend(entry.O, "families",
					objAt(fams, objStr(entry, "lens")))
				lenses.A = replaceLens(lenses.A, lid, entry)
			}
			continue
		}
		entry := validation.VObj(
			kv("id", validation.VStr(lid)),
			kv("lens", validation.VStr(lens)),
			kv("surface", validation.VStr("protocol")),
			kv("question", validation.VStr(formatLens(lensQuestions[lens],
				machines))),
			kv("status", validation.VStr("open")),
			kv("families", objAt(fams, lens)),
		)
		added = append(added, entry)
		lenses.A = append(lenses.A, entry)
	}
	plan.O = validation.SetOrAppend(plan.O, "lenses", lenses)
	return added, plan
}

// replaceLens swaps one lens entry back into the plan's lens list.
func replaceLens(lenses []validation.Value, lid string,
	entry validation.Value) []validation.Value {
	for j, e := range lenses {
		if objStr(e, "id") == lid {
			lenses[j] = entry
		}
	}
	return lenses
}

// machinesLabel is the `", ".join(...) or "protocol (none declared)"` label
// every lens question carries.
func machinesLabel(model validation.Value) string {
	var names []string
	for _, m := range listOf(model, "state_machines") {
		id := objAt(m, "id")
		nm := objAt(m, "name")
		switch {
		case pyTruthyBigNonEmpty(id):
			names = append(names, pyStr(id))
		case pyTruthyBigNonEmpty(nm):
			names = append(names, pyStr(nm))
		default:
			names = append(names, "?")
		}
	}
	if len(names) == 0 {
		return "protocol (none declared)"
	}
	return strings.Join(names, ", ")
}

// LoadPlanReadonly is load_plan_readonly: read the plan WITHOUT registration
// side effects (gate/anchor paths).
func LoadPlanReadonly(campaign *state.Campaign) (validation.Value, error) {
	p := filepath.Join(campaign.ArtifactsDir, "campaign_plan.json")
	if _, err := statFile(p); err != nil {
		return validation.VNull(), errValue("no campaign plan at " + p)
	}
	return validation.ReadJson(p)
}

// LensOpts is the optional tail of mark_lens. Nil pointers are Python's None
// (Reason/Ref and FamiliesChecked/Symmetry/Reconcile: `is not None`).
type LensOpts struct {
	Reason          *string
	Ref             *string
	Actor           string
	FamiliesChecked *[]string
	Symmetry        *[]validation.Value
	// Reconcile is FIX-6: the divergence reconciliation an L-04 closure
	// attests — one record per funding-mismatch / member-disagreement surface
	// row ({row_id, cites, finding}), parsed by ParseReconcile. The gate in
	// checkLensReconciliation validates each named row; rows left uncited or
	// unattached refuse the attestation.
	Reconcile *[]validation.Value
}

// MarkLens is mark_lens: close or reopen a canonical lens entry. The
// reason/ref/actor are recorded data; the CLI enforces the written reason on
// closing statuses, and the divergence proof treats a reasonless closure as
// still open (the teeth are data-level, not exception-level).
func MarkLens(campaign *state.Campaign, plan validation.Value, lensID,
	outcome string, opts LensOpts) (validation.Value, error) {
	actor := opts.Actor
	if actor == "" {
		actor = "cli"
	}
	closing := outcome == "answered" || outcome == "not-applicable"
	lenses := objAt(plan, "lenses")
	found := false
	if lenses.Kind == validation.Arr {
		for i, l := range lenses.A {
			if objStr(l, "id") != lensID {
				continue
			}
			// FIX-8, before any mutation: the divergence-gate close demands
			// the mechanical recon on record — a lens attestation over
			// divergence rows the backward slice and the prescreen never
			// saw is prose, not attestation. Unconditional: recon is cheap.
			if closing && objStr(l, "lens") == "primitive-symmetry" {
				if err := checkReconStamps(campaign); err != nil {
					return validation.VNull(), err
				}
			}
			// FIX-6, before any mutation: closing the primitive-symmetry lens
			// attests a reconciliation for every divergence row in the
			// current surface — the refusal must leave the plan untouched,
			// and only records the gate actually validated land on the lens.
			if closing && objStr(l, "lens") == "primitive-symmetry" {
				validated, err := checkLensReconciliation(campaign, l, opts)
				if err != nil {
					return validation.VNull(), err
				}
				if opts.Reconcile != nil {
					opts.Reconcile = &validated
				}
			}
			lenses.A[i] = markLensEntry(l, outcome, closing, actor, opts)
			found = true
			break
		}
	}
	if !found {
		return validation.VNull(), errKey("no lens " +
			validation.PyReprStr(lensID) + " in the campaign plan")
	}
	plan.O = validation.SetOrAppend(plan.O, "lenses", lenses)
	if _, err := SavePlan(campaign, plan); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(
		kv("status", validation.VStr(outcome)),
		kv("reason", optStr(opts.Reason)),
		kv("ref", optStr(opts.Ref)),
		kv("actor", validation.VStr(actor)),
	)
	if _, err := campaign.Log("plan.lens_status", &lensID, &data); err != nil {
		return validation.VNull(), err
	}
	return plan, nil
}

// markLensEntry applies one lens status flip (the loop body of mark_lens).
func markLensEntry(l validation.Value, outcome string, closing bool,
	actor string, opts LensOpts) validation.Value {
	l.O = validation.SetOrAppend(l.O, "status", validation.VStr(outcome))
	if !closing {
		for _, k := range []string{"closed_reason", "closed_ref", "closed_at",
			"closed_by", "families_checked", "symmetry", "reconciliation"} {
			l.O = dropKey(l.O, k)
		}
		return l
	}
	if opts.Reason != nil {
		l.O = validation.SetOrAppend(l.O, "closed_reason", validation.VStr(*opts.Reason))
	}
	if opts.Ref != nil {
		l.O = validation.SetOrAppend(l.O, "closed_ref", validation.VStr(*opts.Ref))
	}
	l.O = validation.SetOrAppend(l.O, "closed_at", validation.VStr(nowIso()))
	l.O = validation.SetOrAppend(l.O, "closed_by", validation.VStr(actor))
	l.O = dropKey(l.O, "reopen_reason")
	l.O = dropKey(l.O, "reopened_at")
	if opts.Symmetry != nil {
		l.O = validation.SetOrAppend(l.O, "symmetry", validation.VArr(*opts.Symmetry...))
		l.O = validation.SetOrAppend(l.O, "families_checked",
			strArr(symmetryFamilies(*opts.Symmetry)))
	} else if opts.FamiliesChecked != nil {
		l.O = validation.SetOrAppend(l.O, "families_checked", strArr(*opts.FamiliesChecked))
	}
	// FIX-6: the reconciliation is part of the attestation record, the same
	// way symmetry is — SetOrAppend replaces, so a re-attestation cannot
	// double-fire a row's reconciliation.
	if opts.Reconcile != nil {
		l.O = validation.SetOrAppend(l.O, "reconciliation",
			validation.VArr(*opts.Reconcile...))
	}
	return l
}

// symmetryFamilies is `[s.get("family") for s in symmetry if s.get("family")]`.
func symmetryFamilies(symmetry []validation.Value) []string {
	out := []string{}
	for _, s := range symmetry {
		if f := objAt(s, "family"); pyTruthyBigNonEmpty(f) {
			out = append(out, pyStr(f))
		}
	}
	return out
}

// optStr is a *string as a Value (nil -> null).
func optStr(s *string) validation.Value {
	if s == nil {
		return validation.VNull()
	}
	return validation.VStr(*s)
}

// RolePrivilegeSurface is _role_privilege_surface: privilege entries grouped
// by normalized role, roles in sorted order. Deliberately a local
// re-derivation of privileged.path_constraints (4 lines of duplication)
// rather than an import: the planner must not gain a dependency on the
// privileged track's module graph.
func RolePrivilegeSurface(model validation.Value) map[string][]validation.Value {
	groups := map[string][]validation.Value{}
	for _, p := range listOf(model, "privileges") {
		role := objAt(p, "role")
		if !pyTruthyBigNonEmpty(role) {
			continue
		}
		label := capabilities.NormalizeLabel(pyStr(role))
		groups[label] = append(groups[label], p)
	}
	out := map[string][]validation.Value{}
	for _, r := range sortedMapKeys(groups) {
		out[r] = groups[r]
	}
	return out
}

// EcoTransforms is eco_transforms: the deterministic adversarial
// transformation list for trajectory B.
func EcoTransforms(campaign *state.Campaign,
	model validation.Value) []validation.Value {
	return economics.GenerateTransforms(model)
}
