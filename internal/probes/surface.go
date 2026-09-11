package probes

import (
	"path/filepath"
	"sort"

	"websec/internal/state"
	"websec/internal/structidx"
	"websec/internal/validation"
)

// ValidateKnobs is validate_knobs: fail loud on quota knobs that would rebuild
// the vacuous closure. nil means "the caller does not own that knob".
func ValidateKnobs(perAxis, total, floor *int) error {
	if perAxis != nil && *perAxis < 1 {
		return errf("--per-axis must be >= 1, got %d: a zero quota ranks rows "+
			"and emits none, so every axis would report `emitted` with zero "+
			"obligations and the lens would close on a shrug", *perAxis)
	}
	if total != nil && *total < 1 {
		return errf("--total must be >= 1, got %d: a zero ceiling leaves every "+
			"axis with rows under-filled (missing[]) — the surface would rank "+
			"work and oblige nothing", *total)
	}
	if floor != nil && *floor < 0 {
		return errf("--floor must be >= 0, got %d: the floor is a reserved "+
			"minimum, never a negative quota", *floor)
	}
	return nil
}

// IndexSha is index_sha: the rebuild-stable content hash of a structural
// index. The implementation lives in structidx (it owns the artifact); this
// is the probes.py entry point the surface stamps.
func IndexSha(index validation.Value) string { return structidx.IndexSha(index) }

// TreeFacts is tree_facts: the rebuild-stable projection of an index.
func TreeFacts(index validation.Value) validation.Value { return structidx.TreeFacts(index) }

// ProbeOpts are the Go-only surface enrichments (IMPROVEMENTS C1). The zero
// value reproduces the reference (Python) surface byte-for-byte, which is what
// the parity goldens pin.
type ProbeOpts struct {
	// StageTables attaches the uncovered (write, read) enforcement stage pairs
	// of each assertion-strength row's concept keys.
	StageTables bool
	// Symmetry adds the family-level primitive-matrix divergences (C2) as
	// custody-primitive rows: members of one inheritance family disagreeing
	// about the custody primitive for a (direction, asset).
	Symmetry bool
	// AbsenceRows adds the never-asserted-consumption rows (C3) as
	// assertion-strength rows: a concept written to storage by one stage
	// and read by a stage declared below it, while nothing in the closure
	// asserts it at any class. OFF in ProdProbeOpts — the row rides the
	// existing axis, probe id, anchors and schema, and only its `why` is
	// rewritten (the reference template assumes an asserter).
	//
	// Measured on the Morph tree (500 files, 8082 index entries) before
	// being switched off: the ungated form emitted 421 enforcement-timing
	// rows and the hand-off gate still emitted 276, whose top-ranked
	// members are constructors, pure address/hash computations, test
	// scaffolding and `msg:sender` — at tier 0 with assertion_gap 4, i.e.
	// above the rows that carry real defects. The G-01-shaped row the
	// campaign actually needed (`Rollup.commitBatch`, asserted later in
	// `finalizeBatch`) is emitted by the reference probe itself once the
	// surface can be built at all; the absence rows added noise, not
	// coverage. Kept behind the flag for a future iteration with a
	// tighter obligation shape.
	AbsenceRows bool
	// SentinelForm marks the assertion-strength rows whose consumer guards
	// the concept with a SENTINEL check only — `!= 0`, `!= bytes32(0)`,
	// `> 0`, `.length > 0` — a check that cannot express the truth of the
	// value it guards: any non-zero lie passes it. Such a row carries
	// own_form="sentinel", the guard's own text, and an adversarial `why`
	// that demands the value passing the check before the pair can be
	// called covered. Opt-in for the same reason as the enrichments above:
	// the reference surface (the parity goldens) never classified guard
	// form, and a Go-only field would move a pinned vector.
	SentinelForm bool
}

// ProdProbeOpts is what the shipped surface is built with: the reference
// surface plus the Go-only enrichments that survived measurement (C1 stage
// tables, C2 symmetry, the sentinel-form clause). C3 (AbsenceRows) is NOT
// shipped — see the field's comment for the Morph numbers that retired it.
func ProdProbeOpts() ProbeOpts {
	return ProbeOpts{StageTables: true, Symmetry: true, SentinelForm: true}
}

// buildAxes runs every registered probe, collapses + ranks its rows and
// returns the internal axis table (with `_rows`).
func buildAxes(index, model validation.Value, paths map[string]string,
	opts ProbeOpts) ([]validation.Value, error) {
	axes := []validation.Value{}
	stageMemo := map[string][]validation.Value{}
	for _, probeID := range ProbeIDs() {
		spec := probesTable[probeID]
		out, err := spec.fn(index, model)
		if err != nil {
			return nil, err
		}
		raw := out.rows
		sites := out.sites
		var symExtras map[string]validation.Value
		if opts.Symmetry && probeID == "custody-primitive" {
			var symRows []validation.Value
			symRows, symExtras = symmetryRawRows(index, model)
			raw = append(append([]validation.Value(nil), raw...), symRows...)
		}
		absent := map[string]string{}
		if probeID == "assertion-strength" {
			// OBS-1 (Morph): one joined key fanned out into near-dup
			// near-key entries attesting the tokenizer rather than the
			// code. Unconditional — the collapse only drops duplicates
			// from the reference's own blind list.
			out.blind = collapseNearKeys(out.blind)
		}
		if opts.AbsenceRows && probeID == "assertion-strength" {
			var ar []validation.Value
			var err error
			ar, absent, err = absenceRawRows(index, model)
			if err != nil {
				return nil, err
			}
			raw = append(append([]validation.Value(nil), raw...), ar...)
			sites += len(ar)
		}
		rows := rankRows(collapse(raw, probeID, spec, paths), spec)
		final := make([]validation.Value, len(rows))
		for i, r := range rows {
			final[i] = finalize(r, probeID, spec)
		}
		if opts.SentinelForm && probeID == "assertion-strength" {
			final = attachSentinelForm(index, final)
		}
		if opts.StageTables && probeID == "assertion-strength" {
			final = attachStageTables(index, final, stageMemo)
		}
		if opts.AbsenceRows && probeID == "assertion-strength" {
			final = attachAbsence(final, absent)
		}
		if opts.Symmetry && probeID == "custody-primitive" {
			final = attachSymmetry(final, symExtras)
		}
		axes = append(axes, validation.VObj(
			kv("probe", validation.VStr(probeID)),
			kv("axis", validation.VStr(spec.axis)),
			kv("lens", validation.VStr(spec.lens)),
			kv("sites", validation.VInt(int64(sites))),
			kv("rows", validation.VInt(int64(len(rows)))),
			kv("blind", validation.VArr(out.blind...)),
			kv("blind_total", validation.VInt(int64(out.blindTotal))),
			kv("_rows", validation.VArr(final...))))
	}
	return axes, nil
}

// applyQuota is _apply_quota: per-axis quota, then the campaign ceiling may
// only trim the highest-volume axes and never below the reserved floor.
func applyQuota(axes []validation.Value, perAxis, total, floor int) {
	for i := range axes {
		rows := vInt(axes[i], "rows")
		vSet(&axes[i], "per_axis", validation.VInt(int64(perAxis)))
		vSet(&axes[i], "floor", validation.VInt(int64(minInt(floor, rows))))
		wanted := minInt(perAxis, rows)
		vSet(&axes[i], "wanted", validation.VInt(int64(wanted)))
		vSet(&axes[i], "emitted", validation.VInt(int64(wanted)))
	}
	excess := 0
	for _, a := range axes {
		excess += vInt(a, "emitted")
	}
	excess -= total
	if excess > 0 {
		order := append([]validation.Value(nil), axes...)
		sort.SliceStable(order, func(i, j int) bool {
			if x, y := vInt(order[i], "wanted"), vInt(order[j], "wanted"); x != y {
				return x > y
			}
			return vStr(order[i], "probe") < vStr(order[j], "probe")
		})
		for _, axis := range order {
			if excess <= 0 {
				break
			}
			room := vInt(axis, "emitted") - vInt(axis, "floor")
			if room <= 0 {
				continue
			}
			cut := minInt(room, excess)
			index := axisIndex(axes, vStr(axis, "probe"))
			vSet(&axes[index], "emitted",
				validation.VInt(int64(vInt(axes[index], "emitted")-cut)))
			excess -= cut
		}
	}
	for i := range axes {
		emitted := vInt(axes[i], "emitted")
		vSet(&axes[i], "tail",
			validation.VInt(int64(vInt(axes[i], "rows")-emitted)))
		switch {
		case vInt(axes[i], "sites") == 0:
			vSet(&axes[i], "status", validation.VStr("no-sites"))
		case vInt(axes[i], "rows") == 0:
			vSet(&axes[i], "status", validation.VStr("blind"))
		case emitted == 0 || emitted < vInt(axes[i], "wanted"):
			vSet(&axes[i], "status", validation.VStr("under-filled"))
		default:
			vSet(&axes[i], "status", validation.VStr("emitted"))
		}
	}
}

// axisIndex finds an axis by probe id (the trim loop mutates the original).
func axisIndex(axes []validation.Value, probe string) int {
	for i := range axes {
		if vStr(axes[i], "probe") == probe {
			return i
		}
	}
	return -1
}

// quotaWarnings is _quota_warnings: an arithmetic overrun the operator must
// SEE, not deduce from missing[].
func quotaWarnings(axes []validation.Value, total, floor int) []validation.Value {
	reserved, floored, emitted := 0, 0, 0
	for _, a := range axes {
		reserved += vInt(a, "floor")
		if vInt(a, "floor") != 0 {
			floored++
		}
		emitted += vInt(a, "emitted")
	}
	if reserved <= total {
		return nil
	}
	return []validation.Value{validation.VObj(
		kv("kind", validation.VStr("floor-reserve-exceeds-total")),
		kv("message", validation.VStr(sprintf("floor reserve %d (floor %d x %d "+
			"axes with rows) exceeds --total %d: the ceiling may not trim below "+
			"the reserve, so the surface emits %d rows and every axis with a "+
			"floor reports `under-filled`. Raise --total to >= %d or lower the "+
			"floor", reserved, floor, floored, total, emitted, reserved))))}
}

// BuildSurface is build_surface: run every registered probe and assemble the
// deterministic surface. Pure: same (index, model, knobs) -> byte-identical
// JSON.
func BuildSurface(index, model validation.Value, perAxis, total, floor int,
	generatedAt string) (validation.Value, error) {
	return BuildSurfaceOpts(index, model, perAxis, total, floor, generatedAt,
		ProbeOpts{})
}

// BuildSurfaceOpts is BuildSurface with the Go-only enrichments selected by
// opts. The zero ProbeOpts is byte-identical to the reference surface.
func BuildSurfaceOpts(index, model validation.Value, perAxis, total, floor int,
	generatedAt string, opts ProbeOpts) (validation.Value, error) {
	if err := ValidateKnobs(&perAxis, &total, &floor); err != nil {
		return validation.VNull(), err
	}
	if err := structidx.RequireParseVersion(index, "structural index"); err != nil {
		return validation.VNull(), err
	}
	paths := contractPaths(index)
	axes, err := buildAxes(index, model, paths, opts)
	if err != nil {
		return validation.VNull(), err
	}
	applyQuota(axes, perAxis, total, floor)
	emitted := []validation.Value{}
	missing := []validation.Value{}
	for _, axis := range axes {
		n := vInt(axis, "emitted")
		rows := vList(axis, "_rows")
		if n > len(rows) {
			n = len(rows)
		}
		emitted = append(emitted, rows[:n]...)
		if vStr(axis, "status") == "under-filled" {
			missing = append(missing, missingEntry(axis))
		}
	}
	public := []validation.Value{}
	for _, axis := range axes {
		pub := copyObj(axis)
		vDel(&pub, "_rows")
		public = append(public, pub)
	}
	return validation.VObj(
		kv("campaign_id", validation.VStr(vStr(index, "campaign_id"))),
		kv("snapshot_id", vGet(index, "snapshot_id")),
		kv("parse_version", vGet(index, "parse_version")),
		kv("index_sha", validation.VStr(IndexSha(index))),
		kv("generated_at", validation.VStr(orNowIso(generatedAt))),
		kv("per_axis", validation.VInt(int64(perAxis))),
		kv("total", validation.VInt(int64(total))),
		kv("floor", validation.VInt(int64(floor))),
		kv("axes", validation.VArr(public...)),
		kv("rows", validation.VArr(emitted...)),
		kv("missing", validation.VArr(missing...)),
		kv("warnings", validation.VArr(quotaWarnings(public, total, floor)...)),
		kv("stats", surfaceStats(axes, missing)),
	), nil
}

// missingEntry is one under-filled axis's missing[] blocker.
func missingEntry(axis validation.Value) validation.Value {
	return validation.VObj(
		kv("axis", vGet(axis, "axis")),
		kv("probe", vGet(axis, "probe")),
		kv("lens", vGet(axis, "lens")),
		kv("rows", vGet(axis, "rows")),
		kv("sites", vGet(axis, "sites")),
		kv("emitted", vGet(axis, "emitted")),
		kv("wanted", vGet(axis, "wanted")),
		kv("floor", vGet(axis, "floor")),
		kv("reason", validation.VStr("quota under-filled: "+vStr(axis, "probe")+
			" produced "+itoa(vInt(axis, "rows"))+" rows, emitted "+
			itoa(vInt(axis, "emitted"))+" — raise --per-axis or disposition "+
			"the tail")))
}

// surfaceStats is build_surface's stats block.
func surfaceStats(axes, missing []validation.Value) validation.Value {
	withRows, sites, rows, emitted, tail, blind := 0, 0, 0, 0, 0, 0
	for _, a := range axes {
		if vInt(a, "rows") != 0 {
			withRows++
		}
		sites += vInt(a, "sites")
		rows += vInt(a, "rows")
		emitted += vInt(a, "emitted")
		tail += vInt(a, "tail")
		blind += vInt(a, "blind_total")
	}
	return validation.VObj(
		kv("probes", validation.VInt(int64(len(axes)))),
		kv("axes_with_rows", validation.VInt(int64(withRows))),
		kv("sites", validation.VInt(int64(sites))),
		kv("rows", validation.VInt(int64(rows))),
		kv("emitted", validation.VInt(int64(emitted))),
		kv("tail", validation.VInt(int64(tail))),
		kv("blind", validation.VInt(int64(blind))),
		kv("missing", validation.VInt(int64(len(missing)))),
	)
}

// RunProbes is run_probes: write artifacts/probe_surface.json, register it
// through the living-artifact path and log one `probes.run` event.
func RunProbes(c *state.Campaign, index, model validation.Value, perAxis,
	total, floor int) (validation.Value, error) {
	surface, err := BuildSurfaceOpts(index, model, perAxis, total, floor, "",
		ProdProbeOpts())
	if err != nil {
		return validation.VNull(), err
	}
	out := filepath.Join(c.ArtifactsDir, "probe_surface.json")
	if err := validation.WriteJson(out, surface, "probe_surface"); err != nil {
		return validation.VNull(), err
	}
	stats := vGet(surface, "stats")
	// Python: register_or_refresh("probe-surface", out, reason=...) — the
	// note stays "" and only the refresh reason carries the counts.
	if _, err := c.RegisterOrRefresh("probe-surface", out, "",
		nil, sprintf("%d rows across %d axes", vInt(stats, "emitted"),
			vInt(stats, "probes"))); err != nil {
		return validation.VNull(), err
	}
	if err := logProbesRun(c, surface, perAxis, total, floor); err != nil {
		return validation.VNull(), err
	}
	return surface, nil
}

// logProbesRun is run_probes' `probes.run` event payload.
func logProbesRun(c *state.Campaign, surface validation.Value, perAxis, total,
	floor int) error {
	stats := vGet(surface, "stats")
	axes := validation.VObj()
	for _, a := range vList(surface, "axes") {
		vSet(&axes, vStr(a, "probe"), validation.VObj(
			kv("sites", vGet(a, "sites")),
			kv("rows", vGet(a, "rows")),
			kv("emitted", vGet(a, "emitted")),
			kv("tail", vGet(a, "tail")),
			kv("status", vGet(a, "status"))))
	}
	data := validation.VObj(
		kv("emitted", vGet(stats, "emitted")),
		kv("rows", vGet(stats, "rows")),
		kv("sites", vGet(stats, "sites")),
		kv("tail", vGet(stats, "tail")),
		kv("blind", vGet(stats, "blind")),
		kv("missing", vGet(stats, "missing")),
		kv("per_axis", validation.VInt(int64(perAxis))),
		kv("total", validation.VInt(int64(total))),
		kv("floor", validation.VInt(int64(floor))),
		kv("index_sha", vGet(surface, "index_sha")),
		kv("axes", axes))
	_, err := c.Log("probes.run", nil, &data)
	return err
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// orNowIso is `generated_at or now_iso()`.
func orNowIso(generatedAt string) string {
	if generatedAt != "" {
		return generatedAt
	}
	return state.NowIso()
}
