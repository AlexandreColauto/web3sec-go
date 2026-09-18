// cmd_probes_run: `probes <c> run` — building the probe
// surface, the effective-quota resolution and the index/model loaders.
package cli

import (
	"fmt"
	"path/filepath"
	"strings"

	"websec/internal/probes"
	"websec/internal/state"
	"websec/internal/validation"
)

// probesRun is cli.py _probes_run.
func probesRun(a *probesArgs, c *state.Campaign, r *Runner) error {
	// An explicit flag is validated exactly as it always was, before the
	// artifact is consulted, so `--per-axis 0` keeps its existing message.
	var perAxisKnob, totalKnob *int
	if a.perAxisSet {
		perAxisKnob = &a.perAxis
	}
	if a.totalSet {
		totalKnob = &a.total
	}
	if err := probes.ValidateKnobs(perAxisKnob, totalKnob, nil); err != nil {
		return t14ExitErr(2, "probes: %v\n", err)
	}
	perAxis, total, provenance, err := effectiveProbeQuotas(a, c)
	if err != nil {
		return err
	}
	index, err := loadProbeIndex(c)
	if err != nil {
		return err
	}
	model := loadProbeModel(c)
	surface, err := probes.RunProbes(c, index, model, perAxis, total, 3)
	if err != nil {
		return err
	}
	stats := validation.ObjAt(surface, "stats")
	fmt.Fprintf(r.Out, "probe surface: %d rows emitted (%d ranked, %d sites) "+
		"— index_sha %s\n", objInt(stats, "emitted"), objInt(stats, "rows"),
		objInt(stats, "sites"), t29Trunc(validation.ObjStr(surface, "index_sha"), 12))
	fmt.Fprintf(r.Out, "quotas: --per-axis %d --total %d (%s)\n", perAxis,
		total, provenance)
	for _, line := range probeAxisLines(surface, nil, true) {
		fmt.Fprintln(r.Out, line)
	}
	// B5(b) / r35 F1 convention (the kept-ghost disclosure,
	// cmd_artifact_register.go): the quota disclosures are warnings, not
	// results — they ride stderr so a caller
	// piping stdout gets the surface summary alone. The axis lines, the two
	// count lines and the emit summary stay on stdout. Bytes per line are
	// unchanged; only the destination stream moved.
	for _, line := range probeWarningLines(surface) {
		fmt.Fprintln(r.Err, line)
	}
	for _, m := range t14List(surface, "missing").A {
		fmt.Fprintf(r.Err, "  missing: %s\n", validation.ObjStr(m, "reason"))
	}
	if !a.emit {
		fmt.Fprintf(r.Out, "next: webv2 probes %s run --emit  (turn the rows "+
			"into plan obligations)\n", c.CampaignID)
		return nil
	}
	planPath := filepath.Join(c.ArtifactsDir, "campaign_plan.json")
	if !t29FileExists(planPath) {
		return t14ExitErr(2, "probes --emit: no campaign plan for %s — run "+
			"`webv2 plan %s <plan.json>` first\n", c.CampaignID, c.CampaignID)
	}
	plan, err := validation.ReadJson(planPath)
	if err != nil {
		return err
	}
	res, err := probes.EmitRows(c, plan, surface, &index)
	if err != nil {
		return err
	}
	fmt.Fprintf(r.Out, "emit: created %d, updated %d, kept %d, reopened %d, "+
		"orphaned %d\n", len(t14List(res, "created").A),
		len(t14List(res, "updated").A), len(t14List(res, "kept").A),
		len(t14List(res, "reopened").A), len(t14List(res, "orphaned").A))
	if orph := t14List(res, "orphaned").A; len(orph) > 0 {
		parts := make([]string, 0, len(orph))
		for _, o := range orph {
			parts = append(parts, scalarStr(o))
		}
		fmt.Fprintf(r.Out, "  orphaned (in the plan, absent from this surface): "+
			"%s\n", strings.Join(parts, ", "))
	}
	return nil
}

// probeQuotaArtifact names the surface artifact an unset quota flag reads its
// value from; the provenance line and the invalid-record error both use it.
const probeQuotaArtifact = "probe_surface.json"

// effectiveProbeQuotas resolves the run's quotas one flag at a time: an
// explicit flag wins, else the value the existing surface artifact records,
// else the compiled-in default. The artifact is only read when a flag is
// unset, so an explicit pair never depends on it. The returned provenance
// describes where each effective value came from.
func effectiveProbeQuotas(a *probesArgs, c *state.Campaign) (int, int,
	string, error) {
	perAxis, total := a.perAxis, a.total
	perAxisSrc, totalSrc := "passed on the command line",
		"passed on the command line"
	if !a.perAxisSet {
		perAxisSrc = "defaults"
	}
	if !a.totalSet {
		totalSrc = "defaults"
	}
	if a.perAxisSet && a.totalSet {
		return perAxis, total, quotaProvenance(perAxisSrc, totalSrc), nil
	}
	path := filepath.Join(c.ArtifactsDir, probeQuotaArtifact)
	surface, err := probes.CampaignSurface(c)
	if err != nil {
		return 0, 0, "", t14ExitErr(2, "probes: unreadable %s (%s) — "+
			"delete or repair it, or pass --per-axis and --total explicitly\n",
			path, err.Error())
	}
	if surface == nil {
		return perAxis, total, quotaProvenance(perAxisSrc, totalSrc), nil
	}
	// JSON that parses but is not an object records no quotas at all: the same
	// silent fallback the unreadable-artifact branch exists to remove.
	if surface.Kind != validation.Obj {
		return 0, 0, "", t14ExitErr(2, "probes: unreadable %s (not a JSON "+
			"object) — delete or repair it, or pass --per-axis and --total "+
			"explicitly\n", path)
	}
	if !a.perAxisSet {
		n, src, err := recordedProbeQuota(*surface, path, "per_axis",
			"--per-axis", perAxis)
		if err != nil {
			return 0, 0, "", err
		}
		perAxis, perAxisSrc = n, src
	}
	if !a.totalSet {
		n, src, err := recordedProbeQuota(*surface, path, "total",
			"--total", total)
		if err != nil {
			return 0, 0, "", err
		}
		total, totalSrc = n, src
	}
	return perAxis, total, quotaProvenance(perAxisSrc, totalSrc), nil
}

// recordedProbeQuota reads one quota knob from an existing surface. A knob
// that is not an integer is no record at all and the default stands; an
// integer that fails ValidateKnobs is an error naming the artifact and the
// value — a bad record must never be silently ignored.
func recordedProbeQuota(surface validation.Value, path, key, flag string,
	def int) (int, string, error) {
	raw := validation.ObjAt(surface, key)
	if raw.Kind != validation.Int {
		return def, "default (" + probeQuotaArtifact +
			" records no integer)", nil
	}
	n := int(objInt(surface, key))
	knob := &n
	var err error
	if key == "per_axis" {
		err = probes.ValidateKnobs(knob, nil, nil)
	} else {
		err = probes.ValidateKnobs(nil, knob, nil)
	}
	if err != nil {
		return 0, "", t14ExitErr(2, "probes: %s records an invalid %s %d: "+
			"%v\n", path, flag, n, err)
	}
	return n, "recorded in " + probeQuotaArtifact, nil
}

// quotaProvenance names where each effective quota came from, collapsing the
// two entries when they share a source.
func quotaProvenance(perAxisSrc, totalSrc string) string {
	if perAxisSrc == totalSrc {
		return perAxisSrc
	}
	return fmt.Sprintf("--per-axis %s; --total %s", perAxisSrc, totalSrc)
}

// loadProbeIndex is cli.py _load_probe_index.
func loadProbeIndex(c *state.Campaign) (validation.Value, error) {
	p := filepath.Join(c.ArtifactsDir, "structural_index.json")
	if !t29FileExists(p) {
		return validation.VNull(), t14ExitErr(2, "probes: no structural "+
			"index for %s — run `webv2 index %s --src <target>` first\n",
			c.CampaignID, c.CampaignID)
	}
	idx, err := validation.ReadJson(p)
	if err != nil {
		return validation.VNull(), t14ExitErr(2, "probes: unreadable "+
			"structural index (%s) — re-run `webv2 index %s --src <target>`\n",
			err.Error(), c.CampaignID)
	}
	return idx, nil
}

// loadProbeModel is cli.py _load_probe_model: None is a legitimate input.
func loadProbeModel(c *state.Campaign) validation.Value {
	p := filepath.Join(c.ArtifactsDir, "protocol_model.json")
	if !t29FileExists(p) {
		return validation.VNull()
	}
	m, err := validation.ReadJson(p)
	if err != nil {
		return validation.VNull()
	}
	return m
}
