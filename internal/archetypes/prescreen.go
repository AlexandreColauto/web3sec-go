// prescreen.go: prescreen — run every archetype against the index, persist
// operator overrides and write the report artifact. HINT-only: the report
// never sets a finding status, mints a hypothesis or blocks the pipeline.
package archetypes

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"websec/internal/state"
	"websec/internal/structidx"
	"websec/internal/validation"
)

// PrescreenFile is the artifact name prescreen writes.
const PrescreenFile = "archetype_prescreen.json"

// overridesFile is archetype_overrides.json — operator state, persisted.
const overridesFile = "archetype_overrides.json"

func overridesPath(c *state.Campaign) string {
	return filepath.Join(c.ArtifactsDir, overridesFile)
}

func nowIso() string {
	if v := os.Getenv("WEBV2_NOW"); v != "" {
		return v
	}
	return state.NowIso()
}

// Prescreen is prescreen: run every archetype against the index and write
// the report artifact. force adds operator overrides (persisted + logged). A
// stale stored index is rebuilt first (structidx.EnsureFreshIndex), so the
// report carries the active pin and a post-re-pin re-run clears STALE.
func Prescreen(c *state.Campaign, snapshotRoot string,
	force []string) (validation.Value, error) {
	idx, err := structidx.EnsureFreshIndex(c, snapshotRoot)
	if err != nil {
		return validation.VNull(), err
	}
	overrides, problems, err := loadOverrides(c)
	if err != nil {
		return validation.VNull(), err
	}
	if err := logOverrideProblems(c, problems); err != nil {
		return validation.VNull(), err
	}
	forcedIDs := map[string]bool{}
	for _, o := range overrides {
		forcedIDs[objStr(o, "archetype_id")] = true
	}
	available, err := AvailableArchetypes()
	if err != nil {
		return validation.VNull(), err
	}
	if err := applyForces(c, &overrides, forcedIDs, force, available); err != nil {
		return validation.VNull(), err
	}
	results, matched, forcedCount, err := runArchetypes(idx, available, forcedIDs)
	if err != nil {
		return validation.VNull(), err
	}
	report := prescreenReport(c, idx, results, matched, forcedCount, problems)
	report, err = appendCorpusSurface(c, report)
	if err != nil {
		return validation.VNull(), err
	}
	if err := persistPrescreen(c, report, snapshotRoot, matched, forcedIDs); err != nil {
		return validation.VNull(), err
	}
	return report, nil
}

// logOverrideProblems records a corrupt overrides file (the report still
// carries the problem note; the prescreen never crashes on it).
func logOverrideProblems(c *state.Campaign, problems []string) error {
	if len(problems) == 0 {
		return nil
	}
	data := validation.VObj(validation.KV{K: "problems", V: strArr(problems)})
	_, err := c.Log("prescreen.overrides_corrupt", nil, &data)
	return err
}

// applyForces validates the --force ids, appends the new operator overrides
// and persists them. Unknown ids fail loud (UnknownArchetypeError).
func applyForces(c *state.Campaign, overrides *[]validation.Value,
	forcedIDs map[string]bool, force, available []string) error {
	if len(force) == 0 {
		return nil
	}
	for _, aid := range force {
		if !containsStr(available, aid) {
			return &UnknownArchetypeError{ID: aid}
		}
		if forcedIDs[aid] {
			continue
		}
		forcedIDs[aid] = true
		*overrides = append(*overrides, validation.VObj(
			validation.KV{K: "archetype_id", V: validation.VStr(aid)},
			validation.KV{K: "at", V: validation.VStr(nowIso())},
		))
		ref := aid
		data := validation.VObj(validation.KV{K: "note", V: validation.VStr(
			"operator forced a non-matching archetype")})
		if _, err := c.Log("prescreen.override", &ref, &data); err != nil {
			return err
		}
	}
	return validation.WriteJson(overridesPath(c),
		validation.VArr(*overrides...), "")
}

// runArchetypes evaluates every available archetype, returning the rows plus
// the matched ids and the forced count.
func runArchetypes(idx validation.Value, available []string,
	forcedIDs map[string]bool) ([]validation.Value, []string, int64, error) {
	results := make([]validation.Value, 0, len(available))
	for _, aid := range available {
		arch, err := LoadArchetypeByName(aid)
		if err != nil {
			return nil, nil, 0, err
		}
		row, err := prescreenRow(aid, arch, idx, forcedIDs[aid])
		if err != nil {
			return nil, nil, 0, err
		}
		results = append(results, row)
	}
	matched := []string{}
	forcedCount := int64(0)
	for _, r := range results {
		if objAt(r, "match").B {
			matched = append(matched, objStr(r, "id"))
		}
		if objAt(r, "forced").B {
			forcedCount++
		}
	}
	return results, matched, forcedCount, nil
}

// prescreenReport is the artifact body (before the corpus-surface section).
// campaign_id (FIX-E) binds the artifact to the campaign it ran under — the
// same binding the recon stamps carry — so the L-04 divergence gate can
// refuse a prescreen copied from another campaign's artifacts directory, not
// only a stale one. The property is optional in every consumer that reads
// this artifact (briefing reads matched_ids), so pre-binding artifacts stay
// readable.
func prescreenReport(c *state.Campaign, idx validation.Value,
	results []validation.Value, matched []string, forcedCount int64,
	problems []string) validation.Value {
	return validation.VObj(
		validation.KV{K: "generated_at", V: validation.VStr(nowIso())},
		validation.KV{K: "campaign_id", V: validation.VStr(c.CampaignID)},
		validation.KV{K: "snapshot_id", V: objAt(idx, "snapshot_id")},
		validation.KV{K: "results", V: validation.VArr(results...)},
		validation.KV{K: "matched_ids", V: strArr(matched)},
		validation.KV{K: "stats", V: validation.VObj(
			validation.KV{K: "archetypes", V: validation.VInt(int64(len(results)))},
			validation.KV{K: "matched", V: validation.VInt(int64(len(matched)))},
			validation.KV{K: "forced", V: validation.VInt(forcedCount)},
		)},
		validation.KV{K: "problems", V: strArr(problems)},
	)
}

// appendCorpusSurface adds the additive corpus-surface section (Task 10):
// advisory context only, and only when the sweep artifact already exists —
// prescreen never requires the sweep.
func appendCorpusSurface(c *state.Campaign,
	report validation.Value) (validation.Value, error) {
	csPath := filepath.Join(c.ArtifactsDir, "corpus_surface.json")
	if _, err := os.Stat(csPath); err != nil {
		return report, nil
	}
	cs, err := validation.ReadJson(csPath)
	if err != nil {
		return report, nil
	}
	section, err := corpusSurfaceSection(cs)
	if err != nil {
		return validation.VNull(), err
	}
	report.O = append(report.O, validation.KV{K: "corpus_surface", V: section})
	return report, nil
}

// persistPrescreen writes the artifact, registers it and logs completion.
func persistPrescreen(c *state.Campaign, report validation.Value,
	snapshotRoot string, matched []string, forcedIDs map[string]bool) error {
	out := filepath.Join(c.ArtifactsDir, PrescreenFile)
	if err := validation.WriteJson(out, report, ""); err != nil {
		return err
	}
	reason := itoa(int64(len(matched))) + " matched"
	if _, err := c.RegisterOrRefresh("archetype-prescreen", out, "", nil,
		reason); err != nil {
		return err
	}
	// FIX-C: the prescreen stamps itself the way the sinks verb does
	// (state.recon.prescreen = {campaign_id, src, at}) — the L-04
	// divergence-gate close binds the sinks run to the tree the prescreen saw
	// (planner.checkReconStamps); the artifact's snapshot_id stays the
	// staleness binding (reused, never duplicated).
	if err := c.StampRecon("prescreen", snapshotRoot); err != nil {
		return err
	}
	data := validation.VObj(
		validation.KV{K: "matched", V: strArr(matched)},
		validation.KV{K: "forced", V: strArr(sortedKeys(forcedIDs))},
	)
	_, err := c.Log("prescreen.completed", nil, &data)
	return err
}

// prescreenRow is one archetype's report row.
func prescreenRow(aid string, arch, idx validation.Value,
	forced bool) (validation.Value, error) {
	checksOut := []validation.Value{}
	allPresent := true
	var near []string
	for _, check := range listAt(arch, "checks") {
		result, detail, err := EvaluatePrecondition(check, idx)
		if err != nil {
			return validation.VNull(), err
		}
		checksOut = append(checksOut, validation.VObj(
			validation.KV{K: "type", V: validation.VStr(objStr(check, "type"))},
			validation.KV{K: "result", V: validation.VStr(result)},
			validation.KV{K: "detail", V: validation.VStr(detail)},
		))
		if result == "absent" {
			allPresent = false
			for _, cand := range NearMatches(check, idx, 3) {
				if !containsStr(near, cand) {
					near = append(near, cand)
				}
			}
		}
	}
	sort.Strings(near)
	if len(near) > 10 {
		near = near[:10]
	}
	return validation.VObj(
		validation.KV{K: "id", V: validation.VStr(aid)},
		validation.KV{K: "name", V: objAt(arch, "name")},
		validation.KV{K: "criticality", V: objAt(arch, "criticality")},
		validation.KV{K: "match", V: validation.VBool(allPresent)},
		validation.KV{K: "forced", V: validation.VBool(forced)},
		validation.KV{K: "checks", V: validation.VArr(checksOut...)},
		validation.KV{K: "near_matches", V: strArr(near)},
		validation.KV{K: "playbook_hint", V: objAt(arch, "playbook_hint")},
	), nil
}

// corpusSurfaceSection is prescreen's additive corpus-surface block.
func corpusSurfaceSection(cs validation.Value) (validation.Value, error) {
	exposure := listAt(cs, "class_exposure")
	if len(exposure) > 10 {
		exposure = exposure[:10]
	}
	top := make([]validation.Value, 0, len(exposure))
	for _, r := range exposure {
		top = append(top, validation.VObj(
			validation.KV{K: "bug_class", V: objAt(r, "bug_class")},
			validation.KV{K: "exposed", V: objAt(r, "exposed")},
			validation.KV{K: "score", V: objAt(r, "score")},
			validation.KV{K: "confidence", V: objAt(r, "confidence")},
		))
	}
	matches := listAt(cs, "shape_matches")
	if len(matches) > 20 {
		matches = matches[:20]
	}
	files := make([]string, 0, len(matches))
	for _, m := range matches {
		files = append(files, objStr(m, "file"))
	}
	return validation.VObj(
		validation.KV{K: "top_exposure", V: validation.VArr(top...)},
		validation.KV{K: "shape_match_files", V: strArr(files)},
	), nil
}

// UnknownArchetypeError is the ValueError `unknown archetype {aid!r}`.
type UnknownArchetypeError struct{ ID string }

func (e *UnknownArchetypeError) Error() string {
	return "unknown archetype " + validation.PyReprStr(e.ID)
}

// loadOverrides is _load_overrides: stored operator overrides plus any load
// problems. A malformed overrides file never crashes the prescreen: it
// degrades to "no stored overrides" with a problem note for the report.
func loadOverrides(c *state.Campaign) ([]validation.Value, []string, error) {
	p := overridesPath(c)
	if _, err := os.Stat(p); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	raw, err := validation.ReadJson(p)
	if err != nil {
		return nil, []string{overridesUnreadable(err)}, nil
	}
	if raw.Kind != validation.Arr {
		return nil, []string{overridesMalformed()}, nil
	}
	for _, o := range raw.A {
		if o.Kind != validation.Obj || objAt(o, "archetype_id").Kind != validation.Str {
			return nil, []string{overridesMalformed()}, nil
		}
	}
	return raw.A, nil, nil
}

func overridesUnreadable(err error) string {
	return "archetype_overrides.json unreadable (" + err.Error() + ") -- " +
		"stored overrides not applied"
}

func overridesMalformed() string {
	return "archetype_overrides.json malformed (expected a list of " +
		"{archetype_id, ...} entries) -- stored overrides not applied"
}

func strArr(items []string) validation.Value {
	out := make([]validation.Value, len(items))
	for i, s := range items {
		out[i] = validation.VStr(s)
	}
	return validation.VArr(out...)
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [24]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
