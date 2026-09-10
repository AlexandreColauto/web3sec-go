package planner

import (
	"strings"
	"testing"

	"websec/internal/validation"
)

// TestDivergenceStatusPreA3Oracle pins the pre-A3 gate (no surface): lens
// closure, families attestation, symmetry, diversity and the no-lenses case.
func TestDivergenceStatusPreA3Oracle(t *testing.T) {
	root := oracles(t)
	cases := at(t, root, "divergence")
	if cases.Kind != validation.Arr || len(cases.A) != 11 {
		t.Fatalf("expected 11 pre-A3 cases, got %v", cases.Kind)
	}
	for _, c := range cases.A {
		got := DivergenceStatus(objAt(c, "plan"), DivergenceOpts{})
		requireJSON(t, "divergence/"+objStr(c, "name"), got, objAt(c, "out"))
	}
}

// TestDivergenceStatusA3Oracle pins the A3 gate over the 13 recorded surface
// scenarios: fresh, stale index, missing index, new row, absent axis, open
// row, stale disposition, parked, blocked, blind with/without attestation,
// wrong attestation key and under-filled quota.
func TestDivergenceStatusA3Oracle(t *testing.T) {
	root := oracles(t)
	cases := at(t, root, "a3")
	if cases.Kind != validation.Arr || len(cases.A) != 13 {
		t.Fatalf("expected 13 A3 cases, got %v", cases.Kind)
	}
	for _, c := range cases.A {
		surface := objAt(c, "surface")
		withProbes(t, probeEnv{surface: &surface, sha: shaPtr(c),
			blanks: blanksOf(c)})
		got := DivergenceStatus(objAt(c, "plan"), DivergenceOpts{
			Surface: &surface, CurrentIndexSha: shaPtr(c),
			Blanks: blanksOf(c)})
		requireJSON(t, "a3/"+objStr(c, "name"), got, objAt(c, "out"))
		closure := LensProbeClosure(objAt(c, "plan"), "L-03",
			DivergenceOpts{Surface: &surface, CurrentIndexSha: shaPtr(c),
				Blanks: blanksOf(c)})
		if closure == nil {
			t.Fatalf("a3/%s: closure is nil", objStr(c, "name"))
		}
		requireJSON(t, "a3 closure/"+objStr(c, "name"), *closure,
			objAt(c, "closure"))
	}
}

// shaPtr is the case's current index sha (null = no index).
func shaPtr(c validation.Value) *string {
	if s := objAt(c, "sha"); s.Kind == validation.Str {
		return &s.S
	}
	return nil
}

// blanksOf is the case's attestation map.
func blanksOf(c validation.Value) map[string]validation.Value {
	out := map[string]validation.Value{}
	b := objAt(c, "blanks")
	if b.Kind != validation.Obj {
		return out
	}
	for _, pair := range b.O {
		out[pair.K] = pair.V
	}
	return out
}

// TestProbeMissingHintNamesCampaign pins the missing-axis entry for a
// hand-loaded plan (one that carries no campaign_id of its own): the re-emit
// command names the campaign id the caller supplied, never `<campaign>`.
func TestProbeMissingHintNamesCampaign(t *testing.T) {
	surface, index, plan := pvFixtures(t)
	withProbes(t, probeEnv{surface: &surface, index: &index})
	plan = deepCopy(t, plan)
	plan.O = dropKey(plan.O, "campaign_id")
	bare := jsonValue(t, `{"axes":[],"rows":[]}`)
	got := probeMissing(plan, DivergenceOpts{Surface: &bare,
		CampaignID: "C-abc12345"})
	if len(got) == 0 {
		t.Fatalf("a lens whose axes the surface lacks must report an entry")
	}
	joined := ""
	for _, m := range got {
		joined += objStr(m, "what") + "\n"
	}
	if !strings.Contains(joined,
		"run `webv2 probes C-abc12345 run --emit`") {
		t.Fatalf("missing entry must name the campaign: %s", joined)
	}
	if strings.Contains(joined, "<campaign>") {
		t.Fatalf("missing entry still carries the placeholder: %s", joined)
	}
}

// TestProbeMissingOnlyOracle pins the probe-axis clause entries in isolation
// (fresh closed plan = none; axis absent from the surface = one entry).
func TestProbeMissingOnlyOracle(t *testing.T) {
	root := oracles(t)
	a3 := at(t, root, "a3")
	withProbes(t, probeEnv{})
	closed := objAt(a3.A[0], "plan")
	surface := objAt(a3.A[0], "surface")
	sha := objStr(a3.A[0], "sha")
	got := probeMissing(closed, DivergenceOpts{Surface: &surface,
		CurrentIndexSha: &sha, Blanks: map[string]validation.Value{}})
	requireJSON(t, "fresh_closed missing", validation.VArr(got...),
		at(t, root, "a3_missing_only", "fresh_closed"))
	trimmed := objAt(a3.A[4], "surface")
	got = probeMissing(closed, DivergenceOpts{Surface: &trimmed,
		CurrentIndexSha: &sha, Blanks: map[string]validation.Value{}})
	requireJSON(t, "axis_absent missing", validation.VArr(got...),
		at(t, root, "a3_missing_only", "axis_absent"))
}

// TestDivergenceStatusForReadsCampaign pins the campaign-aware wrapper: it
// pulls surface/sha/blanks through the seam and defaults blanks to the store.
func TestDivergenceStatusForReadsCampaign(t *testing.T) {
	root := oracles(t)
	c := at(t, root, "a3").A[0]
	surface := objAt(c, "surface")
	sha := objAt(c, "sha")
	withProbes(t, probeEnv{surface: &surface, sha: &sha.S})
	camp := newCampaign(t, "dsf")
	got, err := DivergenceStatusFor(camp, objAt(c, "plan"), nil)
	if err != nil {
		t.Fatalf("divergence_status_for: %v", err)
	}
	requireJSON(t, "for", got, objAt(c, "out"))
}

// TestFakeAxisSurfaceBlockerOracle pins the fake's four-state blocker against
// the recorded probes.axis_surface_blocker outputs.
func TestFakeAxisSurfaceBlockerOracle(t *testing.T) {
	root := oracles(t)
	surface := objAt(at(t, root, "a3").A[0], "surface")
	want := at(t, root, "axis_blockers")
	for _, ax := range listOf(surface, "axes") {
		name := objStr(ax, "axis")
		variants := at(t, want, name)
		for _, kind := range []string{"none", "match", "wrong", "noreason"} {
			expected := objAt(variants, kind)
			var blank *validation.Value
			if kind != "none" {
				b := expected
				blank = &b
			}
			got := axisSurfaceBlocker(ax, blank)
			if expected.Kind == validation.Null {
				if got != "" {
					t.Fatalf("blocker(%s/%s) = %q, want none", name, kind, got)
				}
				continue
			}
			if got != expected.S {
				t.Fatalf("blocker(%s/%s) = %q, want %q", name, kind, got,
					expected.S)
			}
		}
	}
}

// TestFakeAnchorRefOracle pins the fake's anchor_ref over every recorded
// row/anchor pair.
func TestFakeAnchorRefOracle(t *testing.T) {
	withProbes(t, probeEnv{})
	refs, err := validation.ReadJson("testdata/anchor_refs.json")
	if err != nil {
		t.Fatalf("read anchor refs: %v", err)
	}
	surface, err := validation.ReadJson("testdata/probe_surface.json")
	if err != nil {
		t.Fatalf("read surface: %v", err)
	}
	index, err := validation.ReadJson("testdata/structural_index.json")
	if err != nil {
		t.Fatalf("read index: %v", err)
	}
	n := 0
	for _, row := range listOf(surface, "rows") {
		want := objAt(refs, objStr(row, "row_id"))
		if want.Kind != validation.Obj {
			continue
		}
		for _, anchor := range want.O {
			got, err := anchorRef(row, anchor.K, &index)
			if err != nil {
				t.Fatalf("anchor_ref(%s, %s): %v", objStr(row, "row_id"),
					anchor.K, err)
			}
			if got != anchor.V.S {
				t.Fatalf("anchor_ref(%s, %s) = %q, want %q",
					objStr(row, "row_id"), anchor.K, got, anchor.V.S)
			}
			n++
		}
	}
	if n < 20 {
		t.Fatalf("expected at least 20 anchor refs, checked %d", n)
	}
}
