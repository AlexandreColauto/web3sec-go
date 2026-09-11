package planner

import (
	"os"
	"path/filepath"
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

// TestCampaignIDForPlanFallback pins the hardening: a direct call whose plan
// carries no campaign_id and whose opts name no campaign has no id to render,
// and an empty id would leave a hole in the command the hint prints, so the
// documented metavariable stands in. No production path reaches this — every
// operator-facing caller goes through DivergenceStatusFor, which supplies the
// campaign — but a library caller must never get a broken command.
func TestCampaignIDForPlanFallback(t *testing.T) {
	plan := validation.VObj()
	if got := campaignIDForPlan(plan, DivergenceOpts{}); got != "<campaign>" {
		t.Fatalf("campaignIDForPlan = %q, want the metavariable fallback", got)
	}
	// the plan's own id, and the caller's, both still win over the fallback.
	withPlanID := validation.VObj(kv("campaign_id", validation.VStr("C-plan")))
	if got := campaignIDForPlan(withPlanID, DivergenceOpts{
		CampaignID: "C-opts"}); got != "C-plan" {
		t.Fatalf("plan id = %q, want C-plan", got)
	}
	if got := campaignIDForPlan(plan, DivergenceOpts{
		CampaignID: "C-opts"}); got != "C-opts" {
		t.Fatalf("caller id = %q, want C-opts", got)
	}
}

// noClassPlan is the recorded grandfather plan: one resolved lens and zero
// priorities, so the diversity clause is the only clause still open.
func noClassPlan(t *testing.T) validation.Value {
	t.Helper()
	for _, c := range at(t, oracles(t), "divergence").A {
		if objStr(c, "name") == "grandfather" {
			return deepCopy(t, objAt(c, "plan"))
		}
	}
	t.Fatalf("oracle case grandfather is missing")
	return validation.VNull()
}

// gateClosed is the gate's closed flag.
func gateClosed(v validation.Value) bool {
	b := objAt(v, "closed")
	return b.Kind == validation.Bool && b.B
}

// divWhat is the missing[] what-text for one subject ("" when absent).
func divWhat(v validation.Value, subject string) string {
	for _, m := range listOf(v, "missing") {
		if objStr(m, "subject") == subject {
			return objStr(m, "what")
		}
	}
	return ""
}

// TestDivergenceDiversityCountsCampaignFindings: the diversity clause stops
// being unsatisfiable when the CAMPAIGN's own findings already named the
// classes — the gate was demanding hand-patching even though the shapes were
// dispositioned by filing findings. Fewer than four classes stay open and the
// hint names both exits; four distinct canonical classes close the clause.
func TestDivergenceDiversityCountsCampaignFindings(t *testing.T) {
	plan := noClassPlan(t)
	open := DivergenceStatus(plan, DivergenceOpts{
		CampaignClasses: []string{"access-control", "reentrancy"}})
	if gateClosed(open) {
		t.Fatal("2 classes must stay open")
	}
	what := divWhat(open, "diversity")
	if !strings.Contains(what,
		"2 distinct bug class(es) named (access-control, reentrancy)") {
		t.Errorf("hint must count the campaign classes: %s", what)
	}
	if !strings.Contains(what, "or file findings naming them") {
		t.Errorf("hint = %s", what)
	}
	closedGate := DivergenceStatus(plan, DivergenceOpts{
		CampaignClasses: []string{"reentrancy", "access-control",
			"logic-error", "authorization", "logic-error"}})
	if !gateClosed(closedGate) {
		t.Fatalf("4 distinct canonical classes must close the diversity "+
			"clause; missing = %s",
			validation.CanonCompact(objAt(closedGate, "missing")))
	}
	if n := len(listOf(closedGate, "missing")); n != 0 {
		t.Errorf("missing = %s",
			validation.CanonCompact(objAt(closedGate, "missing")))
	}
	if n := len(listOf(closedGate, "named_classes")); n != 4 {
		t.Errorf("named_classes = %s",
			validation.CanonCompact(objAt(closedGate, "named_classes")))
	}
}

// TestDivergenceStatusPurePathHintUnchanged is the byte-stability control: a
// pure DivergenceStatus call (no CampaignClasses) counts nothing from the
// campaign, so it keeps the recorded pre-campaign hint verbatim and never
// promises a findings exit that this call cannot honor.
func TestDivergenceStatusPurePathHintUnchanged(t *testing.T) {
	plan := noClassPlan(t)
	got := DivergenceStatus(plan, DivergenceOpts{})
	const legacy = "0 distinct bug class(es) named (none); min 4 — " +
		"set priorities[].bug_class"
	if what := divWhat(got, "diversity"); what != legacy {
		t.Errorf("pure hint moved: %q", what)
	}
	// An empty (non-nil) CampaignClasses slice is the same situation the
	// wrapper hands over for a campaign with no findings: byte-identical too.
	empty := DivergenceStatus(plan, DivergenceOpts{
		CampaignClasses: []string{}})
	requireJSON(t, "empty campaign classes", empty, got)
}

// TestNamedClassesUnionsCampaignClasses pins the union: plan priorities plus
// the campaign's classes, deduped, empty strings dropped, sorted.
func TestNamedClassesUnionsCampaignClasses(t *testing.T) {
	plan := jsonValue(t, `{"priorities":[{"bug_class":"logic-error"},
	  {"bug_class":"logic-error"},{"question":"no class"}]}`)
	got := namedClasses(plan, []string{"reentrancy", "access-control",
		"reentrancy", ""})
	want := []string{"access-control", "logic-error", "reentrancy"}
	if validation.CanonCompact(strArr(got)) != validation.CanonCompact(
		strArr(want)) {
		t.Errorf("namedClasses = %v, want %v", got, want)
	}
}

// TestDivergenceStatusForCountsFindingsClasses pins the collection seam: the
// campaign-aware wrapper reads the campaign's stored findings through
// PB().CampaignBugClasses, keeps only classes the plan validator would accept
// and hands them to the diversity clause. A non-canonical class never counts,
// and losing a class re-opens the gate.
func TestDivergenceStatusForCountsFindingsClasses(t *testing.T) {
	withProbes(t, probeEnv{})
	plan := noClassPlan(t)
	camp := newCampaign(t, "cbg")
	writeFinding := func(id, class string) {
		t.Helper()
		body := `{"finding_id":"` + id + `","campaign_id":"` +
			camp.CampaignID + `","status":"HYPOTHESIS",` +
			`"root_cause":{"class":"` + class + `"}}`
		if err := os.WriteFile(filepath.Join(camp.FindingsDir, id+".json"),
			[]byte(body), 0o644); err != nil {
			t.Fatalf("write finding %s: %v", id, err)
		}
	}
	divOf := func() validation.Value {
		t.Helper()
		got, err := DivergenceStatusFor(camp, plan,
			map[string]validation.Value{})
		if err != nil {
			t.Fatalf("divergence_status_for: %v", err)
		}
		return got
	}
	writeFinding("F-0000000001", "logic-error")
	writeFinding("F-0000000002", "vibes-based") // non-canonical: never counts
	if div := divOf(); gateClosed(div) {
		t.Fatal("one canonical class must not close the gate")
	} else if n := len(listOf(div, "named_classes")); n != 1 {
		t.Errorf("non-canonical finding class counted: %s",
			validation.CanonCompact(objAt(div, "named_classes")))
	}
	writeFinding("F-0000000003", "access-control")
	writeFinding("F-0000000004", "reentrancy")
	writeFinding("F-0000000005", "authorization")
	closedGate := divOf()
	if !gateClosed(closedGate) {
		t.Fatalf("4 canonical finding classes must close the gate; "+
			"missing = %s",
			validation.CanonCompact(objAt(closedGate, "missing")))
	}
	if what := divWhat(closedGate, "diversity"); what != "" {
		t.Errorf("closed gate still carries a diversity entry: %s", what)
	}
	// negative control: drop one class and the gate re-opens.
	if err := os.Remove(filepath.Join(camp.FindingsDir,
		"F-0000000005.json")); err != nil {
		t.Fatalf("remove finding: %v", err)
	}
	if div := divOf(); gateClosed(div) {
		t.Fatal("3 canonical classes must re-open the diversity clause")
	}
}
