package planner

import (
	"strings"
	"testing"

	"websec/internal/validation"
)

// pvFixtures loads the surface/index/plan triple the A3 oracle used.
func pvFixtures(t *testing.T) (validation.Value, validation.Value,
	validation.Value) {
	t.Helper()
	surface, err := validation.ReadJson("testdata/probe_surface.json")
	if err != nil {
		t.Fatalf("read surface: %v", err)
	}
	index, err := validation.ReadJson("testdata/structural_index.json")
	if err != nil {
		t.Fatalf("read index: %v", err)
	}
	plan, err := validation.ReadJson("testdata/plan_probe_rows.json")
	if err != nil {
		t.Fatalf("read plan: %v", err)
	}
	return surface, index, plan
}

// TestProbeLensViewAxesSplit pins the registered/present/missing split for a
// lens whose axis the surface carries and one it does not.
func TestProbeLensViewAxesSplit(t *testing.T) {
	surface, index, plan := pvFixtures(t)
	withProbes(t, probeEnv{surface: &surface, index: &index})
	view := probeLensView(plan, "L-03", DivergenceOpts{Surface: &surface})
	requireJSON(t, "axes", strArr(view.axes), jsonValue(t,
		`["enforcement-timing"]`))
	requireJSON(t, "present", strArr(view.present), jsonValue(t,
		`["enforcement-timing"]`))
	requireJSON(t, "missing axes", strArr(view.missingAxes),
		validation.VArr())
	// a surface that carries no axis at all: the lens reports the axis missing
	bare := jsonValue(t, `{"axes":[],"rows":[]}`)
	view = probeLensView(plan, "L-03", DivergenceOpts{Surface: &bare})
	if len(view.axes) == 0 {
		t.Fatalf("L-03 registers at least one axis")
	}
	if len(view.present) != 0 || len(view.missingAxes) != len(view.axes) {
		t.Fatalf("a lens with no surface axis must report all missing: %s",
			validation.CanonCompact(validation.VObj(
				kv("present", strArr(view.present)),
				kv("missing", strArr(view.missingAxes)))))
	}
	if view.counts != nil {
		t.Fatalf("no present axis means no counts")
	}
}

// TestProbeLensViewCounts pins the counts dict of a fully open axis: every
// ranked row is counted, none is dispositioned.
func TestProbeLensViewCounts(t *testing.T) {
	surface, index, plan := pvFixtures(t)
	withProbes(t, probeEnv{surface: &surface, index: &index})
	view := probeLensView(plan, "L-03", DivergenceOpts{Surface: &surface})
	if view.counts == nil {
		t.Fatalf("expected counts for a present axis")
	}
	c := *view.counts
	requireJSON(t, "rows", objAt(c, "rows"), validation.VInt(10))
	requireJSON(t, "dispositioned", objAt(c, "dispositioned"),
		validation.VInt(0))
	requireJSON(t, "open", objAt(c, "open"), validation.VInt(10))
	requireJSON(t, "closed", objAt(c, "closed"), validation.VBool(false))
	msg := objStr(c, "message")
	if !strings.HasPrefix(msg, "L-03 open — 0/10 rows dispositioned") {
		t.Fatalf("counts message = %q", msg)
	}
}

// TestProbeLensViewStaleDisposition pins the shape_sha gate: a disposition
// stamped against a different row shape is stale, not closed.
func TestProbeLensViewStaleDisposition(t *testing.T) {
	surface, index, plan := pvFixtures(t)
	withProbes(t, probeEnv{surface: &surface, index: &index})
	plan = deepCopy(t, plan)
	for i, p := range listOf(plan, "priorities") {
		if objStr(p, "id") != "Q-005" {
			continue
		}
		prov := objAt(p, "probe")
		prov.O = validation.SetOrAppend(prov.O, "shape_sha", validation.VStr("deadbeef"))
		p.O = validation.SetOrAppend(p.O, "probe", prov)
		p.O = validation.SetOrAppend(p.O, "status", validation.VStr("answered"))
		prios := listOf(plan, "priorities")
		prios[i] = p
		plan.O = validation.SetOrAppend(plan.O, "priorities", validation.VArr(prios...))
	}
	view := probeLensView(plan, "L-03", DivergenceOpts{Surface: &surface})
	c := *view.counts
	requireJSON(t, "stale", objAt(c, "stale"), validation.VInt(1))
	requireJSON(t, "dispositioned", objAt(c, "dispositioned"),
		validation.VInt(0))
	if !strings.Contains(objStr(c, "message"), "0/10 rows dispositioned") {
		t.Fatalf("message = %q", objStr(c, "message"))
	}
	found := false
	for _, iss := range view.issues {
		if strings.Contains(iss, "disposition is stale") {
			found = true
		}
	}
	if !found {
		t.Fatalf("stale row must raise an issue: %v", view.issues)
	}
}

// TestProbeLensViewRefreshHintNamesCampaign pins the refresh command a
// hand-loaded plan (no campaign_id of its own) produces: the campaign id comes
// from the caller, never a `<campaign>` literal.
func TestProbeLensViewRefreshHintNamesCampaign(t *testing.T) {
	surface, index, plan := pvFixtures(t)
	withProbes(t, probeEnv{surface: &surface, index: &index})
	plan = deepCopy(t, plan)
	plan.O = dropKey(plan.O, "campaign_id")
	staleSha := "0000000000000000"
	view := probeLensView(plan, "L-03", DivergenceOpts{Surface: &surface,
		CurrentIndexSha: &staleSha, CampaignID: "C-abc12345"})
	joined := strings.Join(view.issues, " ")
	if !strings.Contains(joined,
		"run `webv2 probes C-abc12345 run --emit`") {
		t.Fatalf("refresh hint must name the campaign: %v", view.issues)
	}
	if strings.Contains(joined, "<campaign>") {
		t.Fatalf("refresh hint still carries the placeholder: %v", view.issues)
	}
}

// TestLensProbeClosureMatchesView pins the internal/public pair: the exported
// closure is the view's counts, and both agree on the message.
func TestLensProbeClosureMatchesView(t *testing.T) {
	surface, index, plan := pvFixtures(t)
	withProbes(t, probeEnv{surface: &surface, index: &index})
	opts := DivergenceOpts{Surface: &surface}
	closure := lensProbeClosure(plan, "L-03", opts)
	view := probeLensView(plan, "L-03", opts)
	requireJSON(t, "closure == counts", *closure, *view.counts)
	pub := LensProbeClosure(plan, "L-03", opts)
	requireJSON(t, "public closure", *pub, *closure)
	if objStr(*closure, "message") == "" {
		t.Fatalf("closure message must not be empty")
	}
}

// TestProbeIndexIssuesStaleIndex pins the index-sha clause: a surface built
// against a different structural index reports the refresh command.
func TestProbeIndexIssuesStaleIndex(t *testing.T) {
	surface, index, _ := pvFixtures(t)
	withProbes(t, probeEnv{surface: &surface, index: &index})
	surface = deepCopy(t, surface)
	surface.O = validation.SetOrAppend(surface.O, "index_sha", validation.VStr("nope"))
	staleSha := "0000000000000000"
	opts := DivergenceOpts{Surface: &surface, CurrentIndexSha: &staleSha}
	issues := probeIndexIssues(surface, opts, "C-259d60d374",
		"run `webv2 probes C-259d60d374 run --emit`")
	if len(issues) == 0 {
		t.Fatalf("a mismatched index_sha must raise an issue")
	}
	joined := strings.Join(issues, " ")
	if !strings.Contains(joined, "run --emit") {
		t.Fatalf("issue must name the refresh command: %v", issues)
	}
}

// TestProbeCountsTailAndBlind pins the denominator arithmetic: rows stay in
// the total even when the quota left them in the tail, and the blind keys are
// summed from blind_total.
func TestProbeCountsTailAndBlind(t *testing.T) {
	surface, index, plan := pvFixtures(t)
	withProbes(t, probeEnv{surface: &surface, index: &index})
	c := *probeCounts(surface, DivergenceOpts{Surface: &surface}, "L-03",
		[]string{"enforcement-timing"}, 4, 6, 0, []string{})
	requireJSON(t, "rows", objAt(c, "rows"), validation.VInt(10))
	requireJSON(t, "emitted", objAt(c, "emitted"), validation.VInt(10))
	requireJSON(t, "tail", objAt(c, "tail"), validation.VInt(0))
	requireJSON(t, "blind", objAt(c, "blind"), validation.VInt(4))
	requireJSON(t, "dispositioned", objAt(c, "dispositioned"),
		validation.VInt(4))
	requireJSON(t, "open", objAt(c, "open"), validation.VInt(6))
	requireJSON(t, "closed", objAt(c, "closed"), validation.VBool(true))
	if msg := objStr(c, "message"); !strings.Contains(msg,
		"4/10 rows dispositioned, 0 in tail, 4 blind keys disclosed") {
		t.Fatalf("message = %q", msg)
	}
	_ = plan
}

// TestProbeCountsAttestedBlind pins blind_attested: a blank whose anchor_blind
// matches a disclosed blind key counts as attested.
func TestProbeCountsAttestedBlind(t *testing.T) {
	surface, index, _ := pvFixtures(t)
	withProbes(t, probeEnv{surface: &surface, index: &index})
	axis := surfaceAxis(surface, "enforcement-timing")
	blind := listOf(axis, "blind")
	if len(blind) == 0 {
		t.Fatalf("fixture axis must disclose a blind key")
	}
	key := objStr(blind[0], "key")
	opts := DivergenceOpts{Surface: &surface, Blanks: map[string]validation.Value{
		"enforcement-timing": validation.VObj(kv("anchor_blind",
			validation.VStr(key)))}}
	c := *probeCounts(surface, opts, "L-03", []string{"enforcement-timing"},
		0, 10, 0, []string{"still open"})
	requireJSON(t, "blind_attested", objAt(c, "blind_attested"),
		validation.VInt(1))
	requireJSON(t, "closed", objAt(c, "closed"), validation.VBool(false))
}
