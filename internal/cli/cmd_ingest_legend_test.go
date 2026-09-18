package cli

// tests/test_ingest_discoverability.py, CLI half: the enum legend contract,
// --answers-priority/--priority-outcome, the probe-row refusal, and the
// orphan log. The walker half (refs, map schemas, brute-force completeness,
// derivation from the schema file) lives in internal/validation.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/orchestrator"
	"websec/internal/planner"
	"websec/internal/state"
	"websec/internal/validation"
)

// t14bMinimal is the Python fixture MINIMAL payload.
const t14bMinimal = `{"title":"a test hypothesis for ingest discoverability",` +
	`"root_cause":{"class":"logic-error","description":"a logic-flow error in ` +
	`the redemption"},"attacker":{"profile":"arbitrary EOA","capabilities":[]}}`

// t14bPlannedCampaign is _planned_campaign: a campaign with a loaded plan
// (priorities come from the model).
func t14bPlannedCampaign(t *testing.T) (*state.Campaign, string, string) {
	t.Helper()
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestSeed(t, root, cid)
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	return c, root, cid
}

// t14bPayloadFile is _payload_file: MINIMAL on disk.
func t14bPayloadFile(t *testing.T, root string) string {
	t.Helper()
	return t14TestWrite(t, root, "payload.json", t14bMinimal)
}

// t14bPlan is _plan: the saved plan artifact, read raw.
func t14bPlan(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	plan, err := validation.ReadJson(
		filepath.Join(c.ArtifactsDir, "campaign_plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func t14bPriorities(t *testing.T, plan validation.Value) []validation.Value {
	t.Helper()
	prio := validation.ObjAt(plan, "priorities")
	if prio.Kind != validation.Arr || len(prio.A) == 0 {
		t.Fatalf("the fixture plan must queue priorities: %+v", prio)
	}
	return prio.A
}

func t14bEventTypes(t *testing.T, c *state.Campaign) []string {
	t.Helper()
	evs, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(evs))
	for _, e := range evs {
		out = append(out, validation.ObjStr(e, "type"))
	}
	return out
}

// Port of test_legend_order_is_deterministic_and_schema_ordered.
func TestLegendOrderIsDeterministicAndSchemaOrdered(t *testing.T) {
	_, _, first := run(t, "ingest", "--example")
	_, _, second := run(t, "ingest", "--example")
	legend := legendLines(first)
	if len(legend) < 20 {
		t.Fatalf("legend has only %d lines: %q", len(legend), first)
	}
	if strings.Join(legend, "\n") != strings.Join(legendLines(second), "\n") {
		t.Fatal("two runs rendered different legends")
	}
	if !strings.HasPrefix(legend[0], "status: ") ||
		!strings.HasPrefix(legend[1], "trajectory: ") ||
		!strings.HasPrefix(legend[2], "assumptions[]/type: ") {
		t.Fatalf("legend order = %q", legend[:3])
	}
	walker, err := validation.SchemaEnumLegend("finding")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(legend, "\n") != strings.Join(walker, "\n") {
		t.Fatalf("CLI legend != schema walker\n%v\n%v", legend, walker)
	}
}

// legendLines is `[ln for ln in err.splitlines() if ln.startswith("  ")]`
// with the two-space prefix stripped.
func legendLines(errS string) []string {
	out := []string{}
	for _, ln := range strings.Split(errS, "\n") {
		if strings.HasPrefix(ln, "  ") {
			out = append(out, ln[2:])
		}
	}
	return out
}

// Port of test_answers_priority_closes_the_question (3 outcomes).
func TestAnswersPriorityClosesTheQuestion(t *testing.T) {
	for _, outcome := range []string{"answered", "not-applicable",
		"deprioritized"} {
		t.Run(outcome, func(t *testing.T) {
			c, root, cid := t14bPlannedCampaign(t)
			qid := validation.ObjStr(t14bPriorities(t, t14bPlan(t, c))[0], "id")
			code, out, errS := run(t, "--root", root, "ingest", cid,
				"--json-file", t14bPayloadFile(t, root),
				"--answers-priority", qid, "--priority-outcome", outcome)
			if code != 0 {
				t.Fatalf("exit %d: %q", code, errS)
			}
			fid := strings.Fields(out)[1]
			prio := nextPriority(t, t14bPlan(t, c), qid)
			if validation.ObjStr(prio, "status") != outcome {
				t.Fatalf("status = %q, want %q", validation.ObjStr(prio, "status"),
					outcome)
			}
			if validation.ObjStr(prio, "closed_ref") != fid {
				t.Fatalf("closed_ref = %q, want %q", validation.ObjStr(prio,
					"closed_ref"), fid)
			}
			for _, typ := range t14bEventTypes(t, c) {
				if typ == "plan.answer_orphaned" {
					t.Fatal("no orphan log when the plan has the priority")
				}
			}
		})
	}
}

func nextPriority(t *testing.T, plan validation.Value, id string) validation.Value {
	t.Helper()
	for _, p := range validation.ObjAt(plan, "priorities").A {
		if validation.ObjStr(p, "id") == id {
			return p
		}
	}
	t.Fatalf("no priority %s in the plan", id)
	return validation.VNull()
}

// Port of test_invalid_priority_outcome_exits_2_naming_the_values.
func TestInvalidPriorityOutcomeExits2NamingTheValues(t *testing.T) {
	c, root, cid := t14bPlannedCampaign(t)
	qid := validation.ObjStr(t14bPriorities(t, t14bPlan(t, c))[0], "id")
	code, out, errS := run(t, "--root", root, "ingest", cid,
		"--json-file", t14bPayloadFile(t, root),
		"--answers-priority", qid, "--priority-outcome", "bogus")
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	if !strings.Contains(errS, "invalid choice") {
		t.Fatalf("stderr = %q", errS)
	}
	for _, allowed := range []string{"answered", "not-applicable",
		"deprioritized"} {
		if !strings.Contains(errS, allowed) {
			t.Fatalf("stderr must name %q: %q", allowed, errS)
		}
	}
}

// t14bProbePriority is _probe_priority: stamp one plan priority as a probe
// row (the shape `probes --emit` writes).
func t14bProbePriority(t *testing.T, c *state.Campaign, plan validation.Value,
	priorityID, probeID, rowID string) validation.Value {
	t.Helper()
	prios := []validation.Value{}
	var stamped validation.Value
	for _, p := range validation.ObjAt(plan, "priorities").A {
		if validation.ObjStr(p, "id") == priorityID {
			p = setObjFieldCLI(p, "probe", validation.VObj(
				kvT("row_id", validation.VStr(rowID)),
				kvT("probe_id", validation.VStr(probeID)),
				kvT("axis", validation.VStr("liveness")),
				kvT("surface_sha", validation.VStr("deadbeef")),
				kvT("shape_sha", validation.VStr("0123456789abcdef"))))
			stamped = p
		}
		prios = append(prios, p)
	}
	if stamped.Kind != validation.Obj {
		t.Fatalf("no priority %s", priorityID)
	}
	if _, err := planner.SavePlan(c, setObjFieldCLI(plan, "priorities",
		validation.VArr(prios...))); err != nil {
		t.Fatal(err)
	}
	return stamped
}

// Port of test_probe_row_refusal_emits_an_executable_command: the refusal
// prints the remedy, so the remedy has to run.
func TestProbeRowRefusalEmitsAnExecutableCommand(t *testing.T) {
	c, root, cid := t14bPlannedCampaign(t)
	plan := t14bPlan(t, c)
	pid := validation.ObjStr(t14bPriorities(t, plan)[0], "id")
	t14bProbePriority(t, c, plan, pid, "trust-assumption", "0123456789")
	// campaign_surface reads this artifact raw: a minimal row is enough for
	// the anchor validation to fire. The probes module is unported (P3), so
	// the artifact is surfaced through the planner seam exactly as the real
	// module would surface it.
	surface := t14bWriteSurface(t, c, `{"rows":[{"row_id":"0123456789",`+
		`"probe":"trust-assumption","actor":"arbitrary EOA"}]}`)
	t14bWithProbes(t, surface)
	code, _, errS := run(t, "--root", root, "ingest", cid,
		"--json-file", t14bPayloadFile(t, root), "--answers-priority", pid)
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	m := regexp.MustCompile("`(webv2 answered [^`]*)`").FindStringSubmatch(errS)
	if m == nil {
		t.Fatalf("the refusal must print a remedy: %q", errS)
	}
	argv := strings.Fields(m[1])[1:]
	for _, a := range argv {
		if a == "--status" {
			t.Fatal("the outcome is positional, not --status")
		}
	}
	if argv[1] != cid || argv[2] != pid || argv[3] != "answered" {
		t.Fatalf("remedy argv = %v", argv)
	}
	// replay the cockpit's own advice with real values
	for i, a := range argv {
		switch a {
		case "<field>":
			argv[i] = "actor"
		case "<why>":
			argv[i] = "probe row safe"
		case "<you>":
			argv[i] = "pytest"
		}
	}
	args := append([]string{"--root", root}, argv...)
	if code2, _, err2 := run(t, args...); code2 != 0 {
		t.Fatalf("the emitted remedy exited %d: %q", code2, err2)
	}
	saved, err := planner.LoadPlanReadonly(c)
	if err != nil {
		t.Fatal(err)
	}
	closed := nextPriority(t, saved, pid)
	if validation.ObjStr(closed, "status") != "answered" {
		t.Fatalf("status = %q", validation.ObjStr(closed, "status"))
	}
	anchor := validation.ObjAt(validation.ObjAt(closed, "probe"), "anchor")
	if validation.ObjStr(anchor, "field") != "actor" {
		t.Fatalf("probe anchor = %+v", anchor)
	}
}

// Port of test_probe_row_priority_exits_2_before_the_ingest.
func TestProbeRowPriorityExits2BeforeTheIngest(t *testing.T) {
	c, root, cid := t14bPlannedCampaign(t)
	plan := t14bPlan(t, c)
	pid := validation.ObjStr(t14bPriorities(t, plan)[0], "id")
	t14bProbePriority(t, c, plan, pid, "reentrancy", "0123456789")
	before := dirNames(t, c.FindingsDir)
	code, out, errS := run(t, "--root", root, "ingest", cid,
		"--json-file", t14bPayloadFile(t, root), "--answers-priority", pid)
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	if !strings.Contains(errS, pid) || !strings.Contains(errS, "anchor") {
		t.Fatalf("stderr = %q", errS)
	}
	if got := dirNames(t, c.FindingsDir); strings.Join(got, ",") !=
		strings.Join(before, ",") {
		t.Fatalf("a partial write landed: %v -> %v", before, got)
	}
	for _, typ := range t14bEventTypes(t, c) {
		if typ == "finding.ingested" || typ == "plan.priority_status" {
			t.Fatalf("event %s must not be logged on refusal", typ)
		}
	}
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(ents))
	for _, e := range ents {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

// Port of test_example_does_not_silently_ignore_priority_outcome.
func TestExampleDoesNotSilentlyIgnorePriorityOutcome(t *testing.T) {
	code, out, errS := run(t, "ingest", "--example",
		"--priority-outcome", "answered")
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.Contains(errS, "--answers-priority") {
		t.Fatalf("stderr = %q", errS)
	}
	if out != "" {
		t.Fatalf("no example payload may be emitted: %q", out)
	}
}

// Port of test_unknown_priority_without_a_plan_keeps_the_orphan_log.
func TestUnknownPriorityWithoutAPlanKeepsTheOrphanLog(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "ingest", cid,
		"--json-file", t14bPayloadFile(t, root),
		"--answers-priority", "Q-999")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	evs, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	orphans := []validation.Value{}
	for _, e := range evs {
		if validation.ObjStr(e, "type") == "plan.answer_orphaned" {
			orphans = append(orphans, e)
		}
	}
	if len(orphans) != 1 {
		t.Fatalf("orphan events = %d, want 1", len(orphans))
	}
	if validation.ObjStr(orphans[0], "ref") != "Q-999" {
		t.Fatalf("ref = %q", validation.ObjStr(orphans[0], "ref"))
	}
	if validation.ObjStr(validation.ObjAt(orphans[0], "data"), "finding") !=
		strings.Fields(out)[1] {
		t.Fatalf("orphan data = %+v", orphans[0])
	}
}

// Port of test_unknown_priority_with_a_plan_is_reported_not_swallowed.
func TestUnknownPriorityWithAPlanIsReportedNotSwallowed(t *testing.T) {
	_, root, cid := t14bPlannedCampaign(t)
	code, out, errS := run(t, "--root", root, "ingest", cid,
		"--json-file", t14bPayloadFile(t, root),
		"--answers-priority", "Q-999")
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	if !strings.Contains(errS, "Q-999") {
		t.Fatalf("stderr = %q", errS)
	}
}

// Port of test_flags_absent_leave_the_api_defaults_alone.
func TestFlagsAbsentLeaveTheAPIDefaultsAlone(t *testing.T) {
	c, root, cid := t14bPlannedCampaign(t)
	before := validation.CanonCompact(t14bPlan(t, c))
	code, _, errS := run(t, "--root", root, "ingest", cid,
		"--json-file", t14bPayloadFile(t, root))
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if got := validation.CanonCompact(t14bPlan(t, c)); got != before {
		t.Fatal("the plan changed without --answers-priority")
	}
	for _, typ := range t14bEventTypes(t, c) {
		if strings.HasPrefix(typ, "plan.answer") {
			t.Fatalf("event %s logged without --answers-priority", typ)
		}
	}
	// the library default is unchanged: outcome defaults to "answered"
	root2 := mkroot(t)
	cid2 := initOne(t, root2)
	c2, err := state.Open(root2, cid2)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := validation.ParseOrdered([]byte(t14bMinimal))
	if err != nil {
		t.Fatal(err)
	}
	f, err := orchestrator.New(c2).Ingest(payload, orchestrator.IngestOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(f, "status") != "HYPOTHESIS" {
		t.Fatalf("library status = %q", validation.ObjStr(f, "status"))
	}
	loaded, err := findings.LoadFinding(c2, validation.ObjStr(f, "finding_id"))
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(loaded, "status") != "HYPOTHESIS" {
		t.Fatalf("on-disk status = %q", validation.ObjStr(loaded, "status"))
	}
}

// t14bWriteSurface writes probe_surface.json and returns it parsed.
func t14bWriteSurface(t *testing.T, c *state.Campaign,
	doc string) validation.Value {
	t.Helper()
	path := filepath.Join(c.ArtifactsDir, "probe_surface.json")
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	surface, err := validation.ReadJson(path)
	if err != nil {
		t.Fatal(err)
	}
	return surface
}

// t14bWithProbes installs the probes seam (P3 unported) for one test: the
// surface, the trust-assumption registry row, and the anchor derivation.
func t14bWithProbes(t *testing.T, surface validation.Value) {
	t.Helper()
	anchors := []string{"actor", "asserter", "guard"}
	planner.SetProbes(planner.ProbesAPI{
		CampaignSurface: func(*state.Campaign) (*validation.Value, error) {
			s := surface
			return &s, nil
		},
		Probes: map[string]planner.ProbeSpec{
			"trust-assumption": {Anchors: &anchors},
		},
		AnchorAllowed: func(probeID, anchor string) bool {
			return probeID == "trust-assumption" && anchor == "actor"
		},
		RowAnchorValue: func(row validation.Value,
			anchor string) (validation.Value, error) {
			return validation.ObjAt(row, anchor), nil
		},
		AnchorRef: func(row validation.Value, anchor string,
			index *validation.Value) (string, error) {
			return "probe_surface.json#" + validation.ObjStr(row, "row_id") + "#" +
				anchor, nil
		},
		RowShapeSha: func(validation.Value) string {
			return "0123456789abcdef"
		},
	})
	t.Cleanup(func() { planner.SetProbes(planner.ProbesAPI{}) })
}
