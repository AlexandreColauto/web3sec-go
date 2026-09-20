package planner

import (
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// maSurface loads the probe surface + index the mark_answered oracle used.
func maSurface(t *testing.T) (*validation.Value, *validation.Value) {
	t.Helper()
	surface, err := validation.ReadJson("testdata/probe_surface.json")
	if err != nil {
		t.Fatalf("read surface: %v", err)
	}
	index, err := validation.ReadJson("testdata/structural_index.json")
	if err != nil {
		t.Fatalf("read index: %v", err)
	}
	return &surface, &index
}

// maPlan loads one of the two recorded plans.
func maPlan(t *testing.T, name string) validation.Value {
	t.Helper()
	v, err := validation.ReadJson("testdata/" + name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return v
}

// maOpts is the case's keyword tail as AnsweredOpts.
func maOpts(t *testing.T, c validation.Value) AnsweredOpts {
	t.Helper()
	kw := validation.ObjAt(c, "kw")
	o := AnsweredOpts{}
	if r := validation.ObjAt(kw, "reason"); r.Kind == validation.Str {
		o.Reason = &r.S
	}
	if r := validation.ObjAt(kw, "ref"); r.Kind == validation.Str {
		o.Ref = &r.S
	}
	if a := validation.ObjAt(kw, "anchor"); a.Kind == validation.Str {
		o.Anchor = &a.S
	}
	// morph §6.1/§7.1: the recorded oracle's anchor_ok case prices the
	// enforcement-timing row's interim window, the way every high-risk
	// closure of one now has to.
	if v := validation.ObjAt(kw, "interim"); v.Kind == validation.Str {
		o.Interim = &v.S
	}
	return o
}

// TestMarkAnsweredOracle pins all nine recorded mark_answered cases: the A4
// anchor enforcement (missing, wrong, non-enum, non-probe, no surface), the
// blocked non-disposition, reopening, and the unknown-priority KeyError.
func TestMarkAnsweredOracle(t *testing.T) {
	root := oracles(t)
	t.Setenv("WEBV2_NOW", "2026-09-09T12:00:00.000000+00:00")
	surface, index := maSurface(t)
	openPlan := maPlan(t, "plan_probe_rows.json")
	closedPlan := maPlan(t, "plan_probe_closed.json")
	cases := at(t, root, "mark_answered", "cases")
	if cases.Kind != validation.Arr || len(cases.A) != 9 {
		t.Fatalf("expected 9 mark_answered cases, got %v", cases.Kind)
	}
	for _, c := range cases.A {
		name := validation.ObjStr(c, "name")
		env := probeEnv{surface: surface, index: index}
		if name == "no_surface" {
			env.surface = nil
		}
		withProbes(t, env)
		camp := newCampaign(t, "ma-"+name)
		plan := deepCopy(t, openPlan)
		if name == "reopen_clears_anchor" {
			plan = deepCopy(t, closedPlan)
		}
		plan, err := MarkAnswered(camp, plan, validation.ObjStr(c, "pid"),
			validation.ObjStr(c, "outcome"), maOpts(t, c))
		wantErr := validation.ObjAt(c, "error")
		if name == "no_surface" {
			// The recording carries Python's uncopyable `<campaign>`
			// literal; the port deliberately names the campaign, so the
			// expectation is rewritten to the id in hand while the rest
			// of the recorded message stays pinned.
			wantErr = campaignNamed(t, wantErr, camp.CampaignID)
		}
		if wantErr.Kind != validation.Null {
			requireErr(t, name, err, wantErr)
			continue
		}
		if err != nil {
			t.Fatalf("%s: unexpected error %v", name, err)
		}
		requireJSON(t, name+"/plan", plan, validation.ObjAt(c, "after"))
		checkPlanEvents(t, name, camp, c)
	}
}

// checkPlanEvents pins the plan.priority_status log row a successful
// mark_answered emits (status/reason/ref/actor + the anchor record).
func checkPlanEvents(t *testing.T, name string, camp *state.Campaign,
	c validation.Value) {
	t.Helper()
	events := at(t, c, "events")
	want := validation.VNull()
	for _, e := range events.A {
		if validation.ObjStr(e, "type") == "plan.priority_status" {
			want = e
		}
	}
	if want.Kind == validation.Null {
		t.Fatalf("%s: oracle recorded no plan.priority_status event", name)
	}
	got, err := camp.Events()
	if err != nil {
		t.Fatalf("%s: events: %v", name, err)
	}
	found := false
	for _, e := range got {
		if validation.ObjStr(e, "type") != "plan.priority_status" {
			continue
		}
		found = true
		requireJSON(t, name+"/event data", validation.ObjAt(e, "data"), validation.ObjAt(want, "data"))
		requireJSON(t, name+"/event ref", validation.ObjAt(e, "ref"), validation.ObjAt(want, "ref"))
	}
	if !found {
		t.Fatalf("%s: no plan.priority_status event was logged", name)
	}
}

// TestMarkAnsweredReopenDropsAnchor pins the reopening arm: closure
// provenance and the probe anchor are removed, and the log row carries no
// anchor key.
func TestMarkAnsweredReopenDropsAnchor(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-09-09T12:00:00.000000+00:00")
	surface, index := maSurface(t)
	withProbes(t, probeEnv{surface: surface, index: index})
	camp := newCampaign(t, "ma-reopen")
	plan := maPlan(t, "plan_probe_closed.json")
	plan, err := MarkAnswered(camp, plan, "Q-005", "open", AnsweredOpts{
		Reason: strPtr("reopening to re-check")})
	if err != nil {
		t.Fatalf("mark_answered: %v", err)
	}
	p := probePriority(t, plan, "Q-005")
	for _, k := range []string{"closed_reason", "closed_ref", "closed_at",
		"closed_by"} {
		if hasKey(p, k) {
			t.Fatalf("reopening left %s on the priority", k)
		}
	}
	if hasKey(validation.ObjAt(p, "probe"), "anchor") {
		t.Fatalf("reopening left probe.anchor in place")
	}
}

// TestMarkAnsweredBlockedIsNotDisposition pins that `blocked` needs no anchor
// even on a probe row (A3: blocked is not a decision to stop looking).
func TestMarkAnsweredBlockedIsNotDisposition(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-09-09T12:00:00.000000+00:00")
	surface, index := maSurface(t)
	withProbes(t, probeEnv{surface: surface, index: index})
	camp := newCampaign(t, "ma-blocked")
	plan, err := MarkAnswered(camp, maPlan(t, "plan_probe_rows.json"), "Q-005",
		"blocked", AnsweredOpts{Reason: strPtr("blocked by the harness")})
	if err != nil {
		t.Fatalf("mark_answered blocked: %v", err)
	}
	p := probePriority(t, plan, "Q-005")
	requireJSON(t, "status", validation.ObjAt(p, "status"), validation.VStr("blocked"))
	if hasKey(validation.ObjAt(p, "probe"), "anchor") {
		t.Fatalf("blocked must not record an anchor")
	}
}

// probePriority finds one priority by id.
func probePriority(t *testing.T, plan validation.Value, pid string) validation.Value {
	t.Helper()
	for _, p := range listOf(plan, "priorities") {
		if validation.ObjStr(p, "id") == pid {
			return p
		}
	}
	t.Fatalf("priority %s not in plan", pid)
	return validation.VNull()
}

// strPtr is a *string helper.
func strPtr(s string) *string { return &s }

// campaignNamed rewrites the recorded oracle's `<campaign>` placeholder to the
// campaign id the port names, keeping the rest of the recorded message pinned.
func campaignNamed(t *testing.T, want validation.Value,
	cid string) validation.Value {
	t.Helper()
	return validation.VObj(
		kv("type", validation.ObjAt(want, "type")),
		kv("msg", validation.VStr(strings.Replace(validation.ObjStr(want, "msg"),
			"<campaign>", cid, 1))),
	)
}

// TestMarkAnsweredNoSurfaceHintNamesCampaign pins the hint an operator sees
// when a probe-row disposition has no surface to check against: the campaign
// id in hand, not Python's uncopyable `<campaign>` literal.
func TestMarkAnsweredNoSurfaceHintNamesCampaign(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-09-09T12:00:00.000000+00:00")
	withProbes(t, probeEnv{})
	camp := newCampaign(t, "ma-no-surface-hint")
	_, err := MarkAnswered(camp, maPlan(t, "plan_probe_rows.json"), "Q-005",
		"answered", AnsweredOpts{Reason: strPtr("checked by hand"),
			Anchor: strPtr("consumer")})
	if err == nil {
		t.Fatalf("a disposition with no probe surface must be an error")
	}
	want := "priority Q-005 cites probe row '81dfad6492' but the campaign " +
		"has no probe surface — run `webv2 probes " + camp.CampaignID +
		" run` first"
	if got := err.Error(); got != want {
		t.Fatalf("hint mismatch\n got: %q\nwant: %q", got, want)
	}
	if strings.Contains(err.Error(), "<campaign>") {
		t.Fatalf("hint still carries the placeholder: %q", err.Error())
	}
}

// TestMarkAnsweredAbsentRowHintNamesCampaign pins the other disposition error:
// the cited row is not in the current surface, and the re-emit command names
// the campaign id.
func TestMarkAnsweredAbsentRowHintNamesCampaign(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-09-09T12:00:00.000000+00:00")
	surface, index := maSurface(t)
	withProbes(t, probeEnv{surface: surface, index: index})
	camp := newCampaign(t, "ma-absent-row-hint")
	plan := deepCopy(t, maPlan(t, "plan_probe_rows.json"))
	for i, p := range listOf(plan, "priorities") {
		if validation.ObjStr(p, "id") != "Q-005" {
			continue
		}
		prov := validation.ObjAt(p, "probe")
		prov.O = validation.SetOrAppend(prov.O, "row_id",
			validation.VStr("ffffffffffff"))
		p.O = validation.SetOrAppend(p.O, "probe", prov)
		prios := listOf(plan, "priorities")
		prios[i] = p
		plan.O = validation.SetOrAppend(plan.O, "priorities",
			validation.VArr(prios...))
	}
	_, err := MarkAnswered(camp, plan, "Q-005", "answered", AnsweredOpts{
		Reason: strPtr("checked by hand"), Anchor: strPtr("consumer")})
	if err == nil {
		t.Fatalf("a row absent from the surface must be an error")
	}
	want := "probe row 'ffffffffffff' is not in the current surface — " +
		"re-run `webv2 probes " + camp.CampaignID + " run --emit`"
	if got := err.Error(); got != want {
		t.Fatalf("hint mismatch\n got: %q\nwant: %q", got, want)
	}
	if strings.Contains(err.Error(), "<campaign>") {
		t.Fatalf("hint still carries the placeholder: %q", err.Error())
	}
}

// TestSiblingRescanOracle pins the DISPROVED-side mirror: a lifecycle finding
// spawns a sibling priority, --adjacent-clear logs instead, and a missing or
// whitespace adjacent raises the Python message.
func TestSiblingRescanOracle(t *testing.T) {
	root := oracles(t)
	t.Setenv("WEBV2_NOW", "2026-09-09T12:00:00.000000+00:00")
	cases := at(t, root, "sibling_rescan")
	if cases.Kind != validation.Arr || len(cases.A) != 5 {
		t.Fatalf("expected 5 sibling_rescan cases, got %v", cases.Kind)
	}
	addPlan := validation.ObjAt(cases.A[0], "plan")
	camp := pinnedCampaign(t, "sb", addPlan)
	writeModel(t, camp, jsonValue(t, `{"protocol_id":"sib","name":"Sib Fixture",
		"contracts":[{"name":"L1Gateway","path":"a.sol",
			"entry_points":["deposit","finalizeWithdrawal"]},
			{"name":"L2Gateway","path":"b.sol",
			"entry_points":["withdraw","drop"]}],
		"actors":[],"assets":[],"relations":[],
		"state_machines":[{"name":"rollup","states":[{"id":"open"}],
			"transitions":[{"from":"open","to":"fin","trigger":"finalize"}]}]}`))
	plan, err := DefaultPlanFromModel(camp, ModelOrEmpty(camp))
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	if _, err := SavePlan(camp, plan); err != nil {
		t.Fatalf("save plan: %v", err)
	}
	lcFinding := jsonValue(t, `{"finding_id":"F-001","status":"DISPROVED",
		"affected":[{"contract":"L1Gateway"},{"contract":"L2Gateway"}],
		"root_cause":{"class":"logic-error"}}`)
	pid, err := SiblingRescan(camp, lcFinding, SiblingOpts{
		Adjacent: "the other root in the same struct"})
	if err != nil {
		t.Fatalf("sibling_rescan add: %v", err)
	}
	requirePID(t, "add pid", pid, validation.ObjAt(cases.A[0], "pid"))
	requireJSON(t, "add plan", mustReadPlan(t, camp), validation.ObjAt(cases.A[0], "plan"))
	pid, err = SiblingRescan(camp, lcFinding, SiblingOpts{Clear: true,
		Reason: strPtr("sibling already checked")})
	if err != nil {
		t.Fatalf("sibling_rescan clear: %v", err)
	}
	requirePID(t, "clear pid", pid, validation.ObjAt(cases.A[1], "pid"))
	requireJSON(t, "clear plan", mustReadPlan(t, camp), validation.ObjAt(cases.A[1], "plan"))
	_, err = SiblingRescan(camp, lcFinding, SiblingOpts{})
	requireErr(t, "no_adjacent", err, validation.ObjAt(cases.A[2], "error"))
	noop := jsonValue(t, `{"finding_id":"F-009","status":"DISPROVED",
		"affected":[{"contract":"NoSuchContract"}],
		"root_cause":{"class":"logic-error"}}`)
	pid, err = SiblingRescan(camp, noop, SiblingOpts{})
	if err != nil {
		t.Fatalf("sibling_rescan noop: %v", err)
	}
	requirePID(t, "noop pid", pid, validation.ObjAt(cases.A[3], "pid"))
	requireJSON(t, "noop plan", mustReadPlan(t, camp), validation.ObjAt(cases.A[3], "plan"))
	ws := jsonValue(t, `{"finding_id":"F-010","status":"DISPROVED",
		"affected":[{"contract":"L1Gateway"},{"contract":"L2Gateway"}],
		"root_cause":{"class":"logic-error"}}`)
	_, err = SiblingRescan(camp, ws, SiblingOpts{Adjacent: "   "})
	requireErr(t, "whitespace_adjacent", err, validation.ObjAt(cases.A[4], "error"))
}

// TestSiblingRescanSkipsExistingPriorityID pins the id-collision loop: with
// one priority named Q-002, len+1 = Q-002 is taken, so the sibling becomes
// Q-003 (Python: n += 1 until free).
func TestSiblingRescanSkipsExistingPriorityID(t *testing.T) {
	camp := portSibSetup(t)
	plan := mustReadPlan(t, camp)
	one := jsonValue(t, `{"budget_class":"cheap","bug_class":"logic-error",
		"components":[],"id":"Q-002","invariant_ids":[],
		"question":"already there, keep this row","recommended_stages":[],
		"required_context":[],"risk":0.5,"status":"open",
		"trajectories":["code"]}`)
	plan.O = validation.SetOrAppend(plan.O, "priorities", validation.VArr(one))
	if _, err := SavePlan(camp, plan); err != nil {
		t.Fatalf("save plan: %v", err)
	}
	pid, err := SiblingRescan(camp, portLCFinding(t), SiblingOpts{
		Adjacent: "the other root in the same struct"})
	if err != nil {
		t.Fatalf("sibling_rescan: %v", err)
	}
	requirePID(t, "collision pid", pid, validation.VStr("Q-003"))
	after := mustReadPlan(t, camp)
	if n := len(listOf(after, "priorities")); n != 2 {
		t.Fatalf("expected 2 priorities, got %d", n)
	}
}

// requirePID compares a returned pid ("" = Python None) with the oracle.
func requirePID(t *testing.T, label, got string, want validation.Value) {
	t.Helper()
	if want.Kind == validation.Null {
		if got != "" {
			t.Fatalf("%s: got %q, want None", label, got)
		}
		return
	}
	if got != want.S {
		t.Fatalf("%s: got %q, want %q", label, got, want.S)
	}
}

// mustReadPlan loads the campaign's current plan from disk.
func mustReadPlan(t *testing.T, camp *state.Campaign) validation.Value {
	t.Helper()
	plan, err := LoadPlanReadonly(camp)
	if err != nil {
		t.Fatalf("load plan readonly: %v", err)
	}
	return plan
}

// TestSiblingRescanClearLogs pins the clear arm's log row (reason/actor/
// families) and that the plan is untouched.
func TestSiblingRescanClearLogs(t *testing.T) {
	camp := newCampaign(t, "sb2")
	writeModel(t, camp, jsonValue(t, `{"contracts":[
		{"name":"L1Gateway","entry_points":["deposit"]},
		{"name":"L2Gateway","entry_points":["withdraw"]}]}`))
	plan, err := DefaultPlanFromModel(camp, ModelOrEmpty(camp))
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	if _, err := SavePlan(camp, plan); err != nil {
		t.Fatalf("save plan: %v", err)
	}
	finding := jsonValue(t, `{"finding_id":"F-777","status":"DISPROVED",
		"affected":[{"contract":"L1Gateway"}]}`)
	pid, err := SiblingRescan(camp, finding, SiblingOpts{Clear: true,
		Reason: strPtr("checked by hand"), Actor: "tester"})
	if err != nil {
		t.Fatalf("sibling_rescan clear: %v", err)
	}
	if pid != "" {
		t.Fatalf("clear returned pid %q", pid)
	}
	events, err := camp.Events()
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	last := events[len(events)-1]
	requireJSON(t, "clear event type", validation.ObjAt(last, "type"),
		validation.VStr("plan.sibling_cleared"))
	requireJSON(t, "clear event data", validation.ObjAt(last, "data"),
		jsonValue(t, `{"reason":"checked by hand","actor":"tester",
			"families":["deposit"]}`))
	requireJSON(t, "clear event ref", validation.ObjAt(last, "ref"), validation.VStr("F-777"))
}
