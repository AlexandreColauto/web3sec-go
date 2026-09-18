// golden_dispatch_test.go: the op table that replays a recorded Python call
// through the Go twin.
package orchestrator

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// realPath maps the oracle's <ROOT> placeholder back to the temp tree.
func realPath(root, s string) string {
	return strings.ReplaceAll(s, rootPlaceholder, root)
}

// strListOf converts a JSON array value into a Go slice.
func strListOf(v validation.Value) []string {
	out := []string{}
	if v.Kind == validation.Arr {
		for _, item := range v.A {
			out = append(out, item.S)
		}
	}
	return out
}

// dumpTree reads every file under root into a sorted path -> content map.
func dumpTree(root string) map[string]string {
	out := map[string]string{}
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return nil
		}
		out[filepath.ToSlash(rel)] = string(raw)
		return nil
	})
	return out
}

// supersededFiles reads artifacts/superseded/*.json as path -> content.
func supersededFiles(c *state.Campaign, root string) validation.Value {
	matches, _ := filepath.Glob(filepath.Join(c.ArtifactsDir, "superseded",
		"*.json"))
	sort.Strings(matches)
	out := []validation.KV{}
	for _, p := range matches {
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			continue
		}
		out = append(out, kvOf(filepath.ToSlash(rel), validation.VStr(string(raw))))
	}
	return validation.VObj(out...)
}

// ingestOptsOf reads the recorded ingest keyword tail.
func ingestOptsOf(args validation.Value) IngestOpts {
	return IngestOpts{
		Trajectory:      strAt(args, "trajectory"),
		Stage:           strAt(args, "stage"),
		Model:           strAt(args, "model"),
		AnswersPriority: strAt(args, "answers_priority"),
		PriorityOutcome: strAt(args, "priority_outcome"),
	}
}

// dispatchGolden runs one recorded op: the facade calls first, then the
// fixture ops that set the campaign up, then the test-only probes.
func dispatchGolden(t *testing.T, o *Orchestrator, c *state.Campaign,
	doc, step validation.Value, ids *idMap, root string) (validation.Value, error) {
	t.Helper()
	op := strAt(step, "op")
	args := validation.ObjAt(step, "args")
	if v, err, done := dispatchFacade(t, o, c, doc, op, args, ids, root); done {
		return v, err
	}
	if v, err, done := dispatchFixture(t, o, c, doc, op, args, ids); done {
		return v, err
	}
	if strings.HasPrefix(op, "next_actions@") {
		phase := strings.TrimPrefix(op, "next_actions@")
		if err := c.SetPhase(phase, "oracle"); err != nil {
			return validation.VNull(), err
		}
		return NextActions(c)
	}
	t.Fatalf("unknown op %q", op)
	return validation.VNull(), nil
}

// dispatchFacade handles the orchestrator's own methods.
func dispatchFacade(t *testing.T, o *Orchestrator, c *state.Campaign,
	doc validation.Value, op string, args validation.Value, ids *idMap,
	root string) (validation.Value, error, bool) {
	t.Helper()
	switch op {
	case "scope", "scope_result":
		v, err := o.Scope(realPath(root, strAt(args, "policy_path")))
		return v, err, true
	case "snapshot":
		opts := SnapshotOpts{}
		if cfg := validation.ObjAt(args, "config"); cfg.Kind != validation.Null {
			opts.Config = &cfg
		}
		v, err := o.Snapshot(realPath(root, strAt(args, "target")), opts)
		return v, err, true
	case "next_actions":
		if phase := strAt(args, "phase"); phase != "" {
			if err := c.SetPhase(phase, "oracle"); err != nil {
				return validation.VNull(), err, true
			}
		}
		v, err := NextActions(c)
		return v, err, true
	case "status", "status_verbose":
		v, err := o.Status(boolAt(args, "verbose"))
		return v, err, true
	case "plan_reachability":
		v, err := o.PlanReachability()
		return v, err, true
	case "triage_all":
		v, err := o.TriageAll()
		return v, err, true
	case "reproduction_queue":
		v, err := o.ReproductionQueue()
		return v, err, true
	case "independent_verification_queue":
		v, err := o.IndependentVerificationQueue()
		return v, err, true
	case "calibrate_all":
		v, err := o.CalibrateAll()
		return v, err, true
	case "chaining":
		v, err := o.Chaining()
		return v, err, true
	case "run_dedup":
		v, err := o.RunDedup()
		return v, err, true
	case "bounty_gate_all":
		v, err := o.BountyGateAll()
		return v, err, true
	case "build_structural_index":
		v, err := o.BuildStructuralIndex()
		return v, err, true
	}
	if v, err, done := dispatchFacadeInputs(o, doc, op, args, ids,
		root); done {
		return v, err, true
	}
	return dispatchPlan(t, o, c, op, args, root)
}

// dispatchFacadeInputs handles the facade methods that take or return
// finding-shaped input.
func dispatchFacadeInputs(o *Orchestrator, doc validation.Value, op string,
	args validation.Value, ids *idMap,
	root string) (validation.Value, error, bool) {
	switch op {
	case "critic_context":
		v, err := o.CriticContext()
		return v, err, true
	case "discovery_context":
		extra := strListOf(validation.ObjAt(args, "extra"))
		for i := range extra {
			extra[i] = realPath(root, extra[i])
		}
		v, err := o.DiscoveryContext(strAt(args, "stage"), extra)
		return v, err, true
	case "load_protocol_model":
		v, err := o.LoadProtocolModel(validation.ObjAt(doc, "model"))
		return v, err, true
	case "ingest", "ingest_answered", "ingest_orphaned":
		f, err := o.Ingest(validation.ObjAt(args, "payload"), ingestOptsOf(args))
		ids.note(f)
		return f, err, true
	case "verify_independently":
		v, err := o.VerifyIndependently(resolveFinding(args, ids),
			strAt(args, "exec_id"), strAt(args, "description"),
			strAt(args, "verifier"))
		return v, err, true
	}
	return validation.VNull(), nil, false
}

// dispatchPlan handles plan()'s recorded flavors and the file probes.
func dispatchPlan(t *testing.T, o *Orchestrator, c *state.Campaign, op string,
	args validation.Value, root string) (validation.Value, error, bool) {
	t.Helper()
	switch op {
	case "plan", "plan_clobber":
		v, err := o.Plan(validation.ObjAt(args, "plan"), validation.VNull(),
			boolAt(args, "rebuild"))
		return v, err, true
	case "plan_readonly":
		v, err := o.Plan(validation.VNull(), validation.VNull(),
			boolAt(args, "rebuild"))
		return v, err, true
	case "plan_rebuild":
		v, err := o.Plan(validation.VNull(), validation.ObjAt(args, "model"), true)
		return v, err, true
	case "plan_readonly_unchanged":
		before := dumpTree(root)
		if _, err := o.Plan(validation.VNull(), validation.VNull(),
			false); err != nil {
			return validation.VNull(), err, true
		}
		return validation.VBool(mapEqual(before, dumpTree(root))), nil, true
	case "plan_superseded_files":
		return supersededFiles(c, root), nil, true
	}
	return validation.VNull(), nil, false
}

// dispatchFixture handles the build-only ops that shape a campaign.
func dispatchFixture(t *testing.T, o *Orchestrator, c *state.Campaign,
	doc validation.Value, op string, args validation.Value,
	ids *idMap) (validation.Value, error, bool) {
	t.Helper()
	switch op {
	case "ingest_all":
		v, err := ingestAll(o, doc, ids)
		return v, err, true
	case "mutate_finding":
		v, err := mutateFinding(c, args, ids)
		return v, err, true
	case "set_stage":
		return validation.VNull(), c.SetStage(strAt(args, "stage"),
			strAt(args, "status"), validation.VStr(strAt(args, "note")),
			nil), true
	case "set_phase":
		return validation.VNull(), c.SetPhase(strAt(args, "phase"),
			strAt(args, "reason")), true
	}
	return validation.VNull(), nil, false
}

// ingestAll replays the recorded hypothesis list.
func ingestAll(o *Orchestrator, doc validation.Value,
	ids *idMap) (validation.Value, error) {
	out := []validation.Value{}
	for _, h := range validation.ObjAt(doc, "hypos").A {
		payload := copyObj(h)
		payload.O = dropKeys(payload.O, "trajectory", "stage")
		f, err := o.Ingest(payload, IngestOpts{
			Trajectory: strAt(h, "trajectory"),
			Stage:      strAt(h, "stage"),
		})
		if err != nil {
			return validation.VNull(), err
		}
		ids.note(f)
		out = append(out, f)
	}
	return validation.VArr(out...), nil
}

// resolveFinding maps a recorded finding reference (a relabelled id or a
// 1-based creation index) to this twin's own id.
func resolveFinding(args validation.Value, ids *idMap) string {
	if fid := strAt(args, "finding_id"); fid != "" {
		return ids.real(fid)
	}
	idx := int(intAt(args, "finding_index")) - 1
	if idx < 0 || idx >= len(ids.order) {
		return ""
	}
	return ids.order[idx]
}

// mutateFinding applies a recorded field patch to a created finding.
func mutateFinding(c *state.Campaign, args validation.Value,
	ids *idMap) (validation.Value, error) {
	fid := resolveFinding(args, ids)
	if fid == "" {
		return validation.VNull(), orchestrationError(
			"no such created finding: " + strAt(args, "finding_id"))
	}
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		return validation.VNull(), err
	}
	for _, kv := range validation.ObjAt(args, "fields").O {
		f.O = validation.SetOrAppend(f.O, kv.K, kv.V)
	}
	if err := findings.SaveFinding(c, &f); err != nil {
		return validation.VNull(), err
	}
	return f, nil
}

// dropKeys removes the named keys, keeping Python's insertion order.
func dropKeys(in []validation.KV, keys ...string) []validation.KV {
	drop := map[string]struct{}{}
	for _, k := range keys {
		drop[k] = struct{}{}
	}
	out := []validation.KV{}
	for _, kv := range in {
		if _, ok := drop[kv.K]; ok {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// mapEqual compares two path -> content trees.
func mapEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}
