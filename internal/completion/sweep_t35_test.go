package completion

// T35 testmap re-triage: tests/test_plan_lenses.py's divergence-gate rows —
// the discovery proof blocks on an open lens, blocks on diversity, passes when
// the gate is closed, and a waiver removes the block.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/planner"
	"websec/internal/state"
	"websec/internal/validation"
)

// t35MorphModel is tests/test_plan_lenses.py MODEL.
func t35MorphModel() validation.Value {
	return validation.VObj(
		kv("protocol_id", validation.VStr("morph-l2")),
		kv("name", validation.VStr("Morph L2")),
		kv("contracts", validation.VArr(validation.VObj(
			kv("name", validation.VStr("Rollup")),
			kv("path", validation.VStr("contracts/l2/Rollup.sol")),
			kv("role", validation.VStr("core")),
			kv("in_scope", validation.VBool(true)),
			kv("entry_points", validation.VArr(validation.VStr("commitBatch"),
				validation.VStr("finalizeBatch")))))),
		kv("state_machines", validation.VArr(validation.VObj(
			kv("id", validation.VStr("rollup-lifecycle")),
			kv("transitions", validation.VArr(validation.VStr("commit"),
				validation.VStr("challenge"),
				validation.VStr("finalize")))))))
}

// t35LensCampaign is _campaign_with_model.
func t35LensCampaign(t *testing.T) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "Morph L2", state.InitOpts{
		CampaignID: "C-lens1234"})
	if err != nil {
		t.Fatal(err)
	}
	model := t35MorphModel()
	model.O = t35Set(model.O, "state_machines", validation.VArr(
		validation.VObj(
			kv("name", validation.VStr("rollup-lifecycle")),
			kv("states", validation.VArr(validation.VObj(
				kv("id", validation.VStr("open"))))),
			kv("transitions", validation.VArr(validation.VObj(
				kv("from", validation.VStr("open")),
				kv("to", validation.VStr("finalized")),
				kv("trigger", validation.VStr("finalize"))))))))
	model.O = append(model.O,
		kv("actors", validation.VArr()),
		kv("assets", validation.VArr()),
		kv("relations", validation.VArr()))
	art := filepath.Join(c.ArtifactsDir, "protocol_model.json")
	if err := validation.WriteJson(art, model, "protocol_model"); err != nil {
		t.Fatalf("write model: %v", err)
	}
	return c
}

// t35PlanClosedExcept is _plan_closed_except: every gate item resolved except
// `skip` (a lens id or "diversity").
// reconOnRecord puts both FIX-8 recon stamps on record for one campaign.
// The real verbs are off-limits here for two test-local reasons: the real
// prescreen/sinks would rebuild this campaign's fixture index from the
// shared sink tree (EnsureFreshIndex), and — in packages structidx wires —
// importing them is an import cycle in test. So the prescreen artifact is
// seeded as a fixture file and the sinks stamp rides the REAL
// state.StampRecon write path; the end-to-end real-verb version of this
// setup lives in internal/cli (cmd_recon_gate_test.go).
func reconOnRecord(t *testing.T, c *state.Campaign) {
	t.Helper()
	prescreen := validation.VObj(
		kv("snapshot_id", validation.VStr("S-0123456789abcdef")))
	if err := validation.WriteJson(filepath.Join(c.ArtifactsDir,
		"archetype_prescreen.json"), prescreen, ""); err != nil {
		t.Fatalf("seed prescreen artifact: %v", err)
	}
	if err := c.StampRecon("sinks", "src"); err != nil {
		t.Fatalf("stamp sinks: %v", err)
	}
}

func t35PlanClosedExcept(t *testing.T, c *state.Campaign, skip string) {
	t.Helper()
	reconOnRecord(t, c)
	plan, err := planner.DefaultPlanFromModel(c, t35MorphModel())
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	prios0 := listAt(plan, "priorities")
	for i := range prios0 {
		prios0[i].O = t35Set(prios0[i].O, "status",
			validation.VStr("answered"))
	}
	plan.O = t35Set(plan.O, "priorities", validation.VArr(prios0...))
	reason := "fixture: nothing to check"
	checked := []string{"none-applicable"}
	for _, lid := range []string{"L-01", "L-02", "L-03", "L-04"} {
		if lid == skip {
			continue
		}
		plan, err = planner.MarkLens(c, plan, lid, "not-applicable",
			planner.LensOpts{Reason: &reason, Actor: "pytest",
				FamiliesChecked: &checked})
		if err != nil {
			t.Fatalf("mark_lens %s: %v", lid, err)
		}
	}
	if skip != "diversity" {
		classes := []string{"reentrancy", "logic-error",
			"oracle-manipulation", "access-control"}
		prios := append([]validation.Value{}, listAt(plan, "priorities")...)
		for i, cls := range classes {
			prios = append(prios, validation.VObj(
				kv("id", validation.VStr(fmt.Sprintf("Q-%03d", i+1))),
				kv("question", validation.VStr(fmt.Sprintf(
					"shape %d: canonical bug class named", i+1))),
				kv("risk", validation.VFloat(0.5)),
				kv("trajectories", validation.VArr(validation.VStr("code"))),
				kv("status", validation.VStr("answered")),
				kv("closed_reason", validation.VStr("answered by the fixture")),
				kv("closed_by", validation.VStr("pytest")),
				kv("bug_class", validation.VStr(cls))))
		}
		plan.O = t35Set(plan.O, "priorities", validation.VArr(prios...))
	}
	if _, err := planner.SavePlan(c, plan); err != nil {
		t.Fatalf("save plan: %v", err)
	}
}

func t35DiscoveryProof(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	res, err := ProofStatus(c, "discovery")
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestDiscoveryProofBlocksOnOpenLenses(t *testing.T) {
	c := t35LensCampaign(t)
	t35PlanClosedExcept(t, c, "L-03")
	res := t35DiscoveryProof(t, c)
	if isDone(t, res) {
		t.Fatalf("discovery proof must block: %s", validation.CanonCompact(res))
	}
	missing := missingOf(t, res)
	if !anyContains(missing, "L-03:") {
		t.Errorf("missing does not name L-03: %v", missing)
	}
	if !strings.Contains(objStr(res, "note"), "divergence gate") {
		t.Errorf("note = %q, want it to name the divergence gate",
			objStr(res, "note"))
	}
}

func TestDiscoveryProofBlocksOnDiversity(t *testing.T) {
	c := t35LensCampaign(t)
	t35PlanClosedExcept(t, c, "diversity")
	res := t35DiscoveryProof(t, c)
	if isDone(t, res) {
		t.Fatalf("discovery proof must block on diversity: %s",
			validation.CanonCompact(res))
	}
	if !anyContains(missingOf(t, res), "diversity:") {
		t.Errorf("missing does not name diversity: %v", missingOf(t, res))
	}
}

func TestDiscoveryProofPassesWhenGateClosed(t *testing.T) {
	c := t35LensCampaign(t)
	t35PlanClosedExcept(t, c, "")
	res := t35DiscoveryProof(t, c)
	if !isDone(t, res) {
		t.Fatalf("discovery proof must pass: %s", validation.CanonCompact(res))
	}
}

func TestDivergenceGateIsWaivable(t *testing.T) {
	c := t35LensCampaign(t)
	t35PlanClosedExcept(t, c, "L-02")
	reason := "single-module fixture with one state machine; incentive " +
		"paths are out of scope for this audit"
	if _, err := Waive(c, "discovery", "L-02", reason, "pytest"); err != nil {
		t.Fatalf("waive: %v", err)
	}
	res := t35DiscoveryProof(t, c)
	if anyContains(missingOf(t, res), "L-02:") {
		t.Errorf("waived L-02 still blocks: %v", missingOf(t, res))
	}
	raw, err := os.ReadFile(WaiversPath(c))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"subject": "L-02"`) &&
		!strings.Contains(string(raw), `"subject":"L-02"`) {
		t.Errorf("waivers.jsonl does not record L-02:\n%s", raw)
	}
}

// t35Set replaces (or appends) one key in a KV list.
func t35Set(o []validation.KV, key string,
	v validation.Value) []validation.KV {
	out := make([]validation.KV, 0, len(o)+1)
	replaced := false
	for _, kv := range o {
		if kv.K == key {
			out = append(out, validation.KV{K: key, V: v})
			replaced = true
			continue
		}
		out = append(out, kv)
	}
	if !replaced {
		out = append(out, validation.KV{K: key, V: v})
	}
	return out
}
