package pipeline

// T35 testmap re-triage: test_budget.py::test_pipeline_runs_normally_within_ceiling.
// The halt half is pinned by TestCostCeilingHaltMatchesPython; this is the
// other half — a ceiling that is never crossed must not halt the run.

import (
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

func TestPipelineRunsNormallyWithinCeiling(t *testing.T) {
	e := newEnv(t)
	useDefaultSeams(t)
	limit := validation.VFloat(1000000.0)
	if _, err := e.c.SetCostCeiling(&limit, "lead"); err != nil {
		t.Fatal(err)
	}
	p := New(e.c, e.o, map[string]Handler{"snapshot": e.snapHandler()})
	summary := run(t, p, RunOpts{MaxStages: iptr(3)})
	assertStr(t, "ran", pyListRepr(stringsOf(validation.ObjAt(summary, "ran"))),
		"['scope', 'snapshot', 'structural-index']")
	for _, et := range eventTypes(t, e.c) {
		if et == "pipeline.budget_halt" {
			t.Fatalf("a ceiling never crossed must not halt: %v",
				eventTypes(t, e.c))
		}
	}
}

// --- tests/test_design_upgrades.py section 3: the DAG scheduler -----------

// unreviewedDiscovery is the Python fixture's discovery handler: one open,
// unreviewed access-control hypothesis, which is what makes hostile-review's
// completion proof fail.
func unreviewedDiscovery() Handler {
	return func(c *state.Campaign) (validation.Value, error) {
		return findings.IngestHypothesis(c, validation.VObj(
			kv("title", vstr("withdraw has no ownership check")),
			kv("root_cause", validation.VObj(
				kv("class", vstr("access-control")),
				kv("description", vstr(
					"withdraw() sends funds to the caller unchecked")))),
			kv("affected", validation.VArr(validation.VObj(
				kv("path", vstr("Vault.sol")),
				kv("contract", vstr("Vault")),
				kv("function", vstr("withdraw"))))),
			kv("attacker", validation.VObj(
				kv("profile", vstr("arbitrary EOA")),
				kv("capabilities", validation.VArr()))),
		), "code", "", "")
	}
}

// ranContains reports whether the summary's ran list holds the stage.
func ranContains(summary validation.Value, sid string) bool {
	for _, s := range validation.ObjAt(summary, "ran").A {
		if s.S == sid {
			return true
		}
	}
	return false
}

func TestBlockedModelStageDoesNotStarveIndependentBranch(t *testing.T) {
	e := newEnv(t)
	useWiredSeams(t, false)
	p := New(e.c, e.o, map[string]Handler{
		"snapshot":          e.snapHandler(),
		"protocol-model":    constHandler("model loaded"),
		"campaign-planning": constHandler("plan built"),
		"discovery":         unreviewedDiscovery(),
	})
	summary := run(t, p, RunOpts{})
	if !ranContains(summary, "dedup") {
		t.Fatalf("dedup must run: %v", validation.ObjAt(summary, "ran"))
	}
	got := pyListRepr(stringsOf(validation.ObjAt(summary, "blocked_stages")))
	if got != "['hostile-review']" {
		t.Fatalf("blocked_stages = %s", got)
	}
	if !ranContains(summary, "reproduction") {
		t.Fatal("the independent reproduction branch must not starve")
	}
	assertStr(t, "status", validation.ObjStr(summary, "status"), "needs-model")
	assertStr(t, "needs_model.stage",
		validation.ObjStr(validation.ObjAt(summary, "needs_model"), "stage"), "hostile-review")
	if ranContains(summary, "chaining") {
		t.Fatal("chaining joins BOTH branches and cannot start")
	}
	assertStr(t, "hostile-review status", e.stageStatus(t, "hostile-review"),
		"needs-model")
	assertStr(t, "reproduction status", e.stageStatus(t, "reproduction"), "done")
	// resume: feed hostile-review a handler and the join point runs
	p.Handlers["hostile-review"] = constHandler("critic verdicts in")
	second := run(t, p, RunOpts{})
	if !ranContains(second, "chaining") {
		t.Fatalf("resume must run chaining: %v", validation.ObjAt(second, "ran"))
	}
	if !ranContains(second, "hostile-review") {
		t.Fatalf("resume must run hostile-review: %v", validation.ObjAt(second, "ran"))
	}
}

func TestJoinAnyIsHonoredByTheScheduler(t *testing.T) {
	e := newEnv(t)
	useWiredSeams(t, false)
	prev, had := StageJoins["chaining"]
	StageJoins["chaining"] = mustJoin(t, JoinAny,
		[]string{"hostile-review", "reproduction"}, nil, nil)
	t.Cleanup(func() {
		if had {
			StageJoins["chaining"] = prev
		} else {
			delete(StageJoins, "chaining")
		}
	})
	p := New(e.c, e.o, map[string]Handler{
		"snapshot":          e.snapHandler(),
		"protocol-model":    constHandler("model loaded"),
		"campaign-planning": constHandler("plan built"),
		"discovery":         unreviewedDiscovery(),
		// the model stages past the fork: hostile-review is the ONLY
		// blocked stage, so the any-joined chain is what is under test
		"maximal-exploitation":     constHandler("ladder closed"),
		"independent-verification": constHandler("verified"),
		"risk-calibration":         constHandler("calibrated"),
		"mainnet-fork-poc":         constHandler("fork PoC proven"),
		"bounty-gate":              constHandler("gated (no policy in this fixture)"),
		"report":                   constHandler("report generated"),
		"learning":                 constHandler("lessons logged"),
	})
	summary := run(t, p, RunOpts{})
	got := pyListRepr(stringsOf(validation.ObjAt(summary, "blocked_stages")))
	if got != "['hostile-review']" {
		t.Fatalf("blocked_stages = %s", got)
	}
	if !ranContains(summary, "reproduction") {
		t.Fatal("reproduction must run")
	}
	if !ranContains(summary, "chaining") {
		t.Fatalf("an any-join is satisfied by one predecessor: %v",
			validation.ObjAt(summary, "ran"))
	}
	assertStr(t, "chaining status", e.stageStatus(t, "chaining"), "done")
	for _, sid := range []string{"independent-verification",
		"risk-calibration", "bounty-gate", "report", "learning"} {
		if !ranContains(summary, sid) {
			t.Errorf("the chain must keep flowing past the blocked branch: "+
				"%s did not run", sid)
		}
	}
}

// constHandler is a model-stage handler returning a fixed note.
func constHandler(note string) Handler {
	return func(*state.Campaign) (validation.Value, error) {
		return validation.VStr(note), nil
	}
}
