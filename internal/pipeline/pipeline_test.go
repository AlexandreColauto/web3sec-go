// Port of tests/test_pipeline.py plus the byte-exact contracts the Python
// twin generates into testdata/ (gen: .scratch/t11/gen-vectors.py).
//
// The unported collaborators (orchestrator / adapter / completion /
// maximization) are wired through the package seams with deterministic stubs
// that mirror the Python twin's monkeypatches, so run/completed/next_stage
// are exercised end-to-end and every artifact is compared byte-for-byte.
package pipeline

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/planner"
	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

const nowPin = "2026-01-01T00:00:00.000000+00:00"

const vaultSrc = "contract Vault { function withdraw() external { } }\n"

// kv is the test-only keyed constructor (non-test code spells out
// validation.KV{K: ..., V: ...}).
func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

func vstr(s string) validation.Value { return validation.VStr(s) }

// ---- stub orchestrator (the Python twin's FakeOrch) -----------------------

type fakeOrch struct {
	c *state.Campaign
	// planReadOnly mirrors Orchestrator.plan()'s read-only branch: a plan
	// already on disk is returned unchanged (B1/D1).
	planReadOnly bool
}

func (o *fakeOrch) Scope() (validation.Value, error) {
	if err := o.c.SetPhase("SCOPE", "load bounty policy"); err != nil {
		return validation.VNull(), err
	}
	if err := o.c.SetStage("scope", "done", vstr(""), strPtr("deterministic")); err != nil {
		return validation.VNull(), err
	}
	return validation.VObj(kv("note", vstr("no policy provided; load before BOUNTY_GATE"))), nil
}

func (o *fakeOrch) Snapshot(target string) (validation.Value, error) {
	if err := o.c.SetPhase("SNAPSHOT", "pin audit reality"); err != nil {
		return validation.VNull(), err
	}
	snap, err := snapshot.PinSourceSnapshot(o.c, target, nil, nil)
	if err != nil {
		return validation.VNull(), err
	}
	if err := o.c.SetStage("snapshot", "done", vstr(""), strPtr("deterministic")); err != nil {
		return validation.VNull(), err
	}
	if err := o.c.SetPhase("STRUCTURAL_INDEX", "snapshot pinned"); err != nil {
		return validation.VNull(), err
	}
	return snap, nil
}

func (o *fakeOrch) BuildStructuralIndex() (validation.Value, error) {
	if err := o.c.SetStage("structural-index", "done", vstr(""),
		strPtr("deterministic")); err != nil {
		return validation.VNull(), err
	}
	if err := o.c.SetPhase("PROTOCOL_INTELLIGENCE", "index built"); err != nil {
		return validation.VNull(), err
	}
	stats := validation.VObj(
		kv("solidity_files", validation.VInt(1)),
		kv("contracts", validation.VInt(1)),
		kv("functions", validation.VInt(1)),
		kv("entry_points", validation.VInt(1)),
	)
	return validation.VObj(kv("stats", stats), kv("entry_count", validation.VInt(1))), nil
}

func (o *fakeOrch) RunDedup() (validation.Value, error) {
	return validation.VObj(kv("merged", validation.VInt(0)),
		kv("clusters", validation.VInt(0))), nil
}

func (o *fakeOrch) Chaining() (validation.Value, error) {
	return validation.VObj(kv("chains", validation.VInt(0))), nil
}

func (o *fakeOrch) CalibrateAll() (validation.Value, error)  { return validation.VArr(), nil }
func (o *fakeOrch) BountyGateAll() (validation.Value, error) { return validation.VArr(), nil }
func (o *fakeOrch) Plan() (validation.Value, error) {
	if o.planReadOnly {
		return validation.VObj(kv("plan", vstr("stub")),
			kv("read_only", validation.VBool(true))), nil
	}
	return validation.VObj(kv("plan", vstr("stub"))), nil
}
func (o *fakeOrch) ReproductionQueue() (validation.Value, error) {
	return validation.VArr(), nil
}

// ---- stub adapter / completion / maximization -----------------------------

type fakeAdapter struct {
	prompts map[string]string
	extra   []string
}

func (a *fakeAdapter) BuildContext(_ *state.Campaign, stage string,
	extra []string) (validation.Value, error) {
	a.extra = append([]string{}, extra...)
	path := "/stub/prompts/" + stage + ".md"
	if p, ok := a.prompts[stage]; ok {
		path = p
	}
	blocks := validation.VArr(
		validation.VObj(kv("title", vstr("campaign")), kv("text", vstr("c"))),
		validation.VObj(kv("title", vstr("snapshot")), kv("text", vstr("s"))),
	)
	outputs := validation.VObj(
		kv("hypotheses", vstr("findings.ingest_hypothesis(campaign, payload, trajectory=...)")),
		kv("evidence", vstr("findings.add_evidence(campaign, finding_id, item)")),
	)
	return validation.VObj(
		kv("stage", vstr(stage)),
		kv("prompt_path", vstr(path)),
		kv("prompt", vstr("STUB PROMPT\n")),
		kv("budget_class", vstr("standard")),
		kv("blocks", blocks),
		kv("structured_outputs", outputs),
	), nil
}

type fakeCompletion struct{ done bool }

func (f fakeCompletion) ProofStatus(_ *state.Campaign, stage string) (validation.Value, error) {
	missing := map[string][]string{
		"protocol-model": {"artifacts/protocol_model.json — load the model",
			"invariants seeded", "equations built", "extra 4", "extra 5"},
		"discovery":         {"no hypotheses ingested yet"},
		"campaign-planning": {},
	}[stage]
	if missing == nil {
		missing = []string{"stub proof missing for " + stage}
	}
	done := stage == "protocol-model" && f.done
	note := "proof pending"
	if done {
		note = "proof holds"
	}
	return validation.VObj(kv("done", validation.VBool(done)),
		kv("missing", validation.StrArr(missing)), kv("note", vstr(note))), nil
}

type fakeCosts struct{ bstat validation.Value }

func (f fakeCosts) BudgetStatus(*state.Campaign) (validation.Value, error) {
	return f.bstat, nil
}

// ---- env fixture (tests/test_pipeline.py's `env`) -------------------------

type env struct {
	root   string
	c      *state.Campaign
	target string
	o      *fakeOrch
}

func newEnv(t *testing.T) *env {
	t.Helper()
	t.Setenv("WEBV2_NOW", nowPin)
	root := t.TempDir()
	target := filepath.Join(root, "src")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "Vault.sol"),
		[]byte(vaultSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := state.Init(filepath.Join(root, "ws"), "Acme Program",
		state.InitOpts{CampaignID: "C-0000000000"})
	if err != nil {
		t.Fatal(err)
	}
	return &env{root: root, c: c, target: target, o: &fakeOrch{c: c}}
}

// snapHandler is the Python tests' `handlers={"snapshot": lambda camp: o.snapshot(target)}`.
func (e *env) snapHandler() Handler {
	return func(*state.Campaign) (validation.Value, error) { return e.o.Snapshot(e.target) }
}

func (e *env) stateText(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(e.c.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(raw), e.root, "<ROOT>")
}

func (e *env) eventsText(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(e.c.EventsPath)
	if err != nil {
		t.Fatal(err)
	}
	out := []string{}
	for _, ln := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(ln) != "" {
			out = append(out, strings.ReplaceAll(ln, e.root, "<ROOT>"))
		}
	}
	return out
}

func (e *env) stageStatus(t *testing.T, sid string) string {
	t.Helper()
	st, err := e.c.State()
	if err != nil {
		t.Fatal(err)
	}
	return validation.ObjStr(validation.ObjAt(validation.ObjAt(st, "stages"), sid), "status")
}

func (e *env) stageNote(t *testing.T, sid string) string {
	t.Helper()
	st, err := e.c.State()
	if err != nil {
		t.Fatal(err)
	}
	return validation.ObjStr(validation.ObjAt(validation.ObjAt(st, "stages"), sid), "note")
}

// ---- seams ----------------------------------------------------------------

func useSeams(t *testing.T, a AdapterAPI, c CompletionAPI, m MaximizationAPI) {
	t.Helper()
	prevA, prevC, prevM := adapterImpl, completionImpl, maximizationImpl
	SetAdapter(a)
	SetCompletion(c)
	SetMaximization(m)
	t.Cleanup(func() {
		adapterImpl, completionImpl, maximizationImpl = prevA, prevC, prevM
	})
}

// useDefaultSeams is the Python twin's patch_default(): PROOFS={}, adapter not
// wired, load_ladder -> None.
func useDefaultSeams(t *testing.T) { t.Helper(); useSeams(t, nil, nil, nil) }

// useWiredSeams is the Python twin's patch_wired(done).
func useWiredSeams(t *testing.T, done bool) *fakeAdapter {
	t.Helper()
	a := &fakeAdapter{prompts: map[string]string{
		"protocol-model":       "/stub/prompts/02_protocol_model.md",
		"discovery-specialist": "/stub/prompts/39_trajectory_dispatch.md",
	}}
	useSeams(t, a, fakeCompletion{done: done}, nil)
	return a
}

// ---- oracles --------------------------------------------------------------

type scenario map[string]json.RawMessage

func loadScenarios(t *testing.T) map[string]scenario {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "scenarios.json"))
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]scenario
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func loadOracle[T any](t *testing.T, name string) T {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func (s scenario) str(t *testing.T, key string) string {
	t.Helper()
	raw, ok := s[key]
	if !ok {
		t.Fatalf("scenario has no %q oracle", key)
	}
	var out string
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("scenario[%q]: %v", key, err)
	}
	return out
}

func (s scenario) has(key string) bool { _, ok := s[key]; return ok }

func (s scenario) raw(t *testing.T, key string) json.RawMessage {
	t.Helper()
	raw, ok := s[key]
	if !ok {
		t.Fatalf("scenario has no %q oracle", key)
	}
	return raw
}

func (s scenario) strs(t *testing.T, key string) []string {
	t.Helper()
	raw, ok := s[key]
	if !ok {
		t.Fatalf("scenario has no %q oracle", key)
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("scenario[%q]: %v", key, err)
	}
	return out
}

// ---- assertions -----------------------------------------------------------

func assertSummary(t *testing.T, got validation.Value, want, label string) {
	t.Helper()
	if g := validation.DumpIndented(got); g != want {
		t.Errorf("%s summary mismatch\n--- got ---\n%s\n--- want ---\n%s", label, g, want)
	}
}

func assertState(t *testing.T, e *env, want, label string) {
	t.Helper()
	if got := normalizeEnvHash(e.stateText(t)); got != normalizeEnvHash(want) {
		t.Errorf("%s state mismatch\n--- got ---\n%s\n--- want ---\n%s", label, got, want)
	}
}

// normalizeEnvHash applies KNOWN_DIVERGENCES D3: the snapshot's
// environment_hash / manifest_hash fingerprint the RUNTIME (python 3.14.x vs
// go1.26.2) and can never match across twins, so the golden harness
// normalizes exactly those two values before the byte diff.
var envHashRe = regexp.MustCompile(`environment_hash(\\?": \\?")([0-9a-f]{64})`)
var manifestHashRe = regexp.MustCompile(`manifest_hash(\\?": \\?")([0-9a-f]{64})`)

func normalizeEnvHash(s string) string {
	s = envHashRe.ReplaceAllString(s, "${1}<ENVHASH>")
	return manifestHashRe.ReplaceAllString(s, "${1}<MANIFESTHASH>")
}

func assertEvents(t *testing.T, e *env, want []string, label string) {
	t.Helper()
	got := e.eventsText(t)
	if len(got) != len(want) {
		t.Errorf("%s: %d events, want %d", label, len(got), len(want))
		return
	}
	for i := range got {
		if normalizeEnvHash(got[i]) != normalizeEnvHash(want[i]) {
			t.Errorf("%s event %d mismatch\n got: %s\nwant: %s", label, i, got[i], want[i])
		}
	}
}

func assertStr(t *testing.T, label, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("%s: got %q, want %q", label, got, want)
	}
}

func run(t *testing.T, p *Pipeline, opts RunOpts) validation.Value {
	t.Helper()
	summary, err := p.Run(opts)
	if err != nil {
		t.Fatal(err)
	}
	return summary
}

func iptr(n int64) *int64 { return &n }

// stringsOf is the []string view of a JSON array value.
func stringsOf(v validation.Value) []string {
	out := []string{}
	for _, e := range v.A {
		out = append(out, e.S)
	}
	return out
}

func eventTypes(t *testing.T, c *state.Campaign) []string {
	t.Helper()
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	out := []string{}
	for _, e := range events {
		out = append(out, validation.ObjStr(e, "type"))
	}
	return out
}

// ---- ported tests ---------------------------------------------------------

// tests/test_pipeline.py::test_halts_at_first_model_stage_with_a_context_bundle
func TestHaltsAtFirstModelStageWithAContextBundle(t *testing.T) {
	e := newEnv(t)
	useWiredSeams(t, false)
	p := New(e.c, e.o, map[string]Handler{"snapshot": e.snapHandler()})
	summary := run(t, p, RunOpts{})
	assertStr(t, "status", validation.ObjStr(summary, "status"), "needs-model")
	assertStr(t, "ran", pyListRepr(stringsOf(validation.ObjAt(summary, "ran"))),
		"['scope', 'snapshot', 'structural-index']")
	nm := validation.ObjAt(summary, "needs_model")
	assertStr(t, "needs_model.stage", validation.ObjStr(nm, "stage"), "protocol-model")
	if !strings.HasSuffix(validation.ObjStr(nm, "prompt_path"), "02_protocol_model.md") {
		t.Errorf("prompt_path %q does not end with 02_protocol_model.md",
			validation.ObjStr(nm, "prompt_path"))
	}
	assertStr(t, "budget_class", validation.ObjStr(nm, "budget_class"), "standard")
	if !hasKey(validation.ObjAt(nm, "how_to_feed_back"), "hypotheses") {
		t.Errorf("how_to_feed_back lacks hypotheses: %s", validation.DumpIndented(nm))
	}
	st, err := e.c.State()
	if err != nil {
		t.Fatal(err)
	}
	assertStr(t, "phase", validation.ObjStr(st, "phase"), "PROTOCOL_INTELLIGENCE")
	assertStr(t, "stage status", e.stageStatus(t, "protocol-model"), "needs-model")
}

// tests/test_pipeline.py::test_resume_skips_completed_stages_and_advances
func TestResumeSkipsCompletedStagesAndAdvances(t *testing.T) {
	e := newEnv(t)
	useDefaultSeams(t)
	sc := loadScenarios(t)["resume"]
	calls := map[string]int{}
	p := New(e.c, e.o, map[string]Handler{"snapshot": e.snapHandler()})
	run(t, p, RunOpts{})
	p.Handlers["snapshot"] = e.snapHandler()
	p.Handlers["protocol-model"] = func(*state.Campaign) (validation.Value, error) {
		calls["protocol-model"]++
		return vstr("model loaded"), nil
	}
	p.Handlers["campaign-planning"] = func(*state.Campaign) (validation.Value, error) {
		calls["campaign-planning"]++
		return vstr("plan built"), nil
	}
	second := run(t, p, RunOpts{})
	assertSummary(t, second, sc.str(t, "summary"), "resume")
	assertStr(t, "status", validation.ObjStr(second, "status"), "needs-model")
	assertStr(t, "ran", pyListRepr(stringsOf(validation.ObjAt(second, "ran"))),
		"['protocol-model', 'campaign-planning']")
	assertStr(t, "needs_model.stage", validation.ObjStr(validation.ObjAt(second, "needs_model"), "stage"), "discovery")
	assertStr(t, "protocol-model calls", strconv.Itoa(calls["protocol-model"]), "1")
	assertStr(t, "campaign-planning calls", strconv.Itoa(calls["campaign-planning"]), "1")
	assertStr(t, "skipped_completed", pyListRepr(stringsOf(validation.ObjAt(second, "skipped_completed"))),
		"['scope', 'snapshot', 'structural-index']")
	assertState(t, e, sc.str(t, "state"), "resume")
	assertEvents(t, e, sc.strs(t, "events"), "resume")
}

// tests/test_pipeline.py::test_existing_plan_stage_is_read_only_and_says_so_in_the_note
//
// B1/D1 resume case: a pipeline run that reaches `campaign-planning` with a
// plan ALREADY on disk must reuse it read-only (the plan is the campaign's
// contract — the old builtin regenerated and clobbered it), must complete the
// stage, and must tell the operator in the stage note how to regenerate. The
// note is the one-line human remedy, not the capped JSON blob the raw result
// dict becomes.
func TestExistingPlanStageIsReadOnlyAndSaysSoInTheNote(t *testing.T) {
	e := newEnv(t)
	useDefaultSeams(t)
	plan := validation.VObj(
		kv("campaign_id", vstr(e.c.CampaignID)),
		kv("created_at", vstr("2026-09-08T00:00:00Z")),
		kv("priorities", validation.VArr(validation.VObj(
			kv("id", vstr("Q-001")),
			kv("question", vstr("Can an unprivileged caller drain the vault?")),
			kv("risk", validation.VFloat(0.9)),
			kv("trajectories", validation.VArr(vstr("code"))),
		))),
	)
	if _, err := planner.SavePlan(e.c, plan); err != nil {
		t.Fatal(err)
	}
	planPath := filepath.Join(e.c.ArtifactsDir, "campaign_plan.json")
	beforeBytes, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeInfo, err := os.Stat(planPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeMtime := beforeInfo.ModTime()
	// the real orchestrator answers `read_only: true` for a plan on disk; the
	// stub mirrors that one branch so the builtin's note is exercised.
	e.o.planReadOnly = true
	until := "campaign-planning"
	p := New(e.c, e.o, map[string]Handler{"snapshot": e.snapHandler(),
		"protocol-model": func(*state.Campaign) (validation.Value, error) {
			return vstr("model loaded"), nil
		}})
	summary := run(t, p, RunOpts{Until: &until})
	ranCampaignPlanning := false
	for _, sid := range stringsOf(validation.ObjAt(summary, "ran")) {
		if sid == "campaign-planning" {
			ranCampaignPlanning = true
		}
	}
	if !ranCampaignPlanning {
		t.Errorf("campaign-planning not in ran: %s", validation.DumpIndented(summary))
	}
	assertStr(t, "campaign-planning status", e.stageStatus(t, "campaign-planning"),
		"done")
	note := e.stageNote(t, "campaign-planning")
	assertStr(t, "campaign-planning note", note, "existing plan reused read-only "+
		"— `webv2 plan "+e.c.CampaignID+" --rebuild` to regenerate")
	if strings.HasPrefix(note, "{") { // not a serialized result dict
		t.Errorf("stage note is a serialized result dict: %s", note)
	}
	afterBytes, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterBytes, beforeBytes) {
		t.Errorf("plan file changed:\n%s", afterBytes)
	}
	afterInfo, err := os.Stat(planPath)
	if err != nil {
		t.Fatal(err)
	}
	if !afterInfo.ModTime().Equal(beforeMtime) {
		t.Errorf("plan mtime changed: %s != %s", afterInfo.ModTime(), beforeMtime)
	}
	if _, err := os.Stat(filepath.Join(e.c.ArtifactsDir, "superseded")); !os.IsNotExist(err) {
		t.Errorf("superseded/ exists (err=%v)", err)
	}
}

// tests/test_pipeline.py::test_failing_stage_halts_the_run_and_is_retryable
func TestFailingStageHaltsTheRunAndIsRetryable(t *testing.T) {
	e := newEnv(t)
	useDefaultSeams(t)
	sc := loadScenarios(t)["failing"]
	boom := true
	p := New(e.c, e.o, map[string]Handler{
		"snapshot": e.snapHandler(),
		"protocol-model": func(*state.Campaign) (validation.Value, error) {
			if boom {
				return validation.VNull(), errors.New("model returned garbage")
			}
			return vstr("ok now"), nil
		},
	})
	p.Handlers["campaign-planning"] = func(*state.Campaign) (validation.Value, error) {
		return vstr("plan"), nil
	}
	first := run(t, p, RunOpts{})
	assertSummary(t, first, sc.str(t, "first"), "failing-first")
	assertStr(t, "first status", validation.ObjStr(first, "status"), "halted")
	if !strings.Contains(validation.ObjStr(first, "halt"), "model returned garbage") {
		t.Errorf("halt %q lacks the exception text", validation.ObjStr(first, "halt"))
	}
	completed, err := p.Completed()
	if err != nil {
		t.Fatal(err)
	}
	if containsStr(completed, "protocol-model") {
		t.Errorf("protocol-model must not be completed: %v", completed)
	}
	assertStr(t, "stage status", e.stageStatus(t, "protocol-model"), "failed")
	boom = false
	second := run(t, p, RunOpts{})
	assertSummary(t, second, sc.str(t, "second"), "failing-second")
	if !containsStr(stringsOf(validation.ObjAt(second, "ran")), "protocol-model") {
		t.Errorf("protocol-model was not retried: %s", validation.DumpIndented(second))
	}
	assertStr(t, "second status", validation.ObjStr(second, "status"), "needs-model")
}

// tests/test_pipeline.py::test_builtin_without_orchestrator_or_target_fails_loudly
func TestBuiltinWithoutOrchestratorOrTargetFailsLoudly(t *testing.T) {
	e := newEnv(t)
	useDefaultSeams(t)
	sc := loadScenarios(t)["no_target"]
	p := New(e.c, e.o, nil)
	summary := run(t, p, RunOpts{MaxStages: iptr(5)})
	assertSummary(t, summary, sc.str(t, "summary"), "no_target")
	assertStr(t, "status", validation.ObjStr(summary, "status"), "halted")
	if !strings.Contains(validation.ObjStr(summary, "halt"), "snapshot needs a target path") {
		t.Errorf("halt %q lacks the builtin error", validation.ObjStr(summary, "halt"))
	}
	assertStr(t, "ran", pyListRepr(stringsOf(validation.ObjAt(summary, "ran"))), "['scope']")
}

// tests/test_pipeline.py::test_until_stops_after_the_named_stage
func TestUntilStopsAfterTheNamedStage(t *testing.T) {
	e := newEnv(t)
	useDefaultSeams(t)
	sc := loadScenarios(t)["until"]
	p := New(e.c, e.o, map[string]Handler{"snapshot": e.snapHandler()})
	until := "structural-index"
	summary := run(t, p, RunOpts{Until: &until})
	assertSummary(t, summary, sc.str(t, "summary"), "until")
	assertStr(t, "ran", pyListRepr(stringsOf(validation.ObjAt(summary, "ran"))),
		"['scope', 'snapshot', 'structural-index']")
	assertStr(t, "status", validation.ObjStr(summary, "status"), "until-reached")
	bad := "not-a-stage"
	if _, err := p.Run(RunOpts{Until: &bad}); err == nil {
		t.Fatal("unknown until must raise")
	} else {
		assertStr(t, "unknown stage error", err.Error(), sc.str(t, "unknown_stage"))
	}
}

// TestBlockedNoteMatchesPython pins the resumed-run blocked note and the
// "no completion proof declared" branch (a second run over a finished prefix).
func TestBlockedNoteMatchesPython(t *testing.T) {
	e := newEnv(t)
	useDefaultSeams(t)
	sc := loadScenarios(t)["blocked_note"]
	until := "structural-index"
	p := New(e.c, e.o, map[string]Handler{"snapshot": e.snapHandler()})
	run(t, p, RunOpts{Until: &until})
	second := run(t, p, RunOpts{})
	assertSummary(t, second, sc.str(t, "summary"), "blocked_note")
	assertStr(t, "note", e.stageNote(t, "protocol-model"), sc.str(t, "note"))
	assertStr(t, "status", validation.ObjStr(second, "status"), "needs-model")
	assertStr(t, "ran", pyListRepr(stringsOf(validation.ObjAt(second, "ran"))), "[]")
	assertStr(t, "skipped_completed",
		pyListRepr(stringsOf(validation.ObjAt(second, "skipped_completed"))),
		"['scope', 'snapshot', 'structural-index']")
	assertState(t, e, sc.str(t, "state"), "blocked_note")
}

// tests/test_pipeline.py::test_pipeline_halt_is_written_to_the_event_log
func TestPipelineHaltIsWrittenToTheEventLog(t *testing.T) {
	e := newEnv(t)
	useDefaultSeams(t)
	sc := loadScenarios(t)["event_log"]
	p := New(e.c, e.o, map[string]Handler{"snapshot": e.snapHandler()})
	run(t, p, RunOpts{})
	types := eventTypes(t, e.c)
	assertStr(t, "event types", pyListRepr(types), pyListRepr(sc.strs(t, "types")))
	if !containsStr(types, "pipeline.stage_done") {
		t.Errorf("pipeline.stage_done missing from %v", types)
	}
	if !containsStr(types, "pipeline.blocked") {
		t.Errorf("pipeline.blocked missing from %v", types)
	}
	assertEvents(t, e, sc.strs(t, "events"), "event_log")
}

// ---- golden tables and seam contracts -------------------------------------

func TestStagesTableMatchesPythonGolden(t *testing.T) {
	type row struct {
		ID    string `json:"id"`
		Kind  string `json:"kind"`
		Phase string `json:"phase"`
	}
	want := loadOracle[[]row](t, "stages.json")
	if len(Stages) != 17 || len(want) != 17 {
		t.Fatalf("stage table size: go=%d python=%d", len(Stages), len(want))
	}
	for i, w := range want {
		assertStr(t, fmt.Sprintf("stage[%d].id", i), Stages[i].ID, w.ID)
		assertStr(t, fmt.Sprintf("stage[%d].kind", i), Stages[i].Kind, w.Kind)
		assertStr(t, fmt.Sprintf("stage[%d].phase", i), Stages[i].Phase, w.Phase)
	}
	topo := loadOracle[struct {
		Order []string            `json:"order"`
		Deps  map[string][]string `json:"deps"`
		IDs   []string            `json:"ids"`
	}](t, "topo.json")
	assertStr(t, "stage ids", pyListRepr(StageIDs), pyListRepr(topo.IDs))
}

func TestJoinsTableMatchesPythonGolden(t *testing.T) {
	want := loadOracle[map[string]struct {
		Kind   string   `json:"kind"`
		Deps   []string `json:"deps"`
		Quorum *int     `json:"quorum"`
	}](t, "joins.json")
	if len(want) != len(StageJoins) {
		t.Fatalf("join table size: go=%d python=%d", len(StageJoins), len(want))
	}
	for sid, w := range want {
		spec, ok := StageJoins[sid]
		if !ok {
			t.Fatalf("no Go join for stage %s", sid)
		}
		assertStr(t, sid+".kind", spec.Kind, w.Kind)
		assertStr(t, sid+".deps", pyListRepr(spec.Deps), pyListRepr(w.Deps))
		if (spec.Quorum == nil) != (w.Quorum == nil) {
			t.Errorf("%s.quorum: go=%v python=%v", sid, spec.Quorum, w.Quorum)
		}
		// every canonical stage joins ALL: chaining GENUINELY needs both
		// hostile-review and reproduction
		assertStr(t, sid+".kind is all", spec.Kind, JoinAll)
	}
	assertStr(t, "join order", pyListRepr(stageJoinOrder), pyListRepr(StageIDs))
}

func TestTopologicalOrderMatchesPythonGolden(t *testing.T) {
	topo := loadOracle[struct {
		Order []string            `json:"order"`
		Deps  map[string][]string `json:"deps"`
		IDs   []string            `json:"ids"`
	}](t, "topo.json")
	order, err := TopologicalOrder()
	if err != nil {
		t.Fatal(err)
	}
	assertStr(t, "topological order", pyListRepr(order), pyListRepr(topo.Order))
	pos := map[string]int{}
	for i, sid := range order {
		pos[sid] = i
	}
	for sid, deps := range topo.Deps {
		assertStr(t, sid+".deps", pyListRepr(StageDeps[sid]), pyListRepr(deps))
		for _, d := range deps {
			if pos[d] >= pos[sid] {
				t.Errorf("dependency %s sorts after %s", d, sid)
			}
		}
	}
}

func mustJoin(t *testing.T, kind string, deps []string, quorum *int,
	pred func(*state.Campaign) bool) JoinSpec {
	t.Helper()
	spec, err := Join(kind, deps, quorum, pred)
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func TestJoinValidationMessagesMatchPython(t *testing.T) {
	msg := loadOracle[map[string]*string](t, "messages.json")
	if msg["quorum_empty_deps"] != nil {
		t.Fatalf("python oracle for empty-deps quorum must be no error, got %q",
			*msg["quorum_empty_deps"])
	}
	n := func(i int) *int { return &i }
	cases := []struct {
		label string
		call  func() error
	}{
		{"bad_kind", func() error { _, err := Join("bogus", nil, nil, nil); return err }},
		{"quorum_zero", func() error {
			_, err := Join(JoinQuorum, []string{"a", "b"}, n(0), nil)
			return err
		}},
		{"quorum_none", func() error {
			_, err := Join(JoinQuorum, []string{"a", "b"}, nil, nil)
			return err
		}},
		{"quorum_too_big", func() error {
			_, err := Join(JoinQuorum, []string{"a", "b"}, n(3), nil)
			return err
		}},
		{"predicate_missing", func() error {
			_, err := Join(JoinPredicate, []string{"a"}, nil, nil)
			return err
		}},
		{"unknown_join_kind", func() error {
			_, err := JoinSatisfied(JoinSpec{Kind: "nope"}, nil, nil)
			return err
		}},
		{"quorum_empty_deps_zero", func() error {
			_, err := Join(JoinQuorum, []string{}, n(0), nil)
			return err
		}},
	}
	for _, c := range cases {
		err := c.call()
		if err == nil {
			t.Errorf("%s: expected an error", c.label)
			continue
		}
		assertStr(t, c.label, err.Error(), *msg[c.label])
	}
	if _, err := Join(JoinQuorum, []string{}, n(1), nil); err != nil {
		t.Errorf("quorum over empty deps clamps to 1: %v", err)
	}
	assertStr(t, "join kinds repr", pyTupleRepr(JoinKinds), *msg["join_kinds_repr"])
	assertStr(t, "stage ids repr", pyListRepr(StageIDs), *msg["stage_ids_repr"])
}

func TestJoinSatisfiedSemanticsMatchPython(t *testing.T) {
	table := loadOracle[map[string]bool](t, "joinsem.json")
	yes := &state.Campaign{CampaignID: "yes"}
	no := &state.Campaign{CampaignID: "no"}
	yesPred := func(c *state.Campaign) bool { return c == yes }
	specs := map[string]JoinSpec{
		"all":       mustJoin(t, JoinAll, []string{"a", "b"}, nil, nil),
		"any":       mustJoin(t, JoinAny, []string{"a", "b"}, nil, nil),
		"quorum1":   mustJoin(t, JoinQuorum, []string{"a", "b"}, intPtr(1), nil),
		"quorum2":   mustJoin(t, JoinQuorum, []string{"a", "b"}, intPtr(2), nil),
		"pred":      mustJoin(t, JoinPredicate, nil, nil, yesPred),
		"empty_all": mustJoin(t, JoinAll, nil, nil, nil),
		"empty_any": mustJoin(t, JoinAny, nil, nil, nil),
	}
	if len(table) != 70 {
		t.Fatalf("expected 70 join-semantics rows, got %d", len(table))
	}
	for key, want := range table {
		parts := strings.Split(key, "|")
		done := map[string]bool{}
		if parts[1] != "" {
			for _, d := range strings.Split(parts[1], ",") {
				done[d] = true
			}
		}
		campaign := no
		if parts[2] == "yes" {
			campaign = yes
		}
		got, err := JoinSatisfied(specs[parts[0]], done, campaign)
		if err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		if got != want {
			t.Errorf("%s: got %v want %v", key, got, want)
		}
	}
}

func intPtr(n int) *int { return &n }

func TestMoneyFormatMatchesPython(t *testing.T) {
	doc := loadOracle[struct {
		Values  [][2]string `json:"values"`
		Special [][2]string `json:"special"`
	}](t, "money.json")
	if len(doc.Values) < 600 {
		t.Fatalf("expected the full Python vector set, got %d", len(doc.Values))
	}
	for _, pair := range doc.Values {
		x, err := strconv.ParseFloat(pair[0], 64)
		if err != nil {
			t.Fatalf("vector %q: %v", pair[0], err)
		}
		if got := pyMoney2f(x); got != pair[1] {
			t.Errorf("pyMoney2f(%s) = %s, want %s", pair[0], got, pair[1])
		}
	}
	for _, pair := range doc.Special {
		x, err := strconv.ParseFloat(pair[0], 64)
		if err != nil {
			t.Fatalf("special %q: %v", pair[0], err)
		}
		assertStr(t, pair[0], pyMoney2f(x), pair[1])
	}
}

func dumpPhaseHistory(t *testing.T, e *env) string {
	t.Helper()
	st, err := e.c.State()
	if err != nil {
		t.Fatal(err)
	}
	return validation.DumpIndented(validation.ObjAt(st, "phase_history"))
}

// TestDefaultSeamBundleMatchesPython pins the feature-absent seams: no
// completion proof (PROOFS={}), the adapter not wired, load_ladder -> None.
func TestDefaultSeamBundleMatchesPython(t *testing.T) {
	e := newEnv(t)
	useDefaultSeams(t)
	sc := loadScenarios(t)["halt_at_model"]
	p := New(e.c, e.o, map[string]Handler{"snapshot": e.snapHandler()})
	summary := run(t, p, RunOpts{})
	assertSummary(t, summary, sc.str(t, "summary"), "halt_at_model")
	assertStr(t, "needs_model", validation.DumpIndented(validation.ObjAt(summary, "needs_model")),
		sc.str(t, "needs_model"))
	assertStr(t, "note", e.stageNote(t, "protocol-model"), sc.str(t, "note"))
	assertStr(t, "phase_history", dumpPhaseHistory(t, e), sc.str(t, "phase_history"))
	assertState(t, e, sc.str(t, "state"), "halt_at_model")
	assertEvents(t, e, sc.strs(t, "events"), "halt_at_model")
	nm := validation.ObjAt(summary, "needs_model")
	assertStr(t, "prompt_path", validation.ObjStr(nm, "prompt_path"), "unmapped")
	assertStr(t, "adapter error", validation.ObjStr(nm, "error"),
		"adapter not wired: no context builder for stage 'protocol-model'")
}

func TestWiredBlockedMatchesPython(t *testing.T) {
	e := newEnv(t)
	useWiredSeams(t, false)
	sc := loadScenarios(t)["wired_blocked"]
	p := New(e.c, e.o, map[string]Handler{"snapshot": e.snapHandler()})
	summary := run(t, p, RunOpts{})
	assertSummary(t, summary, sc.str(t, "summary"), "wired_blocked")
	assertStr(t, "needs_model", validation.DumpIndented(validation.ObjAt(summary, "needs_model")),
		sc.str(t, "needs_model"))
	assertStr(t, "note", e.stageNote(t, "protocol-model"), sc.str(t, "note"))
	assertState(t, e, sc.str(t, "state"), "wired_blocked")
	assertEvents(t, e, sc.strs(t, "events"), "wired_blocked")
}

func TestAutoCompletedProofMatchesPython(t *testing.T) {
	e := newEnv(t)
	useWiredSeams(t, true)
	sc := loadScenarios(t)["auto_completed"]
	until := "protocol-model"
	p := New(e.c, e.o, map[string]Handler{"snapshot": e.snapHandler()})
	summary := run(t, p, RunOpts{Until: &until})
	assertSummary(t, summary, sc.str(t, "summary"), "auto_completed")
	assertStr(t, "executor", validation.ObjStr(validation.ObjAt(validation.ObjAt(mustState(t, e), "stages"), "protocol-model"),
		"executor"), "derived")
	assertStr(t, "note", e.stageNote(t, "protocol-model"),
		"auto-completed: completion proof holds")
	assertStr(t, "phase_history", dumpPhaseHistory(t, e), sc.str(t, "phase_history"))
	assertEvents(t, e, sc.strs(t, "events"), "auto_completed")
}

func mustState(t *testing.T, e *env) validation.Value {
	t.Helper()
	st, err := e.c.State()
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestErrorTextBecomesData(t *testing.T) {
	e := newEnv(t)
	useDefaultSeams(t)
	sc := loadScenarios(t)["error_text"]
	weird := "boom — can't parse 'x' \\ \"y\" é中"
	p := New(e.c, e.o, map[string]Handler{
		"snapshot": e.snapHandler(),
		"protocol-model": func(*state.Campaign) (validation.Value, error) {
			return validation.VNull(), errors.New(weird)
		},
	})
	summary := run(t, p, RunOpts{})
	assertSummary(t, summary, sc.str(t, "summary"), "error_text")
	assertStr(t, "note", e.stageNote(t, "protocol-model"), sc.str(t, "note"))
	assertStr(t, "halt", validation.ObjStr(summary, "halt"),
		"stage 'protocol-model' failed: "+weird)
	assertStr(t, "stage status", e.stageStatus(t, "protocol-model"), "failed")
	assertState(t, e, sc.str(t, "state"), "error_text")
	assertEvents(t, e, sc.strs(t, "events"), "error_text")
}

func TestCostCeilingHaltMatchesPython(t *testing.T) {
	e := newEnv(t)
	useDefaultSeams(t)
	sc := loadScenarios(t)["cost_halt"]
	var raw map[string]any
	if err := json.Unmarshal([]byte(sc.str(t, "budget_status")), &raw); err != nil {
		t.Fatal(err)
	}
	SetCosts(fakeCosts{bstat: validation.FromAny(raw)})
	t.Cleanup(func() { SetCosts(nil) })
	p := New(e.c, e.o, map[string]Handler{"snapshot": e.snapHandler()})
	summary := run(t, p, RunOpts{})
	assertSummary(t, summary, sc.str(t, "summary"), "cost_halt")
	assertStr(t, "status", validation.ObjStr(summary, "status"), "halted")
	assertStr(t, "ran", pyListRepr(stringsOf(validation.ObjAt(summary, "ran"))), "[]")
	events, err := e.c.Events()
	if err != nil {
		t.Fatal(err)
	}
	last := events[len(events)-1]
	assertStr(t, "event type", validation.ObjStr(last, "type"), "pipeline.budget_halt")
	data := validation.ObjAt(last, "data")
	assertStr(t, "spent_usd", validation.CanonCompact(validation.ObjAt(data, "spent_usd")), "1234.567")
	assertStr(t, "limit_usd", validation.CanonCompact(validation.ObjAt(data, "limit_usd")), "1000.0")
}

func TestMaxStagesHalts(t *testing.T) {
	e := newEnv(t)
	useDefaultSeams(t)
	sc := loadScenarios(t)["max_stages"]
	p := New(e.c, e.o, map[string]Handler{"snapshot": e.snapHandler()})
	summary := run(t, p, RunOpts{MaxStages: iptr(2)})
	assertSummary(t, summary, sc.str(t, "summary"), "max_stages")
	assertStr(t, "halt", validation.ObjStr(summary, "halt"), "max_stages=2")
	assertStr(t, "ran", pyListRepr(stringsOf(validation.ObjAt(summary, "ran"))), "['scope', 'snapshot']")
	assertState(t, e, sc.str(t, "state"), "max_stages")
}

func TestNoOrchestratorWiredMatchesPython(t *testing.T) {
	e := newEnv(t)
	useDefaultSeams(t)
	sc := loadScenarios(t)["no_orchestrator"]
	p := New(e.c, nil, nil)
	summary := run(t, p, RunOpts{})
	assertSummary(t, summary, sc.str(t, "summary"), "no_orchestrator")
	assertStr(t, "halt", validation.ObjStr(summary, "halt"),
		"stage 'scope' failed: no orchestrator wired; cannot run stage 'scope'")
	assertState(t, e, sc.str(t, "state"), "no_orchestrator")
}

func TestStatusMatchesPython(t *testing.T) {
	e := newEnv(t)
	useDefaultSeams(t)
	sc := loadScenarios(t)["status"]
	got, err := Status(e.c)
	if err != nil {
		t.Fatal(err)
	}
	assertStr(t, "status empty", validation.DumpIndented(got), sc.str(t, "empty"))
	until := "structural-index"
	p := New(e.c, e.o, map[string]Handler{"snapshot": e.snapHandler()})
	run(t, p, RunOpts{Until: &until})
	mid, err := Status(e.c)
	if err != nil {
		t.Fatal(err)
	}
	assertStr(t, "status mid", validation.DumpIndented(mid), sc.str(t, "mid"))
	assertStr(t, "next", validation.ObjStr(mid, "next"), "protocol-model")
	assertStr(t, "completed", pyListRepr(stringsOf(validation.ObjAt(mid, "completed"))),
		"['scope', 'snapshot', 'structural-index']")
}

func TestSnapshotBuiltinAlreadyPinned(t *testing.T) {
	e := newEnv(t)
	useDefaultSeams(t)
	until := "structural-index"
	p := New(e.c, e.o, map[string]Handler{"snapshot": e.snapHandler()})
	run(t, p, RunOpts{Until: &until})
	active, err := e.c.ActiveSnapshotIDOrNone()
	if err != nil {
		t.Fatal(err)
	}
	if active == nil {
		t.Fatal("expected a pinned snapshot")
	}
	got, err := p.builtin("snapshot")
	if err != nil {
		t.Fatal(err)
	}
	assertStr(t, "already pinned", got.S, "already pinned: "+*active)
	// with no handler and nothing pinned, the builtin refuses to guess
	e2 := newEnv(t)
	p2 := New(e2.c, e2.o, nil)
	if _, err := p2.builtin("snapshot"); err == nil {
		t.Fatal("snapshot builtin must fail without a target")
	} else {
		assertStr(t, "no target", err.Error(), "snapshot needs a target path: "+
			"call orchestrator.snapshot(target) or register a handler for the "+
			"'snapshot' stage")
	}
}

func TestNoBuiltinForUnknownStage(t *testing.T) {
	e := newEnv(t)
	useDefaultSeams(t)
	p := New(e.c, e.o, nil)
	if _, err := p.builtin("mystery"); err == nil {
		t.Fatal("unknown stage must have no builtin")
	} else {
		assertStr(t, "no builtin", err.Error(),
			"no builtin for stage 'mystery'; register a handler")
	}
	got, err := p.builtin("structural-index")
	if err != nil {
		t.Fatal(err)
	}
	assertStr(t, "structural index note", validation.CanonSpaced(got),
		`{"artifact": "artifacts/structural_index.json", "contracts": 1, `+
			`"entry_count": 1, "entry_points": 1, "functions": 1, `+
			`"solidity_files": 1}`)
}

// ---- adapter / maximization seam details ----------------------------------

type badAdapter struct{}

func (badAdapter) BuildContext(_ *state.Campaign, _ string,
	_ []string) (validation.Value, error) {
	return validation.VObj(kv("stage", vstr("protocol-model"))), nil
}

type errAdapter struct{}

func (errAdapter) BuildContext(_ *state.Campaign, _ string,
	_ []string) (validation.Value, error) {
	return validation.VNull(), errors.New("boom")
}

type ladderStub struct{ calls []string }

func (l *ladderStub) LoadLadder(_ *state.Campaign, findingID string) (validation.Value, error) {
	l.calls = append(l.calls, findingID)
	return validation.VObj(kv("ladder_id", vstr("LAD-1"))), nil
}

func TestAdapterSeamFailuresMatchPython(t *testing.T) {
	e := newEnv(t)
	useSeams(t, badAdapter{}, nil, nil)
	p := New(e.c, e.o, nil)
	bundle, err := p.modelBundle("protocol-model")
	if err != nil {
		t.Fatal(err)
	}
	assertStr(t, "missing key error", validation.ObjStr(bundle, "error"), "'prompt_path'")
	assertStr(t, "prompt_path", validation.ObjStr(bundle, "prompt_path"), "unmapped")
	assertStr(t, "completion_missing",
		validation.CanonCompact(validation.ObjAt(bundle, "completion_missing")), "[]")

	useSeams(t, errAdapter{}, nil, nil)
	if _, err := p.modelBundle("protocol-model"); err == nil {
		t.Fatal("a non-FileNotFound adapter error must propagate")
	} else {
		assertStr(t, "adapter error", err.Error(), "boom")
	}
}

func TestLadderPathsPassedToAdapter(t *testing.T) {
	e := newEnv(t)
	stub := &ladderStub{}
	useSeams(t, &fakeAdapter{}, nil, stub)
	fid := "F-000000000001"
	finding := validation.VObj(
		kv("finding_id", vstr(fid)),
		kv("created_at", vstr(nowPin)),
		kv("maximization", validation.VObj(kv("ladder_id", vstr("LAD-1")))),
	)
	if err := validation.WriteJson(findings.FindingPath(e.c, fid), finding, ""); err != nil {
		t.Fatal(err)
	}
	p := New(e.c, e.o, nil)
	extra, err := p.ladderPaths("independent-verification")
	if err != nil {
		t.Fatal(err)
	}
	if len(extra) != 1 {
		t.Fatalf("expected one ladder path, got %v", extra)
	}
	assertStr(t, "ladder path", extra[0], filepath.Join(e.c.Dir, "ladders", fid+".json"))
	assertStr(t, "ladder id asked for", strings.Join(stub.calls, ","), fid)
	none, err := p.ladderPaths("discovery")
	if err != nil {
		t.Fatal(err)
	}
	if len(none) != 0 {
		t.Errorf("discovery must attach no ladders: %v", none)
	}
	// default seam: no ladder -> no extra path
	useSeams(t, &fakeAdapter{}, nil, nil)
	empty, err := p.ladderPaths("independent-verification")
	if err != nil {
		t.Fatal(err)
	}
	if len(empty) != 0 {
		t.Errorf("load_ladder None must attach nothing: %v", empty)
	}
}
