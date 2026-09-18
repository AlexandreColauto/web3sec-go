package pipeline

import (
	"os"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// ---------------------------------------------------------------------------
// r40e — the pipeline package is classified DOCUMENTED ALREADY SAFE, and this
// file is the evidence. The refusal an operator can always hit is the honest
// one: grow the ledger a few events, then cut campaigns/<C>/events.jsonl to a
// shorter PREFIX so the state mirror is LONGER than the log — the next append
// refuses with "events.jsonl holds N event(s) but the state projection mirrors
// M ... run webv2 doctor".
//
// Why no unwind door here (state.AppendJsonlThenLog-style) at
// pipeline.go:715 / 792 / 858:
//
//  1. state.stages is the AUTHORITATIVE stage record, not a projection of
//     pipeline.* events. Nine production orchestrator call sites write a stage
//     status with NO event at all (orchestrator/scope.go:54,97,
//     index.go:90, triage.go:39,101, plan.go:137, model.go:70,
//     discovery.go:80, verify.go:93) — `webv2 scope`, `webv2 snapshot` and
//     every single-verb path mark stages this way — so "a stage record with no
//     pipeline.* event" is the tree's normal state, not a gap this package may
//     invent a rule against. doctor agrees: its mirror rebuild replaces ONLY
//     the events key (doctor.go:153-155) and carries the stages map across the
//     repair, whoever wrote it.
//  2. Nothing reads pipeline.* events. audit section 9 re-derives model-stage
//     completion from completion PROOFS over state.stages
//     (audit/sections/stagecompletions.go:29), and the resume path
//     (p.Completed) counts status=="done" only. A grep over the non-test tree
//     finds no reader of pipeline.stage_done / stage_failed / pipeline.blocked
//     outside this package.
//  3. The state write is not a silent flip: a refusal leaves either the
//     honest failure note (failStage's documented durable record, which the
//     retry overwrites) or a "done" record for a stage that really did run to
//     completion. Unwinding either would REWRITE the authoritative stage
//     ledger — erasing the only surviving record of the failure — on the
//     strength of a refusal in a SUPPLEMENTARY event.
//
// The pins below hold the package to what must be true instead: the phase
// keeps its own rules, verify does not get worse, a refusal can never retire a
// stage the ledger never recorded, and the event-free "done" shape this leaves
// is shown to be the same shape the orchestrator's own verbs produce.
// ---------------------------------------------------------------------------

// r40eEventCount counts one event type in the ledger.
func r40eEventCount(t *testing.T, c *state.Campaign, eventType string) int {
	t.Helper()
	evts, err := c.Events()
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	n := 0
	for _, e := range evts {
		if validation.ObjStr(e, "type") == eventType {
			n++
		}
	}
	return n
}

// r40ePipelineEvents counts every pipeline.* event in the ledger.
func r40ePipelineEvents(t *testing.T, c *state.Campaign) int {
	t.Helper()
	evts, err := c.Events()
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	n := 0
	for _, e := range evts {
		if strings.HasPrefix(validation.ObjStr(e, "type"), "pipeline.") {
			n++
		}
	}
	return n
}

// r40eVerify is the verify verdict's problem list, joined.
func r40eVerify(t *testing.T, c *state.Campaign) string {
	t.Helper()
	v, err := c.VerifyLog()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return strings.Join(v.Problems, " | ")
}

// r40eCutLedger grows the ledger a few events, then cuts events.jsonl to a
// shorter prefix so the state mirror is LONGER than the log. Returns the
// full bytes (the sanctioned out-of-band repair).
func r40eCutLedger(t *testing.T, c *state.Campaign) []byte {
	t.Helper()
	for i := 0; i < 3; i++ {
		data := validation.VObj(kv("note", vstr("r40e ledger growth")))
		if _, err := c.Log("note.added", nil, &data); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(c.EventsPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) < 3 {
		t.Fatalf("ledger too short to cut: %d line(s)", len(lines))
	}
	if err := os.WriteFile(c.EventsPath,
		[]byte(strings.Join(lines[:len(lines)-1], "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return raw
}

// r40eCompleted is p.Completed() (the resume path's skip set).
func r40eCompleted(t *testing.T, p *Pipeline) []string {
	t.Helper()
	got, err := p.Completed()
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// TestR40ERefusedStageFailedEventKeepsTheHonestFailureNote pins the failure
// shape: the stage's failure note survives (it is the only record of the
// failure), the phase is NOT advanced without its own event, verify does not
// get worse, and a "failed" stage can never be read as completed — the retry
// after the heal re-runs it and logs it once.
func TestR40ERefusedStageFailedEventKeepsTheHonestFailureNote(t *testing.T) {
	e := newEnv(t)
	useWiredSeams(t, false)
	p := New(e.c, e.o, map[string]Handler{"snapshot": e.snapHandler()})
	if _, err := p.Run(RunOpts{MaxStages: iptr(1)}); err != nil {
		t.Fatalf("healthy first run: %v", err)
	}
	if got := e.stageStatus(t, "scope"); got != "done" {
		t.Fatalf("scope = %q, want done", got)
	}
	raw := r40eCutLedger(t, e.c)
	verifyBefore := r40eVerify(t, e.c)
	_, err := p.Run(RunOpts{})
	if err == nil || !strings.Contains(err.Error(), "state projection mirrors") {
		t.Fatalf("ledger-door run err = %v (want the projection refusal)", err)
	}
	if got := e.stageStatus(t, "snapshot"); got != "failed" {
		t.Fatalf("snapshot stage = %q, want failed (the failure record is the "+
			"only trace the aborted run leaves)", got)
	}
	if note := e.stageNote(t, "snapshot"); !strings.Contains(note,
		"state projection mirrors") {
		t.Fatalf("the failure note lost the refusal text: %q", note)
	}
	st, serr := e.c.State()
	if serr != nil {
		t.Fatal(serr)
	}
	if got := validation.ObjStr(st, "phase"); got != "SCOPE" {
		t.Fatalf("phase = %q, want SCOPE: SetPhase unwound its own write, so "+
			"the phase must NOT ride a refused event", got)
	}
	if got := r40eVerify(t, e.c); got != verifyBefore {
		t.Fatalf("verify changed across the refusal:\n before %s\n after  %s",
			verifyBefore, got)
	}
	for _, sid := range r40eCompleted(t, p) {
		if sid == "snapshot" {
			t.Fatalf("a FAILED stage was read as completed: %v",
				r40eCompleted(t, p))
		}
	}
	if n := r40eEventCount(t, e.c, "pipeline.stage_failed"); n != 0 {
		t.Fatalf("pipeline.stage_failed events = %d, want 0", n)
	}
	// Repair, then the honest retry: the stage lands once, with its event.
	if err := os.WriteFile(e.c.EventsPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Run(RunOpts{}); err != nil {
		t.Fatalf("retry on a repaired ledger: %v", err)
	}
	if got := e.stageStatus(t, "snapshot"); got != "done" {
		t.Fatalf("snapshot stage after the retry = %q, want done", got)
	}
	if n := r40eEventCount(t, e.c, "pipeline.stage_done"); n != 3 {
		t.Fatalf("pipeline.stage_done events after the retry = %d, want 3 "+
			"(scope + snapshot + structural-index)", n)
	}
	if got := r40eVerify(t, e.c); got != "" {
		t.Fatalf("verify red after the heal: %s", got)
	}
}

// TestR40ERefusedStageDoneEventLeavesAnOrchestratorShapedRecord pins the
// "done" shape: with a handler that appends nothing and a phase that needs no
// advance, the refused pipeline.stage_done leaves the stage marked done — the
// SAME record the orchestrator's own verbs write with no event at all
// (asserted here from a healthy campaign, so the equivalence is observed, not
// claimed).
func TestR40ERefusedStageDoneEventLeavesAnOrchestratorShapedRecord(t *testing.T) {
	e := newEnv(t)
	useWiredSeams(t, false)
	p := New(e.c, e.o, map[string]Handler{})
	p.Handlers["scope"] = func(*state.Campaign) (validation.Value, error) {
		return vstr("scope done by hand"), nil
	}
	raw := r40eCutLedger(t, e.c)
	verifyBefore := r40eVerify(t, e.c)
	_, err := p.Run(RunOpts{Until: strPtr("scope")})
	if err == nil || !strings.Contains(err.Error(), "state projection mirrors") {
		t.Fatalf("ledger-door run err = %v (want the projection refusal)", err)
	}
	if got := e.stageStatus(t, "scope"); got != "done" {
		t.Fatalf("scope stage = %q, want done (the record is written before "+
			"the supplementary event)", got)
	}
	if n := r40eEventCount(t, e.c, "pipeline.stage_done"); n != 0 {
		t.Fatalf("pipeline.stage_done events = %d, want 0", n)
	}
	if got := r40eVerify(t, e.c); got != verifyBefore {
		t.Fatalf("verify changed across the refusal:\n before %s\n after  %s",
			verifyBefore, got)
	}
	// The state record alone now retires the stage (Completed reads
	// state.stages): this is the residue, and it is derived — a retry on the
	// healed ledger skips the stage and re-logs nothing for it.
	if got := r40eCompleted(t, p); len(got) != 1 || got[0] != "scope" {
		t.Fatalf("Completed = %v, want [scope] (state is the resume truth)", got)
	}
	if err := os.WriteFile(e.c.EventsPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Run(RunOpts{Until: strPtr("scope")}); err != nil {
		t.Fatalf("retry on a repaired ledger: %v", err)
	}
	if n := r40eEventCount(t, e.c, "pipeline.stage_done"); n != 0 {
		t.Fatalf("the healed retry re-logged the already-done stage: %d event(s)",
			n)
	}
	// OBSERVED EQUIVALENCE: on a healthy campaign the orchestrator's own
	// verbs write the same record with no event. `scope` here is written by
	// the fake twin of Orchestrator.Scope (orchestrator/scope.go:54); the
	// production sites are the nine listed at the top of this file.
	fresh := newEnv(t)
	useWiredSeams(t, false)
	if _, err := fresh.o.Scope(); err != nil {
		t.Fatalf("orchestrator Scope: %v", err)
	}
	if got := fresh.stageStatus(t, "scope"); got != "done" {
		t.Fatalf("orchestrator wrote scope = %q, want done", got)
	}
	if n := r40ePipelineEvents(t, fresh.c); n != 0 {
		t.Fatalf("the orchestrator path logged %d pipeline.* event(s) for the "+
			"stage it marked done", n)
	}
	if got := r40eVerify(t, fresh.c); got != "" {
		t.Fatalf("verify red after the orchestrator's own event-free stage "+
			"write: %s", got)
	}
}

// TestR40ERefusedBlockedEventKeepsTheNeedsModelRecord is the third pipeline
// site (pipeline.go:858, blockModel). It is only reachable once the earlier
// stages are already recorded, so the fixture runs the lifecycle once on a
// healthy ledger and cuts afterwards: the retry's only append is the
// pipeline.blocked one, and the stage keeps the needs-model record the run
// announced while attempts advances in the state — the documented residue of
// a record whose supplementary event was refused. No stage is retired by the
// refusal (nothing new becomes "done"), and the retry after the heal logs
// exactly one more blocked event.
func TestR40ERefusedBlockedEventKeepsTheNeedsModelRecord(t *testing.T) {
	e := newEnv(t)
	useWiredSeams(t, false)
	p := New(e.c, e.o, map[string]Handler{"snapshot": e.snapHandler()})
	if _, err := p.Run(RunOpts{}); err != nil {
		t.Fatalf("healthy first run: %v", err)
	}
	doneBefore := strings.Join(r40eCompleted(t, p), ",")
	if n := r40eEventCount(t, e.c, "pipeline.blocked"); n != 1 {
		t.Fatalf("healthy pipeline.blocked events = %d, want 1", n)
	}
	raw := r40eCutLedger(t, e.c)
	verifyBefore := r40eVerify(t, e.c)
	_, err := p.Run(RunOpts{})
	if err == nil || !strings.Contains(err.Error(), "state projection mirrors") {
		t.Fatalf("ledger-door run err = %v (want the projection refusal)", err)
	}
	if got := e.stageStatus(t, "protocol-model"); got != "needs-model" {
		t.Fatalf("protocol-model = %q, want needs-model", got)
	}
	if n := r40eEventCount(t, e.c, "pipeline.blocked"); n != 1 {
		t.Fatalf("pipeline.blocked events = %d, want 1 (the refusal added none)",
			n)
	}
	if got := strings.Join(r40eCompleted(t, p), ","); got != doneBefore {
		t.Fatalf("the refusal retired a stage: %q -> %q", doneBefore, got)
	}
	if got := r40eVerify(t, e.c); got != verifyBefore {
		t.Fatalf("verify changed across the refusal:\n before %s\n after  %s",
			verifyBefore, got)
	}
	// Repair, then the honest retry: the block lands once more.
	if err := os.WriteFile(e.c.EventsPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	summary, err := p.Run(RunOpts{})
	if err != nil {
		t.Fatalf("retry on a repaired ledger: %v", err)
	}
	if got := validation.ObjStr(summary, "status"); got != "needs-model" {
		t.Fatalf("retry status = %q, want needs-model", got)
	}
	if got := r40eEventCount(t, e.c, "pipeline.blocked"); got != 2 {
		t.Fatalf("pipeline.blocked events after the retry = %d, want 2", got)
	}
	if got := r40eVerify(t, e.c); got != "" {
		t.Fatalf("verify red after the heal: %s", got)
	}
}

// TestR40ERefusedAutoCompletedEventKeepsTheDerivedRecord is the fourth stage
// site (pipeline.go:816/827, blockModel's completion-proof branch): a stage
// the proof marks done is recorded in state.stages and its
// pipeline.stage_auto_completed append is the SAME pair as the other three.
// The refusal leaves the derived record (the proof still holds, so the next
// run derives it again) and adds no event; the healed retry logs it once.
func TestR40ERefusedAutoCompletedEventKeepsTheDerivedRecord(t *testing.T) {
	e := newEnv(t)
	useWiredSeams(t, false)
	p := New(e.c, e.o, map[string]Handler{"snapshot": e.snapHandler()})
	if _, err := p.Run(RunOpts{}); err != nil {
		t.Fatalf("healthy first run: %v", err)
	}
	if got := e.stageStatus(t, "protocol-model"); got != "needs-model" {
		t.Fatalf("protocol-model = %q, want needs-model", got)
	}
	raw := r40eCutLedger(t, e.c)
	verifyBefore := r40eVerify(t, e.c)
	// The completion proof now holds: the next run DERIVES the stage done.
	useWiredSeams(t, true)
	_, err := p.Run(RunOpts{})
	if err == nil || !strings.Contains(err.Error(), "state projection mirrors") {
		t.Fatalf("ledger-door run err = %v (want the projection refusal)", err)
	}
	if got := e.stageStatus(t, "protocol-model"); got != "done" {
		t.Fatalf("protocol-model = %q, want done", got)
	}
	if n := r40eEventCount(t, e.c, "pipeline.stage_auto_completed"); n != 0 {
		t.Fatalf("pipeline.stage_auto_completed events = %d, want 0", n)
	}
	if got := r40eVerify(t, e.c); got != verifyBefore {
		t.Fatalf("verify changed across the refusal:\n before %s\n after  %s",
			verifyBefore, got)
	}
	if err := os.WriteFile(e.c.EventsPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Run(RunOpts{}); err != nil {
		t.Fatalf("retry on a repaired ledger: %v", err)
	}
	// The healed retry does NOT re-emit the append: the state record alone
	// retires the stage (Completed reads state.stages), so the derived
	// "done" stays and its informational event is never written. That is
	// the whole residue of this site — the record is TRUE and independently
	// re-derivable from the proof the audit reads, and nothing consumes the
	// event.
	if n := r40eEventCount(t, e.c, "pipeline.stage_auto_completed"); n != 0 {
		t.Fatalf("pipeline.stage_auto_completed events after the heal = %d, "+
			"want 0 (the stage is already done in state)", n)
	}
	if got := e.stageStatus(t, "protocol-model"); got != "done" {
		t.Fatalf("protocol-model after the heal = %q, want done", got)
	}
	if got := r40eVerify(t, e.c); got != "" {
		t.Fatalf("verify red after the heal: %s", got)
	}
}

// TestR40EHealthyPipelinesStillWork is the happy-path guard: the reachable
// refusal changes nothing for a healthy ledger (golden shapes included).
func TestR40EHealthyPipelinesStillWork(t *testing.T) {
	e := newEnv(t)
	useWiredSeams(t, false)
	p := New(e.c, e.o, map[string]Handler{"snapshot": e.snapHandler()})
	summary, err := p.Run(RunOpts{})
	if err != nil {
		t.Fatalf("honest run refused: %v", err)
	}
	if got := validation.ObjStr(summary, "status"); got != "needs-model" {
		t.Fatalf("status = %q, want needs-model", got)
	}
	if got := e.stageStatus(t, "protocol-model"); got != "needs-model" {
		t.Fatalf("protocol-model = %q, want needs-model", got)
	}
	if n := r40eEventCount(t, e.c, "pipeline.stage_done"); n != 3 {
		t.Fatalf("pipeline.stage_done events = %d, want 3", n)
	}
	if n := r40eEventCount(t, e.c, "pipeline.blocked"); n != 1 {
		t.Fatalf("pipeline.blocked events = %d, want 1", n)
	}
	if got := r40eVerify(t, e.c); got != "" {
		t.Fatalf("verify red after an honest run: %s", got)
	}
}
