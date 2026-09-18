// task10_open_questions_test.go — plan §Task 10 (2026-09-17-trust-boundary-
// hardening.md): open questions compile into the work queue.
//
// Law: every `open_questions` entry that names a contract reference (`blocks`
// or `applies_to`) produces a work-queue entry `resolve open question Q-…:
// <text>` ranked above generic index work when it names consensus-critical or
// untouched contracts. An empty (or reference-free) `open_questions` list
// leaves the queue byte-identical.
//
// The fixture model is written to the campaign's own protocol_model.json and
// the real `Plan` verb is driven, so the assertion is on the operator-visible
// work_queue, not on an internal helper.
package orchestrator

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// task10ModelTemplate is the Task 10 fixture. Rollup is the consensus-critical,
// untouched contract the open questions name; Alpha and Gateway are the other
// in-scope contracts. %s is the open_questions array under test.
const task10ModelTemplate = `{
 "protocol_id": "rollup-oq",
 "name": "Rollup OQ",
 "snapshot_id": "unpinned",
 "chains": ["ethereum"],
 "subsystems": ["rollup"],
 "contracts": [
  {"name": "Alpha", "path": "src/Alpha.sol", "role": "core", "in_scope": true,
   "entry_points": ["poke"]},
  {"name": "Gateway", "path": "src/Gateway.sol", "role": "peripheral",
   "in_scope": true, "entry_points": ["relay"]},
  {"name": "Rollup", "path": "src/Rollup.sol", "role": "core", "in_scope": true,
   "entry_points": ["propose"]}
 ],
 "actors": [
  {"id": "sequencer", "kind": "ROLE", "trust": "trusted", "can_upgrade": true}
 ],
 "assets": [],
 "liabilities": [],
 "privileges": [],
 "trust_boundaries": [],
 "relations": [],
 "state_machines": [],
 "economic_relations": [],
 "invariants": [
  {"id": "INV-001", "statement": "only the sequencer may propose a root",
   "applies_to": ["Rollup"], "kind": "authorization",
   "severity_if_broken": "critical"}
 ],
 "oracles": [],
 "upgrade_paths": [],
 "open_questions": %s
}`

// task10ModelWith renders the fixture with the given open_questions array.
func task10ModelWith(questions string) string {
	return fmt.Sprintf(task10ModelTemplate, questions)
}

// task10Questioning is the full fixture: one question naming a contract
// through `blocks`, one through `applies_to`, one already resolved, and one
// with no contract reference at all.
const task10Questioning = `[
  {"question": "is the rollup sequencer permissionless?", "blocks": ["Rollup"]},
  {"question": "does the gateway relay unauthenticated batches?",
   "applies_to": ["Gateway"]},
  {"question": "who owns the bridge?", "resolved": true, "blocks": ["Gateway"]},
  {"question": "is the audit report public?"}
 ]`

// task10ReferenceFree keeps only the questions that name no contract.
const task10ReferenceFree = `[
  {"question": "who owns the bridge?", "resolved": true, "blocks": ["Gateway"]},
  {"question": "is the audit report public?"}
 ]`

// task10Queue drives the real Plan verb over a campaign whose model artifact
// is the given document and returns the ordered work queue.
func task10Queue(t *testing.T, model string) []validation.Value {
	t.Helper()
	c, err := state.Init(t.TempDir(), "Rollup OQ Program", state.InitOpts{})
	if err != nil {
		t.Fatalf("init campaign: %v", err)
	}
	path := filepath.Join(c.ArtifactsDir, "protocol_model.json")
	if err := validation.WriteJson(path, portJSON(t, model), ""); err != nil {
		t.Fatalf("write model: %v", err)
	}
	o := New(c)
	planned, err := o.Plan(validation.VNull(), validation.VNull(), false)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return listAt(planned, "work_queue")
}

// TestOpenQuestionsCompileIntoWorkQueue is the Task 10 witness: a question
// naming a contract reference becomes a queue entry whose id it names, and it
// ranks in the top 3.
func TestOpenQuestionsCompileIntoWorkQueue(t *testing.T) {
	queue := task10Queue(t, task10ModelWith(task10Questioning))
	if len(queue) == 0 {
		t.Fatal("empty work queue")
	}
	idx := -1
	for i, row := range queue {
		q := strAt(row, "question")
		if !strings.Contains(q, "is the rollup sequencer permissionless?") {
			continue
		}
		idx = i
		id := strAt(row, "priority_id")
		want := "resolve open question " + id +
			": is the rollup sequencer permissionless?"
		if q != want {
			t.Errorf("queue row %d question = %q, want %q", i, q, want)
		}
	}
	if idx < 0 {
		t.Fatalf("the open question never reached the work queue: %s",
			validation.CanonCompact(validation.VArr(queue...)))
	}
	if idx >= 3 {
		t.Errorf("open question ranked at %d, want top 3: %s", idx,
			validation.CanonCompact(validation.VArr(queue...)))
	}
	// the applies_to reference queues too
	found := false
	for _, row := range queue {
		if strings.Contains(strAt(row, "question"),
			"does the gateway relay unauthenticated batches?") {
			found = true
		}
	}
	if !found {
		t.Errorf("the applies_to open question never reached the work queue")
	}
	// a resolved question and a reference-free question queue nothing
	for _, row := range queue {
		q := strAt(row, "question")
		if strings.Contains(q, "who owns the bridge?") {
			t.Errorf("a resolved open question was queued: %q", q)
		}
		if strings.Contains(q, "is the audit report public?") {
			t.Errorf("a reference-free open question was queued: %q", q)
		}
	}
}

// TestNoOpenQuestionsLeavesQueueUnchanged pins the other half of the law: a
// model whose open_questions carry no contract reference (or are resolved)
// produces the same queue as a model with an empty open_questions list.
func TestNoOpenQuestionsLeavesQueueUnchanged(t *testing.T) {
	refFree := task10Queue(t, task10ModelWith(task10ReferenceFree))
	empty := task10Queue(t, task10ModelWith("[]"))
	if len(refFree) != len(empty) {
		t.Fatalf("queue lengths differ: %d vs %d", len(refFree), len(empty))
	}
	for i := range refFree {
		if got, want := validation.CanonCompact(refFree[i]),
			validation.CanonCompact(empty[i]); got != want {
			t.Fatalf("queue row %d drifted: %s vs %s", i, got, want)
		}
		if strings.Contains(strAt(refFree[i], "question"),
			"resolve open question ") {
			t.Errorf("reference-free/resolved questions must not queue: %s",
				validation.CanonCompact(refFree[i]))
		}
	}
}
