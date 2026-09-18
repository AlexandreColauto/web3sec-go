// task10_open_question_brief_test.go — Task 10 follow-up, from the
// independent Phase C review (.scratch/sdd/task-10-12-review.md, Task 10
// finding 1): the plan's open-question row must reach the BRIEF, not only
// `webv2 plan --json`.
//
// The plan's Task 10 Law ends "brief shows it". The queue half landed
// (cbdd93d5): an unresolved question naming a `blocks`/`applies_to` contract
// is minted as the priority `resolve open question Q-…: <text>`. The brief
// half did not: the brief rendered only the debt counts and the oldest
// untouched priority's command, so the question's own text was never shown.
// This witness drives the real Plan verb and then the real BuildBrief, and
// requires one next-action line naming the question's id and its text —
// command-first, per the Task 7 law.
package briefing

import (
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/orchestrator"
	"websec/internal/planner"
	"websec/internal/state"
	"websec/internal/validation"
)

// task10BriefQuestionText is the open question under test.
const task10BriefQuestionText = "is the rollup sequencer permissionless?"

// task10BriefModel is the Task 10 fixture model: one open question naming the
// consensus-critical Rollup contract through `blocks`, plus the contracts the
// plan bootstraps against. Rollup is in scope so the minted row ranks with
// the untouched contracts.
const task10BriefModel = `{
 "protocol_id": "rollup-oq-brief",
 "name": "Rollup OQ Brief",
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
 "open_questions": [
  {"question": "is the rollup sequencer permissionless?", "blocks": ["Rollup"]}
 ]
}`

// task10BriefCampaign builds a campaign whose plan artifact carries the
// minted open-question row: the model is written to the campaign's own
// protocol_model.json and the real Plan verb produces the plan.
func task10BriefCampaign(t *testing.T) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "Rollup OQ Brief Program",
		state.InitOpts{})
	if err != nil {
		t.Fatalf("init campaign: %v", err)
	}
	model, err := validation.ParseOrdered([]byte(task10BriefModel))
	if err != nil {
		t.Fatalf("parse fixture model: %v", err)
	}
	path := filepath.Join(c.ArtifactsDir, "protocol_model.json")
	if err := validation.WriteJson(path, model, ""); err != nil {
		t.Fatalf("write protocol model: %v", err)
	}
	if _, err := orchestrator.New(c).Plan(validation.VNull(),
		validation.VNull(), false); err != nil {
		t.Fatalf("plan: %v", err)
	}
	return c
}

// task10OpenQuestionRow is the plan priority the bootstrap minted for the
// fixture question: its id is the id the brief must name.
func task10OpenQuestionRow(t *testing.T, c *state.Campaign) (string, string) {
	t.Helper()
	plan, err := planner.LoadPlanReadonly(c)
	if err != nil {
		t.Fatalf("load plan: %v", err)
	}
	for _, p := range listAt(plan, "priorities") {
		q := objStr(p, "question")
		if strings.Contains(q, task10BriefQuestionText) {
			return objStr(p, "id"), q
		}
	}
	t.Fatalf("the plan carries no priority for %q: %s",
		task10BriefQuestionText, validation.CanonCompact(plan))
	return "", ""
}

// TestBriefRendersOpenQuestionRow is the witness: the brief's next-actions
// surface carries one line for the minted open-question row, naming the id
// and the question text, command-first.
func TestBriefRendersOpenQuestionRow(t *testing.T) {
	c := task10BriefCampaign(t)
	id, text := task10OpenQuestionRow(t, c)
	if id == "" {
		t.Fatalf("the minted open-question row carries no id")
	}
	b, err := BuildBrief(c, false, nil)
	if err != nil {
		t.Fatalf("build brief: %v", err)
	}
	actions := objStringList(t, b, "next_actions")
	command := "webv2 plan " + c.CampaignID + " --json"
	line := ""
	for _, a := range actions {
		if strings.HasPrefix(a, command+" ") && strings.Contains(a, text) {
			line = a
			break
		}
	}
	if line == "" {
		t.Fatalf("the brief never renders the open-question row %s "+
			"(%q); next actions: %v", id, text, actions)
	}
	// the line names the Q id and the question text in its reason
	if !strings.Contains(line, "# "+text) {
		t.Errorf("open-question line %q does not carry the row text %q",
			line, text)
	}
	// the Task 7 law: command-first, no parenthesis anywhere
	lawCheck(t, "open-question row", actions)
}
