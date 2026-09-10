package cli

// cmd_prioritize: `webv2 prioritize <campaign>` — the deterministic triage
// view (cli.py cmd_prioritize verbatim):
//   [{queue_slot:>5}] prior={score:.2f} cost={validation_cost:>9}  {finding_id}

import (
	"fmt"

	"websec/internal/orchestrator"
	"websec/internal/state"
	"websec/internal/validation"
)

func runPrioritize(root string, args []string, r *Runner) int {
	if helpRequested(r.Out, "prioritize", args) {
		return 0
	}

	ensureSeams()
	pos, err := plainPositionals(args, "prioritize", 1, "campaign")
	if err != nil {
		return r.fail(root, err)
	}
	c, err := state.Open(root, pos[0])
	if err != nil {
		return r.withErr(root, func() error { return err })
	}
	o := orchestrator.New(c)
	rows, err := o.TriageAll()
	if err != nil {
		return r.withErr(root, func() error { return err })
	}
	for _, t := range rows.A {
		fmt.Fprintf(r.Out, "[%s] prior=%s cost=%s  %s\n",
			pyRight(objStr(t, "queue_slot"), 5),
			pyScore2(objAt(objAt(t, "prior"), "score")),
			pyRight(objStr(t, "validation_cost"), 9),
			objStr(t, "finding_id"))
	}
	return 0
}

func init() {
	register(command{ord: 6, name: "prioritize",
		line: "prioritize <campaign>               deterministic triage view",
		run:  runPrioritize})
}

// pyIntText is Python's f"{n}" for a JSON integer value.
func pyIntText(v validation.Value) string {
	if v.Kind == validation.Int {
		return validation.IntText(v)
	}
	return scalarStr(v)
}
