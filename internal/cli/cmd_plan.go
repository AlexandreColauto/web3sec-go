package cli

// cmd_plan: `webv2 plan <campaign> [file] [--json] [--rebuild]` — load a
// campaign plan (or derive it from the model) plus the structural
// reachability report. A plan already on disk is a READ-ONLY query; only
// --rebuild writes (and archives the outgoing plan first). cli.py cmd_plan
// verbatim.

import (
	"fmt"
	"io"
	"strings"

	"websec/internal/orchestrator"
	"websec/internal/planner"
	"websec/internal/state"
	"websec/internal/validation"
)

const t14PlanUsage = `usage: webv2 plan [-h] [--rebuild] [--json] campaign [file]
`

const t14PlanHelp = `usage: webv2 plan [-h] [--rebuild] [--json] campaign [file]

positional arguments:
  campaign
  file

options:
  -h, --help  show this help message and exit
  --rebuild   regenerate/replace the plan; the outgoing plan is archived as
              artifacts/superseded/campaign_plan.<NNNN>.json and registered as
              plan.superseded
  --json
`

// planNote is the read-only view note (stderr, before the view).
const planNote = "plan: existing plan returned unchanged (read-only view) — " +
	"add --rebuild to regenerate (the current plan is archived)\n"

func runPlan(root string, args []string, r *Runner) error {
	var pos []string
	asJSON, rebuild := false, false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-h" || a == "--help":
			fmt.Fprint(r.Out, t14PlanHelp)
			return nil
		case a == "--json":
			asJSON = true
		case a == "--rebuild":
			rebuild = true
		case strings.HasPrefix(a, "-"):
			return t14Unrecognized(a)
		default:
			pos = append(pos, a)
		}
	}
	if len(pos) < 1 {
		return t14ArgparseErr(t14PlanUsage, "plan",
			"the following arguments are required: campaign")
	}
	if len(pos) > 2 {
		return t14Unrecognized(strings.Join(pos[2:], " "))
	}
	c, err := t14Open(root, pos[0])
	if err != nil {
		return err
	}
	plan := validation.VNull()
	if len(pos) == 2 {
		text, err := t14ReadText(pos[1])
		if err != nil {
			return err
		}
		if plan, err = t14ParseJSON(text); err != nil {
			return err
		}
	}
	res, err := orchestrator.New(c).Plan(plan, validation.VNull(), rebuild)
	if err != nil {
		return t14ExitErr(2, "plan failed: %s\n", err)
	}
	if objAt(res, "read_only").B {
		fmt.Fprint(r.Err, planNote)
	}
	return planOutput(c, res, r.Out, asJSON)
}

// planOutput renders the plan view: JSON when --json, else the operator text.
func planOutput(c *state.Campaign, res validation.Value, stdout io.Writer,
	asJSON bool) error {
	p, perr := planner.LoadPlanReadonly(c)
	if perr != nil {
		p = validation.VNull() // cli.py: FileNotFoundError -> p = None
	}
	if asJSON {
		return planOutputJSON(c, res, p, stdout)
	}
	return planOutputText(c, res, p, stdout)
}

// planOutputJSON is the --json branch: the lens checklist and the divergence
// status are appended to the plan response, then the whole thing is dumped.
func planOutputJSON(c *state.Campaign, res, p validation.Value,
	stdout io.Writer) error {
	if p.Kind != validation.Obj {
		res.O = t14SetOrAppend(res.O, "lenses", validation.VArr())
		res.O = t14SetOrAppend(res.O, "divergence", validation.VNull())
		t14PrintJSON(stdout, res)
		return nil
	}
	res.O = t14SetOrAppend(res.O, "lenses", t14List(p, "lenses"))
	div, err := planner.DivergenceStatusFor(c, p, nil)
	if err != nil {
		return err
	}
	res.O = t14SetOrAppend(res.O, "divergence", div)
	t14PrintJSON(stdout, res)
	return nil
}

// planOutputText is the human view: work queue, reachability, the lens
// checklist and the divergence gate.
func planOutputText(c *state.Campaign, res, p validation.Value,
	stdout io.Writer) error {
	planOutputQueue(res, stdout)
	planOutputReachability(res, stdout)
	if p.Kind != validation.Obj {
		return nil
	}
	div, err := planner.DivergenceStatusFor(c, p, nil)
	if err != nil {
		return err
	}
	planOutputLenses(p, stdout)
	planOutputGate(div, stdout)
	return nil
}

// planOutputQueue is the `plan: N queued priorities` block.
func planOutputQueue(res validation.Value, stdout io.Writer) {
	queue := objAt(res, "work_queue")
	fmt.Fprintf(stdout, "plan: %d queued priorities\n", t14PyLen(queue))
	for _, q := range queue.A {
		// cli.py names the row: q.get('priority_id', '?') — work_queue
		// always sets priority_id, so the marker is the row's id.
		qid := objStr(q, "priority_id")
		if qid == "" {
			qid = "?"
		}
		question := objAt(q, "question")
		if question.Kind == validation.Null {
			question = q
		}
		fmt.Fprintf(stdout, "  [%s] %s\n", qid, scalarStr(question))
	}
}

// planOutputReachability is the E5/E6 unreachable-prerequisite block.
func planOutputReachability(res validation.Value, stdout io.Writer) {
	reach := objAt(res, "reachability")
	fmt.Fprintf(stdout, "  reachability: %s\n", objStr(reach, "note"))
	for _, lvl := range []string{"e5", "e6"} {
		for _, miss := range objAt(reach, lvl).A {
			fmt.Fprintf(stdout, "    %s unreachable: %s\n",
				strings.ToUpper(lvl), scalarStr(miss))
		}
	}
}

// planOutputLenses is the lens checklist (task 7's divergence contract).
func planOutputLenses(p validation.Value, stdout io.Writer) {
	for _, l := range t14List(p, "lenses").A {
		mark := "x"
		if objStr(l, "status") == "open" {
			mark = " "
		}
		fmt.Fprintf(stdout, "  [%s] %s %s (%s): %s\n", mark, objStr(l, "id"),
			objStr(l, "lens"), scalarStr(objAt(l, "surface")),
			objStr(l, "status"))
		fmt.Fprintf(stdout, "    families: %s\n",
			t14Join(t14List(l, "families")))
		fmt.Fprintf(stdout, "    attested: %s\n",
			t14Join(t14List(l, "families_checked")))
		if rr := objAt(l, "reopen_reason"); t14Truthy(rr) {
			fmt.Fprintf(stdout, "    REOPENED: %s\n", scalarStr(rr))
		}
	}
}

// planOutputGate is the divergence gate state and its first five blockers.
func planOutputGate(div validation.Value, stdout io.Writer) {
	gateState := "OPEN"
	if objAt(div, "closed").B {
		gateState = "CLOSED"
	}
	fmt.Fprintf(stdout, "  Divergence gate: %s — %d distinct bug class(es) "+
		"(min %d)\n", gateState, t14PyLen(objAt(div, "named_classes")),
		planner.MinDistinctClasses)
	if objAt(div, "closed").B {
		return
	}
	for i, m := range objAt(div, "missing").A {
		if i >= 5 {
			return
		}
		fmt.Fprintf(stdout, "    - %s: %s\n", objStr(m, "subject"),
			t14Truncate(objStr(m, "what"), 100))
	}
}

func init() {
	register(command{ord: 34, name: "plan",
		line: `plan <campaign> [file] [--json]    load/query the campaign plan`,
		run: func(root string, args []string, r *Runner) int {
			return t14Dispatch(root, r, func() error {
				return runPlan(root, args, r)
			})
		}})
}
