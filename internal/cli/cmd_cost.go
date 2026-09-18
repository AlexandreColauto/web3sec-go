// cmd_cost: `webv2 cost <campaign> --kind K --amount USD [--trajectory T]
// [--stage S] [--actor A] [--note N] [--finding F]` — record one
// operator-reported cost row. cli.py cmd_cost verbatim.
package cli

import (
	"fmt"
	"strconv"
	"strings"

	"websec/internal/costs"
	"websec/internal/validation"
)

const t26CostUsage = `usage: webv2 cost [-h] --kind {model,compute,human-review} --amount AMOUNT
                  [--trajectory TRAJECTORY] [--stage STAGE] [--actor ACTOR]
                  [--note NOTE] [--finding FINDING] [--lens LENS]
                  campaign
`

const t26CostHelp = t26CostUsage + `
positional arguments:
  campaign

options:
  -h, --help            show this help message and exit
  --kind {model,compute,human-review}
  --amount AMOUNT
  --trajectory TRAJECTORY
  --stage STAGE
  --actor ACTOR
  --note NOTE
  --finding FINDING
  --lens LENS           G13 attribution: the check family the spend served
                        (L-01 .. L-99); omit when unknown — the row then
                        carries no lens and bills to "unattributed"
`

// costArgs is the parsed command line (argparse: --actor defaults to
// "operator").
type costArgs struct {
	campaign   string
	kind       string
	amount     float64
	trajectory *string
	stage      *string
	actor      string
	note       *string
	finding    *string
	lens       string
}

func runCost(root string, args []string, r *Runner) error {
	ensureSeams()
	a, err := parseCost(args, r)
	if err != nil || a == nil {
		return err
	}
	c, err := t14Open(root, a.campaign)
	if err != nil {
		return err
	}
	e, err := costs.RecordCost(c, costs.RecordOpts{
		Kind: a.kind, AmountUSD: a.amount, Trajectory: a.trajectory,
		Stage: a.stage, Actor: a.actor, Note: a.note, FindingID: a.finding,
		Lens: a.lens})
	if err != nil {
		return err
	}
	line := "recorded " + validation.ObjStr(e, "cost_id") + " " + validation.ObjStr(e, "kind") +
		" $" + pyFixed2(objFlt(e, "amount_usd"))
	if traj := validation.ObjStr(e, "trajectory"); traj != "" {
		line += " trajectory=" + traj
	}
	if lens := validation.ObjStr(e, "lens"); lens != "" {
		line += " lens=" + lens
	}
	fmt.Fprintln(r.Out, line)
	return nil
}

// parseCost is the argparse layer: campaign, --kind/--amount required.
func parseCost(args []string, r *Runner) (*costArgs, error) {
	a := &costArgs{actor: "operator"}
	var pos []string
	seenKind, seenAmount := false, false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-h" || arg == "--help" {
			fmt.Fprint(r.Out, t26CostHelp)
			return nil, nil
		}
		name, val, hasVal := splitFlag(arg)
		switch name {
		case "--kind", "--amount", "--trajectory", "--stage", "--actor",
			"--note", "--finding", "--lens":
			if !hasVal {
				if i+1 >= len(args) {
					return nil, t14ArgparseErr(t26CostUsage, "cost",
						"argument %s: expected one argument", name)
				}
				val = args[i+1]
				i++
			}
		default:
			if strings.HasPrefix(arg, "-") && !isNegNumberCLI(arg) {
				return nil, t14Unrecognized(arg)
			}
			pos = append(pos, arg)
			continue
		}
		switch name {
		case "--kind":
			if !costKindChoice(val) {
				return nil, t14ArgparseErr(t26CostUsage, "cost",
					"argument --kind: invalid choice: %s (choose from "+
						"'model', 'compute', 'human-review')",
					validation.PyReprStr(val))
			}
			a.kind, seenKind = val, true
		case "--amount":
			f, ferr := strconv.ParseFloat(strings.TrimSpace(val), 64)
			if ferr != nil {
				return nil, t14ArgparseErr(t26CostUsage, "cost",
					"argument --amount: invalid float value: %s",
					validation.PyReprStr(val))
			}
			a.amount, seenAmount = f, true
		case "--trajectory":
			a.trajectory = &val
		case "--stage":
			a.stage = &val
		case "--actor":
			a.actor = val
		case "--note":
			a.note = &val
		case "--finding":
			a.finding = &val
		case "--lens":
			if !costLensShape(val) {
				return nil, t14ArgparseErr(t26CostUsage, "cost",
					"argument --lens: invalid lens id: %s "+
						"(want L-01 .. L-99)",
					validation.PyReprStr(val))
			}
			a.lens = val
		}
	}
	var missing []string
	if len(pos) == 0 {
		missing = append(missing, "campaign")
	}
	if !seenKind {
		missing = append(missing, "--kind")
	}
	if !seenAmount {
		missing = append(missing, "--amount")
	}
	if len(missing) > 0 {
		return nil, t14ArgparseErr(t26CostUsage, "cost",
			"the following arguments are required: %s",
			strings.Join(missing, ", "))
	}
	if len(pos) > 1 {
		return nil, t14Unrecognized(strings.Join(pos[1:], " "))
	}
	a.campaign = pos[0]
	return a, nil
}

func costKindChoice(k string) bool {
	for _, c := range costs.CostKinds {
		if c == k {
			return true
		}
	}
	return false
}

// costLensShape is the --lens typo guard: L-NN. The library stays
// permissive (operator-reported, verbatim); the CLI rejects what cannot
// be a lens id so a typo never silently bills to "unattributed".
func costLensShape(lens string) bool {
	if len(lens) != 4 || lens[0] != 'L' || lens[1] != '-' {
		return false
	}
	return lens[2] >= '0' && lens[2] <= '9' &&
		lens[3] >= '0' && lens[3] <= '9'
}

func init() {
	register(command{ord: 11, name: "cost",
		line: `cost <campaign> --kind K --amount USD [--trajectory T] [--actor A]  record an operator-reported cost row`,
		run: func(root string, args []string, r *Runner) int {
			return t14Dispatch(root, r, func() error {
				return runCost(root, args, r)
			})
		}})
}
