package cli

// cmd_budget: `webv2 budget <campaign> [--set USD] [--set-discovery N]
// [--clear] [--actor A] [--json]` — the cost position against the operator's
// ceiling plus the deterministic discovery ceiling. cli.py cmd_budget
// verbatim over costs.budget_status (T26).

import (
	"fmt"
	"strconv"
	"strings"

	"websec/internal/costs"
	"websec/internal/state"
	"websec/internal/validation"
)

const t14BudgetUsage = `usage: webv2 budget [-h] [--set SET] [--set-discovery N] [--clear]
                    [--actor ACTOR] [--json]
                    campaign
`

const t14BudgetHelp = `usage: webv2 budget [-h] [--set SET] [--set-discovery N] [--clear]
                    [--actor ACTOR] [--json]
                    campaign

positional arguments:
  campaign

options:
  -h, --help         show this help message and exit
  --set SET          set max_total_cost_usd (USD)
  --set-discovery N  set max_discovery_findings (the deterministic discovery
                     ceiling; --actor names the decision)
  --clear            remove the ceiling (unbounded)
  --actor ACTOR      who decides (recorded with the change)
  --json
`

// budgetArgs is the parsed command line.
type budgetArgs struct {
	campaign string
	set      *float64
	setDisc  *int64
	clear    bool
	actor    string
	asJSON   bool
}

func runBudget(root string, args []string, r *Runner) error {
	a, err := parseBudget(args, r)
	if err != nil || a == nil {
		return err
	}
	c, err := t14Open(root, a.campaign)
	if err != nil {
		return err
	}
	if a.setDisc != nil {
		return budgetSetDiscovery(c, a, r)
	}
	return budgetShow(c, a, r)
}

// parseBudget is the argparse layer (required: campaign).
func parseBudget(args []string, r *Runner) (*budgetArgs, error) {
	a := &budgetArgs{}
	var pos []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "-h", "--help":
			fmt.Fprint(r.Out, t14BudgetHelp)
			return nil, nil
		case "--clear":
			a.clear = true
			continue
		case "--json":
			a.asJSON = true
			continue
		}
		name, val, hasVal := splitFlag(arg)
		switch name {
		case "--set", "--set-discovery", "--actor":
			if !hasVal {
				if i+1 >= len(args) || looksLikeOption(args[i+1]) {
					return nil, t14ArgparseErr(t14BudgetUsage, "budget",
						"argument %s: expected one argument", name)
				}
				val = args[i+1]
				i++
			}
		}
		switch name {
		case "--set":
			f, ferr := strconv.ParseFloat(strings.TrimSpace(val), 64)
			if ferr != nil {
				return nil, t14ArgparseErr(t14BudgetUsage, "budget",
					"argument --set: invalid float value: %s",
					validation.PyReprStr(val))
			}
			a.set = &f
		case "--set-discovery":
			n, nerr := strconv.ParseInt(strings.TrimSpace(val), 10, 64)
			if nerr != nil {
				return nil, t14ArgparseErr(t14BudgetUsage, "budget",
					"argument --set-discovery: invalid int value: %s",
					validation.PyReprStr(val))
			}
			a.setDisc = &n
		case "--actor":
			a.actor = val
		default:
			if strings.HasPrefix(arg, "-") {
				return nil, t14Unrecognized(arg)
			}
			pos = append(pos, arg)
		}
	}
	if len(pos) < 1 {
		return nil, t14ArgparseErr(t14BudgetUsage, "budget",
			"the following arguments are required: campaign")
	}
	if len(pos) > 1 {
		return nil, t14Unrecognized(strings.Join(pos[1:], " "))
	}
	// argparse declares --clear and --set as mutually exclusive: silently
	// honouring one of them (--set won, so --clear did nothing) hid the
	// mistake instead of reporting it.
	if a.clear && a.set != nil {
		return nil, t14ArgparseErr(t14BudgetUsage, "budget",
			"argument --clear: not allowed with argument --set")
	}
	a.campaign = pos[0]
	return a, nil
}

// splitFlag splits --name=value into (name, value, true).
func splitFlag(arg string) (string, string, bool) {
	if !strings.HasPrefix(arg, "--") {
		return arg, "", false
	}
	if name, val, ok := strings.Cut(arg, "="); ok {
		return name, val, true
	}
	return arg, "", false
}

// isNegNumberCLI is argparse's _negative_number_matcher: when a parser
// declares no options that look like negative numbers (none of ours do),
// `-1` and `-1.5` are positionals/values, not flags.
func isNegNumberCLI(arg string) bool {
	if len(arg) < 2 || arg[0] != '-' {
		return false
	}
	body := arg[1:]
	dot := -1
	for i := 0; i < len(body); i++ {
		switch {
		case body[i] >= '0' && body[i] <= '9':
		case body[i] == '.' && dot < 0:
			dot = i
		default:
			return false
		}
	}
	return body != "" && body != "."
}

// budgetSetDiscovery is the --set-discovery branch.
func budgetSetDiscovery(c *state.Campaign, a *budgetArgs, r *Runner) error {
	if a.set != nil || a.clear {
		return t14ExitErr(2, "budget: --set-discovery cannot be combined "+
			"with --set/--clear\n")
	}
	actor := a.actor
	if actor == "" {
		actor = "unknown"
	}
	if _, err := c.SetDiscoveryBudget(*a.setDisc, actor); err != nil {
		return t14ExitErr(2, "budget failed: %s\n", err)
	}
	disc, err := c.Budget()
	if err != nil {
		return err
	}
	fmt.Fprintf(r.Out, "discovery: max_discovery_findings -> %d "+
		"(%d risen so far; actor: %s)\n",
		objInt(disc, "max_discovery_findings"),
		objInt(disc, "discovery_findings_so_far"), actor)
	return nil
}

// budgetShow sets the ceiling when asked, then prints the cost position.
func budgetShow(c *state.Campaign, a *budgetArgs, r *Runner) error {
	actor := a.actor
	if actor == "" {
		actor = "unknown"
	}
	if a.clear || a.set != nil {
		// r15 P2: a damaged cost mirror used to half-commit the ceiling
		// (state + budget.limit_set event landed, then the status read
		// died and the operator heard only failure — the limit WAS set).
		// Refuse BEFORE mutating anything: no silent half-landings.
		if probs := costs.CostMirrorProblems(c); len(probs) > 0 {
			return fmt.Errorf("cost projection is damaged (%d problem(s), "+
				"first: %s) — the ceiling was NOT set; `webv2 audit` "+
				"lists every problem, repair first", len(probs), probs[0])
		}
		var ceil *validation.Value
		if a.set != nil {
			v := validation.VFloat(*a.set)
			ceil = &v
		}
		if _, err := c.SetCostCeiling(ceil, actor); err != nil {
			return err
		}
	}
	st, err := costs.BudgetStatus(c)
	if err != nil {
		return err
	}
	if a.asJSON {
		t14PrintJSON(r.Out, st)
		return nil
	}
	disc, err := c.Budget()
	if err != nil {
		return err
	}
	if validation.ObjStr(st, "status") == "no-limit" {
		fmt.Fprintf(r.Out, "cost: $%s spent — NO CEILING SET (unbounded; "+
			"set one with `webv2 budget %s --set USD --actor <name>`)\n",
			t14Money(objFlt(st, "spent_usd")), c.CampaignID)
	} else {
		pos := "within limit"
		if validation.ObjStr(st, "status") == "exceeded" {
			pos = "EXCEEDED by $" + t14Money(objFlt(st, "over_by_usd"))
		}
		fmt.Fprintf(r.Out, "cost: $%s spent vs $%s limit — %s ($%s "+
			"remaining)\n", t14Money(objFlt(st, "spent_usd")),
			t14Money(objFlt(st, "limit_usd")), pos,
			t14Money(objFlt(st, "remaining_usd")))
	}
	fmt.Fprintf(r.Out, "discovery: %d/%d findings risen so far (ceiling: "+
		"webv2 budget %s --set-discovery N)\n",
		objInt(disc, "discovery_findings_so_far"),
		objInt(disc, "max_discovery_findings"), c.CampaignID)
	return nil
}

// objFlt is objAt + the float value (ints widen; absent is 0.0).
func objFlt(v validation.Value, key string) float64 {
	f := validation.ObjAt(v, key)
	switch f.Kind {
	case validation.Flt:
		return f.F
	case validation.Int:
		return float64(objInt(v, key))
	}
	return 0
}

// t14Money is Python's f"{x:,.2f}".
func t14Money(f float64) string {
	s := strconv.FormatFloat(f, 'f', 2, 64)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	intPart, frac, _ := strings.Cut(s, ".")
	var b strings.Builder
	for i, r := range intPart {
		if i > 0 && (len(intPart)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(r)
	}
	out := b.String() + "." + frac
	if neg {
		out = "-" + out
	}
	return out
}

func init() {
	register(command{ord: 39, name: "budget",
		line: `budget <campaign> [--set USD]       cost/discovery ceilings and position`,
		run: func(root string, args []string, r *Runner) int {
			return t14Dispatch(root, r, func() error {
				return runBudget(root, args, r)
			})
		}})
}
