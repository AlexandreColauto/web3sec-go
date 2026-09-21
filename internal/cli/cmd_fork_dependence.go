package cli

// cmd_fork_dependence: `webv2 fork-dependence <campaign> <finding> --set V
// --reason R [--actor A]` — declare a HYPOTHESIS's fork dependence (v1.6
// §2.2). Fork-dependence is a property of the hypothesis, never of the class:
// the class-level value is only a prior, so an override is a recorded
// judgment and one without a reason is a guess — --reason is required and the
// refusal text IS the output (exit 2), printed verbatim from
// findings.SetForkDependence.

import (
	"fmt"

	"websec/internal/findings"
)

// forkDependenceUsage is the verb's own usage line: helpUsageText renders the
// same text from the registry entry, so `-h` and a parse failure cannot
// disagree about the signature.
func forkDependenceUsage() string { return helpUsageText("fork-dependence") }

func runForkDependence(root string, args []string, r *Runner) int {
	return t14Dispatch(root, r, func() error {
		return forkDependenceCmd(root, args, r)
	})
}

func forkDependenceCmd(root string, args []string, r *Runner) error {
	if helpRequested(r.Out, "fork-dependence", args) {
		return nil
	}
	sp := forkDependenceSpec()
	if err := sp.parse(args); err != nil {
		return err
	}
	c, err := t14Open(root, sp.pos[0].val)
	if err != nil {
		return err
	}
	if _, err := findings.SetForkDependence(c, sp.pos[1].val, sp.vals[0].val,
		sp.vals[1].val, sp.vals[2].val); err != nil {
		return t14ExitErr(2, "%v\n", err)
	}
	if _, err := fmt.Fprintf(r.Out, "fork_dependence %s: %s (%s)\n",
		sp.pos[1].val, sp.vals[0].val, sp.vals[1].val); err != nil {
		return err
	}
	return nil
}

// forkDependenceSpec is the argparse shape: two positionals, the two required
// values, and the actor attribution.
func forkDependenceSpec() *argSpec {
	return &argSpec{
		prog:  "fork-dependence",
		usage: forkDependenceUsage(),
		vals: []*valOpt{
			{name: "--set", required: true},
			{name: "--reason", required: true},
			{name: "--actor"},
		},
		pos: []*posOpt{{name: "campaign"}, {name: "finding"}},
	}
}

func init() {
	register(command{ord: 95, name: "fork-dependence",
		line: `fork-dependence <campaign> <finding> --set V --reason R [--actor A]   declare a hypothesis's fork dependence`,
		run:  runForkDependence})
}
