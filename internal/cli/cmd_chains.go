package cli

// cmd_chains: `webv2 chains <campaign>` — the capability-link / chain
// proposal report (cli.py cmd_chains verbatim).

import (
	"fmt"
	"strings"

	"websec/internal/chainengine"
	"websec/internal/validation"
)

func runChains(root string, args []string, r *Runner) int {
	return t14Dispatch(root, r, func() error {
		name, done, err := t23OneArg(args, "chains", r)
		if err != nil || done {
			return err
		}
		c, err := t14Open(root, name)
		if err != nil {
			return err
		}
		rep, err := chainengine.ChainReport(c)
		if err != nil {
			return err
		}
		printChains(r, rep)
		return nil
	})
}

func printChains(r *Runner, rep validation.Value) {
	links := t14List(rep, "capability_links")
	fmt.Fprintf(r.Out, "capability links: %d\n", len(links.A))
	for _, lnk := range links.A {
		fmt.Fprintf(r.Out, "  %s --%s--> %s\n", objStr(lnk, "from"),
			objStr(lnk, "capability"), objStr(lnk, "to"))
	}
	proposals := t14List(rep, "proposals")
	fmt.Fprintf(r.Out, "proposals: %d\n", len(proposals.A))
	for _, p := range proposals.A {
		fmt.Fprintf(r.Out, "  %s\n", strings.Join(t14Strings(
			t14List(p, "members")), " -> "))
	}
	materialized := t14List(rep, "materialized")
	fmt.Fprintf(r.Out, "materialized chains: %d\n", len(materialized.A))
	for _, ch := range materialized.A {
		fmt.Fprintf(r.Out, "  %s [%s] %s (floor %s)\n",
			objStr(ch, "chain_id"), objStr(ch, "status"),
			objStr(ch, "title"), objStr(ch, "evidence_floor"))
	}
}

// t23OneArg parses a verb with exactly one positional and no options. done
// means --help was printed; extras (unknown flags and further positionals)
// are the ROOT parser's unrecognized-arguments failure, reported in the
// order argparse saw them.
func t23OneArg(args []string, cmd string, r *Runner) (string, bool, error) {
	var pos, extras []string
	for _, a := range args {
		if a == "-h" || a == "--help" {
			fmt.Fprint(r.Out, t23HelpFor(cmd))
			return "", true, nil
		}
		if t23IsOption(a) {
			extras = append(extras, a)
			continue
		}
		if len(pos) == 0 {
			pos = append(pos, a)
			continue
		}
		extras = append(extras, a)
	}
	if len(pos) == 0 {
		return "", false, t14ArgparseErr(t23UsageFor(cmd), cmd,
			"the following arguments are required: campaign")
	}
	if len(extras) > 0 {
		return "", false, t14Unrecognized(strings.Join(extras, " "))
	}
	return pos[0], false, nil
}

func init() {
	register(command{ord: 8, name: "chains",
		line: "chains <campaign>                   capability links + chain proposals",
		run:  runChains})
}
