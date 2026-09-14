// cmd_yields: `webv2 yields <campaign>` — cost-adjusted discovery yield per
// trajectory (advisory, never gates). cli.py cmd_yields verbatim.
package cli

import (
	"fmt"
	"strconv"
	"strings"

	"websec/internal/costs"
	"websec/internal/validation"
)

const t26YieldsUsage = `usage: webv2 yields [-h] campaign
`

const t26YieldsHelp = t26YieldsUsage + `
positional arguments:
  campaign

options:
  -h, --help  show this help message and exit
`

func runYields(root string, args []string, r *Runner) int {
	ensureSeams()
	return t14Dispatch(root, r, func() error {
		var pos []string
		for _, a := range args {
			if a == "-h" || a == "--help" {
				fmt.Fprint(r.Out, t26YieldsHelp)
				return nil
			}
			if strings.HasPrefix(a, "-") && !isNegNumberCLI(a) {
				return t14Unrecognized(a)
			}
			pos = append(pos, a)
		}
		if len(pos) < 1 {
			return t14ArgparseErr(t26YieldsUsage, "yields",
				"the following arguments are required: campaign")
		}
		if len(pos) > 1 {
			return t14Unrecognized(strings.Join(pos[1:], " "))
		}
		c, err := t14Open(root, pos[0])
		if err != nil {
			return err
		}
		// r16: "advisory, never gates" is about the pipeline, not a
		// license to print fiction over a damaged mirror — the same
		// cross-check budget refuses on applies here (divergence from
		// the ported cmd_yields, which predates the cost projection).
		if probs := costs.CostMirrorProblems(c); len(probs) > 0 {
			return fmt.Errorf("cost projection is damaged (%d problem(s), "+
				"first: %s) — yields would price advice on untrusted "+
				"spend; `webv2 audit` lists every problem", len(probs), probs[0])
		}
		rep, err := costs.YieldReport(c)
		if err != nil {
			return err
		}
		for _, row := range objAt(rep, "trajectories").A {
			y := objAt(row, "yield_usd_per_usd")
			ys := "n/a"
			if y.Kind != validation.Null {
				ys = t26Fixed1(objFlt(row, "yield_usd_per_usd")) + "x"
			}
			fmt.Fprintf(r.Out, "%s cost=$%s confirmed=%d value=$%s  "+
				"yield=%s\n", pyLeft(objStr(row, "trajectory"), 20),
				pyRight(pyFixed2(objFlt(row, "total_cost_usd")), 9),
				objInt(row, "confirmed_findings"),
				pyRight(pyFixed2(objFlt(row, "confirmed_value_usd")), 12), ys)
		}
		t := objAt(rep, "totals")
		ty := objAt(t, "yield_usd_per_usd")
		tys := "n/a"
		if ty.Kind != validation.Null {
			tys = t26Fixed1(objFlt(t, "yield_usd_per_usd")) + "x"
		}
		fmt.Fprintf(r.Out, "%s cost=$%s confirmed=%d value=$%s  yield=%s\n",
			pyLeft("TOTAL", 20),
			pyRight(pyFixed2(objFlt(t, "total_cost_usd")), 9),
			objInt(t, "confirmed_findings"),
			pyRight(pyFixed2(objFlt(t, "confirmed_value_usd")), 12), tys)
		advice, err := costs.AllocationAdvice(c)
		if err != nil {
			return err
		}
		for _, a := range advice {
			fmt.Fprintf(r.Out, "  advice #%d: %s — %s\n",
				objInt(a, "rank"), objStr(a, "trajectory"),
				objStr(a, "advice"))
		}
		return nil
	})
}

// t26Fixed1 is Python's f"{x:.1f}".
func t26Fixed1(f float64) string {
	return strconv.FormatFloat(f, 'f', 1, 64)
}

func init() {
	register(command{ord: 12, name: "yields",
		line: "yields <campaign>                   cost-adjusted discovery yield",
		run:  runYields})
}
