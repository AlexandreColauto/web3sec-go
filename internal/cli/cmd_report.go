package cli

// cmd_report: `webv2 report <campaign>` — regenerate report.md (cli.py
// cmd_report verbatim: generate, then print the path).

import (
	"fmt"

	"websec/internal/report"
)

const reportUsage = "usage: webv2 report [-h] campaign\n"

const reportHelp = `usage: webv2 report [-h] campaign

positional arguments:
  campaign

options:
  -h, --help  show this help message and exit
`

func runReport(root string, args []string, r *Runner) int {
	ensureSeams()
	return t14Dispatch(root, r, func() error {
		sp := &argSpec{prog: "report", usage: reportUsage,
			pos: []*posOpt{{name: "campaign"}}}
		if err := sp.parse(args); err != nil {
			return err
		}
		if sp.helpSeen {
			fmt.Fprint(r.Out, reportHelp)
			return nil
		}
		c, err := t14Open(root, sp.pos[0].val)
		if err != nil {
			return err
		}
		path, err := report.Generate(c)
		if err != nil {
			return err
		}
		fmt.Fprintln(r.Out, path)
		return nil
	})
}

func init() {
	register(command{ord: 30, name: "report",
		line: "report <campaign>",
		run:  runReport})
}
