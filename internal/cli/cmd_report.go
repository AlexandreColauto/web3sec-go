package cli

// cmd_report: `webv2 report <campaign>` — regenerate report.md (cli.py
// cmd_report verbatim: generate, then print the path).

import (
	"fmt"

	"websec/internal/report"
	"websec/internal/validation"
)

const reportUsage = "usage: webv2 report [-h] [--format {md,immunefi}] campaign\n"

const reportHelp = `usage: webv2 report [-h] [--format {md,immunefi}] campaign

positional arguments:
  campaign

options:
  -h, --help  show this help message and exit
  --format {md,immunefi}
              report format: md writes report.md (default); immunefi writes
              one report-immunefi-<FINDING-ID>.md per submission-ready finding
`

func runReport(root string, args []string, r *Runner) int {
	ensureSeams()
	return t14Dispatch(root, r, func() error {
		sp := &argSpec{prog: "report", usage: reportUsage,
			vals: []*valOpt{{name: "--format"}},
			pos:  []*posOpt{{name: "campaign"}}}
		if err := sp.parse(args); err != nil {
			return err
		}
		if sp.helpSeen {
			fmt.Fprint(r.Out, reportHelp)
			return nil
		}
		format := sp.vals[0].val
		if format == "" {
			format = "md"
		}
		c, err := t14Open(root, sp.pos[0].val)
		if err != nil {
			return err
		}
		switch format {
		case "immunefi":
			paths, err := report.GenerateImmunefi(c)
			if err != nil {
				return err
			}
			if len(paths) == 0 {
				fmt.Fprintln(r.Out, "no submission-ready findings")
				return nil
			}
			for _, p := range paths {
				fmt.Fprintln(r.Out, p)
			}
			return nil
		case "md":
			path, err := report.Generate(c)
			if err != nil {
				return err
			}
			fmt.Fprintln(r.Out, path)
			return nil
		default:
			return t14ArgparseErr(reportUsage, "report",
				"argument --format: invalid choice: %s "+
					"(choose from 'md', 'immunefi')",
				validation.PyReprStr(format))
		}
	})
}

func init() {
	register(command{ord: 30, name: "report",
		line: "report <campaign>",
		run:  runReport})
}
