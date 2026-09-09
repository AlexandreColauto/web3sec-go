package cli

// cmd_forkdiff: `webv2 forkdiff <campaign> --src SRC [--json]` — match the
// target against registered baseline reference trees (cli.py cmd_forkdiff
// verbatim).

import (
	"fmt"

	"websec/internal/forkdiff"
	"websec/internal/validation"
)

const forkdiffUsage = "usage: webv2 forkdiff [-h] --src SRC [--json] campaign\n"

func runForkdiff(root string, args []string, r *Runner) int {
	ensureSeams()
	return t14Dispatch(root, r, func() error {
		cid, src, asJSON, help, err := parseSrcArgs(args, "forkdiff")
		if err != nil {
			return err
		}
		if help {
			fmt.Fprint(r.Out, forkdiffHelp)
			return nil
		}
		// cli.py checks the source tree BEFORE opening the campaign, so a
		// bad --src wins over a malformed campaign id.
		if !isDirPath(src) {
			return t14ExitErr(1, "source tree not found: %s\n", src)
		}
		c, err := t14Open(root, cid)
		if err != nil {
			return err
		}
		rep, err := forkdiff.ForkdiffReport(c, src)
		if err != nil {
			return err
		}
		if asJSON {
			fmt.Fprintln(r.Out, validation.DumpIndentedASCII(rep))
			return nil
		}
		fmt.Fprintf(r.Out, "fork-diff: %s\n", objStr(rep, "diff_summary"))
		for _, m := range objListAt(rep, "all_matches") {
			fmt.Fprintf(r.Out, "  %s: score %s (%s)\n", objStr(m, "baseline"),
				pyScore2(objAt(m, "score")), objStr(m, "verdict"))
		}
		return nil
	})
}

func init() {
	register(command{ord: 18, name: "forkdiff",
		line: "forkdiff <campaign> --src SRC       match against baselines",
		run:  runForkdiff})
}
