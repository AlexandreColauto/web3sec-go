package cli

// cmd_classify: `webv2 classify <campaign> <exec_id>` — classify a FAILED
// exec by cause: environment (fix the box, do NOT spend a fresh-context
// retry), setup (fresh-context retry), logic (the hypothesis lost a round).
// The class routes the retry; it is a hint, not a verdict.

import (
	"fmt"
	"strings"

	"websec/internal/sandbox"
	"websec/internal/state"
	"websec/internal/validation"
)

// classifyHelp is argparse's `webv2 classify --help` output, byte-exact.
const classifyHelp = `usage: webv2 classify [-h] campaign exec_id

positional arguments:
  campaign
  exec_id

options:
  -h, --help  show this help message and exit
`

func runClassify(root string, args []string, r *Runner) int {
	ensureSeams()
	var pos []string
	for _, a := range args {
		if a == "-h" || a == "--help" {
			fmt.Fprint(r.Out, classifyHelp)
			return 0
		}
		if strings.HasPrefix(a, "-") {
			return r.fail(root, usageErrf("unrecognized arguments: %s", a))
		}
		pos = append(pos, a)
	}
	if len(pos) > 2 {
		return r.fail(root, usageErrf("unrecognized arguments: %s", pos[2]))
	}
	missing := []string{}
	if len(pos) < 1 {
		missing = append(missing, "campaign")
	}
	if len(pos) < 2 {
		missing = append(missing, "exec_id")
	}
	if len(missing) > 0 {
		return r.fail(root, requiredErrf("classify", missing...))
	}
	c, err := state.Open(root, pos[0])
	if err != nil {
		return r.withErr(root, func() error { return err })
	}
	execs, err := sandbox.AllExecs(c)
	if err != nil {
		return r.withErr(root, func() error { return err })
	}
	var rec *validation.Value
	for i := range execs {
		if objStr(execs[i], "exec_id") == pos[1] {
			rec = &execs[i]
			break
		}
	}
	if rec == nil {
		fmt.Fprintf(r.Err, "exec %s not found in the campaign's exec ledger\n",
			pos[1])
		return 2
	}
	res := sandbox.ClassifyFailure(*rec)
	fmt.Fprintf(r.Out, "exec %s (exit %s): %s\n", pos[1],
		scalarStr(objAt(*rec, "exit_status")),
		strings.ToUpper(objStr(res, "class")))
	for _, s := range objAt(res, "signals").A {
		fmt.Fprintf(r.Out, "  signal: %s\n", scalarStr(s))
	}
	fmt.Fprintf(r.Out, "  %s\n", objStr(res, "note"))
	return 0
}

func init() {
	register(command{ord: 60, name: "classify",
		line: "classify <campaign> <exec_id>      classify a FAILED exec",
		run:  runClassify})
}
