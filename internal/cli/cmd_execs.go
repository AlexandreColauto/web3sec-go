package cli

// cmd_execs: `webv2 execs <campaign> [--id ID] [--json]` — the exec ledger
// (cli.py cmd_execs verbatim): every command the sandbox ran, with status,
// exit code, output hashes and the evidence that cited it. `--id` shows one
// record in full (its stdout/stderr live under execs/<id>/).

import (
	"fmt"
	"strings"

	"websec/internal/sandbox"
	"websec/internal/state"
	"websec/internal/validation"
)

// execsHelp is argparse's `webv2 execs --help` output, byte-exact.
const execsHelp = `usage: webv2 execs [-h] [--id ID] [--json] campaign

positional arguments:
  campaign

options:
  -h, --help  show this help message and exit
  --id ID
  --json
`

func runExecs(root string, args []string, r *Runner) int {
	ensureSeams()
	id, asJSON, haveID := "", false, false
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--id":
			next, ok := flagValue(args, i)
			if !ok {
				return r.fail(root, argErrf("execs",
					"argument --id: expected one argument"))
			}
			id, haveID = next, true
			i++
		case strings.HasPrefix(a, "--id="):
			id, haveID = strings.TrimPrefix(a, "--id="), true
		case a == "--json":
			asJSON = true
		case a == "-h" || a == "--help":
			fmt.Fprint(r.Out, execsHelp)
			return 0
		case strings.HasPrefix(a, "-"):
			return r.fail(root, usageErrf("unrecognized arguments: %s", a))
		default:
			pos = append(pos, a)
		}
	}
	if len(pos) > 1 {
		return r.fail(root, usageErrf("unrecognized arguments: %s", pos[1]))
	}
	if len(pos) < 1 {
		return r.fail(root, requiredErrf("execs", "campaign"))
	}
	c, err := state.Open(root, pos[0])
	if err != nil {
		return r.withErr(root, func() error { return err })
	}
	execs, err := sandbox.AllExecs(c)
	if err != nil {
		return r.withErr(root, func() error { return err })
	}
	if haveID && id != "" {
		var rec *validation.Value
		for i := range execs {
			if validation.ObjStr(execs[i], "exec_id") == id {
				rec = &execs[i]
				break
			}
		}
		if rec == nil {
			fmt.Fprintf(r.Err, "no exec %s in this campaign\n",
				validation.PyReprStr(id))
			return 2
		}
		fmt.Fprintln(r.Out, validation.DumpIndentedASCII(*rec))
		return 0
	}
	if asJSON {
		fmt.Fprintln(r.Out, validation.DumpIndentedASCII(validation.VArr(execs...)))
		return 0
	}
	if len(execs) == 0 {
		fmt.Fprintln(r.Out, "no exec records in this campaign")
		return 0
	}
	for _, e := range execs {
		profile := "?"
		if p := validation.ObjAt(e, "profile"); p.Kind == validation.Str {
			profile = p.S
		}
		state := execState(e)
		fmt.Fprintf(r.Out, "%s  [%s] %s %s\n", validation.ObjStr(e, "exec_id"), profile,
			pyLeft(state, 12), pyHead(validation.ObjStr(e, "command"), 70))
	}
	return 0
}

// execState is cmd_execs' state column: refused / exit N / incomplete.
func execState(e validation.Value) string {
	verdict := validation.ObjAt(e, "policy_verdict")
	for _, v := range validation.ObjAt(verdict, "violations").A {
		if v.Kind == validation.Str && v.S == "execution-refused" {
			return "refused"
		}
	}
	if validation.ObjAt(e, "finished_at").Kind != validation.Null {
		return "exit " + scalarStr(validation.ObjAt(e, "exit_status"))
	}
	return "incomplete"
}

func init() {
	register(command{ord: 38, name: "execs",
		line: "execs <campaign> [--id ID] [--json]  the exec ledger",
		run:  runExecs})
}
