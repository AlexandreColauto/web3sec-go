package cli

// cmd_sinks: `webv2 sinks <campaign> --src SRC [--json]` — backward slice
// from asset sinks: every unprivileged path that can move value (cli.py
// cmd_sinks verbatim). Writes value_flow.json and registers it.

import (
	"fmt"
	"strings"

	"websec/internal/structidx"
	"websec/internal/validation"
)

const sinksUsage = "usage: webv2 sinks [-h] --src SRC [--json] campaign\n"

func runSinks(root string, args []string, r *Runner) int {
	ensureSeams()
	return t14Dispatch(root, r, func() error {
		cid, src, asJSON, help, err := parseSrcArgs(args, "sinks")
		if err != nil {
			return err
		}
		if help {
			fmt.Fprint(r.Out, sinksHelp)
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
		rep, err := structidx.ValueFlowReport(c, src)
		if err != nil {
			return err
		}
		if asJSON {
			fmt.Fprintln(r.Out, validation.DumpIndentedASCII(rep))
			return nil
		}
		stats := objAt(rep, "stats")
		fmt.Fprintf(r.Out, "sinks: %s  unguarded paths: %s\n",
			pyIntText(objAt(stats, "sinks")),
			pyIntText(objAt(stats, "unguarded_paths")))
		for _, s := range objListAt(rep, "sinks") {
			mark := "guarded"
			if len(t14Strings(objAt(s, "unguarded_entry_points"))) > 0 {
				mark = "UNGUARDED"
			}
			fmt.Fprintf(r.Out, "  %s %s <- %s\n", mark,
				objStr(s, "sink_function"),
				strings.Join(t14Strings(objAt(s, "sink_calls")), ", "))
		}
		return nil
	})
}

// objListAt is v.get(key) as a list (empty when absent or not a list).
func objListAt(v validation.Value, key string) []validation.Value {
	x := objAt(v, key)
	if x.Kind != validation.Arr {
		return nil
	}
	return x.A
}

func init() {
	register(command{ord: 16, name: "sinks",
		line: "sinks <campaign> --src SRC          value-flow backward slice",
		run:  runSinks})
}
