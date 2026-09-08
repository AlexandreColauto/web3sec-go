package cli

// cmd_log: `webv2 log <campaign> [--tail N]` — tail the event log
// (cli.py cmd_log verbatim; default tail 25).

import (
	"fmt"
	"io"
	"strings"

	"websec/internal/state"
)

func runLog(root string, args []string, stdout io.Writer) error {
	tail := 25
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--tail" && i+1 < len(args):
			n, err := parseTail(args[i+1])
			if err != nil {
				return err
			}
			tail = n
			i++
		case strings.HasPrefix(a, "--tail="):
			n, err := parseTail(strings.TrimPrefix(a, "--tail="))
			if err != nil {
				return err
			}
			tail = n
		case strings.HasPrefix(a, "-"):
			return usageErrf("unrecognized arguments: %s", a)
		default:
			pos = append(pos, a)
		}
	}
	if len(pos) != 1 {
		return usageErrf("log requires exactly one <campaign> argument")
	}
	c, err := state.Open(root, pos[0])
	if err != nil {
		return err
	}
	events, err := c.Events()
	if err != nil {
		return err
	}
	// Python events[-tail:]: clamp both ends (negative tails are nonsense
	// input; argparse accepts them, slicing just yields fewer rows).
	idx := len(events) - tail
	if idx < 0 {
		idx = 0
	}
	if idx > len(events) {
		idx = len(events)
	}
	for _, e := range events[idx:] {
		ref := objStr(e, "ref")
		fmt.Fprintf(stdout, "%4d %s  %-28s %s\n",
			objInt(e, "seq"), objStr(e, "at"), objStr(e, "type"), ref)
	}
	return nil
}

func init() {
	register(command{ord: 50, name: "log",
		line: "log <campaign> [--tail N]            tail the event log",
		run: func(root string, args []string, r *Runner) int {
			return r.withErr(root, func() error { return runLog(root, args, r.Out) })
		}})
}
