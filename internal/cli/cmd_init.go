package cli

// cmd_init: `webv2 init --program PROG` — create a campaign.
// Prints `initialized {id} at {dir}` plus the next-step line (cli.py
// cmd_init verbatim).

import (
	"fmt"
	"io"
	"strings"

	"websec/internal/state"
)

func runInit(root string, args []string, stdout io.Writer) error {
	program := ""
	haveProgram := false
	var rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--program" && i+1 < len(args):
			program, haveProgram = args[i+1], true
			i++
		case strings.HasPrefix(a, "--program="):
			program, haveProgram = strings.TrimPrefix(a, "--program="), true
		case strings.HasPrefix(a, "-"):
			return usageErrf("unrecognized arguments: %s", a)
		default:
			rest = append(rest, a)
		}
	}
	if !haveProgram {
		return usageErrf("init requires --program PROG")
	}
	if len(rest) > 0 {
		return usageErrf("unrecognized arguments: %s", strings.Join(rest, " "))
	}
	c, err := state.Init(root, program, state.InitOpts{})
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "initialized %s at %s\n", c.CampaignID, c.Dir)
	fmt.Fprintln(stdout, "next: webv2 snap <campaign> <target>  (or use the Python API for pins)")
	return nil
}
