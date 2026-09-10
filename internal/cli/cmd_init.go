package cli

// cmd_init: `webv2 init --program PROG` — create a campaign, then drop the
// two operating docs (RUNBOOK.md + AGENT_BOOTSTRAP.md) into the campaign
// directory so the working repo carries its own docs even in a fresh
// workspace. Prints `initialized {id} at {dir}` plus the next-step line.

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"websec/assets"
	"websec/internal/state"
)

func runInit(root string, args []string, stdout io.Writer) error {
	if helpRequested(stdout, "init", args) {
		return nil
	}

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
	if err := writeRunbookDocs(c.Dir); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "initialized %s at %s\n", c.CampaignID, c.Dir)
	fmt.Fprintf(stdout, "wrote %s and %s into the campaign\n",
		filepath.Join(c.Dir, "RUNBOOK.md"), filepath.Join(c.Dir, "AGENT_BOOTSTRAP.md"))
	fmt.Fprintln(stdout, "next: webv2 snap <campaign> <target>   (full lifecycle: RUNBOOK.md in the campaign dir)")
	return nil
}

// writeRunbookDocs copies the embedded operating docs (RUNBOOK.md,
// AGENT_BOOTSTRAP.md) into dir. A failure is returned so init fails loudly
// rather than silently leaving a campaign without its docs.
func writeRunbookDocs(dir string) error {
	for _, d := range assets.RunbookNames {
		raw, err := assets.RunbookFS.ReadFile(d.Embed)
		if err != nil {
			return fmt.Errorf("init: reading embedded %s: %w", d.Name, err)
		}
		dst := filepath.Join(dir, d.Name)
		if err := os.WriteFile(dst, raw, 0o644); err != nil {
			return fmt.Errorf("init: writing %s: %w", d.Name, err)
		}
	}
	return nil
}

func init() {
	register(command{ord: 1, name: "init",
		line: "init --program PROG                  create a campaign",
		run: func(root string, args []string, r *Runner) int {
			return r.withErr(root, func() error { return runInit(root, args, r.Out) })
		}})
}
