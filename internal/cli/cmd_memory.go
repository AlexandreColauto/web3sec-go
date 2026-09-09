package cli

// cmd_memory: `webv2 memory <campaign> [--approve MEM] [--by NAME]` — list
// the campaign's learning memory, or record a human approval (cli.py
// cmd_memory verbatim).
//
// B5b/D6: neither path may end in silence — an empty store says so and names
// the command that queues a row, and an `--approve` that changes nothing says
// what was already true instead of claiming an approval. The
// leakage-partition guard runs BEFORE the no-op short-circuit, so a row
// forced to human-approved by a hand edit is still refused.

import (
	"fmt"
	"os"
	"path/filepath"

	"websec/internal/learning"
	"websec/internal/state"
	"websec/internal/validation"
)

const memoryUsage = "usage: webv2 memory [-h] [--approve APPROVE] [--by BY] campaign\n"

// memoryHelp is argparse's `webv2 memory --help` output, byte-exact.
const memoryHelp = `usage: webv2 memory [-h] [--approve APPROVE] [--by BY] campaign

positional arguments:
  campaign

options:
  -h, --help         show this help message and exit
  --approve APPROVE
  --by BY
`

func runMemory(root string, args []string, r *Runner) int {
	ensureSeams()
	return t14Dispatch(root, r, func() error {
		sp := &argSpec{
			prog:  "memory",
			usage: memoryUsage,
			vals:  []*valOpt{{name: "--approve"}, {name: "--by"}},
			pos:   []*posOpt{{name: "campaign"}},
		}
		if err := sp.parse(args); err != nil {
			return err
		}
		if sp.helpSeen {
			fmt.Fprint(r.Out, memoryHelp)
			return nil
		}
		c, err := t14Open(root, sp.pos[0].val)
		if err != nil {
			return err
		}
		by := sp.vals[1].val
		if by == "" {
			by = "unknown"
		}
		if approve := sp.vals[0].val; approve != "" {
			return memoryApprove(c, approve, by, r)
		}
		rows, err := learning.AllMemory(c)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			fmt.Fprint(r.Out, "memory: no rows yet — nothing to show\n")
			fmt.Fprintf(r.Out, "next: a disproved ladder rung queues a "+
				"negative memory row — webv2 ladder %s disprove <F-...> "+
				"<RUNG> --reason '...'\n", c.CampaignID)
			return nil
		}
		for _, m := range rows {
			fmt.Fprintf(r.Out, "%s [%s/%s] promotion=%s  %s\n",
				objStr(m, "memory_id"), objStr(m, "kind"),
				objStr(m, "status"), objStr(m, "promotion_status"),
				pyHead(objStr(m, "pattern"), 80))
		}
		return nil
	})
}

// memoryApprove is the `--approve` half of cmd_memory.
func memoryApprove(c *state.Campaign, approve, by string,
	r *Runner) error {
	rowPath := filepath.Join(c.MemoryDir, approve+".json")
	var prior validation.Value = validation.VNull()
	if _, err := os.Stat(rowPath); err == nil {
		prior, err = validation.ReadJson(rowPath)
		if err != nil {
			return err
		}
	}
	if prior.Kind == validation.Obj {
		// The leakage-partition guard runs BEFORE the no-op short-circuit
		// (fix round 1 / MINOR 1): a row forced to human-approved or
		// promoted by a hand edit or legacy write is still refused, never
		// reported as "nothing changed" with a `publish` that would raise.
		if err := learning.AssertApprovable(approve, prior); err != nil {
			return err
		}
	}
	if prior.Kind == validation.Obj {
		status := objStr(prior, "promotion_status")
		if status == "human-approved" || status == "promoted" {
			// Already at (or past) the approval this command records: write
			// nothing and log nothing, and say why plus the next step.
			fmt.Fprintf(r.Out, "%s: already %s by %s at %s — nothing changed\n",
				approve, status, orUnknown(objStr(prior, "approved_by")),
				orUnknown(objStr(prior, "approved_at")))
			if status == "human-approved" {
				commands, err := learning.PromotionCommands(c, approve, by)
				if err != nil {
					return err
				}
				fmt.Fprintf(r.Out, "next: %s\n", objStr(commands[0], "command"))
			} else {
				fmt.Fprint(r.Out, "next: nothing to do — the row is already "+
					"promoted\n")
			}
			return nil
		}
	}
	mem, err := learning.ApproveMemory(c, approve, by)
	if err != nil {
		return err
	}
	fmt.Fprintf(r.Out, "approved %s by %s\n", objStr(mem, "memory_id"),
		objStr(mem, "approved_by"))
	fmt.Fprint(r.Out, "promote with (in priority order):\n")
	commands, err := learning.PromotionCommands(c, objStr(mem, "memory_id"), by)
	if err != nil {
		return err
	}
	for _, pc := range commands {
		fmt.Fprintf(r.Out, "  [%s] %s\n", objStr(pc, "substrate"),
			objStr(pc, "command"))
		fmt.Fprintf(r.Out, "      %s\n", objStr(pc, "note"))
	}
	return nil
}

// orUnknown is Python's `x or 'unknown'`.
func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func init() {
	register(command{ord: 31, name: "memory",
		line: "memory <campaign> [--approve M]   list learning memory / record approval",
		run:  runMemory})
}
