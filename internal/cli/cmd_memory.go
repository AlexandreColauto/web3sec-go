package cli

// cmd_memory: `webv2 memory <campaign> [--approve MEM] [--by NAME]` — list
// the campaign's learning memory, or record a human approval (cli.py
// cmd_memory verbatim).
//
// D5 (2026-09-10) adds the two flags that close the learning stage's reachable
// surface, on THIS verb rather than as new top-level verbs: `--reflect TEXT`
// (the only writer of learnings.jsonl — learning.ReflectionEntry had no caller
// outside its own test, so the completion proof's "no reflection entry" item
// could never be cleared by any command) and `--reject MEM --reason TEXT`
// (the inbox could only approve; a wrong candidate stayed pending forever).
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
	"strconv"
	"strings"

	"websec/internal/learning"
	"websec/internal/state"
	"websec/internal/validation"
)

const memoryUsage = "usage: webv2 memory [-h] [--approve APPROVE] [--by BY] " +
	"[--reflect TEXT] [--round ROUND] [--reject REJECT] [--reason REASON] " +
	"[--rejection-class CLASS] campaign\n"

// memoryHelp is argparse's `webv2 memory --help` output plus the D5 flags.
const memoryHelp = `usage: webv2 memory [-h] [--approve APPROVE] [--by BY] [--reflect TEXT] [--round ROUND] [--reject REJECT] [--reason REASON] [--rejection-class CLASS] campaign

positional arguments:
  campaign

options:
  -h, --help         show this help message and exit
  --approve APPROVE  record a human approval (prints the promotion commands)
  --by BY            the approving identity
  --reflect TEXT     append one reflection entry to learnings.jsonl
  --round ROUND      the round the reflection belongs to (default 1)
  --reject REJECT    reject a pending memory candidate
  --reason REASON    why it was rejected (required with --reject; logged)
  --rejection-class CLASS
                     invalid-hypothesis | not-exploitable | below-threshold
`

func runMemory(root string, args []string, r *Runner) int {
	ensureSeams()
	return t14Dispatch(root, r, func() error {
		sp := &argSpec{
			prog:  "memory",
			usage: memoryUsage,
			vals: []*valOpt{{name: "--approve"}, {name: "--by"},
				{name: "--reflect"}, {name: "--round"}, {name: "--reject"},
				{name: "--reason"}, {name: "--rejection-class"}},
			pos: []*posOpt{{name: "campaign"}},
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
		reflect, round, reject := sp.vals[2].val, sp.vals[3].val, sp.vals[4].val
		reason, rejectClass := sp.vals[5].val, sp.vals[6].val
		approve := sp.vals[0].val
		// The three actions are mutually exclusive; each carries flags that
		// only make sense with it.
		actions := 0
		for _, set := range []bool{approve != "", reflect != "", reject != ""} {
			if set {
				actions++
			}
		}
		if actions > 1 {
			return t14ArgparseErr(memoryUsage, "memory",
				"argument --approve: not allowed with --reflect or --reject")
		}
		if reason != "" && reject == "" {
			return t14ArgparseErr(memoryUsage, "memory",
				"argument --reason: only meaningful with --reject")
		}
		if rejectClass != "" && reject == "" {
			return t14ArgparseErr(memoryUsage, "memory",
				"argument --rejection-class: only meaningful with --reject")
		}
		if round != "" && reflect == "" {
			return t14ArgparseErr(memoryUsage, "memory",
				"argument --round: only meaningful with --reflect")
		}
		if approve != "" {
			return memoryApprove(c, approve, by, r)
		}
		if reflect != "" {
			return memoryReflect(c, reflect, round, r)
		}
		if reject != "" {
			return memoryReject(c, reject, reason, rejectClass, r)
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

// memoryReflect is the `--reflect` half: one ReflectionOpts entry appended to
// learnings.jsonl. The sentence lands in process_improvements — the field of a
// reflection entry that a one-line observation belongs in (the other four are
// per-round diagnostic lists a model fills).
func memoryReflect(c *state.Campaign, text, round string, r *Runner) error {
	n := int64(1)
	if round != "" {
		parsed, err := strconv.ParseInt(round, 10, 64)
		if err != nil {
			return t14ArgparseErr(memoryUsage, "memory",
				"argument --round: invalid int value: %s", validation.PyReprStr(round))
		}
		n = parsed
	}
	if _, err := learning.ReflectionEntry(c, learning.ReflectionOpts{
		Round:               n,
		ProcessImprovements: []string{text},
	}); err != nil {
		return err
	}
	fmt.Fprintf(r.Out, "reflection recorded (round %d): %s\n", n, pyHead(text, 80))
	fmt.Fprintf(r.Out, "  learnings.jsonl now holds %d entr(ies)\n",
		countLearnings(c))
	return nil
}

// memoryReject is the `--reject` half of cmd_memory.
func memoryReject(c *state.Campaign, reject, reason, class string, r *Runner) error {
	if reason == "" {
		return t14ArgparseErr(memoryUsage, "memory",
			"argument --reason: required with --reject")
	}
	mem, err := learning.RejectMemory(c, reject, reason, class)
	if err != nil {
		return err
	}
	fmt.Fprintf(r.Out, "rejected %s (%s) promotion=%s\n",
		objStr(mem, "memory_id"), orUnknown(objStr(mem, "rejection_class")),
		objStr(mem, "promotion_status"))
	fmt.Fprintf(r.Out, "  reason logged: %s\n", pyHead(reason, 80))
	return nil
}

// countLearnings is the number of lines in learnings.jsonl (0 when absent).
func countLearnings(c *state.Campaign) int {
	raw, err := os.ReadFile(filepath.Join(c.Dir, "learnings.jsonl"))
	if err != nil {
		return 0
	}
	n := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
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
		line: "memory <campaign> [--approve M] [--reflect T] [--reject M]   " +
			"list learning memory / approve / reflect / reject",
		run: runMemory})
}
