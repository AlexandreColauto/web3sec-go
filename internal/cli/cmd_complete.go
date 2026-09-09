package cli

// cmd_complete: `webv2 complete <campaign> --actor A --reason R` — mark the
// pass COMPLETE: an operator decision, actor-attributed and logged. The
// cockpit (brief/status) stops suggesting work; open completion proofs are
// listed, NOTED, not blocking (cli.py cmd_complete verbatim).

import (
	"fmt"
	"strings"

	"websec/internal/completion"
	"websec/internal/validation"
)

const completeUsage = "usage: webv2 complete [-h] [--actor ACTOR] " +
	"[--reason REASON] campaign\n"

const completeHelp = `usage: webv2 complete [-h] [--actor ACTOR] [--reason REASON] campaign

positional arguments:
  campaign

options:
  -h, --help       show this help message and exit
  --actor ACTOR    who is closing the pass (required)
  --reason REASON  written reason: what was closed, why the pass is done (>=
                   10 chars)
`

func runComplete(root string, args []string, r *Runner) int {
	ensureSeams()
	return t14Dispatch(root, r, func() error {
		sp := &argSpec{prog: "complete", usage: completeUsage,
			vals: []*valOpt{{name: "--actor"}, {name: "--reason"}},
			pos:  []*posOpt{{name: "campaign"}}}
		if err := sp.parse(args); err != nil {
			return err
		}
		if sp.helpSeen {
			fmt.Fprint(r.Out, completeHelp)
			return nil
		}
		actor := strings.TrimSpace(sp.vals[0].val)
		reason := strings.TrimSpace(sp.vals[1].val)
		if actor == "" {
			return t14ExitErr(2, "complete requires --actor (who is closing "+
				"the pass)\n")
		}
		if len([]rune(reason)) < 10 {
			return t14ExitErr(2, "complete requires a written --reason "+
				"(>= 10 chars): what was closed and why the pass is done\n")
		}
		c, err := t14Open(root, sp.pos[0].val)
		if err != nil {
			return err
		}
		if _, err := c.Complete(actor, reason); err != nil {
			return err
		}
		fmt.Fprintf(r.Out, "campaign %s marked COMPLETE by %s\n",
			c.CampaignID, actor)
		fmt.Fprintf(r.Out, "reason: %s\n", reason)
		proofs, err := completion.AllProofStatus(c)
		if err != nil {
			return err
		}
		openProofs := []string{}
		for _, pair := range proofs.O {
			pr := pair.V
			if pr.Kind != validation.Obj {
				continue
			}
			if !t14Truthy(objAt(pr, "authoritative")) ||
				t14Truthy(objAt(pr, "done")) {
				continue
			}
			missing := t31Strings(objAt(pr, "missing"))
			if len(missing) > 2 {
				missing = missing[:2]
			}
			openProofs = append(openProofs, pair.K+": "+
				strings.Join(missing, "; "))
		}
		if len(openProofs) > 0 {
			fmt.Fprintf(r.Out, "note: %d model-stage completion proof(s) "+
				"remain open — noted, NOT blocking (the pass is closed by "+
				"decision):\n", len(openProofs))
			for _, p := range openProofs {
				fmt.Fprintf(r.Out, "  - %s\n", p)
			}
		}
		fmt.Fprintln(r.Out, "the cockpit is closed: `webv2 brief` stops "+
			"suggesting work. To resume, run a stage command again "+
			"(e.g. `webv2 run`) — the phase is a projection and moves on "+
			"its own; the closure stays on the log.")
		return nil
	})
}

func init() {
	register(command{ord: 4, name: "complete",
		line: "complete <campaign> --actor A --reason R  mark the pass COMPLETE",
		run:  runComplete})
}
