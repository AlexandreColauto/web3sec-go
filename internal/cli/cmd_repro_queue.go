package cli

// cmd_repro_queue: `webv2 repro-queue <campaign>` — candidates ordered for
// reproduction (cli.py cmd_repro_queue verbatim):
//   prior={prior:.2f} next={next_tier} attempts={attempts}  {finding_id}

import (
	"fmt"

	"websec/internal/orchestrator"
	"websec/internal/state"
)

func runReproQueue(root string, args []string, r *Runner) int {
	if helpRequested(r.Out, "repro-queue", args) {
		return 0
	}

	ensureSeams()
	pos, err := plainPositionals(args, "repro-queue", 1, "campaign")
	if err != nil {
		return r.fail(root, err)
	}
	c, err := state.Open(root, pos[0])
	if err != nil {
		return r.withErr(root, func() error { return err })
	}
	o := orchestrator.New(c)
	rows, err := o.ReproductionQueue()
	if err != nil {
		return r.withErr(root, func() error { return err })
	}
	for _, q := range rows.A {
		fmt.Fprintf(r.Out, "prior=%s next=%s attempts=%s  %s\n",
			pyScore2(objAt(q, "prior")), objStr(q, "next_tier"),
			pyIntText(objAt(q, "attempts")), objStr(q, "finding_id"))
	}
	return 0
}

func init() {
	register(command{ord: 7, name: "repro-queue",
		line: "repro-queue <campaign>              candidates ordered for repro",
		run:  runReproQueue})
}
