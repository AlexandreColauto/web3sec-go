package cli

// cmd_answered: `webv2 answered <campaign> <priority> [priority ...] <status>
// [--reason R] [--reason-all R] [--ref R] [--families F] [--symmetry S]
// [--anchor A] [--passes V] [--interim S] [--finding F] [--actor A]` — set
// plan priorities' (Q-*) or one lens entry's
// (L-*) status WITH closure provenance. cli.py cmd_answered verbatim for the
// single-priority shape: closing statuses REQUIRE --reason, L-* ids route to
// planner.mark_lens, and a probe row's disposition must name its anchor. The
// batch shape (several Q-* priorities, one status for all rows) requires
// --reason-all and runs every row's gates before any mutation lands.
// B10(b) adds one more route: `--rows ROWID,ROWID` names probe-SURFACE rows
// instead of priorities, resolves each to the priority the plan emitted for
// it, and then rides the same batch discipline (see answeredRows).

import (
	"path/filepath"
	"strings"

	"websec/internal/validation"
)

func runAnswered(root string, args []string, r *Runner) error {
	a, err := parseAnswered(args, r)
	if err != nil || a == nil {
		return err
	}
	c, err := t14Open(root, a.campaign)
	if err != nil {
		return err
	}
	planPath := filepath.Join(c.ArtifactsDir, "campaign_plan.json")
	if !t14Exists(planPath) {
		return t14ExitErr(2, "no campaign plan loaded (webv2 plan %s)\n", c.CampaignID)
	}
	closing := a.status == "answered" || a.status == "not-applicable" ||
		a.status == "deprioritized" || a.status == "blocked"
	// B10b: `--rows` names surface rows, so it is its own route (it resolves
	// the row ids to the priorities the plan emitted and then reuses the Q-*
	// batch discipline). It is checked before the batch shape because the
	// rows route has no priority positional at all.
	if a.rows != nil {
		return answeredRows(c, a, closing, r)
	}
	if len(a.priorities) > 1 || a.reasonAll != nil {
		return answeredBatch(c, a, closing, r)
	}
	if closing && (a.reason == nil || strings.TrimSpace(*a.reason) == "") {
		return t14ExitErr(2, "answered: %s requires --reason (why). "+
			"Pass --ref too when the answer rests on evidence "+
			"(finding/exec/artifact/file#L).\n", validation.PyReprStr(a.status))
	}
	if strings.HasPrefix(a.priority, "L-") {
		return answeredLens(c, a, closing, r)
	}
	return answeredPriority(c, a, closing, r)
}

func init() {
	register(command{ord: 35, name: "answered",
		line: `answered <campaign> <priority> [priority ...] <status> [--reason R]
                        [--reason-all R] [--ref R]
                        close/open plan priorities or a lens with provenance`,
		run: func(root string, args []string, r *Runner) int {
			return t14Dispatch(root, r, func() error {
				return runAnswered(root, args, r)
			})
		}})
}
