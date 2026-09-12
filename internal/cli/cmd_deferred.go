package cli

// cmd_deferred: `webv2 deferred <campaign> [--json]` — the FIX-5 reverse
// sweep. Reports every tier-0 probe closure whose recorded reason vocabulary
// implies a failure consequence (unfinalizable, stranded, frozen,
// revert-forever, ...) and that prices none of it — no --finding ref, no
// --interim statement. These are the closures recorded before the
// deferred-consequence gate existed (or through its logged override): the
// G-01 shape, where the tell sat in the accepted prose and nobody was asked
// to price it. The sweep REPORTS — it never mutates; the fix is a re-answer,
// which only the operator can make.

import (
	"fmt"
	"path/filepath"

	"websec/internal/planner"
	"websec/internal/validation"
)

const deferredUsage = "usage: webv2 deferred [-h] [--json] campaign\n"

// deferredHelp is the argparse-style help block. This verb is Go-only, so the
// prose is ours; the wrapping follows argparse's 80-column house style.
const deferredHelp = deferredUsage + `
list the tier-0 probe closures whose recorded reason vocabulary implies a
failure consequence — the row stays unfinalizable, funds strand, the pool
freezes, the queue reverts forever — and that price none of it: no --finding
ref, no --interim statement on the priority. Each listed closure is demanded
a re-answer: --finding F-<id> (a filed finding that records the interim
window) or --interim STATEMENT (citing the row's own surface entry), or an
explicit --override-dismissal --override-reason R. The sweep reports; it does
not mutate.

positional arguments:
  campaign              campaign id

options:
  -h, --help            show this help message and exit
  --json                emit the flags as JSON
`

func runDeferred(root string, args []string, r *Runner) int {
	return t14Dispatch(root, r, func() error { return deferredCmd(root, args, r) })
}

func deferredCmd(root string, args []string, r *Runner) error {
	sp := &argSpec{
		prog:  "deferred",
		usage: deferredUsage,
		flags: []*boolOpt{{name: "--json"}},
		pos:   []*posOpt{{name: "campaign"}},
	}
	if err := sp.parse(args); err != nil {
		return err
	}
	if sp.helpSeen {
		fmt.Fprint(r.Out, deferredHelp)
		return nil
	}
	c, err := t14Open(root, sp.pos[0].val)
	if err != nil {
		return err
	}
	planPath := filepath.Join(c.ArtifactsDir, "campaign_plan.json")
	if !t14Exists(planPath) {
		return t14ExitErr(2, "no campaign plan loaded (webv2 plan %s)\n",
			c.CampaignID)
	}
	plan, err := validation.ReadJson(planPath)
	if err != nil {
		return t14ExitErr(2, "deferred failed: %s\n", err)
	}
	flags, skipped, err := planner.DeferredConsequenceReview(c, plan)
	if err != nil {
		return t14ExitErr(2, "deferred failed: %s\n", err)
	}
	if sp.flags[0].set {
		rep := validation.VObj(
			validation.KV{K: "flags", V: deferredFlagsVal(flags)})
		fmt.Fprintln(r.Out, validation.DumpIndentedASCII(rep))
		deferredPrintSkipped(r, skipped)
		return nil
	}
	deferredPrint(r, flags)
	deferredPrintSkipped(r, skipped)
	return nil
}

// deferredPrintSkipped is the FIX-3 half of the report: closures the sweep
// could not rank because their probe row no longer resolves against the
// current surface are named, not dropped — the reader decides what an
// unpriced tell on an unrankable row is worth.
func deferredPrintSkipped(r *Runner, skipped []string) {
	if len(skipped) == 0 {
		return
	}
	fmt.Fprintf(r.Out, "deferred: skipped %d closure(s) whose probe rows "+
		"are not in the current surface (the risk rank is the surface's, "+
		"not the plan's):\n", len(skipped))
	for _, s := range skipped {
		fmt.Fprintln(r.Out, "  "+s)
	}
}

// deferredFlagsVal renders the flags as the JSON view's array.
func deferredFlagsVal(flags []planner.DeferredFlag) validation.Value {
	out := validation.VArr()
	for _, f := range flags {
		tokens := validation.VArr()
		for _, t := range f.Tokens {
			tokens.A = append(tokens.A, validation.VStr(t))
		}
		out.A = append(out.A, validation.VObj(
			validation.KV{K: "priority", V: validation.VStr(f.Priority)},
			validation.KV{K: "row_id", V: validation.VStr(f.RowID)},
			validation.KV{K: "tier", V: validation.VInt(f.Tier)},
			validation.KV{K: "assertion_gap", V: validation.VInt(f.Gap)},
			validation.KV{K: "reason", V: validation.VStr(f.Reason)},
			validation.KV{K: "tokens", V: tokens},
		))
	}
	return out
}

// deferredPrint renders the report: the headline, one block per flagged
// closure, and the re-answer each one is demanded.
func deferredPrint(r *Runner, flags []planner.DeferredFlag) {
	if len(flags) == 0 {
		fmt.Fprintln(r.Out, "deferred: no tier-0 closure defers its check "+
			"on unpriced consequence vocabulary")
		return
	}
	fmt.Fprintf(r.Out, "deferred: %d tier-0 closure(s) whose reason defers "+
		"the check without pricing it (report only — nothing mutated)\n",
		len(flags))
	for _, f := range flags {
		fmt.Fprintf(r.Out, "  %s probe row %s (tier %d, assertion_gap %d)\n",
			f.Priority, f.RowID, f.Tier, f.Gap)
		fmt.Fprintf(r.Out, "    reason: %s\n", validation.PyReprStr(f.Reason))
		fmt.Fprintf(r.Out, "    tokens: %s\n", pyReprStrs(f.Tokens))
		fmt.Fprintln(r.Out, "    re-answer with --finding F-<id> or "+
			"--interim STATEMENT (citing the row's own surface entry), or "+
			"--override-dismissal --override-reason R")
	}
}

// pyReprStrs is a Python list repr of strings.
func pyReprStrs(items []string) string {
	arr := validation.VArr()
	for _, s := range items {
		arr.A = append(arr.A, validation.VStr(s))
	}
	return validation.PyRepr(arr)
}

func init() {
	register(command{ord: 82, name: "deferred",
		line: "deferred <campaign> [--json]          tier-0 closures that defer the check without pricing it",
		run:  runDeferred})
}
