package cli

// cmd_fact_read: `webv2 fact-read <campaign> <finding> --command C --value V
// --block N [--chain C] [--actor A] [--read-only]` — record a value READ from
// the deployment (framework-plan-v1.6 Part 8, non-negotiable 5). The snapshot
// proves which CODE runs, never what the INSTANCE holds, so a value the
// exploit turns on is a fact only when it carries the command that read it and
// the block it was read at (RUNBOOK §4c).
//
// The refusal text IS the output (exit 2): the pinned-block and
// mutating-command refusals come from findings.RecordFactRead and are printed
// verbatim, so an operator reading stderr sees the rule, not a wrapper.

import (
	"fmt"
	"strconv"

	"websec/internal/findings"
	"websec/internal/validation"
)

// factReadUsage is the verb's own usage line: helpUsageText renders the same
// text from the registry entry, so `-h` and a parse failure cannot disagree
// about the signature.
func factReadUsage() string { return helpUsageText("fact-read") }

func runFactRead(root string, args []string, r *Runner) int {
	return t14Dispatch(root, r, func() error {
		return factReadCmd(root, args, r)
	})
}

func factReadCmd(root string, args []string, r *Runner) error {
	if helpRequested(r.Out, "fact-read", args) {
		return nil
	}
	sp := factReadSpec()
	if err := sp.parse(args); err != nil {
		return err
	}
	block, err := factReadBlock(sp.vals[2].val)
	if err != nil {
		return err
	}
	c, err := t14Open(root, sp.pos[0].val)
	if err != nil {
		return err
	}
	if _, err := findings.RecordFactRead(c, sp.pos[1].val, sp.vals[0].val,
		sp.vals[1].val, sp.vals[3].val, sp.vals[4].val, block,
		sp.flags[0].set); err != nil {
		return t14ExitErr(2, "%v\n", err)
	}
	if _, err := fmt.Fprintf(r.Out, "fact read on %s at block %d: %s\n",
		sp.pos[1].val, block, sp.vals[1].val); err != nil {
		return err
	}
	return nil
}

// factReadSpec is the argparse shape: two positionals, the three required
// values, the two optional ones, and the store_true attestation.
func factReadSpec() *argSpec {
	return &argSpec{
		prog:  "fact-read",
		usage: factReadUsage(),
		vals: []*valOpt{
			{name: "--command", required: true},
			{name: "--value", required: true},
			{name: "--block", required: true},
			{name: "--chain"},
			{name: "--actor"},
		},
		flags: []*boolOpt{{name: "--read-only"}},
		pos:   []*posOpt{{name: "campaign"}, {name: "finding"}},
	}
}

// factReadBlock parses --block: the pinned block, refused downstream when it
// is not a positive number.
func factReadBlock(raw string) (int64, error) {
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, t14ArgparseErr(factReadUsage(), "fact-read",
			"argument --block: invalid int value: %s",
			validation.PyReprStr(raw))
	}
	return n, nil
}

func init() {
	register(command{ord: 94, name: "fact-read",
		line: `fact-read <campaign> <finding> --command C --value V --block N [--chain C] [--actor A] [--read-only]   record a deployment read as a fact`,
		run:  runFactRead})
}
