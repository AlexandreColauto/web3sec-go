package cli

// cmd_sequence: `webv2 sequence run <campaign> <spec> --finding F` and
// `webv2 sequence verify <campaign> <finding> [--exec E]` — the multi-tx
// sequence PoC surface (cli.py cmd_sequence_run / cmd_sequence_verify,
// verbatim). `sequence` is the first subparser command in the port: the
// dispatch, the {run,verify} usage block, the "sequence_cmd" required error
// and the invalid-choice text are all argparse's own (pinned from the live
// CLI at COLUMNS=80).
//
// Exit contract (cli.py): run exits 2 on any handler failure; verify exits
// 0 covered, 3 not covered, 2 error. argparse failures exit 2.

import (
	"fmt"
	"strings"

	"websec/internal/findings"
	"websec/internal/sandbox"
	"websec/internal/sequencepoc"
	"websec/internal/state"
	"websec/internal/validation"
)

// ---- pinned argparse text (COLUMNS=80, live cli.py) -----------------------

const t14SequenceUsage = "usage: webv2 sequence [-h] {run,verify} ...\n"

const t14SequenceRunUsage = "usage: webv2 sequence run [-h] --finding FINDING [--workdir WORKDIR]\n" +
	"                          campaign spec\n"

const t14SequenceVerifyUsage = "usage: webv2 sequence verify [-h] [--exec EXEC] campaign finding\n"

const t14SequenceHelp = `usage: webv2 sequence [-h] {run,verify} ...

positional arguments:
  {run,verify}
    run         validate + execute a sequence spec (records the T4 attempt)
    verify      check a finding's attempts for verified sequence coverage

options:
  -h, --help    show this help message and exit
`

// t14SequenceRunHelp is the pinned run help plus the D5 coverage line: the
// other verbs' prose is ours, this one line documents the rule the operator
// would otherwise only learn by failing it. The rest is pinned argparse
// text from the live cli.py at COLUMNS=80.
const t14SequenceRunHelp = `usage: webv2 sequence run [-h] --finding FINDING [--workdir WORKDIR]
                          campaign spec

coverage: the executed steps must use every actor the finding's exploit_sequence
declares — a declared role that sends no transaction still counts until that
sequence drops it

positional arguments:
  campaign
  spec               path to the sequence PoC spec JSON

options:
  -h, --help         show this help message and exit
  --finding FINDING  finding whose exploit_sequence this covers
  --workdir WORKDIR  working directory (bind-mounted)
`

const t14SequenceVerifyHelp = `usage: webv2 sequence verify [-h] [--exec EXEC] campaign finding

positional arguments:
  campaign
  finding

options:
  -h, --help   show this help message and exit
  --exec EXEC  verify one specific exec instead of all attempts
`

// ---- dispatch -------------------------------------------------------------

func runSequence(root string, args []string, r *Runner) int {
	return t14Dispatch(root, r, func() error {
		return sequenceDispatch(root, args, r)
	})
}

// sequenceDispatch is argparse's subparser step: the first NON-option token
// selects run or verify (options seen before it are forwarded to that
// subparser as unknowns, exactly as argparse hands them down); -h at this
// level prints the sequence help; no subcommand token at all is the
// required-argument error.
func sequenceDispatch(root string, args []string, r *Runner) error {
	var pre []string
	for i, tok := range args {
		if tok == "-h" || tok == "--help" {
			fmt.Fprint(r.Out, t14SequenceHelp)
			return nil
		}
		if !isOptionToken(tok) {
			rest := append(append([]string{}, pre...), args[i+1:]...)
			switch tok {
			case "run":
				return sequenceRunCmd(root, rest, r)
			case "verify":
				return sequenceVerifyCmd(root, rest, r)
			}
			return t14ArgparseErr(t14SequenceUsage, "sequence",
				"argument sequence_cmd: invalid choice: %s (choose from "+
					"'run', 'verify')", validation.PyReprStr(tok))
		}
		pre = append(pre, tok)
	}
	return t14ArgparseErr(t14SequenceUsage, "sequence",
		"the following arguments are required: sequence_cmd")
}

// ---- run ------------------------------------------------------------------

// seqRunArgs is the parsed shape of `sequence run` (argparse's namespace).
type seqRunArgs struct {
	pos        []string
	unknown    []string
	finding    string
	workdir    string
	findingSet bool
	workdirSet bool
}

// isOptionToken is argparse's "looks like an option": starts with '-' but is
// not the bare "-" (which is a legal positional/option value).
func isOptionToken(s string) bool {
	return strings.HasPrefix(s, "-") && s != "-"
}

// parseSequenceRun is argparse.parse_args for the run subparser: -h prints
// help immediately, an option missing its value fails immediately, and
// unknown arguments are only collected — argparse reports missing required
// arguments ahead of them, so they cannot be raised while parsing.
func parseSequenceRun(args []string, r *Runner) (seqRunArgs, bool, error) {
	var a seqRunArgs
	for i := 0; i < len(args); i++ {
		tok := args[i]
		switch {
		case tok == "-h" || tok == "--help":
			fmt.Fprint(r.Out, t14SequenceRunHelp)
			return a, true, nil
		case tok == "--finding":
			if i+1 >= len(args) || isOptionToken(args[i+1]) {
				return a, false, t14ArgparseErr(t14SequenceRunUsage,
					"sequence run",
					"argument --finding: expected one argument")
			}
			a.finding, a.findingSet = args[i+1], true
			i++
		case strings.HasPrefix(tok, "--finding="):
			a.finding, a.findingSet = tok[len("--finding="):], true
		case tok == "--workdir":
			if i+1 >= len(args) || isOptionToken(args[i+1]) {
				return a, false, t14ArgparseErr(t14SequenceRunUsage,
					"sequence run",
					"argument --workdir: expected one argument")
			}
			a.workdir, a.workdirSet = args[i+1], true
			i++
		case strings.HasPrefix(tok, "--workdir="):
			a.workdir, a.workdirSet = tok[len("--workdir="):], true
		case isOptionToken(tok):
			a.unknown = append(a.unknown, tok)
		default:
			if len(a.pos) < 2 {
				a.pos = append(a.pos, tok)
			} else {
				a.unknown = append(a.unknown, tok)
			}
		}
	}
	return a, false, nil
}

// resolve is argparse's post-parse error order: missing required arguments
// (declaration order) first, then unrecognized arguments.
func (a seqRunArgs) resolve() error {
	var missing []string
	if len(a.pos) < 1 {
		missing = append(missing, "campaign")
	}
	if len(a.pos) < 2 {
		missing = append(missing, "spec")
	}
	if !a.findingSet {
		missing = append(missing, "--finding")
	}
	if len(missing) > 0 {
		return t14ArgparseErr(t14SequenceRunUsage, "sequence run",
			"the following arguments are required: %s",
			strings.Join(missing, ", "))
	}
	if len(a.unknown) > 0 {
		return t14Unrecognized(strings.Join(a.unknown, " "))
	}
	return nil
}

func sequenceRunCmd(root string, args []string, r *Runner) error {
	a, help, err := parseSequenceRun(args, r)
	if help || err != nil {
		return err
	}
	if err := a.resolve(); err != nil {
		return err
	}
	return sequenceRunExec(root, a, r)
}

// sequenceRunExec is cmd_sequence_run's body: one spec load, one
// run_sequence call, then the summary line (Python's try block).
func sequenceRunExec(root string, a seqRunArgs, r *Runner) error {
	c, err := t14Open(root, a.pos[0])
	if err != nil {
		return err
	}
	spec, err := sequencepoc.LoadSequenceSpec(a.pos[1])
	if err != nil {
		return t14ExitErr(2, "sequence run failed: %v\n", err)
	}
	opts := sequencepoc.RunSequenceOpts{FindingID: &a.finding}
	if a.workdirSet && a.workdir != "" {
		opts.Workdir = &a.workdir
	}
	rec, err := sequencepoc.RunSequenceFunc(c, a.pos[1], opts)
	if err != nil {
		return t14ExitErr(2, "sequence run failed: %v\n", err)
	}
	exit := validation.ObjAt(rec, "exit_status")
	fmt.Fprintf(r.Out, "%s  [fork-runner] exit=%s spec=%s steps=%d\n",
		validation.ObjStr(rec, "exec_id"), scalarStr(exit), validation.ObjStr(spec, "spec_id"),
		len(listOfSequence(validation.ObjAt(spec, "steps"))))
	if exit.Kind == validation.Int && exit.I == 0 && exit.Big == "" {
		fmt.Fprintf(r.Out, "T4 attempt recorded + E5 fork-test evidence "+
			"minted — check coverage with `webv2 sequence verify %s %s`\n",
			a.pos[0], a.finding)
		return nil
	}
	fmt.Fprintf(r.Out, "T4 attempt recorded as failed (exit %s) — inspect %s\n",
		scalarStr(exit), validation.ObjStr(rec, "stderr_path"))
	return nil
}

// ---- verify ---------------------------------------------------------------

// seqVerifyArgs is the parsed shape of `sequence verify`.
type seqVerifyArgs struct {
	pos     []string
	unknown []string
	execID  string
	execSet bool
}

// parseSequenceVerify mirrors parseSequenceRun for the verify subparser.
func parseSequenceVerify(args []string, r *Runner) (seqVerifyArgs, bool, error) {
	var a seqVerifyArgs
	for i := 0; i < len(args); i++ {
		tok := args[i]
		switch {
		case tok == "-h" || tok == "--help":
			fmt.Fprint(r.Out, t14SequenceVerifyHelp)
			return a, true, nil
		case tok == "--exec":
			if i+1 >= len(args) || isOptionToken(args[i+1]) {
				return a, false, t14ArgparseErr(t14SequenceVerifyUsage,
					"sequence verify",
					"argument --exec: expected one argument")
			}
			a.execID, a.execSet = args[i+1], true
			i++
		case strings.HasPrefix(tok, "--exec="):
			a.execID, a.execSet = tok[len("--exec="):], true
		case isOptionToken(tok):
			a.unknown = append(a.unknown, tok)
		default:
			if len(a.pos) < 2 {
				a.pos = append(a.pos, tok)
			} else {
				a.unknown = append(a.unknown, tok)
			}
		}
	}
	return a, false, nil
}

// resolve is argparse's post-parse error order for the verify subparser.
func (a seqVerifyArgs) resolve() error {
	var missing []string
	if len(a.pos) < 1 {
		missing = append(missing, "campaign")
	}
	if len(a.pos) < 2 {
		missing = append(missing, "finding")
	}
	if len(missing) > 0 {
		return t14ArgparseErr(t14SequenceVerifyUsage, "sequence verify",
			"the following arguments are required: %s",
			strings.Join(missing, ", "))
	}
	if len(a.unknown) > 0 {
		return t14Unrecognized(strings.Join(a.unknown, " "))
	}
	return nil
}

func sequenceVerifyCmd(root string, args []string, r *Runner) error {
	a, help, err := parseSequenceVerify(args, r)
	if help || err != nil {
		return err
	}
	if err := a.resolve(); err != nil {
		return err
	}
	return sequenceVerifyExec(root, a, r)
}

// sequenceVerifyExec is cmd_sequence_verify: exit 0 covered, 3 not covered,
// 2 error.
func sequenceVerifyExec(root string, a seqVerifyArgs, r *Runner) error {
	c, err := t14Open(root, a.pos[0])
	if err != nil {
		return err
	}
	findingID := a.pos[1]
	f, err := findings.LoadFinding(c, findingID)
	if err != nil {
		return t14ExitErr(2, "sequence verify failed: %v\n", err)
	}
	if !sequencepoc.IsSequenceRequired(f) {
		return t14ExitOut(0, "%s: not sequence-required — coverage is "+
			"vacuous\n", findingID)
	}
	targets, err := seqVerifyTargets(c, f, a)
	if err != nil {
		return err
	}
	return seqVerifyReport(c, f, targets, r)
}

// seqVerifyTargets selects the exec records to verify: the named --exec, or
// every recorded attempt that traces to a ledger exec (I2 normalization).
func seqVerifyTargets(c *state.Campaign, f validation.Value,
	a seqVerifyArgs) ([]validation.Value, error) {
	recs, err := sandbox.AllExecs(c)
	if err != nil {
		return nil, err
	}
	execs := map[string]validation.Value{}
	for _, rec := range recs {
		if eid := validation.ObjStr(rec, "exec_id"); eid != "" {
			execs[eid] = rec
		}
	}
	var targets []validation.Value
	if a.execSet {
		rec, ok := execs[a.execID]
		if !ok {
			return nil, t14ExitErr(2,
				"sequence verify failed: unknown exec %s\n", a.execID)
		}
		return append(targets, rec), nil
	}
	// I2: on-disk blocks are unvalidated — the gate normalizes the identical
	// inputs fail-closed (findings._as_dict), so the CLI must too instead of
	// dereferencing .get on whatever is there (attempts=None /
	// verification="confirmed" used to traceback, exit 1, outside the 0/2/3
	// contract).
	ver := asDict(validation.ObjAt(f, "verification"))
	repro := asDict(validation.ObjAt(ver, "reproduction"))
	raw := validation.ObjAt(repro, "attempts")
	var attempts []validation.Value
	if t14Truthy(raw) && raw.Kind == validation.Arr {
		attempts = raw.A
	}
	for _, a := range attempts {
		if a.Kind != validation.Obj {
			continue
		}
		if rec, ok := execs[validation.ObjStr(a, "artifact_id")]; ok {
			targets = append(targets, rec)
		}
	}
	return targets, nil
}

// seqVerifyReport prints one line per target and exits 0 when covered.
func seqVerifyReport(c *state.Campaign, f validation.Value,
	targets []validation.Value, r *Runner) error {
	covered := false
	for _, rec := range targets {
		ok, reasons := sequencepoc.VerifySequenceCoverage(c, f, rec)
		verdict := "FAIL"
		if ok {
			verdict = "PASS"
		}
		fmt.Fprintf(r.Out, "%s: %s\n", validation.ObjStr(rec, "exec_id"), verdict)
		for _, reason := range reasons {
			fmt.Fprintf(r.Out, "  - %s\n", reason)
		}
		covered = covered || ok
	}
	if len(targets) == 0 {
		fmt.Fprintln(r.Out, "no recorded attempts trace to exec records")
	}
	if covered {
		return &t14Exit{code: 0}
	}
	return &t14Exit{code: 3}
}

// asDict is findings._as_dict: a dict passes through, anything else is {}.
func asDict(v validation.Value) validation.Value {
	if v.Kind == validation.Obj {
		return v
	}
	return validation.VObj()
}

// listOfSequence is Python's len(spec["steps"]) over a list field.
func listOfSequence(v validation.Value) []validation.Value {
	if v.Kind != validation.Arr {
		return nil
	}
	return v.A
}

func init() {
	register(command{ord: 44, name: "sequence",
		line: "sequence run|verify <campaign> ...  multi-tx sequence PoC " +
			"(run / verify coverage)",
		run: runSequence})
}
