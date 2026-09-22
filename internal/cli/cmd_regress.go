package cli

// cmd_regress: `webv2 regress <campaign> {target add|pin|list, run, status}` —
// the v1.6 Part 3a regression suite's record surface. One campaign per target;
// every record is schema-validated and ledgered (internal/regression).
//
// Exit codes: 0 recorded, 2 argparse/usage error, 1 refusal (a real answer of
// "no": unknown target, an unpinnable SHA, a scorer this suite does not read).

import (
	"fmt"
	"strconv"
	"strings"

	"websec/internal/regression"
	"websec/internal/state"
	"websec/internal/validation"
)

const (
	regressUsage = `usage: webv2 regress [-h] campaign {target,run,status} ...
`

	regressHelp = `usage: webv2 regress [-h] campaign {target,run,status} ...

positional arguments:
  campaign

options:
  -h, --help       show this help message and exit

subcommands:
  target add       record one regression target
  target pin       bind a target to a resolved 40-hex SHA and its snapshot
  target list      list the campaign's targets
  run              record one coarse score for a target
  status           the human view of the suite records
`
)

// regressValueFlags is every flag that takes a value. Every later task that
// adds a flag adds its name — WITH the leading "--", because that is the key
// this parser stores. This is the one place the convention lives.
var regressValueFlags = map[string]bool{
	"--kind": true, "--program": true, "--record-id": true, "--repo": true,
	"--codebase-id": true,
	"--shape":       true, "--commit-hint": true, "--resolved-sha": true,
	"--snapshot": true, "--actor": true, "--target": true, "--scorer": true,
	"--score-file": true, "--found": true, "--missed": true,
	"--false-positives": true, "--verdict": true, "--verdict-note": true,
	"--report-url": true, "--artifact": true, "--notes": true,
}

// regressParse is the verb's parsed command line: positionals, flag values,
// and the two boolean switches.
type regressParse struct {
	pos    []string
	vals   map[string]string
	asJSON bool
	help   bool
}

// assignInline applies one `--flag=value` argument.
func (st *regressParse) assignInline(a string) error {
	k, v, found := strings.Cut(a, "=")
	if !found || !regressValueFlags[k] {
		return t14Unrecognized(a)
	}
	st.vals[k] = v
	return nil
}

// assignNext applies one `--flag value` argument and reports how many extra
// arguments it consumed.
func (st *regressParse) assignNext(a string, args []string, i int) (int, error) {
	if i+1 >= len(args) || looksLikeOption(args[i+1]) {
		return 0, t14ArgparseErr(regressUsage, "regress",
			"argument %s: expected one argument", a)
	}
	st.vals[a] = args[i+1]
	return 1, nil
}

// regressFlag applies one argument to the parse state.
func regressFlag(st *regressParse, args []string, i int) (int, error) {
	a := args[i]
	switch {
	case a == "--json":
		st.asJSON = true
		return 0, nil
	case strings.HasPrefix(a, "--") && strings.Contains(a, "="):
		return 0, st.assignInline(a)
	case regressValueFlags[a]:
		return st.assignNext(a, args, i)
	case strings.HasPrefix(a, "-"):
		return 0, t14Unrecognized(a)
	}
	st.pos = append(st.pos, a)
	return 0, nil
}

// parseRegressArgs hand-parses the verb (the house pattern for a new verb
// whose subcommands each take a different flag set — see runScope,
// internal/cli/cmd_scope.go). `-h` wins as soon as it is reached, before any
// later argument is looked at (argparse's order).
func parseRegressArgs(args []string) (*regressParse, error) {
	st := &regressParse{vals: map[string]string{}}
	for i := 0; i < len(args); i++ {
		if a := args[i]; a == "-h" || a == "--help" {
			st.help = true
			return st, nil
		}
		n, err := regressFlag(st, args, i)
		if err != nil {
			return nil, err
		}
		i += n
	}
	return st, nil
}

func runRegress(root string, args []string, r *Runner) int {
	return t14Dispatch(root, r, func() error { return regressCmd(root, args, r) })
}

func regressCmd(root string, args []string, r *Runner) error {
	st, err := parseRegressArgs(args)
	if err != nil {
		return err
	}
	if st.help {
		_, _ = fmt.Fprint(r.Out, regressHelp)
		return nil
	}
	if len(st.pos) < 2 {
		return t14ArgparseErr(regressUsage, "regress",
			"the following arguments are required: campaign, action")
	}
	c, err := t14Open(root, st.pos[0])
	if err != nil {
		return err
	}
	return dispatchRegress(c, st, r)
}

func dispatchRegress(c *state.Campaign, st *regressParse, r *Runner) error {
	switch st.pos[1] {
	case "target":
		return dispatchRegressTarget(c, st, r)
	case "run":
		return regressRun(c, st.vals, r)
	case "status":
		return regressStatus(c, st.asJSON, r)
	}
	return t14ArgparseErr(regressUsage, "regress",
		"argument regress_cmd: invalid choice: %q (choose from 'target', 'run', 'status')",
		st.pos[1])
}

func dispatchRegressTarget(c *state.Campaign, st *regressParse, r *Runner) error {
	if len(st.pos) < 3 {
		return t14ArgparseErr(regressUsage, "regress",
			"the following arguments are required: target_cmd")
	}
	switch st.pos[2] {
	case "add":
		return regressTargetAdd(c, st.vals, r)
	case "pin":
		if len(st.pos) < 4 {
			return t14ArgparseErr(regressUsage, "regress",
				"the following arguments are required: target_id")
		}
		return regressTargetPin(c, st.pos[3], st.vals, r)
	case "list":
		return regressTargetList(c, st.asJSON, r)
	}
	return t14ArgparseErr(regressUsage, "regress",
		"argument target_cmd: invalid choice: %q "+
			"(choose from 'add', 'pin', 'list')", st.pos[2])
}

// requireRegressFlags is argparse's "the following arguments are required"
// for the named flags.
func requireRegressFlags(vals map[string]string, flags ...string) error {
	for _, k := range flags {
		if vals[k] == "" {
			return t14ArgparseErr(regressUsage, "regress",
				"the following arguments are required: %s", k)
		}
	}
	return nil
}

func regressTargetAdd(c *state.Campaign, vals map[string]string, r *Runner) error {
	if err := requireRegressFlags(vals, "--kind", "--program", "--shape"); err != nil {
		return err
	}
	// A scabench target whose dataset commit field is empty must still name
	// the row it came from (the dataset emits "" for Initia Move_b36d06 and
	// Starknet Perpetual_main). argparse-shaped, because it is a missing
	// argument, not a refusal: AddTarget keeps the same rule as a package
	// invariant.
	if vals["--kind"] == "scabench" && vals["--commit-hint"] == "" &&
		(vals["--record-id"] == "" || vals["--repo"] == "") {
		return t14ArgparseErr(regressUsage, "regress",
			"the following arguments are required: --record-id, --repo")
	}
	doc, err := regression.AddTarget(c, regression.TargetSpec{
		Kind: vals["--kind"], Program: vals["--program"],
		RecordID: vals["--record-id"], CodebaseID: vals["--codebase-id"],
		Repo:  vals["--repo"],
		Shape: vals["--shape"], CommitHint: vals["--commit-hint"],
	})
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(r.Out, "regression target %s added (%s, %s)\n",
		validation.ObjStr(doc, "target_id"), vals["--kind"], vals["--shape"])
	return nil
}

func regressTargetPin(c *state.Campaign, tid string, vals map[string]string, r *Runner) error {
	if err := requireRegressFlags(vals, "--resolved-sha", "--snapshot"); err != nil {
		return err
	}
	doc, err := regression.PinTarget(c, regression.PinSpec{
		TargetID: tid, ResolvedSHA: vals["--resolved-sha"],
		SnapshotID: vals["--snapshot"], ResolvedBy: vals["--actor"],
	})
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(r.Out, "pinned %s to %s at snapshot %s\n",
		validation.ObjStr(doc, "target_id"),
		validation.ObjStr(doc, "resolved_sha"),
		validation.ObjStr(doc, "snapshot_id"))
	return nil
}

func regressTargetList(c *state.Campaign, asJSON bool, r *Runner) error {
	targets, err := regression.LoadTargets(c)
	if err != nil {
		return err
	}
	if asJSON {
		_, _ = fmt.Fprintln(r.Out, validation.CanonSpaced(validation.VArr(targets...)))
		return nil
	}
	if len(targets) == 0 {
		_, _ = fmt.Fprintln(r.Out, "no regression targets recorded")
		return nil
	}
	for _, t := range targets {
		_, _ = fmt.Fprintf(r.Out, "%s  %-9s %-24s %-22s sha=%s\n",
			validation.ObjStr(t, "target_id"), validation.ObjStr(t, "kind"),
			validation.ObjStr(t, "program"), validation.ObjStr(t, "shape"),
			orDash(validation.ObjStr(t, "resolved_sha")))
	}
	return nil
}

// runSpecFromVals is the flag map's translation into a RunSpec, including the
// three transcribed counts.
func runSpecFromVals(vals map[string]string) (regression.RunSpec, error) {
	spec := regression.RunSpec{
		TargetID: vals["--target"], Scorer: vals["--scorer"],
		ScoreFile: vals["--score-file"], Verdict: vals["--verdict"],
		VerdictNote: vals["--verdict-note"], ReportURL: vals["--report-url"],
		ArtifactID: vals["--artifact"], Notes: vals["--notes"],
	}
	for _, f := range []struct {
		flag string
		dst  *int64
	}{
		{"--found", &spec.Found}, {"--missed", &spec.Missed},
		{"--false-positives", &spec.FalsePositives},
	} {
		if v := vals[f.flag]; v != "" {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return spec, t14ArgparseErr(regressUsage, "regress",
					"argument %s: invalid int value: %q", f.flag, v)
			}
			*f.dst = n
		}
	}
	return spec, nil
}

// printRegressRun renders one recorded run and the D8 label, in the
// operator's face: the number just recorded is not a detection rate and must
// never be quoted as one (§3a, Part 10 item 4).
func printRegressRun(r *Runner, doc validation.Value) {
	score := validation.ObjAt(doc, "score")
	_, _ = fmt.Fprintf(r.Out, "regression run %s recorded for %s: found=%s missed=%s "+
		"false_positives=%s verdict=%s\n", validation.ObjStr(doc, "run_id"),
		validation.ObjStr(doc, "target_id"),
		validation.IntText(validation.ObjAt(score, "found")),
		validation.IntText(validation.ObjAt(score, "missed")),
		validation.IntText(validation.ObjAt(score, "false_positives")),
		validation.ObjStr(score, "verdict"))
	_, _ = fmt.Fprintln(r.Out, "measurement: rediscovery — this is not a detection rate")
}

func regressRun(c *state.Campaign, vals map[string]string, r *Runner) error {
	if err := requireRegressFlags(vals, "--target", "--scorer"); err != nil {
		return err
	}
	spec, err := runSpecFromVals(vals)
	if err != nil {
		return err
	}
	doc, err := regression.RecordRun(c, spec)
	if err != nil {
		return err
	}
	printRegressRun(r, doc)
	return nil
}

func printRegressTargetLines(r *Runner, targets []validation.Value) {
	for _, t := range targets {
		_, _ = fmt.Fprintf(r.Out, "%s  %-9s %-24s sha=%s snapshot=%s\n",
			validation.ObjStr(t, "target_id"), validation.ObjStr(t, "kind"),
			validation.ObjStr(t, "program"),
			orDash(validation.ObjStr(t, "resolved_sha")),
			orDash(validation.ObjStr(t, "snapshot_id")))
	}
}

func printRegressRunLines(r *Runner, runs []validation.Value) {
	for _, run := range runs {
		_, _ = fmt.Fprintf(r.Out, "%s  target=%s scorer=%s verdict=%s measurement: %s\n",
			validation.ObjStr(run, "run_id"), validation.ObjStr(run, "target_id"),
			validation.ObjStr(run, "scorer"),
			validation.ObjStr(validation.ObjAt(run, "score"), "verdict"),
			validation.ObjStr(run, "measurement"))
	}
}

func regressStatus(c *state.Campaign, asJSON bool, r *Runner) error {
	targets, err := regression.LoadTargets(c)
	if err != nil {
		return err
	}
	runs, err := regression.LoadRuns(c)
	if err != nil {
		return err
	}
	if asJSON {
		_, _ = fmt.Fprintln(r.Out, validation.CanonSpaced(validation.VObj(
			validation.KV{K: "targets", V: validation.VArr(targets...)},
			validation.KV{K: "runs", V: validation.VArr(runs...)},
		)))
		return nil
	}
	_, _ = fmt.Fprintf(r.Out, "%d target(s), %d run(s)\n", len(targets), len(runs))
	printRegressTargetLines(r, targets)
	printRegressRunLines(r, runs)
	return nil
}

// orDash renders an absent key as a dash rather than an empty field, so a
// missing pin reads as missing.
func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func init() {
	register(command{ord: 96, name: "regress",
		line: "regress <campaign>            the Phase 0 regression suite's records",
		run:  runRegress})
}
