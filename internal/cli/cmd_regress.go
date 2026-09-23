package cli

// cmd_regress: `webv2 regress <campaign> {target add|pin|list, run, status}` —
// the v1.6 Part 3a regression suite's record surface. One campaign per target;
// every record is schema-validated and ledgered (internal/regression).
//
// Exit codes: 0 recorded, 2 argparse/usage error, 1 refusal (a real answer of
// "no": unknown target, an unpinnable SHA, a scorer this suite does not read).

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"websec/internal/regression"
	"websec/internal/state"
	"websec/internal/validation"
)

const (
	regressUsage = `usage: webv2 regress [-h] [--rows ROWS] [--out OUT]
                     [--dataset DATASET] [--snapshot-date SNAPSHOT_DATE]
                     {labels,campaign} ...
`

	regressHelp = `usage: webv2 regress [-h] [--rows ROWS] [--out OUT]
                     [--dataset DATASET] [--snapshot-date SNAPSHOT_DATE]
                     {labels,campaign} ...

positional arguments:
  {labels,campaign}
    labels             derive the class labels for one ScaBench snapshot's rows
    campaign           a campaign id (C-...): the target/run/status verbs

options:
  -h, --help       show this help message and exit
  --rows ROWS      labels: a JSON array of the snapshot's rows, as extracted
  --out OUT        labels: the label file to write (plus its .sha256 sidecar)
  --dataset DATASET
                   labels: the dataset name (default: scabench)
  --snapshot-date SNAPSHOT_DATE
                   labels: the snapshot date (default: 2025-08-18)

subcommands:
  target add         record one regression target
  target add-control record the already-exploited control target (incident +
                     pre-patch pin + its own harness)
  target handoff     record the P1 handoff: a CONFIRMED finding on the control
                     target and its extractable_usd — or, when no figure is
                     defensible, the unpriceable decision
                     (--unpriceable --ceiling C --reason R --actor A)
  target pin         bind a target to a resolved 40-hex SHA and its snapshot
  target list        list the campaign's targets
  run                record one coarse score for a target
  status             the human view of the suite records
`
)

// regressDefaultDataset is the dataset the regression suite reads: the
// ScaBench curated snapshot (§3a). It is the default of `regress labels
// --dataset` and the kind string `target add` uses for a dataset-sourced
// target, so the two cannot drift apart.
const regressDefaultDataset = "scabench"

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
	// the control target and the P1 handoff (Task 2)
	"--incident-url": true, "--incident-date": true, "--loss-usd": true,
	"--loss-source": true, "--postmortem-url": true, "--pre-patch-sha": true,
	"--patch-sha": true, "--harness-runner": true, "--harness-command": true,
	"--finding": true, "--extractable-usd": true, "--source": true,
	// the handoff's unpriceable decision (the named-decision escape)
	"--ceiling": true, "--reason": true,
	// the repo-level `labels` action (Task 3)
	"--rows": true, "--out": true, "--dataset": true, "--snapshot-date": true,
}

// regressParse is the verb's parsed command line: positionals, flag values,
// and the boolean switches.
type regressParse struct {
	pos         []string
	vals        map[string]string
	asJSON      bool
	unpriceable bool
	help        bool
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
	case a == "--unpriceable":
		// A SWITCH, like --json: the handoff's named decision is a mode, not
		// a value, and `--unpriceable=true` is refused by the --flag=value
		// arm exactly as argparse's store_true refuses it.
		st.unpriceable = true
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
	if len(st.pos) < 1 {
		return t14ArgparseErr(regressUsage, "regress",
			"the following arguments are required: campaign, action")
	}
	if handled, err := dispatchRegressRepo(st, root, r); handled {
		return err
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

// dispatchRegressRepo runs a repo-level action — one that operates on the eval
// store rather than on a campaign — and reports whether the first positional
// named one. `labels` is the only action today; `select` (Task 4) and `suite`
// (Task 10) join the switch.
//
// The dispatch is by NAME, and that is the point: choosing the branch by the
// absence of a `C-` prefix is what made the routing incidental, and it silently
// changed a pre-existing refusal — `webv2 regress mycamp status` exited 1 with
// "malformed campaign id" and became an argparse "invalid choice" (exit 2). The
// prefix is not the id grammar anyway (^C-[0-9a-z]{8,16}$), so only the
// campaign path can decide a malformed id: an unrecognised first positional
// falls through to it and keeps the old refusal.
func dispatchRegressRepo(st *regressParse, root string, r *Runner) (bool, error) {
	if st.pos[0] != "labels" {
		return false, nil
	}
	if len(st.pos) > 1 {
		// A trailing positional is refused rather than ignored: `regress labels
		// extra` dropping "extra" silently is how an operator typo becomes a run
		// that looks successful. The root parser reports it, as argparse does.
		return true, t14Unrecognized(strings.Join(st.pos[1:], " "))
	}
	// The repo-level actions need the CLI's root, and the global --root was
	// consumed before this verb ran, so hand it down under the parser's own key
	// convention (leading dashes).
	st.vals["--root"] = root
	return true, regressLabels(st.vals, r)
}

// regressLabels derives the label file from a snapshot's rows:
//
//	webv2 regress labels --rows <rows.json> --out <labels.json> \
//	    [--dataset scabench] [--snapshot-date 2025-08-18]
//
// --rows is a JSON array of the snapshot's rows as extracted, verbatim.
func regressLabels(vals map[string]string, r *Runner) error {
	if vals["--rows"] == "" || vals["--out"] == "" {
		return t14ArgparseErr(regressUsage, "regress",
			"the following arguments are required: --rows, --out")
	}
	rows, err := regressLabelRows(vals["--rows"])
	if err != nil {
		return err
	}
	labels, err := regressLabelsFromRows(rows, vals)
	if err != nil {
		return err
	}
	if err := regression.WriteRepoRecord(vals["--out"], labels, "regression_labels"); err != nil {
		return err
	}
	printRegressLabels(r, len(rows), regression.UnmappedCount(labels), vals["--out"])
	return nil
}

// regressLabelsFromRows classifies the extracted rows under the label file's
// provenance (the dataset's defaults unless the operator overrode them).
func regressLabelsFromRows(rows []validation.Value, vals map[string]string) (validation.Value, error) {
	dataset, snapDate := regressLabelProvenance(vals)
	return regression.DeriveLabels(rows, dataset, snapDate)
}

// regressLabelRows reads the extracted snapshot rows: the file must be a JSON
// array, because DeriveLabels classifies a list of vulnerability records and a
// silently-flattened object would classify as zero rows.
func regressLabelRows(path string) ([]validation.Value, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	doc, err := validation.ParseOrdered(raw)
	if err != nil {
		return nil, err
	}
	if doc.Kind != validation.Arr {
		return nil, fmt.Errorf("--rows must be a JSON array of rows, got %v", doc.Kind)
	}
	return doc.A, nil
}

// regressLabelProvenance is the label file's provenance with the curated
// snapshot's own defaults (§3a: scabench, 2025-08-18).
func regressLabelProvenance(vals map[string]string) (string, string) {
	dataset, snapDate := vals["--dataset"], vals["--snapshot-date"]
	if dataset == "" {
		dataset = regressDefaultDataset
	}
	if snapDate == "" {
		snapDate = "2025-08-18"
	}
	return dataset, snapDate
}

// printRegressLabels is the operator-facing half: what was written, and the
// review the named source of error still owes. The unmapped count is printed
// even when it is zero — a blank would read as "no review needed".
func printRegressLabels(r *Runner, rows, unmapped int, out string) {
	_, _ = fmt.Fprintf(r.Out, "%d row(s) labelled, %d unmapped -> %s\n",
		rows, unmapped, out)
	_, _ = fmt.Fprintf(r.Out, "unmapped rows are the named source of error (§3a): read "+
		"them, extend LabelRules where a rule is missing, and re-run before "+
		"committing — set unmapped_reviewed only after that.\n")
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
	case "add-control":
		return regressTargetAddControl(c, st.vals, r)
	case "handoff":
		if len(st.pos) < 4 {
			return t14ArgparseErr(regressUsage, "regress",
				"the following arguments are required: target_id")
		}
		return regressTargetHandoff(c, st.pos[3], st, r)
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
			"(choose from 'add', 'add-control', 'pin', 'handoff', 'list')", st.pos[2])
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
	if vals["--kind"] == regressDefaultDataset && vals["--commit-hint"] == "" &&
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

// regressFloat parses one float-valued flag, with argparse's wording for a
// value it cannot read.
func regressFloat(vals map[string]string, flag string) (float64, error) {
	f, err := strconv.ParseFloat(vals[flag], 64)
	if err != nil {
		return 0, t14ArgparseErr(regressUsage, "regress",
			"argument %s: invalid float value: %q", flag, vals[flag])
	}
	return f, nil
}

// regressTargetAddControl records the already-exploited control target (§3a)
// as TWO records: the target row first (kind=control, shape=already-exploited)
// and the incident/control block second. The order is deliberate — a target is
// a target even before its incident is sourced, and the audit section must be
// able to say "this control target carries no control block yet" rather than
// pretending the row does not exist.
func regressTargetAddControl(c *state.Campaign, vals map[string]string, r *Runner) error {
	loss, err := regressFloat(vals, "--loss-usd")
	if err != nil {
		return err
	}
	target, err := regression.AddTarget(c, regression.TargetSpec{
		Kind: "control", Program: vals["--program"],
		RecordID: vals["--record-id"], Repo: vals["--repo"],
		Shape: "already-exploited", CommitHint: vals["--pre-patch-sha"],
	})
	if err != nil {
		return err
	}
	doc, err := regression.RecordControl(c, regression.ControlSpec{
		TargetID:    validation.ObjStr(target, "target_id"),
		IncidentURL: vals["--incident-url"], IncidentDate: vals["--incident-date"],
		LossUSD: loss, LossSource: vals["--loss-source"],
		PostmortemURL: vals["--postmortem-url"],
		PrePatchSHA:   vals["--pre-patch-sha"], PatchSHA: vals["--patch-sha"],
		HarnessRunner: vals["--harness-runner"], HarnessCommand: vals["--harness-command"],
	})
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(r.Out, "control target %s recorded (pre-patch %s)\n",
		validation.ObjStr(doc, "target_id"), vals["--pre-patch-sha"])
	return nil
}

// regressTargetHandoff records the P1 handoff: the CONFIRMED finding on the
// control target and the extractable figure P1's Task 10 spike consumes — or,
// with --unpriceable, the NAMED DECISION that no figure is defensible
// (ceiling + reason + actor, and no figure). The decision branch is the same
// escape `impact --unpriceable` records on a finding
// (risk.RecordUnpriceable), applied to the handoff the control target needs:
// without it the only way to close the audit's "carries no P1 handoff" was to
// invent a number.
func regressTargetHandoff(c *state.Campaign, tid string, st *regressParse, r *Runner) error {
	vals := st.vals
	// The guard is the flag's PRESENCE, not its value: `--extractable-usd 0`
	// and `--extractable-usd ""` are both the operator asking for a figure on
	// a decision that refuses one, and a dropped flag is exactly the silent
	// laundering the escape must not become (the same reason a trailing
	// positional is refused rather than ignored). The wording is the write
	// path's, because it is the operator's answer either way.
	if _, given := vals["--extractable-usd"]; st.unpriceable && given {
		return fmt.Errorf("an unpriceable handoff must not carry "+
			"extractable_usd (got %q): the escape records why no figure "+
			"exists, not a figure", vals["--extractable-usd"])
	}
	spec := regression.HandoffSpec{
		TargetID: tid, FindingID: vals["--finding"],
		Source: vals["--source"], RecordedBy: vals["--actor"],
		Unpriceable: st.unpriceable, Ceiling: vals["--ceiling"],
		Reason: vals["--reason"],
	}
	if !st.unpriceable {
		usd, err := regressFloat(vals, "--extractable-usd")
		if err != nil {
			return err
		}
		spec.ExtractableUSD = usd
	}
	doc, err := regression.RecordHandoff(c, spec)
	if err != nil {
		return err
	}
	printRegressHandoff(r, tid, validation.ObjAt(doc, "handoff"))
	return nil
}

// printRegressHandoff is the operator-facing half of the record: which finding
// the handoff names and which of the two honest states it carries. An
// unpriceable decision prints the ceiling where the figure used to print —
// never a zero, which would read as a measurement.
func printRegressHandoff(r *Runner, tid string, ho validation.Value) {
	if p := validation.ObjAt(ho, "priceable"); p.Kind == validation.Bool && !p.B {
		_, _ = fmt.Fprintf(r.Out, "handoff recorded: target %s -> finding %s, "+
			"extractable_usd=UNPRICEABLE (ceiling: %s) (P1 Task 10 consumes this)\n",
			tid, validation.ObjStr(ho, "finding_id"),
			validation.ObjStr(ho, "ceiling"))
		return
	}
	_, _ = fmt.Fprintf(r.Out, "handoff recorded: target %s -> finding %s, "+
		"extractable_usd=%v (P1 Task 10 consumes this)\n", tid,
		validation.ObjStr(ho, "finding_id"), validation.ObjAt(ho, "extractable_usd").F)
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

// printRegressControlLines is the control target's own view: the pre-patch pin
// and, when it exists, the P1 handoff. A control target with neither is the
// half-finished state the audit section keeps red, so it prints too — with a
// dash, never a zero. An unpriceable handoff prints its decision and the
// ceiling basis where the figure used to print (the report's own convention
// for a finding's unpriceable impact), so an absent figure can never read as a
// measured one.
func printRegressControlLines(r *Runner, targets []validation.Value) {
	for _, t := range targets {
		if validation.ObjStr(t, "kind") != "control" {
			continue
		}
		ho := validation.ObjAt(t, "handoff")
		_, _ = fmt.Fprintf(r.Out,
			"%s  control pre-patch=%s handoff=%s extractable_usd=%s\n",
			validation.ObjStr(t, "target_id"),
			orDash(validation.ObjStr(validation.ObjAt(t, "control"), "pre_patch_sha")),
			orDash(validation.ObjStr(ho, "finding_id")), handoffUSDCell(ho))
	}
}

// handoffUSDCell renders the status line's figure column: the number when the
// handoff is priceable, "unpriceable (ceiling: ...)" when the named decision
// stands in for it, and a dash when there is no handoff at all.
//
// The number is read Int/Flt-aware: a hand-edited (or reference-written)
// integer 900000 parses as an Int, and reading .F alone printed a 0 the record
// never held — a fabricated measurement in the one column that must never
// carry one. A Flt prints exactly as it always has (%v), so the priceable
// path's bytes do not move.
func handoffUSDCell(ho validation.Value) string {
	if p := validation.ObjAt(ho, "priceable"); p.Kind == validation.Bool && !p.B {
		return fmt.Sprintf("unpriceable (ceiling: %s)",
			validation.ObjStr(ho, "ceiling"))
	}
	switch usd := validation.ObjAt(ho, "extractable_usd"); usd.Kind {
	case validation.Int:
		return validation.IntText(usd)
	case validation.Flt:
		return fmt.Sprintf("%v", usd.F)
	}
	return "-"
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
	printRegressControlLines(r, targets)
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
