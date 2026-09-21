package cli

// cmd_impact: `webv2 impact <campaign> <finding> [--extractable USD]
// [--max-loss USD] [--required-capital USD] [--artifact PATH]
// [--description D]` — record quantified impact numbers and optionally mint
// E7 against a registered artifact. `--unpriceable` is the other honest
// answer: the NAMED DECISION that no USD figure is defensible (cli.py
// cmd_impact verbatim).

import (
	"fmt"
	"strconv"
	"strings"

	"websec/internal/findings"
	"websec/internal/risk"
	"websec/internal/state"
	"websec/internal/validation"
)

// impactArgs is the parsed command line.
type impactArgs struct {
	campaign        string
	finding         string
	extractable     *float64
	maxLoss         *float64
	requiredCapital *float64
	artifact        string
	description     string
	unpriceable     bool
	ceiling         string
	reason          string
	actor           string
	// reversibility (IMPROVEMENTS E5): victim-perspective recoverability —
	// irreversible | trusted-party | reversible, or "none" to clear. May be
	// passed alone (a classification-only call) or alongside the USD flags.
	reversibility string
	// replayable (v1.6 §2.4): the replayability calculator. perRound/gasCost
	// are required with it, frequency is optional, roundsRun nil = the
	// two-round default (the repeatability law's floor), and the two lists
	// are the record's assumptions and blockers.
	replayable  bool
	perRound    *float64
	gasCost     *float64
	frequency   *float64
	roundsRun   *int64
	assumptions []string
	blockers    []string
}

func runImpact(root string, args []string, r *Runner) int {
	return t14Dispatch(root, r, func() error {
		a, err := parseImpact(args, r)
		if err != nil || a == nil {
			return err
		}
		c, err := t14Open(root, a.campaign)
		if err != nil {
			return err
		}
		return impactBody(c, a, r)
	})
}

func impactBody(c *state.Campaign, a *impactArgs, r *Runner) error {
	if a.unpriceable {
		return impactUnpriceable(c, a, r)
	}
	rec, err := impactReplayRecord(a)
	if err != nil {
		return err
	}
	hasUSD := a.extractable != nil || a.maxLoss != nil
	if !hasUSD && a.reversibility == "" {
		return t14ExitErr(2, "impact requires --extractable USD and/or "+
			"--max-loss USD, or --reversibility MODE\n")
	}
	if hasUSD {
		if _, err := risk.RecordEconomicImpact(c, a.finding, t23Flt(a.extractable),
			t23Flt(a.maxLoss), t23Flt(a.requiredCapital)); err != nil {
			return err
		}
	}
	if a.reversibility != "" {
		if _, err := risk.RecordReversibility(c, a.finding,
			a.reversibility); err != nil {
			return err
		}
	}
	if a.replayable {
		if err := impactReplayWrite(c, a, rec, r); err != nil {
			return err
		}
	}
	f, err := findings.LoadFinding(c, a.finding)
	if err != nil {
		return err
	}
	band := validation.ObjAt(validation.ObjAt(validation.ObjAt(f, "risk"), "validated"), "band")
	if hasUSD {
		imp := validation.ObjAt(f, "economic_impact")
		fmt.Fprintf(r.Out, "%s: impact recorded — extractable $%s, max loss "+
			"$%s (risk band %s)\n", a.finding, scalarStr(validation.ObjAt(imp,
			"extractable_usd")), scalarStr(validation.ObjAt(imp, "max_loss_usd")),
			scalarStr(band))
	}
	if a.reversibility != "" {
		rv := validation.ObjStr(validation.ObjAt(f, "risk"), "reversibility")
		if a.reversibility == "none" {
			fmt.Fprintf(r.Out, "%s: reversibility cleared (risk band %s)\n",
				a.finding, scalarStr(band))
		} else {
			fmt.Fprintf(r.Out, "%s: reversibility recorded — %s (risk band %s)\n",
				a.finding, rv, scalarStr(band))
		}
	}
	return impactArtifact(c, a, r)
}

// impactArtifact is the optional E7 mint: the artifact must exist, and the
// impact line has already been printed (Python records first, checks second).
func impactArtifact(c *state.Campaign, a *impactArgs, r *Runner) error {
	if a.artifact == "" {
		return nil
	}
	if !t14Exists(a.artifact) {
		return t14ExitErr(2, "impact artifact not found: %s\n", a.artifact)
	}
	aid, err := c.RegisterOrRefresh("economic-impact", a.artifact, "", nil,
		"E7 impact evidence artifact")
	if err != nil {
		return err
	}
	desc := a.description
	if desc == "" {
		desc = "economic impact quantified"
	}
	if _, err := risk.MintImpactEvidence(c, a.finding, aid, desc); err != nil {
		return err
	}
	fmt.Fprintf(r.Out, "%s: minted E7 evidence vs %s\n", a.finding, aid)
	return nil
}

// impactUnpriceable is the named-decision branch: ceiling/reason/actor are
// all required and a USD figure is mutually exclusive.
func impactUnpriceable(c *state.Campaign, a *impactArgs, r *Runner) error {
	missing := []string{}
	for _, req := range []struct {
		flag string
		val  string
	}{{"--ceiling", a.ceiling}, {"--reason", a.reason}, {"--actor", a.actor}} {
		if strings.TrimSpace(req.val) == "" {
			missing = append(missing, req.flag)
		}
	}
	if len(missing) > 0 {
		return t14ExitErr(2, "impact --unpriceable requires %s\n",
			strings.Join(missing, ", "))
	}
	priced := []string{}
	for _, p := range []struct {
		flag string
		set  bool
	}{{"--extractable", a.extractable != nil}, {"--max-loss", a.maxLoss != nil},
		{"--required-capital", a.requiredCapital != nil},
		{"--artifact", a.artifact != ""}} {
		if p.set {
			priced = append(priced, p.flag)
		}
	}
	if len(priced) > 0 {
		return t14ExitErr(2, "impact --unpriceable cannot be combined with "+
			"%s — 'no figure is defensible' and a figure are mutually "+
			"exclusive\n", strings.Join(priced, ", "))
	}
	f, err := risk.RecordUnpriceable(c, a.finding, a.ceiling, a.reason, a.actor)
	if err != nil {
		return err
	}
	imp := validation.ObjAt(f, "economic_impact")
	fmt.Fprintf(r.Out, "%s: impact recorded — UNPRICEABLE (ceiling: %s) — "+
		"named decision logged (finding.unpriceable, actor %s)\n", a.finding,
		scalarStr(validation.ObjAt(imp, "ceiling")), a.actor)
	return nil
}

// t23Flt is the optional-float → JSON value conversion (None → null).
func t23Flt(f *float64) validation.Value {
	if f == nil {
		return validation.VNull()
	}
	return validation.VFloat(*f)
}

// parseImpact is the argparse layer (nil, nil means --help was printed).
func parseImpact(args []string, r *Runner) (*impactArgs, error) {
	a := &impactArgs{}
	var pos, extras []string
	for i := 0; i < len(args); i++ {
		consumed, done, handled, err := impactFlag(args, i, a, r)
		if err != nil {
			return nil, err
		}
		if done {
			return nil, nil
		}
		if handled {
			i += consumed
			continue
		}
		if len(pos) < 2 {
			pos = append(pos, args[i])
		} else {
			extras = append(extras, args[i])
		}
	}
	if len(pos) < 2 {
		missing := []string{"campaign", "finding"}
		return nil, t14ArgparseErr(t23ImpactUsage, "impact",
			"the following arguments are required: %s",
			strings.Join(missing[len(pos):], ", "))
	}
	if len(extras) > 0 {
		return nil, t14Unrecognized(strings.Join(extras, " "))
	}
	a.campaign, a.finding = pos[0], pos[1]
	return a, nil
}

// impactFlag consumes one option. Order mirrors argparse: --help, then the
// float flags, then the string flags, then --unpriceable, then --flag=value.
func impactFlag(args []string, i int, a *impactArgs,
	r *Runner) (consumed int, done, handled bool, err error) {
	arg := args[i]
	if arg == "-h" || arg == "--help" {
		fmt.Fprint(r.Out, t23ImpactHelp)
		return 0, true, true, nil
	}
	if arg == "--unpriceable" {
		a.unpriceable = true
		return 0, false, true, nil
	}
	if consumed, handled, err := impactReplayFlag(args, i, a); handled || err != nil {
		return consumed, false, handled, err
	}
	if name, dst := impactFloatDst(a, arg); dst != nil {
		raw, err := t23ValueArg(args, i, t23ImpactUsage, "impact", name)
		if err != nil {
			return 0, false, true, err
		}
		f, err := t23FloatArg("impact", name, raw)
		if err != nil {
			return 0, false, true, err
		}
		*dst = &f
		return 1, false, true, nil
	}
	if name, dst := impactStrDst(a, arg); dst != nil {
		raw, err := t23ValueArg(args, i, t23ImpactUsage, "impact", name)
		if err != nil {
			return 0, false, true, err
		}
		*dst = raw
		return 1, false, true, nil
	}
	if handled, err := impactEq(a, arg); handled || err != nil {
		return 0, false, handled, err
	}
	if t23IsOption(arg) {
		return 0, false, true, t14Unrecognized(arg)
	}
	return 0, false, false, nil
}

func impactFloatDst(a *impactArgs, arg string) (string, **float64) {
	switch arg {
	case "--extractable":
		return arg, &a.extractable
	case "--max-loss":
		return arg, &a.maxLoss
	case "--required-capital":
		return arg, &a.requiredCapital
	}
	return "", nil
}

func impactStrDst(a *impactArgs, arg string) (string, *string) {
	switch arg {
	case "--artifact":
		return arg, &a.artifact
	case "--description":
		return arg, &a.description
	case "--ceiling":
		return arg, &a.ceiling
	case "--reason":
		return arg, &a.reason
	case "--actor":
		return arg, &a.actor
	case "--reversibility":
		return arg, &a.reversibility
	}
	return "", nil
}

// impactEq handles the --flag=value spellings.
func impactEq(a *impactArgs, arg string) (bool, error) {
	for _, f := range []struct {
		name string
		dst  **float64
	}{{"--extractable", &a.extractable}, {"--max-loss", &a.maxLoss},
		{"--required-capital", &a.requiredCapital}} {
		if strings.HasPrefix(arg, f.name+"=") {
			v, err := t23FloatArg("impact", f.name,
				strings.TrimPrefix(arg, f.name+"="))
			if err != nil {
				return true, err
			}
			*f.dst = &v
			return true, nil
		}
	}
	for _, f := range []struct {
		name string
		dst  *string
	}{{"--artifact", &a.artifact}, {"--description", &a.description},
		{"--ceiling", &a.ceiling}, {"--reason", &a.reason},
		{"--actor", &a.actor}, {"--reversibility", &a.reversibility}} {
		if strings.HasPrefix(arg, f.name+"=") {
			*f.dst = strings.TrimPrefix(arg, f.name+"=")
			return true, nil
		}
	}
	return false, nil
}

// ---- the --replayable family (v1.6 §2.4) ----------------------------------

// impactReplayRecord is the pre-write half of the replayability calculator:
// every refusal below fires BEFORE the economic-impact write, so a refused
// total-loss claim leaves the finding byte-identical. !replayable is VNull.
func impactReplayRecord(a *impactArgs) (validation.Value, error) {
	if !a.replayable {
		return validation.VNull(), nil
	}
	if a.perRound == nil || a.maxLoss == nil || a.gasCost == nil {
		return validation.VNull(), t14ExitErr(2, "impact --replayable "+
			"requires --extractable-per-round, --max-loss and --gas-cost\n")
	}
	if a.replayRounds() < 2 {
		return validation.VNull(), t14ExitErr(2, "impact --replayable requires "+
			"at least two rounds (the repeatability law, v1.6 §2.4)\n")
	}
	if *a.perRound <= 0 || *a.maxLoss <= 0 {
		return validation.VNull(), t14ExitErr(2, "impact --replayable requires "+
			"positive --extractable-per-round and --max-loss\n")
	}
	rec := risk.ComputeReplay(a.replayRounds(), *a.perRound, *a.maxLoss,
		*a.gasCost, a.frequency)
	rec = risk.SetReplayAssumptions(rec, a.assumptions, a.blockers)
	if err := risk.ValidateReplayProfitability(rec); err != nil {
		return validation.VNull(), t14ExitErr(2, "%v\n", err)
	}
	return rec, nil
}

// impactReplayWrite records the built replay block and prints BOTH labeled
// quantities: demonstrated first (what the run extracted), computed second
// (the arithmetic ceiling). The report never conflates them; neither does
// this line.
func impactReplayWrite(c *state.Campaign, a *impactArgs, rec validation.Value,
	r *Runner) error {
	if _, err := risk.RecordReplay(c, a.finding, rec, risk.ReplayRuleCited,
		a.actor); err != nil {
		return err
	}
	demo := validation.ObjAt(rec, "demonstrated")
	comp := validation.ObjAt(rec, "computed")
	rounds := validation.ObjAt(demo, "rounds_run").I
	per := validation.ObjAt(demo, "extracted_usd_per_round").F
	if _, err := fmt.Fprintf(r.Out, "demonstrated: %d rounds x $%.2f = $%.2f "+
		"extracted\n", rounds, per, float64(rounds)*per); err != nil {
		return err
	}
	_, err := fmt.Fprintf(r.Out, "computed:     %d rounds to exhaustion, "+
		"ceiling $%.2f, attack cost $%.2f\n",
		validation.ObjAt(comp, "rounds_to_exhaustion").I,
		validation.ObjAt(comp, "ceiling_usd").F,
		validation.ObjAt(comp, "cumulative_attack_cost_usd").F)
	return err
}

// replayRounds is --rounds-run with the law's floor as the default: an absent
// flag means two rounds, never the one-round claim the schema refuses.
func (a *impactArgs) replayRounds() int64 {
	if a.roundsRun == nil {
		return 2
	}
	return *a.roundsRun
}

// impactReplayFlag consumes one --replayable-family option. handled=false
// means the token is not ours and the caller keeps scanning.
func impactReplayFlag(args []string, i int, a *impactArgs) (int, bool, error) {
	arg := args[i]
	switch {
	case arg == "--replayable":
		a.replayable = true
		return 0, true, nil
	case strings.HasPrefix(arg, "--replay-"):
		return impactReplayList(args, i, a, arg)
	case strings.HasPrefix(arg, "--extractable-per-round") ||
		strings.HasPrefix(arg, "--gas-cost") ||
		strings.HasPrefix(arg, "--frequency") ||
		strings.HasPrefix(arg, "--rounds-run"):
		return impactReplayScalar(args, i, a, arg)
	}
	return 0, false, nil
}

// impactReplayList appends one repeatable --replay-assumption/--replay-blocker.
func impactReplayList(args []string, i int, a *impactArgs,
	arg string) (int, bool, error) {
	blocker := strings.HasPrefix(arg, "--replay-blocker")
	name := "--replay-assumption"
	if blocker {
		name = "--replay-blocker"
	}
	raw, eq, err := impactOptValue(args, i, name)
	if err != nil {
		return 0, true, err
	}
	if blocker {
		a.blockers = append(a.blockers, raw)
	} else {
		a.assumptions = append(a.assumptions, raw)
	}
	if eq {
		return 0, true, nil
	}
	return 1, true, nil
}

// impactReplayScalar consumes one valued replay option: --rounds-run is an
// int, the three cost figures are floats.
func impactReplayScalar(args []string, i int, a *impactArgs,
	arg string) (int, bool, error) {
	name := impactReplayName(arg)
	raw, eq, err := impactOptValue(args, i, name)
	if err != nil {
		return 0, true, err
	}
	if err := impactReplayAssign(a, name, raw); err != nil {
		return 0, true, err
	}
	if eq {
		return 0, true, nil
	}
	return 1, true, nil
}

// impactReplayName is the option name an argv token spells. The list is
// longest-first so --extractable-per-round never resolves to a shorter name.
func impactReplayName(arg string) string {
	for _, n := range []string{"--extractable-per-round", "--gas-cost",
		"--frequency", "--rounds-run"} {
		if strings.HasPrefix(arg, n) {
			return n
		}
	}
	return ""
}

// impactReplayAssign parses one replay option's value into its field.
func impactReplayAssign(a *impactArgs, name, raw string) error {
	if name == "--rounds-run" {
		n, err := impactRoundsArg(raw)
		if err != nil {
			return err
		}
		a.roundsRun = &n
		return nil
	}
	f, err := t23FloatArg("impact", name, raw)
	if err != nil {
		return err
	}
	switch name {
	case "--extractable-per-round":
		a.perRound = &f
	case "--gas-cost":
		a.gasCost = &f
	case "--frequency":
		a.frequency = &f
	}
	return nil
}

// impactOptValue reads an option's raw value in either spelling: the
// --flag=value tail, or the next token under argparse's value-slot rules.
func impactOptValue(args []string, i int, name string) (string, bool, error) {
	if strings.HasPrefix(args[i], name+"=") {
		return strings.TrimPrefix(args[i], name+"="), true, nil
	}
	raw, err := t23ValueArg(args, i, t23ImpactUsage, "impact", name)
	return raw, false, err
}

// impactRoundsArg parses --rounds-run with argparse's int error text.
func impactRoundsArg(raw string) (int64, error) {
	n, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return 0, t14ArgparseErr(t23ImpactUsage, "impact",
			"argument --rounds-run: invalid int value: %s",
			validation.PyReprStr(raw))
	}
	return n, nil
}

func init() {
	register(command{ord: 47, name: "impact",
		line: "impact <campaign> <finding>        record quantified impact / mint E7",
		run:  runImpact})
}
