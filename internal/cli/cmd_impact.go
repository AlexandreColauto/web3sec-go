package cli

// cmd_impact: `webv2 impact <campaign> <finding> [--extractable USD]
// [--max-loss USD] [--required-capital USD] [--artifact PATH]
// [--description D]` — record quantified impact numbers and optionally mint
// E7 against a registered artifact. `--unpriceable` is the other honest
// answer: the NAMED DECISION that no USD figure is defensible (cli.py
// cmd_impact verbatim).

import (
	"fmt"
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

func init() {
	register(command{ord: 47, name: "impact",
		line: "impact <campaign> <finding>        record quantified impact / mint E7",
		run:  runImpact})
}
