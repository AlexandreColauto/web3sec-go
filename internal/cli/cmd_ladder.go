package cli

// cmd_ladder: `webv2 ladder <campaign> {start,show,explore,add,repro,
// disprove,set-maximal,complete,waive,report} [finding] [rung] [axis]
// [options]` — the variant ladder for one CONFIRMED finding: base ->
// amplified -> maximal (cli.py cmd_ladder verbatim, including the
// ValueError/KeyError/RuntimeError -> `ladder <a> failed: ...` exit 2).

import (
	"errors"
	"fmt"
	"strings"

	"websec/internal/maximization"
	"websec/internal/state"
	"websec/internal/validation"
)

// ladderArgs is the parsed command line. The optional positionals are "" when
// absent, which the maximization port renders as Python's None.
type ladderArgs struct {
	campaign    string
	action      string
	finding     string
	rung        string
	axis        string
	name        string
	description string
	axes        string
	capital     *float64
	ratio       *float64
	removes     string
	note        string
	reason      string
	execID      string
	actor       string
}

func runLadder(root string, args []string, r *Runner) int {
	return t14Dispatch(root, r, func() error {
		a, err := parseLadder(args, r)
		if err != nil || a == nil {
			return err
		}
		c, err := t14Open(root, a.campaign)
		if err != nil {
			return err
		}
		return ladderBody(c, a, r)
	})
}

// ladderBody is cli.py's try block: campaign-open failures stay with the
// generic handler (exit 1); everything the ladder raises becomes
// `ladder <action> failed: <e>` on stderr, exit 2. The OSErrors main also
// maps (FileNotFoundError / PermissionError) are NOT caught in Python, so
// they keep the generic `error: {e}` handler and exit 1.
func ladderBody(c *state.Campaign, a *ladderArgs, r *Runner) error {
	if err := ladderDispatch(c, a, r); err != nil {
		var exit *t14Exit
		if errors.As(err, &exit) ||
			strings.HasPrefix(err.Error(), "no finding ") ||
			strings.HasPrefix(err.Error(), "[Errno ") {
			return err
		}
		return t14ExitErr(2, "ladder %s failed: %s\n", a.action, err)
	}
	return nil
}

func ladderDispatch(c *state.Campaign, a *ladderArgs, r *Runner) error {
	switch a.action {
	case "start":
		return ladderStart(c, a, r)
	case "show":
		return ladderShow(c, a, r)
	case "explore":
		return ladderExplore(c, a, r)
	case "add":
		return ladderAdd(c, a, r)
	case "repro":
		return ladderRepro(c, a, r)
	case "disprove":
		return ladderDisprove(c, a, r)
	case "set-maximal":
		return ladderSetMaximal(c, a, r)
	case "complete":
		return ladderComplete(c, a, r)
	case "waive":
		return ladderWaive(c, a, r)
	}
	return ladderReport(c, a, r)
}

func ladderStart(c *state.Campaign, a *ladderArgs, r *Runner) error {
	if a.finding == "" {
		// Python: load_finding(None) -> "no finding None in <campaign>".
		return errors.New("no finding None in " + c.CampaignID)
	}
	lad, err := maximization.StartLadder(c, a.finding)
	if err != nil {
		return err
	}
	fmt.Fprintf(r.Out, "ladder %s started for %s (rung 0 = the finding's "+
		"current claim)\n", objStr(lad, "ladder_id"), a.finding)
	return nil
}

func ladderShow(c *state.Campaign, a *ladderArgs, r *Runner) error {
	if a.finding == "" {
		return t14ExitErr(1, "None: no ladder yet — `webv2 ladder %s start "+
			"None`\n", a.campaign)
	}
	lad, err := maximization.LoadLadder(c, a.finding)
	if err != nil {
		return err
	}
	if lad == nil {
		return t14ExitErr(1, "%s: no ladder yet — `webv2 ladder %s start "+
			"%s`\n", a.finding, a.campaign, a.finding)
	}
	fmt.Fprintln(r.Out, prettyASCII(*lad))
	return nil
}

func ladderExplore(c *state.Campaign, a *ladderArgs, r *Runner) error {
	lad, err := maximization.ExploreAxis(c, a.finding, a.axis, a.note)
	if err != nil {
		return err
	}
	explored := t14Strings(t14List(lad, "axes_explored"))
	fmt.Fprintf(r.Out, "axis %s explored (%d/5: %s)\n", a.axis,
		len(explored), strings.Join(explored, ", "))
	return nil
}

func ladderAdd(c *state.Campaign, a *ladderArgs, r *Runner) error {
	desc := a.description
	if desc == "" {
		desc = a.name
	}
	var axes []string
	if a.axes != "" {
		axes = strings.Split(a.axes, ",")
	}
	var removes []string
	if a.removes != "" {
		removes = strings.Split(a.removes, ";")
	}
	rung, err := maximization.AddVariant(c, a.finding, a.name, desc, axes,
		a.capital, a.ratio, removes, nil)
	if err != nil {
		return err
	}
	fmt.Fprintf(r.Out, "rung %s recorded: %s (status %s)\n",
		objStr(rung, "rung_id"), objStr(rung, "name"), objStr(rung, "status"))
	return nil
}

func ladderRepro(c *state.Campaign, a *ladderArgs, r *Runner) error {
	rung, err := maximization.ReproduceRung(c, a.finding, a.rung, a.execID, nil)
	if err != nil {
		return err
	}
	fmt.Fprintf(r.Out, "rung %s (%s) reproduced from %s — evidence minted "+
		"onto %s\n", a.rung, objStr(rung, "name"), a.execID, a.finding)
	return nil
}

func ladderDisprove(c *state.Campaign, a *ladderArgs, r *Runner) error {
	rung, err := maximization.DisproveRung(c, a.finding, a.rung, a.reason)
	if err != nil {
		return err
	}
	fmt.Fprintf(r.Out, "rung %s (%s) disproved — negative memory queued "+
		"(the next campaign starts smarter)\n", a.rung, objStr(rung, "name"))
	return nil
}

func ladderSetMaximal(c *state.Campaign, a *ladderArgs, r *Runner) error {
	f, err := maximization.SetMaximal(c, a.finding, a.rung)
	if err != nil {
		return err
	}
	ei := objAt(f, "economic_impact")
	attacker := objAt(f, "attacker")
	fmt.Fprintf(r.Out, "maximal rung pinned: %s — claim now follows the "+
		"measurement (extraction %s, required capital $%s)\n", a.rung,
		scalarStr(objAt(ei, "extraction_ratio")),
		scalarStr(objAt(attacker, "required_capital_usd")))
	return nil
}

func ladderComplete(c *state.Campaign, a *ladderArgs, r *Runner) error {
	actor := a.actor
	if actor == "" {
		actor = "cli"
	}
	lad, err := maximization.CompleteLadder(c, a.finding, actor)
	if err != nil {
		return err
	}
	fmt.Fprintf(r.Out, "ladder %s COMPLETE — maximal %s\n",
		objStr(lad, "ladder_id"), scalarStr(objAt(lad, "maximal_rung_id")))
	return nil
}

func ladderWaive(c *state.Campaign, a *ladderArgs, r *Runner) error {
	if _, err := maximization.WaiveLadder(c, a.finding, a.reason,
		a.actor); err != nil {
		return err
	}
	fmt.Fprintf(r.Out, "ladder for %s WAIVED (logged, actor %s)\n",
		a.finding, a.actor)
	return nil
}

func ladderReport(c *state.Campaign, a *ladderArgs, r *Runner) error {
	rep, err := maximization.LadderReport(c, a.finding)
	if err != nil {
		return err
	}
	fmt.Fprintln(r.Out, prettyASCII(rep))
	return nil
}

// --- argparse layer --------------------------------------------------------

func parseLadder(args []string, r *Runner) (*ladderArgs, error) {
	a := &ladderArgs{}
	var pos, extras []string
	for i := 0; i < len(args); i++ {
		consumed, done, handled, err := ladderFlag(args, i, a, r)
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
		if len(pos) < 5 {
			pos = append(pos, args[i])
		} else {
			extras = append(extras, args[i])
		}
	}
	if len(pos) < 2 {
		names := []string{"campaign", "action"}
		return nil, t14ArgparseErr(t23LadderUsage, "ladder",
			"the following arguments are required: %s",
			strings.Join(names[len(pos):], ", "))
	}
	if len(extras) > 0 {
		return nil, t14Unrecognized(strings.Join(extras, " "))
	}
	a.campaign, a.action = pos[0], pos[1]
	for i := 2; i < len(pos); i++ {
		switch i {
		case 2:
			a.finding = pos[i]
		case 3:
			a.rung = pos[i]
		case 4:
			a.axis = pos[i]
		}
	}
	if !t14InList(a.action, t23LadderActions) {
		return nil, t14ArgparseErr(t23LadderUsage, "ladder",
			"argument action: invalid choice: %s (choose from %s)",
			validation.PyReprStr(a.action),
			"'"+strings.Join(t23LadderActions, "', '")+"'")
	}
	return a, nil
}

func ladderFlag(args []string, i int, a *ladderArgs,
	r *Runner) (consumed int, done, handled bool, err error) {
	arg := args[i]
	if arg == "-h" || arg == "--help" {
		fmt.Fprint(r.Out, t23LadderHelp)
		return 0, true, true, nil
	}
	if name, dst := ladderFloatDst(a, arg); dst != nil {
		raw, err := t23ValueArg(args, i, t23LadderUsage, "ladder", name)
		if err != nil {
			return 0, false, true, err
		}
		f, err := t23FloatArg("ladder", name, raw)
		if err != nil {
			return 0, false, true, err
		}
		*dst = &f
		return 1, false, true, nil
	}
	if name, dst := ladderStrDst(a, arg); dst != nil {
		raw, err := t23ValueArg(args, i, t23LadderUsage, "ladder", name)
		if err != nil {
			return 0, false, true, err
		}
		*dst = raw
		return 1, false, true, nil
	}
	if handled, err := ladderEq(a, arg); handled || err != nil {
		return 0, false, handled, err
	}
	if t23IsOption(arg) {
		return 0, false, true, t14Unrecognized(arg)
	}
	return 0, false, false, nil
}

func ladderFloatDst(a *ladderArgs, arg string) (string, **float64) {
	switch arg {
	case "--capital":
		return arg, &a.capital
	case "--ratio":
		return arg, &a.ratio
	}
	return "", nil
}

// ladderStrDst maps the string flags; --exec is argparse's dest=exec_id.
func ladderStrDst(a *ladderArgs, arg string) (string, *string) {
	switch arg {
	case "--name":
		return arg, &a.name
	case "--description":
		return arg, &a.description
	case "--axes":
		return arg, &a.axes
	case "--removes":
		return arg, &a.removes
	case "--note":
		return arg, &a.note
	case "--reason":
		return arg, &a.reason
	case "--exec":
		return arg, &a.execID
	case "--actor":
		return arg, &a.actor
	}
	return "", nil
}

func ladderEq(a *ladderArgs, arg string) (bool, error) {
	for _, f := range []struct {
		name string
		dst  **float64
	}{{"--capital", &a.capital}, {"--ratio", &a.ratio}} {
		if strings.HasPrefix(arg, f.name+"=") {
			v, err := t23FloatArg("ladder", f.name,
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
	}{{"--name", &a.name}, {"--description", &a.description},
		{"--axes", &a.axes}, {"--removes", &a.removes}, {"--note", &a.note},
		{"--reason", &a.reason}, {"--exec", &a.execID}, {"--actor", &a.actor}} {
		if strings.HasPrefix(arg, f.name+"=") {
			*f.dst = strings.TrimPrefix(arg, f.name+"=")
			return true, nil
		}
	}
	return false, nil
}

func init() {
	register(command{ord: 53, name: "ladder",
		line: "ladder <campaign> {start,show,...}  variant ladder for one finding",
		run:  runLadder})
}
