package cli

// cmd_floors: `webv2 floors <campaign> [--json] [list|set|unset] ...` — the
// instance-level evidence floors. `list` (the default) shows the effective
// table; `set`/`unset` record or lift a per-class override with actor and
// reason. cli.py cmd_floors verbatim.

import (
	"errors"
	"fmt"
	"strings"

	"websec/internal/floors"
	"websec/internal/state"
	"websec/internal/validation"

	"websec/internal/taxonomy"
)

const t14FloorsUsage = `usage: webv2 floors [-h] [--json] campaign {list,set,unset} ...
`

const t14FloorsHelp = `usage: webv2 floors [-h] [--json] campaign {list,set,unset} ...

positional arguments:
  campaign
  {list,set,unset}
    list            show the effective table (default)
    set             record an operator override (logged, actor-attributed)
    unset           lift a recorded override

options:
  -h, --help        show this help message and exit
  --json
`

const t14FloorsSetUsage = `usage: webv2 floors campaign set [-h] --actor ACTOR --reason REASON
                                 class_ {E4,E5,E6,E7}
`

const t14FloorsUnsetUsage = `usage: webv2 floors campaign unset [-h] --actor ACTOR --reason REASON class_
`

var t14FloorChoices = []string{"E4", "E5", "E6", "E7"}

// floorsArgs is the parsed command line.
type floorsArgs struct {
	campaign string
	cmd      string // "" means list (the default subcommand)
	asJSON   bool
	class    string
	floor    string
	actor    *string
	reason   *string
}

func runFloors(root string, args []string, r *Runner) error {
	a, err := parseFloors(args, r)
	if err != nil || a == nil {
		return err
	}
	c, err := t14Open(root, a.campaign)
	if err != nil {
		return err
	}
	switch a.cmd {
	case "set":
		return floorsSet(c, a, r)
	case "unset":
		return floorsUnset(c, a, r)
	default:
		return floorsList(c, a, r)
	}
}

// parseFloors is the argparse layer: the parent accepts --json BEFORE the
// subcommand (argparse gives the subparser everything after it), then the
// subcommand's own positionals and flags.
func parseFloors(args []string, r *Runner) (*floorsArgs, error) {
	a := &floorsArgs{}
	i := 0
	for i < len(args) {
		arg := args[i]
		if arg == "-h" || arg == "--help" {
			fmt.Fprint(r.Out, t14FloorsHelp)
			return nil, nil
		}
		if arg == "--json" {
			a.asJSON = true
			i++
			continue
		}
		if strings.HasPrefix(arg, "-") {
			return nil, t14Unrecognized(arg)
		}
		if a.campaign == "" {
			a.campaign = arg
			i++
			continue
		}
		// the first non-flag token after the campaign is the subcommand;
		// everything after it belongs to the subparser (argparse semantics)
		a.cmd = arg
		i++
		if !t14InList(a.cmd, []string{"list", "set", "unset"}) {
			return nil, t14ArgparseErr(t14FloorsUsage, "floors",
				"argument floors_cmd: invalid choice: %s (choose from %s)",
				validation.PyReprStr(a.cmd), "'list', 'set', 'unset'")
		}
		break
	}
	if a.campaign == "" {
		return nil, t14ArgparseErr(t14FloorsUsage, "floors",
			"the following arguments are required: campaign")
	}
	rest := args[i:]
	if a.cmd == "set" {
		return a, parseFloorsSet(a, rest)
	}
	if a.cmd == "unset" {
		return a, parseFloorsUnset(a, rest)
	}
	if len(rest) > 0 {
		return nil, t14Unrecognized(strings.Join(rest, " "))
	}
	return a, nil
}

// parseFloorsSet is `floors <c> set CLASS FLOOR --actor A --reason R`.
func parseFloorsSet(a *floorsArgs, args []string) error {
	var pos []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--actor", "--reason":
			if i+1 >= len(args) {
				return t14ArgparseErr(t14FloorsSetUsage,
					"floors campaign set",
					"argument %s: expected one argument", arg)
			}
			v := args[i+1]
			if arg == "--actor" {
				a.actor = &v
			} else {
				a.reason = &v
			}
			i++
			continue
		}
		if strings.HasPrefix(arg, "--actor=") {
			v := strings.TrimPrefix(arg, "--actor=")
			a.actor = &v
			continue
		}
		if strings.HasPrefix(arg, "--reason=") {
			v := strings.TrimPrefix(arg, "--reason=")
			a.reason = &v
			continue
		}
		if strings.HasPrefix(arg, "-") {
			return t14Unrecognized(arg)
		}
		pos = append(pos, arg)
	}
	var missing []string
	if len(pos) < 1 {
		missing = append(missing, "class_")
	}
	if len(pos) < 2 {
		missing = append(missing, "floor")
	}
	if a.actor == nil {
		missing = append(missing, "--actor")
	}
	if a.reason == nil {
		missing = append(missing, "--reason")
	}
	if len(missing) > 0 {
		return t14ArgparseErr(t14FloorsSetUsage, "floors campaign set",
			"the following arguments are required: %s",
			strings.Join(missing, ", "))
	}
	if len(pos) > 2 {
		return t14Unrecognized(strings.Join(pos[2:], " "))
	}
	a.class, a.floor = pos[0], pos[1]
	if !t14InList(a.floor, t14FloorChoices) {
		return t14ArgparseErr(t14FloorsSetUsage, "floors campaign set",
			"argument floor: invalid choice: %s (choose from %s)",
			validation.PyReprStr(a.floor), "'E4', 'E5', 'E6', 'E7'")
	}
	return nil
}

// parseFloorsUnset is `floors <c> unset CLASS --actor A --reason R`.
func parseFloorsUnset(a *floorsArgs, args []string) error {
	var pos []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--actor", "--reason":
			if i+1 >= len(args) {
				return t14ArgparseErr(t14FloorsUnsetUsage,
					"floors campaign unset",
					"argument %s: expected one argument", arg)
			}
			v := args[i+1]
			if arg == "--actor" {
				a.actor = &v
			} else {
				a.reason = &v
			}
			i++
			continue
		}
		if strings.HasPrefix(arg, "--actor=") {
			v := strings.TrimPrefix(arg, "--actor=")
			a.actor = &v
			continue
		}
		if strings.HasPrefix(arg, "--reason=") {
			v := strings.TrimPrefix(arg, "--reason=")
			a.reason = &v
			continue
		}
		if strings.HasPrefix(arg, "-") {
			return t14Unrecognized(arg)
		}
		pos = append(pos, arg)
	}
	var missing []string
	if len(pos) < 1 {
		missing = append(missing, "class_")
	}
	if a.actor == nil {
		missing = append(missing, "--actor")
	}
	if a.reason == nil {
		missing = append(missing, "--reason")
	}
	if len(missing) > 0 {
		return t14ArgparseErr(t14FloorsUnsetUsage, "floors campaign unset",
			"the following arguments are required: %s",
			strings.Join(missing, ", "))
	}
	if len(pos) > 1 {
		return t14Unrecognized(strings.Join(pos[1:], " "))
	}
	a.class = pos[0]
	return nil
}

// floorsSet records an override and echoes the entry.
func floorsSet(c *state.Campaign, a *floorsArgs, r *Runner) error {
	entry, err := floors.SetFloorPolicy(c, a.class, a.floor, *a.actor,
		*a.reason)
	if err != nil {
		return err
	}
	fmt.Fprintf(r.Out, "floor policy set: %s -> %s (actor %s, %s)\n",
		validation.ObjStr(entry, "class"), validation.ObjStr(entry, "floor"),
		validation.ObjStr(entry, "actor"), validation.ObjStr(entry, "at"))
	if _, known := taxonomy.KnownClasses()[a.class]; !known {
		// r8: the open-vocabulary law is deliberate — a class may exist
		// in the taxonomy tomorrow, and refusing unknown names would
		// re-close the door the override table exists to hold open. But
		// an operator who TYPOGUARDED a real class deserves to know the
		// floor is inert today, before a "protected" finding ships over
		// it. Advisory visibility, never silent acceptance.
		fmt.Fprintf(r.Err, "note: %s is not a known taxonomy class — this "+
			"floor binds nothing until a finding carries it (open "+
			"vocabulary is legal, typos are not free)\n", a.class)
	}
	return nil
}

// floorsUnset lifts an override; a class with none is a KeyError (exit 2).
func floorsUnset(c *state.Campaign, a *floorsArgs, r *Runner) error {
	err := floors.ClearFloorPolicy(c, a.class, *a.actor, *a.reason)
	if err != nil {
		var ke *floors.KeyError
		if errors.As(err, &ke) {
			return t14ExitErr(2, "clear failed: %s\n",
				validation.PyReprStr(ke.Msg))
		}
		return err
	}
	fmt.Fprintf(r.Out, "floor policy cleared: %s (actor %s) — falls back to "+
		"the built-in default\n", a.class, *a.actor)
	return nil
}

// floorsList renders the effective table (the default subcommand).
func floorsList(c *state.Campaign, a *floorsArgs, r *Runner) error {
	rep, err := floors.FloorTableReport(c)
	if err != nil {
		return err
	}
	if a.asJSON {
		t14PrintJSON(r.Out, rep)
		return nil
	}
	rows := t14List(rep, "rows")
	fmt.Fprintf(r.Out, "effective CONFIRMED floors (%d classes):\n", len(rows.A))
	for _, row := range rows.A {
		eff := validation.ObjAt(row, "effective_floor")
		def := scalarStr(validation.ObjAt(row, "default_floor"))
		if def == "" || def == "None" {
			def = "E5"
		}
		mark := ""
		if eff.S == "E5" || eff.S == "E6" {
			mark = " *"
		}
		tag := "default " + def
		if ov := validation.ObjAt(row, "override"); ov.Kind == validation.Obj {
			tag = fmt.Sprintf("OVERRIDE of %s (by %s: %s)", def,
				validation.ObjStr(ov, "actor"), t14Truncate(validation.ObjStr(ov, "reason"), 70))
		}
		fmt.Fprintf(r.Out, "  %s %s%s  %s\n", t14Pad(validation.ObjStr(row, "class"), 28),
			scalarStr(eff), mark, tag)
	}
	fmt.Fprintln(r.Out, "  * = floor needs a deployment/chain pin and fork "+
		"RPC — `webv2 brief` shows which are structurally unreachable")
	fmt.Fprintf(r.Out, "  %s\n", validation.ObjStr(rep, "default_note"))
	return nil
}

// t14Pad is Python's `{s:<n}`: left-justified to n code points.
func t14Pad(s string, n int) string {
	w := len([]rune(s))
	if w >= n {
		return s
	}
	return s + strings.Repeat(" ", n-w)
}

func init() {
	register(command{ord: 37, name: "floors",
		line: `floors <campaign> [--json] [set|unset] effective evidence floors`,
		run: func(root string, args []string, r *Runner) int {
			return t14Dispatch(root, r, func() error {
				return runFloors(root, args, r)
			})
		}})
}
