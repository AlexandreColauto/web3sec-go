package cli

// cmd_probes: `webv2 probes <campaign> {run,list,blank}` — the operator
// surface for the mechanical candidate plane. cli.py cmd_probes verbatim:
// `run` builds (and optionally emits) the surface, `list` is the operator
// view, `blank` records the named decision that closes a blind axis.
import (
	"fmt"
	"strconv"
	"strings"

	"websec/internal/probes"
	"websec/internal/state"
	"websec/internal/validation"
)

const t29ProbesUsage = `usage: webv2 probes [-h] campaign {run,list,blank} ...
`

// consoleRowCap bounds the console table; --json stays complete. It is the
// package-wide console convention (probes rows, snap dry-run path dumps):
// a dump longer than this prints its first consoleRowCap entries and one
// pointer line, never the whole list.
const consoleRowCap = 40

const t29ProbesHelp = `usage: webv2 probes [-h] campaign {run,list,blank} ...

positional arguments:
  campaign
  {run,list,blank}
    run             build the surface from the current structural index
                    (--emit turns its rows into plan obligations)
    list            the surface as an operator view: rows, anchors,
                    dispositions, blind keys
    blank           record the named decision that closes a BLIND axis, citing
                    a key the probe actually published

options:
  -h, --help        show this help message and exit
`

const t29ProbesRunUsage = `usage: webv2 probes campaign run [-h] [--emit] [--per-axis N] [--total N]
`

const t29ProbesRunHelp = `usage: webv2 probes campaign run [-h] [--emit] [--per-axis N] [--total N]

quotas: a quota flag the run was not given adopts the value already recorded
in probe_surface.json (else the default), so a bare run repairs the surface
the campaign has instead of shrinking it

options:
  -h, --help    show this help message and exit
  --emit        also emit one plan priority per emitted row
  --per-axis N  per-axis quota (default 12)
  --total N     campaign ceiling across axes (default 40)
`

const t29ProbesListUsage = `usage: webv2 probes campaign list [-h] [--axis A] [--all] [--json]
`

const t29ProbesListHelp = `usage: webv2 probes campaign list [-h] [--axis A] [--all] [--json]

options:
  -h, --help  show this help message and exit
  --axis A    one axis: L-0n or the probe axis name
  --all       every axis (incl. no-sites/blind) + the published blind keys
  --json
`

const t29ProbesBlankUsage = `usage: webv2 probes campaign blank [-h] --axis L-0n --anchor-blind K
                                   --reason REASON --actor ACTOR
`

const t29ProbesBlankHelp = `usage: webv2 probes campaign blank [-h] --axis L-0n --anchor-blind K
                                   --reason REASON --actor ACTOR

options:
  -h, --help        show this help message and exit
  --axis L-0n       the blind axis: its probe axis name, or a lens id (L-0n) —
                    a lens spelling is resolved by the cited --anchor-blind
                    key to the ONE probe on that lens that published it
  --anchor-blind K  one of that axis's blind[] keys; on a lens spelling it
                    also selects the axis
  --reason REASON
  --actor ACTOR
`

// probesArgs is the parsed command line.
type probesArgs struct {
	campaign    string
	cmd         string // "" means list (the default subcommand)
	emit        bool
	perAxis     int
	perAxisSet  bool
	total       int
	totalSet    bool
	axis        *string
	all         bool
	asJSON      bool
	anchorBlind *string
	reason      *string
	actor       *string
}

func runProbes(root string, args []string, r *Runner) error {
	a, err := parseProbes(args, r)
	if err != nil || a == nil {
		return err
	}
	c, err := t14Open(root, a.campaign)
	if err != nil {
		return err
	}
	switch a.cmd {
	case "run":
		return probesRun(a, c, r)
	case "blank":
		return probesBlank(a, c, r)
	default:
		return probesList(a, c, r)
	}
}

// parseProbes is the argparse layer: campaign, then the subcommand (default
// `list`), then that subparser's own flags.
func parseProbes(args []string, r *Runner) (*probesArgs, error) {
	a := &probesArgs{perAxis: 12, total: 40}
	i := 0
	for i < len(args) {
		arg := args[i]
		if arg == "-h" || arg == "--help" {
			fmt.Fprint(r.Out, t29ProbesHelp)
			return nil, nil
		}
		if strings.HasPrefix(arg, "-") {
			return nil, t14Unrecognized(arg)
		}
		if a.campaign == "" {
			a.campaign = arg
			i++
			continue
		}
		a.cmd = arg
		i++
		if !t14InList(a.cmd, []string{"run", "list", "blank"}) {
			return nil, t14ArgparseErr(t29ProbesUsage, "probes",
				"argument probes_cmd: invalid choice: %s (choose from %s)",
				validation.PyReprStr(a.cmd), "'run', 'list', 'blank'")
		}
		break
	}
	if a.campaign == "" {
		return nil, t14ArgparseErr(t29ProbesUsage, "probes",
			"the following arguments are required: campaign")
	}
	rest := args[i:]
	var perr error
	switch a.cmd {
	case "run":
		perr = parseProbesRun(a, rest, r)
	case "blank":
		perr = parseProbesBlank(a, rest, r)
	case "list":
		perr = parseProbesList(a, rest, r)
	}
	if perr != nil {
		if perr == errHelpShown {
			return nil, nil
		}
		return nil, perr
	}
	return a, nil
}

// parseProbesRun is `probes <c> run [--emit] [--per-axis N] [--total N]`.
func parseProbesRun(a *probesArgs, args []string, r *Runner) error {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-h" || arg == "--help" {
			fmt.Fprint(r.Out, t29ProbesRunHelp)
			return errHelpShown
		}
		switch arg {
		case "--emit":
			a.emit = true
			continue
		}
		// splitFlag is the shared argparse splitter (cmd_budget.go): the
		// value flags take both `--flag VALUE` and `--flag=VALUE`, exactly as
		// the converted verbs do.
		name, val, hasVal := splitFlag(arg)
		switch name {
		case "--per-axis", "--total":
			if !hasVal {
				if i+1 >= len(args) {
					return t14ArgparseErr(t29ProbesRunUsage,
						"probes campaign run",
						"argument %s: expected one argument", name)
				}
				val = args[i+1]
				i++
			}
			n, err := strconv.Atoi(val)
			if err != nil {
				return t14ArgparseErr(t29ProbesRunUsage,
					"probes campaign run", "argument %s: invalid int value: %s",
					name, validation.PyReprStr(val))
			}
			if name == "--per-axis" {
				a.perAxis = n
				a.perAxisSet = true
			} else {
				a.total = n
				a.totalSet = true
			}
			continue
		}
		return t14Unrecognized(arg)
	}
	return nil
}

// parseProbesList is `probes <c> list [--axis A] [--all] [--json]`.
func parseProbesList(a *probesArgs, args []string, r *Runner) error {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-h" || arg == "--help" {
			fmt.Fprint(r.Out, t29ProbesListHelp)
			return errHelpShown
		}
		switch arg {
		case "--all":
			a.all = true
			continue
		case "--json":
			a.asJSON = true
			continue
		}
		name, val, hasVal := splitFlag(arg)
		switch name {
		case "--axis":
			if !hasVal {
				if i+1 >= len(args) {
					return t14ArgparseErr(t29ProbesListUsage,
						"probes campaign list",
						"argument --axis: expected one argument")
				}
				val = args[i+1]
				i++
			}
			a.axis = &val
			continue
		}
		return t14Unrecognized(arg)
	}
	return nil
}

// parseProbesBlank is `probes <c> blank --axis --anchor-blind --reason --actor`.
func parseProbesBlank(a *probesArgs, args []string, r *Runner) error {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-h" || arg == "--help" {
			fmt.Fprint(r.Out, t29ProbesBlankHelp)
			return errHelpShown
		}
		name, val, hasVal := splitFlag(arg)
		switch name {
		case "--axis", "--anchor-blind", "--reason", "--actor":
			if !hasVal {
				if i+1 >= len(args) {
					return t14ArgparseErr(t29ProbesBlankUsage,
						"probes campaign blank",
						"argument %s: expected one argument", name)
				}
				val = args[i+1]
				i++
			}
			switch name {
			case "--axis":
				a.axis = &val
			case "--anchor-blind":
				a.anchorBlind = &val
			case "--reason":
				a.reason = &val
			default:
				a.actor = &val
			}
			continue
		}
		return t14Unrecognized(arg)
	}
	missing := []string{}
	if a.axis == nil {
		missing = append(missing, "--axis")
	}
	if a.anchorBlind == nil {
		missing = append(missing, "--anchor-blind")
	}
	if a.reason == nil {
		missing = append(missing, "--reason")
	}
	if a.actor == nil {
		missing = append(missing, "--actor")
	}
	if len(missing) > 0 {
		return t14ArgparseErr(t29ProbesBlankUsage, "probes campaign blank",
			"the following arguments are required: %s", strings.Join(missing, ", "))
	}
	return nil
}

// errHelpShown is the sentinel a subparser help path returns: parseProbes
// already wrote the help and must not continue.
var errHelpShown = fmt.Errorf("help shown")

// probesBlank is cli.py _probes_blank.
func probesBlank(a *probesArgs, c *state.Campaign, r *Runner) error {
	entry, err := probes.SetBlank(c, *a.axis, *a.anchorBlind, *a.reason, *a.actor)
	if err != nil {
		return t14ExitErr(2, "probes blank: %v\n", err)
	}
	fmt.Fprintf(r.Out, "blank attestation recorded: %s cites %s (actor %s) — "+
		"`webv2 brief %s` now sees the axis attested\n", validation.ObjStr(entry, "axis"),
		validation.PyReprStr(validation.ObjStr(entry, "anchor_blind")),
		validation.ObjStr(entry, "actor"), c.CampaignID)
	return nil
}

func init() {
	register(command{ord: 36, name: "probes",
		line: `probes <campaign> [run|list|blank]  the mechanical candidate surface`,
		run: func(root string, args []string, r *Runner) int {
			return t14Dispatch(root, r, func() error {
				return runProbes(root, args, r)
			})
		}})
}
