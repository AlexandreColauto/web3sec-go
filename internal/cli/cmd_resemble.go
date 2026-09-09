package cli

// cmd_resemble: `webv2 resemble <campaign> <finding>` — the derived
// 'resembles' query: the capability-coverage delta between a candidate and
// every confirmed primitive. Never stored, recomputed (cli.py cmd_resemble
// verbatim).

import (
	"fmt"
	"strings"

	"websec/internal/relations"
	"websec/internal/validation"
)

const resembleUsage = "usage: webv2 resemble [-h] campaign finding\n"

// resembleHelp is argparse's `webv2 resemble --help` output, byte-exact.
const resembleHelp = `usage: webv2 resemble [-h] campaign finding

positional arguments:
  campaign
  finding

options:
  -h, --help  show this help message and exit
`

func runResemble(root string, args []string, r *Runner) int {
	ensureSeams()
	return t14Dispatch(root, r, func() error {
		sp := &argSpec{
			prog:  "resemble",
			usage: resembleUsage,
			pos:   []*posOpt{{name: "campaign"}, {name: "finding"}},
		}
		if err := sp.parse(args); err != nil {
			return err
		}
		if sp.helpSeen {
			fmt.Fprint(r.Out, resembleHelp)
			return nil
		}
		c, err := t14Open(root, sp.pos[0].val)
		if err != nil {
			return err
		}
		rep, err := relations.ResemblanceReport(c, sp.pos[1].val)
		if err != nil {
			return err
		}
		required := joinOrNone(listStringsCLI(objAt(rep, "candidate_required")))
		fmt.Fprintf(r.Out, "candidate %s (class %s, requires %s)\n",
			objStr(rep, "candidate_id"),
			scalarStr(objAt(rep, "candidate_class")), required)
		matches := objAt(rep, "matches").A
		if len(matches) == 0 {
			fmt.Fprint(r.Out,
				"  no confirmed primitive resembles this candidate\n")
			return nil
		}
		for _, m := range matches {
			tag := "cap-overlap"
			if objAt(m, "class_match").B {
				tag = "class-match"
			}
			term := ""
			if objAt(m, "candidate_reaches_terminal").B {
				term = " [reaches terminal]"
			}
			overlap := joinOrNone(listStringsCLI(objAt(m, "granted_overlap")))
			fmt.Fprintf(r.Out, "  %s [%s] similarity=%s overlap=%s%s\n",
				objStr(m, "primitive_id"), tag,
				scalarStr(objAt(m, "similarity")), overlap, term)
			if missing := listStringsCLI(objAt(m, "missing")); len(missing) > 0 {
				fmt.Fprintf(r.Out, "    missing required caps: %s\n",
					strings.Join(missing, ", "))
			}
			fmt.Fprintf(r.Out, "    %s\n", objStr(m, "advisory"))
		}
		return nil
	})
}

// listStringsCLI is the []string view of a JSON array of strings.
func listStringsCLI(v validation.Value) []string {
	out := make([]string, 0, len(v.A))
	for _, item := range v.A {
		if item.Kind == validation.Str {
			out = append(out, item.S)
		}
	}
	return out
}

// joinOrNone is Python's `', '.join(xs) or '(none)'`.
func joinOrNone(xs []string) string {
	if len(xs) == 0 {
		return "(none)"
	}
	return strings.Join(xs, ", ")
}

func init() {
	register(command{ord: 14, name: "resemble",
		line: "resemble <campaign> <finding>      capability-coverage delta (derived)",
		run:  runResemble})
}
