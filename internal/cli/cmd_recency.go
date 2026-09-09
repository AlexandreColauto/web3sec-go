// cmd_recency: `webv2 recency <campaign> --target GIT --src TREE [--json]` —
// recency-weighted file prioritization (fresh + exposed = hunt first).
// cli.py cmd_recency verbatim.
package cli

import (
	"fmt"
	"strings"

	"websec/internal/histmining"
	"websec/internal/validation"
)

const t26RecencyUsage = `usage: webv2 recency [-h] --target TARGET --src SRC [--json] campaign
`

const t26RecencyHelp = t26RecencyUsage + `
positional arguments:
  campaign

options:
  -h, --help       show this help message and exit
  --target TARGET  git repo to mine dates from
  --src SRC        source tree to score
  --json
`

func runRecency(root string, args []string, r *Runner) int {
	ensureSeams()
	return t14Dispatch(root, r, func() error {
		var pos []string
		target, src := "", ""
		asJSON := false
		for i := 0; i < len(args); i++ {
			arg := args[i]
			switch arg {
			case "-h", "--help":
				fmt.Fprint(r.Out, t26RecencyHelp)
				return nil
			case "--json":
				asJSON = true
				continue
			}
			name, val, hasVal := splitFlag(arg)
			switch name {
			case "--target", "--src":
				if !hasVal {
					if i+1 >= len(args) {
						return t14ArgparseErr(t26RecencyUsage, "recency",
							"argument %s: expected one argument", name)
					}
					val = args[i+1]
					i++
				}
				if name == "--target" {
					target = val
				} else {
					src = val
				}
				continue
			}
			if strings.HasPrefix(arg, "-") && !isNegNumberCLI(arg) {
				return t14Unrecognized(arg)
			}
			pos = append(pos, arg)
		}
		var missing []string
		if len(pos) == 0 {
			missing = append(missing, "campaign")
		}
		if target == "" {
			missing = append(missing, "--target")
		}
		if src == "" {
			missing = append(missing, "--src")
		}
		if len(missing) > 0 {
			return t14ArgparseErr(t26RecencyUsage, "recency",
				"the following arguments are required: %s",
				strings.Join(missing, ", "))
		}
		if len(pos) > 1 {
			return t14Unrecognized(strings.Join(pos[1:], " "))
		}
		if !isDir(src) {
			return t14ExitErr(1, "source tree not found: %s\n", src)
		}
		c, err := t14Open(root, pos[0])
		if err != nil {
			return err
		}
		rep, err := histmining.RecencyScores(c, target, src)
		if err != nil {
			return err
		}
		if asJSON {
			t14PrintJSON(r.Out, rep)
			return nil
		}
		stats := objAt(rep, "stats")
		fmt.Fprintf(r.Out, "recency: %d files, %d changed in window\n",
			objInt(stats, "files"), objInt(stats, "changed_in_window"))
		for _, row := range firstN(objAt(rep, "hot_files").A, 10) {
			days := "never"
			if d := objAt(row, "days_ago"); d.Kind == validation.Int {
				days = scalarStr(d) + "d ago"
			}
			fmt.Fprintf(r.Out, "  %s w=%s %s  %s\n",
				pyFixed2(objFlt(row, "score")),
				t26Fixed1(objFlt(row, "exposure_weight")),
				pyRight(days, 10), objStr(row, "path"))
		}
		return nil
	})
}

func init() {
	register(command{ord: 19, name: "recency",
		line: "recency <campaign> --target GIT --src TREE  recency-weighted prioritization",
		run:  runRecency})
}
