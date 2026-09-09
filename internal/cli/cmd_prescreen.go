package cli

// cmd_prescreen: `webv2 prescreen <campaign> --src SRC [--force ARCH]...
// [--json]` — archetype pre-screen over the structural index (cli.py
// cmd_prescreen verbatim).

import (
	"fmt"
	"strings"

	"websec/internal/archetypes"
	"websec/internal/validation"
)

const prescreenUsage = "usage: webv2 prescreen [-h] --src SRC [--force ARCH] [--json] campaign\n"

// prescreenHelp is argparse's `webv2 prescreen --help` output, byte-exact.
const prescreenHelp = `usage: webv2 prescreen [-h] --src SRC [--force ARCH] [--json] campaign

positional arguments:
  campaign

options:
  -h, --help    show this help message and exit
  --src SRC     source tree to screen
  --force ARCH  operator override: include a non-matching archetype
                (repeatable)
  --json
`

func runPrescreen(root string, args []string, r *Runner) int {
	ensureSeams()
	return t14Dispatch(root, r, func() error {
		cid, src, force, asJSON, help, err := parsePrescreenArgs(args)
		if err != nil {
			return err
		}
		if help {
			fmt.Fprint(r.Out, prescreenHelp)
			return nil
		}
		// cli.py checks the source tree BEFORE opening the campaign.
		if !isDirPath(src) {
			return t14ExitErr(1, "source tree not found: %s\n", src)
		}
		c, err := t14Open(root, cid)
		if err != nil {
			return err
		}
		rep, err := archetypes.Prescreen(c, src, force)
		if err != nil {
			return err
		}
		active, err := c.ActiveSnapshotIDOrNone()
		if err != nil {
			return err
		}
		stale := active != nil && objStr(rep, "snapshot_id") != *active
		if asJSON {
			fmt.Fprintln(r.Out, validation.DumpIndentedASCII(rep))
			return nil
		}
		for _, row := range listAtCLI(rep, "results") {
			mark := "no"
			switch {
			case boolAtCLI(row, "match"):
				mark = "MATCH"
			case boolAtCLI(row, "forced"):
				mark = "forced"
			}
			fmt.Fprintf(r.Out, "  [%s] %s (%s)\n", mark, objStr(row, "id"),
				objStr(row, "criticality"))
			if !boolAtCLI(row, "match") {
				if near := strListAtCLI(row, "near_matches"); len(near) > 0 {
					fmt.Fprintf(r.Out, "        near-matches: %s\n",
						strings.Join(near, ", "))
				}
			}
		}
		if stale {
			fmt.Fprintf(r.Out, "NOTE: report is from snapshot %s, active pin "+
				"is %s — re-run `webv2 prescreen` after re-pinning\n",
				objStr(rep, "snapshot_id"), *active)
		}
		for _, prob := range strListAtCLI(rep, "problems") {
			fmt.Fprintf(r.Out, "PROBLEM: %s\n", prob)
		}
		return nil
	})
}

// parsePrescreenArgs parses the prescreen parser's arguments with argparse's
// error precedence and help action.
func parsePrescreenArgs(args []string) (campaign, src string, force []string,
	asJSON, help bool, err error) {
	sp := &argSpec{
		prog:  "prescreen",
		usage: prescreenUsage,
		vals: []*valOpt{{name: "--src", required: true},
			{name: "--force", append: true}},
		flags: []*boolOpt{{name: "--json"}},
		pos:   []*posOpt{{name: "campaign"}},
	}
	if err := sp.parse(args); err != nil {
		return "", "", nil, false, false, err
	}
	if sp.helpSeen {
		return "", "", nil, false, true, nil
	}
	return sp.pos[0].val, pyPathText(sp.vals[0].val), sp.vals[1].multi,
		sp.flags[0].set, false, nil
}

func init() {
	register(command{ord: 17, name: "prescreen",
		line: "prescreen <campaign> --src SRC  archetype pre-screen over the index",
		run:  runPrescreen})
}
