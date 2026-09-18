package cli

// cmd_globalize: `webv2 globalize --actor A [--tier {root,global}]
// [--program KEY]` — mark shared-store rows scope=global: recalled by EVERY
// campaign, whatever its program. Sanctioned, actor-attributed,
// manifest-logged (cli.py cmd_globalize verbatim).

import (
	"fmt"

	"websec/internal/sharedmem"
	"websec/internal/validation"
)

const globalizeUsage = "usage: webv2 globalize [-h] --actor ACTOR [--tier {root,global}]\n" +
	"                       [--program PROGRAM]\n"

// globalizeHelp is argparse's `webv2 globalize --help` output, byte-exact.
const globalizeHelp = `usage: webv2 globalize [-h] --actor ACTOR [--tier {root,global}]
                       [--program PROGRAM]

options:
  -h, --help            show this help message and exit
  --actor ACTOR
  --tier {root,global}  which store tier to re-scope (default: global)
  --program PROGRAM     only rows with this program_key (default: all rows)
`

var globalizeTiers = []string{"root", "global"}

func runGlobalize(root string, args []string, r *Runner) int {
	ensureSeams()
	return t14Dispatch(root, r, func() error {
		sp := &argSpec{
			prog:  "globalize",
			usage: globalizeUsage,
			vals: []*valOpt{
				{name: "--actor", required: true},
				{name: "--tier", val: "global"},
				{name: "--program"},
			},
		}
		if err := sp.parse(args); err != nil {
			return err
		}
		if sp.helpSeen {
			fmt.Fprint(r.Out, globalizeHelp)
			return nil
		}
		tier := sp.vals[1].val
		if tier != "root" && tier != "global" {
			return t14ArgparseErr(globalizeUsage, "globalize",
				"argument --tier: invalid choice: %s (choose from %s)",
				validation.PyReprStr(tier), quotedList(globalizeTiers))
		}
		rep, err := sharedmem.SetScope(root, "global", sp.vals[0].val,
			sp.vals[2].val, tier)
		if err != nil {
			return t14ExitOut(1, "globalize failed: %s\n", err.Error())
		}
		fmt.Fprintf(r.Out, "%s: scope=global on %s memory row(s) and %s "+
			"signature(s) [%s tier, selector=%s]\n",
			validation.ObjStr(rep, "record_id"), pyIntText(validation.ObjAt(rep, "memory_updated")),
			pyIntText(validation.ObjAt(rep, "signatures_updated")), validation.ObjStr(rep, "tier"),
			scalarStr(validation.ObjAt(rep, "program_key")))
		fmt.Fprintf(r.Out, "store: %s\n", validation.ObjStr(rep, "store"))
		return nil
	})
}

func init() {
	register(command{ord: 27, name: "globalize",
		line: "globalize --actor A              mark shared rows scope=global",
		run:  runGlobalize})
}
