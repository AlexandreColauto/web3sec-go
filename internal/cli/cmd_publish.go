package cli

// cmd_publish: `webv2 publish <campaign> --actor A [--global]` — publish this
// campaign's confirmed knowledge to the shared store (cli.py cmd_publish
// verbatim). Explicit, logged, actor-attributed. A ValueError from the store
// layer is a `publish failed: ...` line on stdout and exit 1.

import (
	"fmt"
	"strings"

	"websec/internal/sharedmem"
	"websec/internal/validation"
)

const publishUsage = "usage: webv2 publish [-h] --actor ACTOR [--global] campaign\n"

// publishHelp is argparse's `webv2 publish --help` output, byte-exact.
const publishHelp = `usage: webv2 publish [-h] --actor ACTOR [--global] campaign

positional arguments:
  campaign

options:
  -h, --help     show this help message and exit
  --actor ACTOR
  --global       write to ~/.webv2/shared-memory (visible from every root)
                 instead of the root-tier store
`

func runPublish(root string, args []string, r *Runner) int {
	ensureSeams()
	return t14Dispatch(root, r, func() error {
		sp := &argSpec{
			prog:  "publish",
			usage: publishUsage,
			vals:  []*valOpt{{name: "--actor", required: true}},
			flags: []*boolOpt{{name: "--global"}},
			pos:   []*posOpt{{name: "campaign"}},
		}
		if err := sp.parse(args); err != nil {
			return err
		}
		if sp.helpSeen {
			fmt.Fprint(r.Out, publishHelp)
			return nil
		}
		c, err := t14Open(root, sp.pos[0].val)
		if err != nil {
			return err
		}
		rep, err := sharedmem.PublishCampaign(c, sp.vals[0].val,
			sp.flags[0].set)
		if err != nil {
			return t14ExitOut(1, "publish failed: %s\n", err.Error())
		}
		fmt.Fprintf(r.Out, "published %s signature(s) and %s approved "+
			"memory row(s) for %s to the %s tier\n",
			pyIntText(objAt(rep, "signatures_added")),
			pyIntText(objAt(rep, "memory_added")),
			objStr(rep, "program_key"), objStr(rep, "tier"))
		noop := objAt(rep, "noop")
		if noop.Kind != validation.Null {
			// B5b/D6: a publish that adds nothing says so, and why — the
			// reason is computed by publish_campaign from the same data it
			// used, never re-derived (and never invented) here.
			fmt.Fprintf(r.Out, "nothing changed — %s\n",
				strings.Join(listStringsCLI(objAt(noop, "reasons")), "; "))
			next := listStringsCLI(objAt(noop, "next"))
			if len(next) > 0 {
				fmt.Fprintf(r.Out, "next: %s\n", strings.Join(next, " | "))
			} else {
				fmt.Fprintf(r.Out, "next: nothing to do — everything "+
					"publishable is already in the %s tier (publish again "+
					"after new confirmations or approvals)\n",
					objStr(rep, "tier"))
			}
		}
		fmt.Fprintf(r.Out, "store: %s  record: %s\n",
			objStr(rep, "store"), objStr(rep, "record_id"))
		return nil
	})
}

func init() {
	register(command{ord: 26, name: "publish",
		line: "publish <campaign> --actor A     publish confirmed knowledge to the shared store",
		run:  runPublish})
}
