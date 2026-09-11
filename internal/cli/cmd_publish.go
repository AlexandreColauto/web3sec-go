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

const publishUsage = "usage: webv2 publish [-h] --actor ACTOR [--global] [--disclosure FILE] campaign\n"

// publishHelp is argparse's `webv2 publish --help` output, byte-exact.
const publishHelp = `usage: webv2 publish [-h] --actor ACTOR [--global] [--disclosure FILE] campaign

positional arguments:
  campaign

options:
  -h, --help     show this help message and exit
  --actor ACTOR
  --global       write to ~/.webv2/shared-memory (visible from every root)
                 instead of the root-tier store
  --disclosure FILE
                 attach an operator-supplied disclosure bundle (JSON). The
                 bundle stays campaign-local; its sha256 and embargo date ride
                 the publish record and its prose never enters the shared
                 store. The embargo is RECORDED, not enforced.
`

func runPublish(root string, args []string, r *Runner) int {
	ensureSeams()
	return t14Dispatch(root, r, func() error {
		sp := &argSpec{
			prog:  "publish",
			usage: publishUsage,
			vals: []*valOpt{{name: "--actor", required: true},
				{name: "--disclosure"}},
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
		// I6: load + validate the bundle BEFORE the publish, then write and
		// register the campaign-local artifact. A refused bundle exits 1 with
		// nothing written; a publish that fails afterwards leaves only the
		// campaign-local artifact (never the store).
		opts := sharedmem.PublishOpts{}
		var disc *sharedmem.Disclosure
		if file := sp.vals[1].val; file != "" {
			disc, err = sharedmem.LoadDisclosure(c, file)
			if err != nil {
				return t14ExitOut(1, "publish failed: %s\n", err.Error())
			}
			if err := sharedmem.WriteDisclosureArtifact(c, disc); err != nil {
				return t14ExitOut(1, "publish failed: %s\n", err.Error())
			}
			opts.DisclosureSHA256 = disc.SHA256
			opts.DisclosureEmbargoUntil = disc.EmbargoUntil
		}
		rep, err := sharedmem.PublishCampaignWith(c, sp.vals[0].val,
			sp.flags[0].set, opts)
		if err != nil {
			return t14ExitOut(1, "publish failed: %s\n", err.Error())
		}
		fmt.Fprintf(r.Out, "published %s signature(s) and %s approved "+
			"memory row(s) for %s to the %s tier\n",
			pyIntText(objAt(rep, "signatures_added")),
			pyIntText(objAt(rep, "memory_added")),
			objStr(rep, "program_key"), objStr(rep, "tier"))
		if disc != nil {
			// I6: the state is made legible, never enforced — the framework
			// does not refuse, delay, or suppress the publish while an
			// embargo is open.
			id := disc.SHA256
			if len(id) > 12 {
				id = id[:12]
			}
			if disc.EmbargoUntil != "" {
				fmt.Fprintf(r.Out, "disclosure: bundle %s (%d findings), "+
					"embargo_until %s — recorded, not enforced\n",
					id, len(disc.FindingIDs), disc.EmbargoUntil)
			} else {
				fmt.Fprintf(r.Out, "disclosure: bundle %s (%d findings), "+
					"no embargo\n", id, len(disc.FindingIDs))
			}
		}
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
