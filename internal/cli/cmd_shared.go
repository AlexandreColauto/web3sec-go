package cli

// cmd_shared: `webv2 shared [--verify]` — the shared store, both tiers: its
// view and/or its integrity (cli.py cmd_shared verbatim).

import (
	"fmt"

	"websec/internal/sharedmem"
)

const sharedUsage = "usage: webv2 shared [-h] [--verify]\n"

// sharedHelp is argparse's `webv2 shared --help` output, byte-exact.
const sharedHelp = `usage: webv2 shared [-h] [--verify]

options:
  -h, --help  show this help message and exit
  --verify
`

func runShared(root string, args []string, r *Runner) int {
	ensureSeams()
	return t14Dispatch(root, r, func() error {
		sp := &argSpec{
			prog:  "shared",
			usage: sharedUsage,
			flags: []*boolOpt{{name: "--verify"}},
		}
		if err := sp.parse(args); err != nil {
			return err
		}
		if sp.helpSeen {
			fmt.Fprint(r.Out, sharedHelp)
			return nil
		}
		v, err := sharedmem.StoreView(root)
		if err != nil {
			return err
		}
		fmt.Fprintf(r.Out, "merged view: %s signature(s), %s approved "+
			"memory row(s) (%s global-scope)\n",
			pyIntText(objAt(v, "signature_count")),
			pyIntText(objAt(v, "memory_count")),
			pyIntText(objAt(v, "global_scope_memory_rows")))
		for _, tier := range objAt(v, "tiers").A {
			flag := ""
			if !objAt(tier, "exists").B {
				flag = "  (absent)"
			}
			fmt.Fprintf(r.Out, "  [%s] %s%s\n", objStr(tier, "tier"),
				objStr(tier, "dir"), flag)
			if objAt(tier, "exists").B {
				fmt.Fprintf(r.Out, "      signatures: %s   memory: %s   "+
					"global-scope: %s   records: %s\n",
					pyIntText(objAt(tier, "signature_count")),
					pyIntText(objAt(tier, "memory_count")),
					pyIntText(objAt(tier, "global_scope_rows")),
					pyIntText(objAt(tier, "publish_records")))
			}
		}
		for _, p := range objAt(v, "programs").A {
			fmt.Fprintf(r.Out, "  program: %s\n", scalarStr(p))
		}
		if sp.flags[0].set {
			rep, err := sharedmem.VerifySharedStore(root)
			if err != nil {
				return err
			}
			if !objAt(rep, "exists").B {
				fmt.Fprintf(r.Out, "  integrity: %s\n", objStr(rep, "note"))
				return nil
			}
			verdict := "FAIL"
			if objAt(rep, "ok").B {
				verdict = "PASS"
			}
			fmt.Fprintf(r.Out, "  integrity: %s — %d problem(s)\n", verdict,
				len(objAt(rep, "problems").A))
			for _, p := range objAt(rep, "problems").A {
				fmt.Fprintf(r.Out, "    %s\n", scalarStr(p))
			}
		}
		return nil
	})
}

func init() {
	register(command{ord: 29, name: "shared",
		line: "shared [--verify]                the shared store, both tiers",
		run:  runShared})
}
