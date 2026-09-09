package cli

// cmd_shield: `webv2 shield <campaign> <finding> --reason R
// [--extraction] [--actor A]` — the plausibility-shield adjudication: the
// docs call the mechanism INTENTIONAL; record the explicit answer to whether
// the effect is still extraction (cli.py cmd_shield verbatim).

import (
	"fmt"

	"websec/internal/findings"
	"websec/internal/validation"
)

const shieldUsage = "usage: webv2 shield [-h] [--extraction] --reason REASON " +
	"[--actor ACTOR]\n                    campaign finding\n"

const shieldHelp = `usage: webv2 shield [-h] [--extraction] --reason REASON [--actor ACTOR]
                    campaign finding

positional arguments:
  campaign
  finding

options:
  -h, --help       show this help message and exit
  --extraction     the effect IS extraction despite being intended
  --reason REASON
  --actor ACTOR
`

func runShield(root string, args []string, r *Runner) int {
	ensureSeams()
	return t14Dispatch(root, r, func() error {
		sp := &argSpec{prog: "shield", usage: shieldUsage,
			vals: []*valOpt{{name: "--reason", required: true},
				{name: "--actor"}},
			flags: []*boolOpt{{name: "--extraction"}},
			pos:   []*posOpt{{name: "campaign"}, {name: "finding"}}}
		if err := sp.parse(args); err != nil {
			return err
		}
		if sp.helpSeen {
			fmt.Fprint(r.Out, shieldHelp)
			return nil
		}
		c, err := t14Open(root, sp.pos[0].val)
		if err != nil {
			return err
		}
		finding := sp.pos[1].val
		actor := sp.vals[1].val
		if actor == "" {
			actor = "cli"
		}
		f, err := findings.SetShieldAdjudication(c, finding,
			sp.flags[0].set, sp.vals[0].val, actor)
		if err != nil {
			return err
		}
		adj := objAt(objAt(f, "verification"), "shield_adjudication")
		fmt.Fprintf(r.Out, "%s: shield adjudicated — "+
			"extraction_despite_intent=%s (actor %s)\n", finding,
			pyBoolLower(objAt(adj, "extraction_despite_intent")),
			objStr(adj, "actor"))
		return nil
	})
}

// pyBoolLower is Python's str(True/False) inside an f-string.
func pyBoolLower(v validation.Value) string {
	if v.Kind == validation.Bool {
		if v.B {
			return "True"
		}
		return "False"
	}
	return scalarStr(v)
}

func init() {
	register(command{ord: 61, name: "shield",
		line: "shield <campaign> <finding> --reason R  record the " +
			"plausibility-shield adjudication",
		run: runShield})
}
