package cli

// cmd_audit: `webv2 audit <campaign> [--json]` — full integrity audit
// (cli.py cmd_audit verbatim). Summary line to stdout, then
// `  [{section}] {problem}` lines; exit 1 when not ok.

import (
	"fmt"
	"io"
	"strings"

	"websec/internal/audit"
	"websec/internal/state"
	"websec/internal/validation"
)

func runAudit(root string, args []string, stdout io.Writer) error {
	if helpRequested(stdout, "audit", args) {
		return nil
	}

	jsonOut := false
	var pos []string
	for _, a := range args {
		switch {
		case a == "--json":
			jsonOut = true
		case strings.HasPrefix(a, "-"):
			// R3-9e: the deep integrity sweep rides the brief, so the
			// refusal says so — house law, every refusal names the next
			// command (the same error class, only the sentence grows).
			if a == "--deep" {
				target := "<campaign>"
				if len(pos) > 0 {
					target = pos[0]
				}
				return usageErrf("unrecognized arguments: --deep — the "+
					"deep integrity sweep rides the brief: webv2 brief "+
					"%s --deep", target)
			}
			return usageErrf("unrecognized arguments: %s", a)
		default:
			pos = append(pos, a)
		}
	}
	if len(pos) != 1 {
		return usageErrf("audit requires exactly one <campaign> argument")
	}
	c, err := state.Open(root, pos[0])
	if err != nil {
		return err
	}
	audit.Setup()
	report, err := audit.AuditCampaign(c)
	if err != nil {
		return err
	}
	if jsonOut {
		fmt.Fprintln(stdout, validation.DumpIndentedASCII(report))
	} else {
		fmt.Fprintln(stdout, audit.AuditSummaryLine(report))
		for _, kv := range validation.ObjAt(report, "sections").O {
			for _, p := range validation.ObjAt(kv.V, "problems").A {
				fmt.Fprintf(stdout, "  [%s] %s\n", kv.K, p.S)
			}
		}
	}
	if ok := validation.ObjAt(report, "ok"); ok.Kind != validation.Bool || !ok.B {
		return failSilent{}
	}
	return nil
}

func init() {
	register(command{ord: 52, name: "audit",
		line: "audit <campaign> [--json]            full integrity audit",
		run: func(root string, args []string, r *Runner) int {
			return r.withErr(root, func() error { return runAudit(root, args, r.Out) })
		}})
}
