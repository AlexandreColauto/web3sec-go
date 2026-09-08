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
	jsonOut := false
	var pos []string
	for _, a := range args {
		switch {
		case a == "--json":
			jsonOut = true
		case strings.HasPrefix(a, "-"):
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
		fmt.Fprintln(stdout, prettyASCII(report))
	} else {
		fmt.Fprintln(stdout, audit.AuditSummaryLine(report))
		for _, kv := range objAt(report, "sections").O {
			for _, p := range objAt(kv.V, "problems").A {
				fmt.Fprintf(stdout, "  [%s] %s\n", kv.K, p.S)
			}
		}
	}
	if ok := objAt(report, "ok"); ok.Kind != validation.Bool || !ok.B {
		return failSilent{}
	}
	return nil
}
