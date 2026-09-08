package cli

// cmd_verdict: `webv2 verdict <campaign> <finding> --verdict V --reason R` —
// record the hostile-critic verdict with its reasoning (cli.py cmd_verdict
// verbatim: the FULL reasoning is printed — it is persisted in full at
// dedup_meta.critic_reasoning, so truncating the console line would read as
// data loss).

import (
	"fmt"
	"strings"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

var criticVerdicts = []string{"pending", "confirmed", "possible", "disproved",
	"duplicate", "out_of_scope", "informational"}

func runVerdict(root string, args []string, r *Runner) int {
	ensureSeams()
	verdict, reason := "", ""
	haveVerdict, haveReason := false, false
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--verdict" && i+1 < len(args):
			verdict, haveVerdict = args[i+1], true
			i++
		case strings.HasPrefix(a, "--verdict="):
			verdict, haveVerdict = strings.TrimPrefix(a, "--verdict="), true
		case a == "--verdict":
			return r.fail(root, argErrf("verdict",
				"argument --verdict: expected one argument"))
		case a == "--reason" && i+1 < len(args):
			reason, haveReason = args[i+1], true
			i++
		case strings.HasPrefix(a, "--reason="):
			reason, haveReason = strings.TrimPrefix(a, "--reason="), true
		case a == "--reason":
			return r.fail(root, argErrf("verdict",
				"argument --reason: expected one argument"))
		case strings.HasPrefix(a, "-"):
			return r.fail(root, usageErrf("unrecognized arguments: %s", a))
		default:
			pos = append(pos, a)
		}
		if haveVerdict && !containsStrCLI(criticVerdicts, verdict) {
			return r.fail(root, argErrf("verdict",
				"argument --verdict: invalid choice: %s (choose from %s)",
				validation.PyReprStr(verdict), quotedList(criticVerdicts)))
		}
	}
	missing := []string{}
	if len(pos) < 1 {
		missing = append(missing, "campaign")
	}
	if len(pos) < 2 {
		missing = append(missing, "finding")
	}
	if !haveVerdict {
		missing = append(missing, "--verdict")
	}
	if !haveReason {
		missing = append(missing, "--reason")
	}
	if len(missing) > 0 {
		return r.fail(root, requiredErrf("verdict", missing...))
	}
	if len(pos) > 2 {
		return r.fail(root, usageErrf("unrecognized arguments: %s", pos[2]))
	}
	c, err := state.Open(root, pos[0])
	if err != nil {
		return r.withErr(root, func() error { return err })
	}
	if _, err := findings.SetCriticVerdict(c, pos[1], verdict, reason); err != nil {
		return r.withErr(root, func() error { return err })
	}
	fmt.Fprintf(r.Out, "critic verdict on %s: %s\n", pos[1], verdict)
	fmt.Fprintf(r.Out, "  reason: %s\n", reason)
	fmt.Fprintln(r.Out, "  (persisted in full at dedup_meta.critic_reasoning)")
	return 0
}

// quotedList is Python's "', '".join(repr choices): 'a', 'b', 'c'.
func quotedList(items []string) string {
	parts := make([]string, 0, len(items))
	for _, it := range items {
		parts = append(parts, validation.PyReprStr(it))
	}
	return strings.Join(parts, ", ")
}

func init() {
	register(command{ord: 45, name: "verdict",
		line: "verdict <campaign> <finding> --verdict V --reason R",
		run:  runVerdict})
}
