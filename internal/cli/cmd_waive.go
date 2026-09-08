package cli

// cmd_waive: `webv2 waive <campaign> <stage> --reason R --actor A
// [--subject S]` — waive a completion-proof subject ('*' = the whole stage).
// Named actor, written reason, append-only, logged (cli.py cmd_waive
// verbatim; --subject omitted means '*').

import (
	"fmt"
	"strings"

	"websec/internal/completion"
	"websec/internal/state"
)

func runWaive(root string, args []string, r *Runner) int {
	ensureSeams()
	subject, reason, actor := "", "", ""
	haveReason, haveActor := false, false
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--subject" && i+1 < len(args):
			subject = args[i+1]
			i++
		case strings.HasPrefix(a, "--subject="):
			subject = strings.TrimPrefix(a, "--subject=")
		case a == "--subject":
			return r.fail(root, argErrf("waive",
				"argument --subject: expected one argument"))
		case a == "--reason" && i+1 < len(args):
			reason, haveReason = args[i+1], true
			i++
		case strings.HasPrefix(a, "--reason="):
			reason, haveReason = strings.TrimPrefix(a, "--reason="), true
		case a == "--reason":
			return r.fail(root, argErrf("waive",
				"argument --reason: expected one argument"))
		case a == "--actor" && i+1 < len(args):
			actor, haveActor = args[i+1], true
			i++
		case strings.HasPrefix(a, "--actor="):
			actor, haveActor = strings.TrimPrefix(a, "--actor="), true
		case a == "--actor":
			return r.fail(root, argErrf("waive",
				"argument --actor: expected one argument"))
		case strings.HasPrefix(a, "-"):
			return r.fail(root, usageErrf("unrecognized arguments: %s", a))
		default:
			pos = append(pos, a)
		}
	}
	missing := []string{}
	if len(pos) < 1 {
		missing = append(missing, "campaign")
	}
	if len(pos) < 2 {
		missing = append(missing, "stage")
	}
	if !haveReason {
		missing = append(missing, "--reason")
	}
	if !haveActor {
		missing = append(missing, "--actor")
	}
	if len(missing) > 0 {
		return r.fail(root, requiredErrf("waive", missing...))
	}
	if len(pos) > 2 {
		return r.fail(root, usageErrf("unrecognized arguments: %s", pos[2]))
	}
	c, err := state.Open(root, pos[0])
	if err != nil {
		return r.withErr(root, func() error { return err })
	}
	stage := pos[1]
	row, err := completion.Waive(c, stage, subject, reason, actor)
	if err != nil {
		return r.withErr(root, func() error { return err })
	}
	fmt.Fprintf(r.Out, "waived %s/%s (actor %s): %s\n", stage,
		objStr(row, "subject"), actor, pyHead(reason, 60))
	return 0
}

func init() {
	register(command{ord: 54, name: "waive",
		line: "waive <campaign> <stage> --reason R --actor A",
		run:  runWaive})
}
