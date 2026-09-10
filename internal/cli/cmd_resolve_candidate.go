package cli

// cmd_resolve_candidate: `webv2 resolve-candidate <campaign> <finding>
// <of_finding> --verdict {same|distinct} [--note N] [--actor A]` — the
// missing verdict step: a tier-3 near-duplicate flag is recorded on both
// sides of the pair and (for 'same') the younger finding is merged (cli.py
// cmd_resolve_candidate verbatim).
//
// Error taxonomy: Python catches (KeyError, ValueError) and exits 2 with
// `resolve-candidate failed: {e}` — str(KeyError) is repr(message), which
// dedup.ResolveCandidate already renders. A missing FINDING is a
// FileNotFoundError in Python, so it falls through to main's handler
// (exit 1); Go's error for that case is the same `no finding ...` message.

import (
	"fmt"
	"strings"

	"websec/internal/dedup"
	"websec/internal/state"
	"websec/internal/validation"
)

var resolveVerdicts = []string{"same", "distinct"}

func runResolveCandidate(root string, args []string, r *Runner) int {
	if helpRequested(r.Out, "resolve-candidate", args) {
		return 0
	}

	ensureSeams()
	verdict, note, actor := "", "", ""
	haveVerdict := false
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--verdict" && i+1 < len(args):
			verdict, haveVerdict = args[i+1], true
			i++
		case strings.HasPrefix(a, "--verdict="):
			verdict, haveVerdict = strings.TrimPrefix(a, "--verdict="), true
		case a == "--note" && i+1 < len(args):
			note = args[i+1]
			i++
		case strings.HasPrefix(a, "--note="):
			note = strings.TrimPrefix(a, "--note=")
		case a == "--actor" && i+1 < len(args):
			actor = args[i+1]
			i++
		case strings.HasPrefix(a, "--actor="):
			actor = strings.TrimPrefix(a, "--actor=")
		case a == "--verdict":
			return r.fail(root, argErrf("resolve-candidate",
				"argument --verdict: expected one argument"))
		case a == "--note":
			return r.fail(root, argErrf("resolve-candidate",
				"argument --note: expected one argument"))
		case a == "--actor":
			return r.fail(root, argErrf("resolve-candidate",
				"argument --actor: expected one argument"))
		case strings.HasPrefix(a, "-"):
			return r.fail(root, usageErrf("unrecognized arguments: %s", a))
		default:
			pos = append(pos, a)
		}
		if haveVerdict && !containsStrCLI(resolveVerdicts, verdict) {
			return r.fail(root, argErrf("resolve-candidate",
				"argument --verdict: invalid choice: %s (choose from %s)",
				validation.PyReprStr(verdict), quotedList(resolveVerdicts)))
		}
	}
	if len(pos) > 3 {
		return r.fail(root, usageErrf("unrecognized arguments: %s", pos[3]))
	}
	missing := []string{}
	if len(pos) < 1 {
		missing = append(missing, "campaign")
	}
	if len(pos) < 2 {
		missing = append(missing, "finding")
	}
	if len(pos) < 3 {
		missing = append(missing, "of_finding")
	}
	if !haveVerdict {
		missing = append(missing, "--verdict")
	}
	if len(missing) > 0 {
		return r.fail(root, requiredErrf("resolve-candidate", missing...))
	}
	if actor == "" {
		actor = "cli"
	}
	c, err := state.Open(root, pos[0])
	if err != nil {
		return r.withErr(root, func() error { return err })
	}
	if _, err := dedup.ResolveCandidate(c, pos[1], pos[2], verdict, note,
		actor); err != nil {
		if strings.HasPrefix(err.Error(), "no finding ") {
			return r.withErr(root, func() error { return err })
		}
		fmt.Fprintf(r.Err, "resolve-candidate failed: %s\n", err.Error())
		return 2
	}
	fmt.Fprintf(r.Out, "candidate pair %s vs %s: %s (recorded on both sides)\n",
		pos[1], pos[2], verdict)
	return 0
}

func init() {
	register(command{ord: 64, name: "resolve-candidate",
		line: "resolve-candidate <campaign> <f> <of>  record a pair verdict",
		run:  runResolveCandidate})
}
