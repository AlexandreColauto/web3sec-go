package cli

// cmd_invariant_contradict: `webv2 invariant-contradict <campaign> <inv_id>
// --evidence E` — mark a model invariant CONTRADICTED by code (cli.py
// cmd_invariant_contradict verbatim; the KeyError renders as repr, hence
// PyReprStr on the Go error).

import (
	"fmt"
	"strings"

	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/validation"
)

func runInvariantContradict(root string, args []string, r *Runner) int {
	if helpRequested(r.Out, "invariant-contradict", args) {
		return 0
	}

	ensureSeams()
	evidence, haveEvidence := "", false
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--evidence" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			evidence, haveEvidence = args[i+1], true
			i++
		case strings.HasPrefix(a, "--evidence="):
			evidence, haveEvidence = strings.TrimPrefix(a, "--evidence="), true
		case a == "--evidence":
			return r.fail(root, argErrf("invariant-contradict",
				"argument --evidence: expected one argument"))
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
		missing = append(missing, "inv_id")
	}
	if !haveEvidence {
		missing = append(missing, "--evidence")
	}
	if len(missing) > 0 {
		return r.fail(root, requiredErrf("invariant-contradict", missing...))
	}
	c, err := state.Open(root, pos[0])
	if err != nil {
		return r.withErr(root, func() error { return err })
	}
	invID := pos[1]
	entry, err := invariants.ContradictInvariantStatement(c, invID, evidence)
	if err != nil {
		fmt.Fprintf(r.Err, "invariant contradict failed: %s\n",
			validation.PyReprStr(err.Error()))
		return 2
	}
	fmt.Fprintf(r.Out, "%s: CONTRADICTED (%s)\n", invID,
		validation.ObjStr(entry, "contradiction"))
	return 0
}

func init() {
	register(command{ord: 25, name: "invariant-contradict",
		line: "invariant-contradict <campaign> <inv_id> --evidence E",
		run:  runInvariantContradict})
}
