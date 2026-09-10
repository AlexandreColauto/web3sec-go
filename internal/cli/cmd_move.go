package cli

// cmd_move: `webv2 move <campaign> <finding> TO_STATUS --reason R
// [--actor A] [--adjacent NAME] [--adjacent-clear]` — the ONLY way a
// finding's status changes: the same transition table, evidence floor and
// CONFIRMED gate bundle the API enforces (cli.py cmd_move verbatim).
//
// Error contract (cli.py cmd_move): IllegalTransition and ValueError are
// printed by the HANDLER as `move failed: {e}` on stderr with exit 2 — NOT
// through main's `error: {e}` handler (which keeps exit 1 for everything
// else, e.g. the FileNotFoundError of an unknown finding). t14ExitErr
// carries that bespoke shape; the two Python exception classes are matched
// by the port's error shapes: findings.IllegalTransition, and the single
// ValueError the transition itself raises (planner.ADJACENT_REQUIRED_MSG).

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"websec/internal/findings"
	"websec/internal/planner"
	"websec/internal/state"
	"websec/internal/validation"
)

// moveUsage is argparse's `move` usage block, pinned byte-for-byte from the
// live Python CLI (COLUMNS=80).
const moveUsage = `usage: webv2 move [-h] --reason REASON [--actor ACTOR] [--adjacent ADJACENT]
                  [--adjacent-clear]
                  campaign finding to_status
`

func runMove(root string, args []string, r *Runner) int {
	return t14Dispatch(root, r, func() error { return moveCmd(root, args, r) })
}

func moveCmd(root string, args []string, r *Runner) error {
	if helpRequested(r.Out, "move", args) {
		return nil
	}

	ensureSeams()
	reason, actor, adjacent := "", "", ""
	haveReason := false
	adjacentClear := false
	// unrecognized tokens are reported by the ROOT parser in ARGV order.
	type moveUnk struct {
		idx int
		tok string
	}
	var pos []string
	var posIdx []int
	var unknown []moveUnk
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--reason":
			v, ok := flagValue(args, i)
			if !ok {
				return t14ArgparseErr(moveUsage, "move",
					"argument --reason: expected one argument")
			}
			reason, haveReason = v, true
			i++
		case strings.HasPrefix(a, "--reason="):
			reason, haveReason = strings.TrimPrefix(a, "--reason="), true
		case a == "--actor":
			v, ok := flagValue(args, i)
			if !ok {
				return t14ArgparseErr(moveUsage, "move",
					"argument --actor: expected one argument")
			}
			actor = v
			i++
		case strings.HasPrefix(a, "--actor="):
			actor = strings.TrimPrefix(a, "--actor=")
		case a == "--adjacent":
			v, ok := flagValue(args, i)
			if !ok {
				return t14ArgparseErr(moveUsage, "move",
					"argument --adjacent: expected one argument")
			}
			adjacent = v
			i++
		case strings.HasPrefix(a, "--adjacent="):
			adjacent = strings.TrimPrefix(a, "--adjacent=")
		case a == "--adjacent-clear":
			adjacentClear = true
		case strings.HasPrefix(a, "--adjacent-clear="):
			return t14ArgparseErr(moveUsage, "move",
				"argument --adjacent-clear: ignored explicit argument %s",
				validation.PyReprStr(strings.TrimPrefix(a, "--adjacent-clear=")))
		case strings.HasPrefix(a, "-"):
			unknown = append(unknown, moveUnk{i, a})
		default:
			pos = append(pos, a)
			posIdx = append(posIdx, i)
		}
	}
	// argparse checks the subparser's required arguments BEFORE the root
	// parser's "unrecognized arguments" (parse_known_args): `move --bogus`
	// reports the missing positionals, not --bogus.
	missing := []string{}
	if len(pos) < 1 {
		missing = append(missing, "campaign")
	}
	if len(pos) < 2 {
		missing = append(missing, "finding")
	}
	if len(pos) < 3 {
		missing = append(missing, "to_status")
	}
	if !haveReason {
		missing = append(missing, "--reason")
	}
	if len(missing) > 0 {
		return t14ArgparseErr(moveUsage, "move",
			"the following arguments are required: %s", strings.Join(missing, ", "))
	}
	// Positionals are assigned greedily; the overflow is unrecognized.
	if len(pos) > 3 {
		for j, t := range pos[3:] {
			unknown = append(unknown, moveUnk{posIdx[3+j], t})
		}
		pos = pos[:3]
	}
	if len(unknown) > 0 {
		sort.Slice(unknown, func(i, j int) bool {
			return unknown[i].idx < unknown[j].idx
		})
		toks := make([]string, len(unknown))
		for i, u := range unknown {
			toks[i] = u.tok
		}
		return t14Unrecognized(strings.Join(toks, " "))
	}
	if actor == "" {
		actor = "cli" // args.actor or "cli"
	}
	c, err := state.Open(root, pos[0])
	if err != nil {
		return err
	}
	f, err := findings.Transition(c, pos[1], pos[2], reason, actor, adjacent,
		adjacentClear)
	if err != nil {
		if moveHandlerError(err) {
			return t14ExitErr(2, "move failed: %s\n", err)
		}
		return err
	}
	level, err := findings.FindingLevel(f)
	if err != nil {
		return err
	}
	fmt.Fprintf(r.Out, "%s: %s (evidence level %s)\n", pos[1],
		objStr(f, "status"), level)
	return nil
}

// moveHandlerError reports whether transition's error is one of the two
// Python exception classes cmd_move prints itself (exit 2): IllegalTransition
// and ValueError. The only ValueError transition raises is the adjacent-
// property guard, whose message is planner.ADJACENT_REQUIRED_MSG (the seam
// findings' guard is wired from).
func moveHandlerError(err error) bool {
	var it *findings.IllegalTransition
	if errors.As(err, &it) {
		return true
	}
	return err.Error() == planner.AdjacentRequiredMsg
}

func init() {
	register(command{ord: 42, name: "move",
		line: "move <campaign> <finding> TO_STATUS  transition a finding's status",
		run:  runMove})
}
