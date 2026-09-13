package cli

// cmd_move: `webv2 move <campaign> <finding> TO_STATUS --reason R
// [--actor A] [--adjacent NAME] [--adjacent-clear] [--of FINDING]` — the ONLY
// way a finding's status changes: the same transition table, evidence floor
// and CONFIRMED gate bundle the API enforces (cli.py cmd_move verbatim).
//
// --of is additive (Task 7c): moving to DUPLICATE must name the finding it
// duplicates, and DUPLICATE -> HYPOTHESIS is the operator's undo (it clears
// the recorded target). cli.py had no such flag — the Python `dedup` sweep was
// the only writer of a DUPLICATE, and a wrong merge could not be undone.
// The flag is consumed ONLY by a move whose to_status is DUPLICATE (the merge
// writes the dedup pointer; the reopen clears it without ever reading --of),
// so anywhere else it is refused at exit 2, never silently dropped (round-2
// contract: flags are never inert). The value is trimmed at the parse layer —
// the transition layer trims it for its own blank check, so the recorded
// pointer must not carry spelling whitespace the checks never see.
//
// Error contract (cli.py cmd_move): IllegalTransition and ValueError are
// printed by the HANDLER as `move failed: {e}` on stderr with exit 2 — NOT
// through main's `error: {e}` handler (which keeps exit 1 for everything
// else, e.g. the FileNotFoundError of an unknown finding). t14ExitErr
// carries that bespoke shape; the two Python exception classes are matched
// by the port's error shapes: findings.IllegalTransition, and the single
// ValueError the transition itself raises (planner.ADJACENT_REQUIRED_MSG).
// findings.DuplicateTargetRequired joins that handler class: the move cannot
// proceed until the operator supplies the missing name. So does
// findings.DuplicateTargetInvalid (FIX-1): a --of that names a ghost id, the
// finding itself, or re-targets an existing merge cannot proceed either —
// the operator repairs with a real target or a reopen first.

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
// live Python CLI (COLUMNS=80) plus the additive `--of` (Task 7c; cli.py has
// no such flag — the DUPLICATE target used to be the dedup sweep's private
// business).
const moveUsage = `usage: webv2 move [-h] --reason REASON [--actor ACTOR] [--adjacent ADJACENT]
                  [--adjacent-clear] [--of OF]
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
	reason, actor, adjacent, duplicateOf := "", "", "", ""
	haveReason := false
	haveOf := false
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
		case a == "--of" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			duplicateOf, haveOf = strings.TrimSpace(args[i+1]), true
			i++
		case strings.HasPrefix(a, "--of="):
			// even an empty value counts as the flag being passed: the
			// route refusal below keys on presence, not on the value
			duplicateOf, haveOf = strings.TrimSpace(
				strings.TrimPrefix(a, "--of=")), true
		case a == "--of":
			return t14ArgparseErr(moveUsage, "move",
				"argument --of: expected one argument")
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
	// Round-3 chief item 4: --of is only ever consumed by a move to
	// DUPLICATE — the merge writes the dedup pointer, and the reopen
	// (DUPLICATE -> HYPOTHESIS) clears that pointer without ever reading
	// --of. On any other to_status the flag would be silently dropped at
	// exit 0, so it is refused here, before the campaign is even opened,
	// naming the only route that consumes it.
	if haveOf && pos[2] != "DUPLICATE" {
		return t14ExitErr(2, "move: --of records the duplicate-of pointer "+
			"of a move to DUPLICATE — %s is not one, so there is no merge "+
			"pointer to write: drop --of\n", validation.PyReprStr(pos[2]))
	}
	if actor == "" {
		actor = "cli" // args.actor or "cli"
	}
	// r6 (critic issue 5): --adjacent and --adjacent-clear are two answers
	// to one question; the library branch clears first and the named
	// property would vanish silently. The CLI refuses the combination —
	// flags are never inert here.
	if adjacent != "" && adjacentClear {
		return t14ArgparseErr(moveUsage, "move",
			"--adjacent and --adjacent-clear are mutually exclusive — name"+
				" the new adjacent property, or clear it, not both")
	}
	c, err := state.Open(root, pos[0])
	if err != nil {
		return err
	}
	f, err := findings.TransitionWith(c, pos[1], pos[2], reason,
		findings.TransitionOpts{Actor: actor, Adjacent: adjacent,
			AdjacentClear: adjacentClear, DuplicateOf: duplicateOf})
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

// moveHandlerError reports whether transition's error is one of the Python
// exception classes cmd_move prints itself (exit 2): IllegalTransition and
// ValueError. The only ValueError transition raises is the adjacent-
// property guard, whose message is planner.ADJACENT_REQUIRED_MSG (the seam
// findings' guard is wired from). findings.DuplicateTargetRequired is the
// Go-only third member of that class (Task 7c): a targeted move that has not
// been told its target. findings.DuplicateTargetInvalid is the fourth (FIX-1):
// a --of target that does not exist, is the finding itself, or re-targets a
// recorded merge.
func moveHandlerError(err error) bool {
	var it *findings.IllegalTransition
	if errors.As(err, &it) {
		return true
	}
	var dt *findings.DuplicateTargetRequired
	if errors.As(err, &dt) {
		return true
	}
	var di *findings.DuplicateTargetInvalid
	if errors.As(err, &di) {
		return true
	}
	return err.Error() == planner.AdjacentRequiredMsg
}

func init() {
	register(command{ord: 42, name: "move",
		line: "move <campaign> <finding> TO_STATUS  transition a finding's status",
		run:  runMove})
}
