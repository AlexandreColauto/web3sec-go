package cli

// cmd_supersede: `webv2 supersede <campaign> <new-finding> --of <old-finding>
// [--actor A]` — retire an old finding in favor of a new one (G14a
// sanctioned verb exception).
//
// The old finding transitions to SUPERSEDED (history + event discipline
// intact); the new finding gains a copy of every old evidence item stamped
// re_parented_from, plus dedup_meta.supersedes; finding.superseded is
// logged. Gates: the old finding must not already be terminal, and new !=
// old (both exit 2).
//
// Go-only verb (no Python twin): argparse semantics follow the house style
// (see cmd_chain).

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"websec/internal/findings"
)

const supersedeUsage = `usage: webv2 supersede [-h] --of OLD_FINDING [--actor ACTOR]
                      campaign new_finding
`

const supersedeHelp = supersedeUsage + `
retire a filed finding in favor of a new one. The old finding transitions
to SUPERSEDED (the ONLY status move here — floor, history and event
discipline intact); the new finding gains a COPY of every old evidence
item stamped re_parented_from, plus dedup_meta.supersedes pointing at the
old finding. The old finding's evidence array is left untouched
(append-only store). Logs finding.superseded.

positional arguments:
  campaign              campaign id
  new_finding           finding id that supersedes

options:
  -h, --help            show this help message and exit
  --of OLD_FINDING      finding id being superseded (required)
  --actor ACTOR         actor recorded in history/event (default: model)
`

func runSupersede(root string, args []string, r *Runner) int {
	return t14Dispatch(root, r, func() error { return supersedeCmd(root, args, r) })
}

func supersedeCmd(root string, args []string, r *Runner) error {
	oldID, actor := "", "model"
	haveOld := false
	var pos []string
	var posIdx []int
	var unknown []immunizeUnk
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-h" || a == "--help":
			// argparse's help action fires while parsing, before required
			// arguments are checked, and exits 0.
			fmt.Fprint(r.Out, supersedeHelp)
			return nil
		case a == "--of" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			// trimmed at the parse layer, the way `move --of` trims: the
			// recorded pointer must not carry spelling whitespace
			oldID, haveOld = strings.TrimSpace(args[i+1]), true
			i++
		case strings.HasPrefix(a, "--of="):
			oldID, haveOld = strings.TrimSpace(
				strings.TrimPrefix(a, "--of=")), true
		case a == "--of":
			return t14ArgparseErr(supersedeUsage, "supersede",
				"argument --of: expected one argument")
		case a == "--actor" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			actor = args[i+1]
			i++
		case strings.HasPrefix(a, "--actor="):
			actor = strings.TrimPrefix(a, "--actor=")
		case a == "--actor":
			return t14ArgparseErr(supersedeUsage, "supersede",
				"argument --actor: expected one argument")
		case strings.HasPrefix(a, "-"):
			unknown = append(unknown, immunizeUnk{i, a})
		default:
			pos = append(pos, a)
			posIdx = append(posIdx, i)
		}
	}
	// argparse checks the subparser's required arguments BEFORE the root
	// parser's "unrecognized arguments" (parse_known_args).
	missing := []string{}
	if len(pos) < 1 {
		missing = append(missing, "campaign")
	}
	if len(pos) < 2 {
		missing = append(missing, "new_finding")
	}
	if !haveOld {
		missing = append(missing, "--of")
	}
	if len(missing) > 0 {
		return t14ArgparseErr(supersedeUsage, "supersede",
			"the following arguments are required: %s", strings.Join(missing, ", "))
	}
	// Positionals are assigned greedily; the overflow is unrecognized.
	if len(pos) > 2 {
		for j, t := range pos[2:] {
			unknown = append(unknown, immunizeUnk{posIdx[2+j], t})
		}
		pos = pos[:2]
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
	c, err := t14Open(root, pos[0])
	if err != nil {
		return err
	}
	// r13: capture the old row's capability grants BEFORE the move — the
	// chain sweeps speak one TERMINAL law now (r12), so a SUPERSEDED
	// granter silently stops granting and its capabilities stop seeding
	// proposals. That is right (terminal rows answer nothing) but was
	// SILENT: warn loudly when the retired row carried grants the
	// successor does not, and name the one command that matters.
	oldFinding, oldErr := findings.LoadFinding(c, oldID)
	newFinding, err := findings.Supersede(c, pos[1], oldID, actor)
	if err != nil {
		var rej *findings.RejectedError
		if errors.As(err, &rej) {
			return t14ExitErr(2, "supersede failed: %s\n", err)
		}
		var it *findings.IllegalTransition
		if errors.As(err, &it) {
			return t14ExitErr(2, "supersede failed: %s\n", err)
		}
		return err
	}
	reparented := 0
	for _, it := range objAt(newFinding, "evidence").A {
		if objStr(it, "re_parented_from") == oldID {
			reparented++
		}
	}
	fmt.Fprintf(r.Out, "superseded %s by %s (%d evidence items re-parented)\n",
		oldID, pos[1], reparented)
	if oldErr == nil {
		warnDyingGrants(r.Err, oldID, "SUPERSEDED", oldFinding, &newFinding)
	}
	return nil
}

func init() {
	register(command{ord: 78, name: "supersede",
		line: "supersede <campaign> <new> --of <old>  retire a finding in favor of a new one",
		run:  runSupersede})
}
