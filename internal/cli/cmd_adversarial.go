// cmd_adversarial: `webv2 adversarial-game <campaign> <finding>
// --who-profit WHO --mechanism MECH --interplay INTERPLAY` — records the
// adversarial-game clause (IMPROVEMENTS B2): who profits from the
// freeze/halt, how the profit works, and why the challenge path does not
// undo it. All three fields are mandatory and must reach 20 chars (the gate,
// check15, re-validates the stored values). The clause is DATA on the
// finding (adversarial_game) plus one finding.adversarial_game_set event.
//
// Go-only verb (no Python twin): argparse semantics follow the house style
// (see cmd_exploit). A short field exits 2 with
// `adversarial-game failed: {e}`; a missing FINDING falls through to the
// generic handler (exit 1).
package cli

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"websec/internal/findings"
	"websec/internal/state"
)

const adversarialUsage = `usage: webv2 adversarial-game [-h] --who-profit WHO --mechanism MECH --interplay INTERPLAY
                               campaign finding
`

// adversarialHelp is the argparse-style help block (Go-only verb: the prose
// is ours, the wrapping is argparse's 80-column house style).
const adversarialHelp = adversarialUsage + `
record the adversarial-game answers the bounty gate requires of a live
liveness finding: who profits from the protocol being down, the mechanism
that pays them, and how it interacts with the path to the terminal.

positional arguments:
  campaign              campaign id
  finding               finding id (F-...)

options:
  -h, --help            show this help message and exit
  --who-profit WHO      who profits while the protocol is degraded
  --mechanism MECH      how the profit is realised
  --interplay INTERPLAY how that interacts with the exploit path
`

func runAdversarialGame(root string, args []string, r *Runner) int {
	return t14Dispatch(root, r, func() error {
		return adversarialCmd(root, args, r)
	})
}

func adversarialCmd(root string, args []string, r *Runner) error {
	ensureSeams()
	who, mech, inter := "", "", ""
	var pos []string
	var posIdx []int
	var unknown []immunizeUnk
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-h" || a == "--help":
			fmt.Fprint(r.Out, adversarialHelp)
			return nil
		case a == "--who-profit" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			who = args[i+1]
			i++
		case strings.HasPrefix(a, "--who-profit="):
			who = strings.TrimPrefix(a, "--who-profit=")
		case a == "--who-profit":
			return t14ArgparseErr(adversarialUsage, "adversarial-game",
				"argument --who-profit: expected one argument")
		case a == "--mechanism" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			mech = args[i+1]
			i++
		case strings.HasPrefix(a, "--mechanism="):
			mech = strings.TrimPrefix(a, "--mechanism=")
		case a == "--mechanism":
			return t14ArgparseErr(adversarialUsage, "adversarial-game",
				"argument --mechanism: expected one argument")
		case a == "--interplay" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			inter = args[i+1]
			i++
		case strings.HasPrefix(a, "--interplay="):
			inter = strings.TrimPrefix(a, "--interplay=")
		case a == "--interplay":
			return t14ArgparseErr(adversarialUsage, "adversarial-game",
				"argument --interplay: expected one argument")
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
		missing = append(missing, "finding")
	}
	if who == "" {
		missing = append(missing, "--who-profit")
	}
	if mech == "" {
		missing = append(missing, "--mechanism")
	}
	if inter == "" {
		missing = append(missing, "--interplay")
	}
	if len(missing) > 0 {
		return t14ArgparseErr(adversarialUsage, "adversarial-game",
			"the following arguments are required: %s",
			strings.Join(missing, ", "))
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
	c, err := state.Open(root, pos[0])
	if err != nil {
		return err
	}
	f, err := findings.SetAdversarialGame(c, pos[1], who, mech, inter)
	if err != nil {
		var ie *findings.InputError
		if errors.As(err, &ie) {
			return t14ExitErr(2, "adversarial-game failed: %s\n", err)
		}
		// missing campaign / finding: the generic handler (exit 1).
		return err
	}
	ag := objAt(f, "adversarial_game")
	runes := int64(len([]rune(objStr(ag, "who_profits"))))
	fmt.Fprintf(r.Out, "%s: adversarial-game clause recorded (who_profits %d "+
		"chars) — the adversarial-game gate clause is now complete\n",
		pos[1], runes)
	return nil
}

func init() {
	register(command{ord: 71, name: "adversarial-game",
		line: "adversarial-game <campaign> <f>  record who profits from the freeze, how, and why the challenge path can't undo it",
		run:  runAdversarialGame})
}
