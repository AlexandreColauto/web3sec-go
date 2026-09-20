// cmd_adversarial: `webv2 adversarial-game <campaign> <finding>
// --who-profit WHO --mechanism MECH --interplay INTERPLAY
// --strongest-attacker ATTACKER` — records the
// adversarial-game clause (IMPROVEMENTS B2): who profits from the
// freeze/halt, how the profit works, why the challenge path does not
// undo it, and whether that answer survives the strongest attacker variant
// (morph §7.2: a proof-VALID bad state). All four fields are mandatory and
// must reach 20 chars (the gate,
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
	"websec/internal/validation"

	"websec/internal/findings"
	"websec/internal/state"
)

const adversarialUsage = `usage: webv2 adversarial-game [-h] --who-profit WHO --mechanism MECH --interplay INTERPLAY
                               --strongest-attacker ATTACKER
                               campaign finding
`

// adversarialHelp is the argparse-style help block (Go-only verb: the prose
// is ours, the wrapping is argparse's 80-column house style).
const adversarialHelp = adversarialUsage + `
record the adversarial-game answers the bounty gate requires of a live
liveness finding: who profits from the protocol being down, the mechanism
that pays them, how it interacts with the path to the terminal, and
whether that interplay claim survives the strongest attacker variant (a
bad state whose transition is itself proof-valid).

positional arguments:
  campaign              campaign id
  finding               finding id (F-...)

options:
  -h, --help            show this help message and exit
  --who-profit WHO      who profits while the protocol is degraded
  --mechanism MECH      how the profit is realised
  --interplay INTERPLAY how that interacts with the exploit path
  --strongest-attacker ATTACKER  whether the interplay answer survives a proof-valid bad state
`

func runAdversarialGame(root string, args []string, r *Runner) int {
	return t14Dispatch(root, r, func() error {
		return adversarialCmd(root, args, r)
	})
}

// adversarialArgs carries the parsed argv of the adversarial-game verb.
type adversarialArgs struct {
	who, mech, inter, strongest string
	pos                         []string
	posIdx                      []int
	unknown                     []immunizeUnk
	helpSeen                    bool
}

// adversarialParseArgs parses the flag loop, printing the help block and
// flagging it when -h/--help appears mid-argv.
func adversarialParseArgs(args []string, r *Runner) (*adversarialArgs, error) {
	pa := &adversarialArgs{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-h" || a == "--help":
			fmt.Fprint(r.Out, adversarialHelp)
			pa.helpSeen = true
			return pa, nil
		case a == "--who-profit" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			pa.who = args[i+1]
			i++
		case strings.HasPrefix(a, "--who-profit="):
			pa.who = strings.TrimPrefix(a, "--who-profit=")
		case a == "--who-profit":
			return nil, t14ArgparseErr(adversarialUsage, "adversarial-game",
				"argument --who-profit: expected one argument")
		case a == "--mechanism" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			pa.mech = args[i+1]
			i++
		case strings.HasPrefix(a, "--mechanism="):
			pa.mech = strings.TrimPrefix(a, "--mechanism=")
		case a == "--mechanism":
			return nil, t14ArgparseErr(adversarialUsage, "adversarial-game",
				"argument --mechanism: expected one argument")
		case a == "--interplay" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			pa.inter = args[i+1]
			i++
		case strings.HasPrefix(a, "--interplay="):
			pa.inter = strings.TrimPrefix(a, "--interplay=")
		case a == "--interplay":
			return nil, t14ArgparseErr(adversarialUsage, "adversarial-game",
				"argument --interplay: expected one argument")
		case a == "--strongest-attacker" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			pa.strongest = args[i+1]
			i++
		case strings.HasPrefix(a, "--strongest-attacker="):
			pa.strongest = strings.TrimPrefix(a, "--strongest-attacker=")
		case a == "--strongest-attacker":
			return nil, t14ArgparseErr(adversarialUsage, "adversarial-game",
				"argument --strongest-attacker: expected one argument")
		case strings.HasPrefix(a, "-"):
			pa.unknown = append(pa.unknown, immunizeUnk{i, a})
		default:
			pa.pos = append(pa.pos, a)
			pa.posIdx = append(pa.posIdx, i)
		}
	}
	return pa, nil
}

// adversarialCheckArgs applies argparse's post-loop checks in its own order:
// required arguments, then the positional overflow, then the unknown flags.
func adversarialCheckArgs(pa *adversarialArgs) error {
	// argparse checks the subparser's required arguments BEFORE the root
	// parser's "unrecognized arguments" (parse_known_args).
	missing := []string{}
	if len(pa.pos) < 1 {
		missing = append(missing, "campaign")
	}
	if len(pa.pos) < 2 {
		missing = append(missing, "finding")
	}
	if pa.who == "" {
		missing = append(missing, "--who-profit")
	}
	if pa.mech == "" {
		missing = append(missing, "--mechanism")
	}
	if pa.inter == "" {
		missing = append(missing, "--interplay")
	}
	if pa.strongest == "" {
		missing = append(missing, "--strongest-attacker")
	}
	if len(missing) > 0 {
		return t14ArgparseErr(adversarialUsage, "adversarial-game",
			"the following arguments are required: %s",
			strings.Join(missing, ", "))
	}
	// Positionals are assigned greedily; the overflow is unrecognized.
	if len(pa.pos) > 2 {
		for j, t := range pa.pos[2:] {
			pa.unknown = append(pa.unknown, immunizeUnk{pa.posIdx[2+j], t})
		}
		pa.pos = pa.pos[:2]
	}
	if len(pa.unknown) > 0 {
		sort.Slice(pa.unknown, func(i, j int) bool {
			return pa.unknown[i].idx < pa.unknown[j].idx
		})
		toks := make([]string, len(pa.unknown))
		for i, u := range pa.unknown {
			toks[i] = u.tok
		}
		return t14Unrecognized(strings.Join(toks, " "))
	}
	return nil
}

// adversarialRecord stores the clause and prints the confirmation line.
func adversarialRecord(root string, pa *adversarialArgs, r *Runner) error {
	c, err := state.Open(root, pa.pos[0])
	if err != nil {
		return err
	}
	f, err := findings.SetAdversarialGame(c, pa.pos[1], pa.who, pa.mech,
		pa.inter, pa.strongest)
	if err != nil {
		var ie *findings.InputError
		if errors.As(err, &ie) {
			return t14ExitErr(2, "adversarial-game failed: %s\n", err)
		}
		// missing campaign / finding: the generic handler (exit 1).
		return err
	}
	ag := validation.ObjAt(f, "adversarial_game")
	runes := int64(len([]rune(validation.ObjStr(ag, "who_profits"))))
	fmt.Fprintf(r.Out, "%s: adversarial-game clause recorded (who_profits %d "+
		"chars) — the adversarial-game gate clause is now complete\n",
		pa.pos[1], runes)
	return nil
}

func adversarialCmd(root string, args []string, r *Runner) error {
	ensureSeams()
	pa, err := adversarialParseArgs(args, r)
	if err != nil {
		return err
	}
	if pa.helpSeen {
		return nil
	}
	if err := adversarialCheckArgs(pa); err != nil {
		return err
	}
	return adversarialRecord(root, pa, r)
}

func init() {
	register(command{ord: 71, name: "adversarial-game",
		line: "adversarial-game <campaign> <f>  record who profits from the freeze, how, and why the challenge path can't undo it",
		run:  runAdversarialGame})
}
