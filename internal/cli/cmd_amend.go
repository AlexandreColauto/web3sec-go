package cli

// cmd_amend: `webv2 amend <campaign> <finding> [--title T] [--class C]
// [--claim K] [--note N] [--actor A]` — correct a filed finding in place
// (G14a sanctioned verb exception).
//
// Every successful amend bumps claim_version, appends a history entry and
// logs finding.amended; the status NEVER moves here. At least one of
// --title/--class/--claim/--note is required (exit 2 otherwise).
//
// Go-only verb (no Python twin): argparse semantics follow the house style
// (see cmd_chain). Operator-rejected amends (no field flag, unknown class)
// exit 2 with an `amend failed: ...` line; a missing campaign/finding is
// the generic handler (exit 1).

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"websec/internal/findings"
	"websec/internal/validation"
)

const amendUsage = `usage: webv2 amend [-h] [--title TITLE] [--class CLASS] [--claim CLAIM]
                   [--note NOTE] [--actor ACTOR]
                   campaign finding
`

const amendHelp = amendUsage + `
correct a filed finding without lying to the hash chain. At least one of
--title, --class, --claim or --note is required. Every successful amend
bumps claim_version (re-staling critic verdicts pinned to the old claim),
appends a history entry "amend: <keys> [-- <note>]" and logs
finding.amended. The status never changes via amend.

--claim edits root_cause.description (that IS the claim text); --class is
checked against taxonomy.known_classes and rejects unknown classes.

positional arguments:
  campaign              campaign id
  finding               finding id

options:
  -h, --help            show this help message and exit
  --title TITLE         corrected title
  --class CLASS         corrected bug class (canonical only)
  --claim CLAIM         corrected claim text (root_cause.description)
  --note NOTE           note recorded in the history entry reason
  --actor ACTOR         actor recorded in history/event (default: model)
`

func runAmend(root string, args []string, r *Runner) int {
	return t14Dispatch(root, r, func() error { return amendCmd(root, args, r) })
}

func amendCmd(root string, args []string, r *Runner) error {
	var opts findings.AmendOpts
	actorSet := false
	var pos []string
	var posIdx []int
	var unknown []immunizeUnk
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-h" || a == "--help":
			// argparse's help action fires while parsing, before required
			// arguments are checked, and exits 0.
			fmt.Fprint(r.Out, amendHelp)
			return nil
		case a == "--title" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			opts.Title, opts.HasTitle = args[i+1], true
			i++
		case strings.HasPrefix(a, "--title="):
			opts.Title, opts.HasTitle = strings.TrimPrefix(a, "--title="), true
		case a == "--title":
			return t14ArgparseErr(amendUsage, "amend",
				"argument --title: expected one argument")
		case a == "--class" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			opts.Class, opts.HasClass = args[i+1], true
			i++
		case strings.HasPrefix(a, "--class="):
			opts.Class, opts.HasClass = strings.TrimPrefix(a, "--class="), true
		case a == "--class":
			return t14ArgparseErr(amendUsage, "amend",
				"argument --class: expected one argument")
		case a == "--claim" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			opts.Claim, opts.HasClaim = args[i+1], true
			i++
		case strings.HasPrefix(a, "--claim="):
			opts.Claim, opts.HasClaim = strings.TrimPrefix(a, "--claim="), true
		case a == "--claim":
			return t14ArgparseErr(amendUsage, "amend",
				"argument --claim: expected one argument")
		case a == "--note" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			opts.Note = args[i+1]
			i++
		case strings.HasPrefix(a, "--note="):
			opts.Note = strings.TrimPrefix(a, "--note=")
		case a == "--note":
			return t14ArgparseErr(amendUsage, "amend",
				"argument --note: expected one argument")
		case a == "--actor" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			opts.Actor = args[i+1]
			actorSet = true
			i++
		case strings.HasPrefix(a, "--actor="):
			opts.Actor = strings.TrimPrefix(a, "--actor=")
			actorSet = true
		case a == "--actor":
			return t14ArgparseErr(amendUsage, "amend",
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
		missing = append(missing, "finding")
	}
	if len(missing) > 0 {
		return t14ArgparseErr(amendUsage, "amend",
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
	if !opts.HasTitle && !opts.HasClass && !opts.HasClaim && opts.Note == "" {
		return t14ArgparseErr(amendUsage, "amend",
			"at least one of --title, --class, --claim, --note is required")
	}
	if !actorSet {
		opts.Actor = "model"
	}
	c, err := t14Open(root, pos[0])
	if err != nil {
		return err
	}
	// R3 (critic): a class amend that RAISES a filed finding's floor is the
	// conversion path the T6 advisory recommends — legal, but never silent:
	// name the new bar and the work it creates.
	oldClass, oldStatus := "", ""
	if pre, perr := findings.LoadFinding(c, pos[1]); perr == nil {
		oldClass = validation.ObjStr(validation.ObjAt(pre, "root_cause"), "class")
		oldStatus = validation.ObjStr(pre, "status")
	}
	f, err := findings.Amend(c, pos[1], opts)
	if err != nil {
		var rej *findings.RejectedError
		if errors.As(err, &rej) {
			return t14ExitErr(2, "amend failed: %s\n", err)
		}
		return err
	}
	fmt.Fprintf(r.Out, "amended %s: claim_version %s (%s)\n", pos[1],
		validation.IntText(validation.ObjAt(f, "claim_version")), amendKeysText(opts))
	if opts.HasClass && oldStatus == "CONFIRMED" {
		newClass := validation.ObjStr(validation.ObjAt(f, "root_cause"), "class")
		was := findings.RequiredLevelForCampaign(c, "CONFIRMED", oldClass)
		now := findings.RequiredLevelForCampaign(c, "CONFIRMED", newClass)
		if was != now {
			fmt.Fprintf(r.Err, "note: the CONFIRMED floor for this finding "+
				"moved %s -> %s with the class (status stands; the gate now "+
				"treats verification below %s as MANDATORY work — brief and "+
				"rank will show it)\n", was, now, now)
		}
	}
	return nil
}

// amendKeysText names the amended fields for the summary line.
func amendKeysText(opts findings.AmendOpts) string {
	var keys []string
	if opts.HasTitle {
		keys = append(keys, "title")
	}
	if opts.HasClass {
		keys = append(keys, "class")
	}
	if opts.HasClaim {
		keys = append(keys, "claim")
	}
	if len(keys) == 0 {
		keys = []string{"note"}
	}
	return strings.Join(keys, ", ")
}

func init() {
	register(command{ord: 77, name: "amend",
		line: "amend <campaign> <finding> [--title T] [--class C] [--claim K] [--note N]  correct a filed finding (bumps claim_version)",
		run:  runAmend})
}
