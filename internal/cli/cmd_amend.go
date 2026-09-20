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

// amendArgs carries the parsed argv of the amend verb.
type amendArgs struct {
	opts     findings.AmendOpts
	actorSet bool
	pos      []string
	posIdx   []int
	unknown  []immunizeUnk
	helpSeen bool
}

// amendParseArgs parses the flag loop, printing the help block and flagging
// it when -h/--help appears mid-argv.
func amendParseArgs(args []string, r *Runner) (*amendArgs, error) {
	pa := &amendArgs{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-h" || a == "--help":
			// argparse's help action fires while parsing, before required
			// arguments are checked, and exits 0.
			fmt.Fprint(r.Out, amendHelp)
			pa.helpSeen = true
			return pa, nil
		case a == "--title" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			pa.opts.Title, pa.opts.HasTitle = args[i+1], true
			i++
		case strings.HasPrefix(a, "--title="):
			pa.opts.Title, pa.opts.HasTitle = strings.TrimPrefix(a, "--title="), true
		case a == "--title":
			return nil, t14ArgparseErr(amendUsage, "amend",
				"argument --title: expected one argument")
		case a == "--class" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			pa.opts.Class, pa.opts.HasClass = args[i+1], true
			i++
		case strings.HasPrefix(a, "--class="):
			pa.opts.Class, pa.opts.HasClass = strings.TrimPrefix(a, "--class="), true
		case a == "--class":
			return nil, t14ArgparseErr(amendUsage, "amend",
				"argument --class: expected one argument")
		case a == "--claim" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			pa.opts.Claim, pa.opts.HasClaim = args[i+1], true
			i++
		case strings.HasPrefix(a, "--claim="):
			pa.opts.Claim, pa.opts.HasClaim = strings.TrimPrefix(a, "--claim="), true
		case a == "--claim":
			return nil, t14ArgparseErr(amendUsage, "amend",
				"argument --claim: expected one argument")
		case a == "--note" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			pa.opts.Note = args[i+1]
			i++
		case strings.HasPrefix(a, "--note="):
			pa.opts.Note = strings.TrimPrefix(a, "--note=")
		case a == "--note":
			return nil, t14ArgparseErr(amendUsage, "amend",
				"argument --note: expected one argument")
		case a == "--actor" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			pa.opts.Actor = args[i+1]
			pa.actorSet = true
			i++
		case strings.HasPrefix(a, "--actor="):
			pa.opts.Actor = strings.TrimPrefix(a, "--actor=")
			pa.actorSet = true
		case a == "--actor":
			return nil, t14ArgparseErr(amendUsage, "amend",
				"argument --actor: expected one argument")
		case strings.HasPrefix(a, "-"):
			pa.unknown = append(pa.unknown, immunizeUnk{i, a})
		default:
			pa.pos = append(pa.pos, a)
			pa.posIdx = append(pa.posIdx, i)
		}
	}
	return pa, nil
}

// amendCheckArgs applies argparse's post-loop checks in its own order:
// required arguments, the positional overflow, the unknown flags, then the
// at-least-one-field rule.
func amendCheckArgs(pa *amendArgs) error {
	// argparse checks the subparser's required arguments BEFORE the root
	// parser's "unrecognized arguments" (parse_known_args).
	missing := []string{}
	if len(pa.pos) < 1 {
		missing = append(missing, "campaign")
	}
	if len(pa.pos) < 2 {
		missing = append(missing, "finding")
	}
	if len(missing) > 0 {
		return t14ArgparseErr(amendUsage, "amend",
			"the following arguments are required: %s", strings.Join(missing, ", "))
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
	if !pa.opts.HasTitle && !pa.opts.HasClass && !pa.opts.HasClaim && pa.opts.Note == "" {
		return t14ArgparseErr(amendUsage, "amend",
			"at least one of --title, --class, --claim, --note is required")
	}
	return nil
}

// amendApply opens the campaign, applies the amend and prints the summary
// line plus the CONFIRMED-floor note.
func amendApply(root string, pa *amendArgs, r *Runner) error {
	if !pa.actorSet {
		pa.opts.Actor = "model"
	}
	c, err := t14Open(root, pa.pos[0])
	if err != nil {
		return err
	}
	// R3 (critic): a class amend that RAISES a filed finding's floor is the
	// conversion path the T6 advisory recommends — legal, but never silent:
	// name the new bar and the work it creates.
	oldClass, oldStatus, oldVerdict := "", "", ""
	oldClaim := "0"
	if pre, perr := findings.LoadFinding(c, pa.pos[1]); perr == nil {
		oldClass = validation.ObjStr(validation.ObjAt(pre, "root_cause"), "class")
		oldStatus = validation.ObjStr(pre, "status")
		oldVerdict = validation.ObjStr(
			validation.ObjAt(pre, "verification"), "critic_verdict")
		if v := validation.ObjAt(pre, "claim_version"); v.Kind == validation.Int {
			oldClaim = validation.IntText(v)
		}
	}
	f, err := findings.Amend(c, pa.pos[1], pa.opts)
	if err != nil {
		var rej *findings.RejectedError
		if errors.As(err, &rej) {
			return t14ExitErr(2, "amend failed: %s\n", err)
		}
		return err
	}
	fmt.Fprintf(r.Out, "amended %s: claim_version %s (%s)\n", pa.pos[1],
		validation.IntText(validation.ObjAt(f, "claim_version")), amendKeysText(pa.opts))
	if pa.opts.HasClass && oldStatus == "CONFIRMED" {
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
	// R3-9a: the verdict twin of the floor note. Every successful amend
	// bumps claim_version (findings.Amend's law — even a same-bytes
	// note-only amend), and the boundary critic refuses a verdict pinned
	// to an older claim; a recorded verdict therefore silently goes stale
	// the moment the claim is amended. Silence is the lie; say it, once,
	// with the version it pinned and the verb that re-attests.
	if oldVerdict != "" {
		fmt.Fprintf(r.Err, "note: the critic verdict pinned claim version "+
			"%s — re-run webv2 verdict to re-attest\n", oldClaim)
	}
	return nil
}

func amendCmd(root string, args []string, r *Runner) error {
	pa, err := amendParseArgs(args, r)
	if err != nil {
		return err
	}
	if pa.helpSeen {
		return nil
	}
	if err := amendCheckArgs(pa); err != nil {
		return err
	}
	return amendApply(root, pa, r)
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
