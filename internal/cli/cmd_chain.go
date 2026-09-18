package cli

// cmd_chain: `webv2 chain <campaign> <f> <f> [...] [--unproven] [--note NOTE]
// [--title TITLE]` — materialize a chain (IMPROVEMENTS B3).
//
// The default path is the hard gate every proven chain passes: every member
// CONFIRMED (or CHAIN), every member on one shared source pin, and a CHAIN
// super-finding is written. With --unproven the members may sit at any status
// (that is the point: a HYPOTHESIS freeze finding can already form a chain),
// the pin gate relaxes to "one shared pin, or all pinned to the active
// snapshot", every link is stamped with its member's evidence level, the
// chain doc is marked provenance "unproven", the event is
// chain.materialized_unproven — and NO super-finding is created, so nothing
// downstream can count a hypothesis-level chain as evidence-confirmed.
//
// Go-only verb (no Python twin): argparse semantics follow the house style
// (see cmd_exploit). A member set that fails the PROVEN gate exits 2 with the
// --unproven hint; a missing campaign/member is the generic handler (exit 1).

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"websec/internal/chainengine"
	"websec/internal/findings"
	"websec/internal/validation"
)

const chainUsage = `usage: webv2 chain [-h] [--unproven] [--note NOTE] [--title TITLE]
                   campaign member [member ...]
`

// chainHelp is the argparse-style help block. This verb is Go-only, so the
// prose is ours; the wrapping follows argparse's 80-column house style.
const chainHelp = chainUsage + `
materialize an exploit chain from two or more findings. Without --unproven
every member must be CONFIRMED (or a CHAIN super-finding) on one shared
source pin, and a CHAIN super-finding is written. With --unproven the chain
is materialized at HYPOTHESIS level: any member status, mixed source pins
allowed, each capability link stamped with its member's evidence level,
provenance "unproven", event chain.materialized_unproven — and NO
super-finding, so the result is a LEAD and is never counted as confirmed.

positional arguments:
  campaign              campaign id
  member                finding id (two or more; path order = argument order)

options:
  -h, --help            show this help message and exit
  --unproven            materialize at hypothesis level (lead, no evidence)
  --note NOTE           note recorded as the chain narrative
  --title TITLE         chain title (default: the member path)
`

func runChain(root string, args []string, r *Runner) int {
	return t14Dispatch(root, r, func() error { return chainCmd(root, args, r) })
}

// chainArgs carries the parsed argv of the chain verb.
type chainArgs struct {
	unproven bool
	note     string
	title    string
	pos      []string
	unknown  []immunizeUnk
	helpSeen bool
}

// chainParseArgs parses the flag loop, printing the help block and flagging
// it when -h/--help appears mid-argv.
func chainParseArgs(args []string, r *Runner) (*chainArgs, error) {
	pa := &chainArgs{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-h" || a == "--help":
			// argparse's help action fires while parsing, before required
			// arguments are checked, and exits 0.
			fmt.Fprint(r.Out, chainHelp)
			pa.helpSeen = true
			return pa, nil
		case a == "--unproven":
			pa.unproven = true
		case strings.HasPrefix(a, "--unproven="):
			// store_true takes no value.
			return nil, t14ArgparseErr(chainUsage, "chain",
				"argument --unproven: ignored explicit argument %s",
				validation.PyReprStr(strings.TrimPrefix(a, "--unproven=")))
		case a == "--note" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			pa.note = args[i+1]
			i++
		case strings.HasPrefix(a, "--note="):
			pa.note = strings.TrimPrefix(a, "--note=")
		case a == "--note":
			return nil, t14ArgparseErr(chainUsage, "chain",
				"argument --note: expected one argument")
		case a == "--title" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			pa.title = args[i+1]
			i++
		case strings.HasPrefix(a, "--title="):
			pa.title = strings.TrimPrefix(a, "--title=")
		case a == "--title":
			return nil, t14ArgparseErr(chainUsage, "chain",
				"argument --title: expected one argument")
		case strings.HasPrefix(a, "-"):
			pa.unknown = append(pa.unknown, immunizeUnk{i, a})
		default:
			pa.pos = append(pa.pos, a)
		}
	}
	return pa, nil
}

// chainCheckArgs applies argparse's post-loop checks in its own order:
// required arguments, then the unknown flags.
func chainCheckArgs(pa *chainArgs) error {
	// argparse checks the subparser's required arguments before the root
	// parser's "unrecognized arguments" (parse_known_args).
	missing := []string{}
	if len(pa.pos) < 1 {
		missing = append(missing, "campaign")
	}
	if len(pa.pos) < 2 {
		missing = append(missing, "member")
	}
	if len(missing) > 0 {
		return t14ArgparseErr(chainUsage, "chain",
			"the following arguments are required: %s", strings.Join(missing, ", "))
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

// chainMaterialize opens the campaign, materializes the chain and prints the
// result line.
func chainMaterialize(root string, pa *chainArgs, r *Runner) error {
	c, err := t14Open(root, pa.pos[0])
	if err != nil {
		return err
	}
	members := pa.pos[1:]
	if pa.title == "" {
		// The chain schema wants a titled chain (>= 10 runes); the member
		// path is the deterministic default (two F- ids are 29+ runes), and
		// it is what the report heading and the `chains` row already show.
		pa.title = strings.Join(members, " -> ")
	}
	doc, err := chainengine.MaterializeChainOpts(c, members, pa.title, pa.note, nil,
		nil, chainengine.MaterializeOpts{Unproven: pa.unproven})
	if err != nil {
		var it *findings.IllegalTransition
		if errors.As(err, &it) && !pa.unproven {
			return t14ExitErr(2, "chain failed: %s — pass --unproven to "+
				"materialize a hypothesis-level chain\n", err)
		}
		return err
	}
	kind := "chain"
	if pa.unproven {
		kind = "unproven chain"
	}
	line := fmt.Sprintf("%s: %s materialized from %d members (evidence floor %s)",
		validation.ObjStr(doc, "chain_id"), kind, len(members),
		validation.ObjStr(doc, "evidence_floor"))
	if t := validation.ObjAt(doc, "terminal"); t.Kind == validation.Obj {
		line += fmt.Sprintf(", terminal %s via %s", validation.ObjStr(t, "capability"),
			validation.ObjStr(t, "via_finding"))
	}
	if pa.unproven {
		line += ", no super-finding (hypothesis-level)"
	}
	fmt.Fprintln(r.Out, line)
	return nil
}

func chainCmd(root string, args []string, r *Runner) error {
	pa, err := chainParseArgs(args, r)
	if err != nil {
		return err
	}
	if pa.helpSeen {
		return nil
	}
	if err := chainCheckArgs(pa); err != nil {
		return err
	}
	return chainMaterialize(root, pa, r)
}

func init() {
	register(command{ord: 72, name: "chain",
		line: "chain <campaign> <f> <f> [...]    materialize a chain (--unproven: hypothesis-level)",
		run:  runChain})
}
