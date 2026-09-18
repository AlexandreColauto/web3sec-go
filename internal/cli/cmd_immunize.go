package cli

// cmd_immunize: `webv2 immunize <campaign> <finding> --poc-exec EXEC
// --patch PATCH --mutations M1;M2;M3 [--bypass B] [--actor A]` — the
// patch-verification step: the patch must BLOCK the finding's mainnet FORK
// PoC and all 3 boundary mutations (cli.py cmd_immunize verbatim).
//
// Error taxonomy: Python catches (ValueError, KeyError) and exits 2 with
// `immunize failed: {e}`. A missing FINDING is a FileNotFoundError, so it
// falls through to main's handler (exit 1).

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"websec/internal/validation"

	"websec/internal/immunize"
	"websec/internal/state"
)

const t21ImmunizeUsage = `usage: webv2 immunize [-h] --poc-exec POC_EXEC --patch PATCH
                      --mutations MUTATIONS [--bypass BYPASS] [--actor ACTOR]
                      campaign finding
`

// immunizeUnk is one unrecognized argv token with its position: argparse
// reports them in ARGV order.
type immunizeUnk struct {
	idx int
	tok string
}

func runImmunize(root string, args []string, r *Runner) int {
	return t14Dispatch(root, r, func() error { return immunizeCmd(root, args, r) })
}

func immunizeCmd(root string, args []string, r *Runner) error {
	if helpRequested(r.Out, "immunize", args) {
		return nil
	}

	ensureSeams()
	fl, err := immunizeParseFlags(args)
	if err != nil {
		return err
	}
	if err := immunizeRequireArgs(fl); err != nil {
		return err
	}
	o := immunizeBuildOptions(fl)
	c, err := state.Open(root, fl.pos[0])
	if err != nil {
		return err
	}
	fnd, err := immunize.Immunize(c, fl.pos[1], o)
	if err != nil {
		var ie *immunize.InputError
		if errors.As(err, &ie) {
			return t14ExitErr(2, "immunize failed: %s\n", err)
		}
		return err
	}
	immunizePrintResult(r.Out, fl.pos[1], fnd)
	return nil
}

// immunizeFlags carries the parsed `immunize` command line: the flag values,
// their presence bits, and the positional/unknown tokens still to be checked.
type immunizeFlags struct {
	pocExec       string
	patch         string
	mutations     string
	bypass        string
	actor         string
	havePOC       bool
	havePatch     bool
	haveMutations bool
	haveBypass    bool
	pos           []string
	posIdx        []int
	unknown       []immunizeUnk
}

// immunizeParseFlags scans the raw arguments with cli.py's hand-rolled loop.
func immunizeParseFlags(args []string) (*immunizeFlags, error) {
	fl := &immunizeFlags{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--poc-exec" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			fl.pocExec, fl.havePOC = args[i+1], true
			i++
		case strings.HasPrefix(a, "--poc-exec="):
			fl.pocExec, fl.havePOC = strings.TrimPrefix(a, "--poc-exec="), true
		case a == "--patch" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			fl.patch, fl.havePatch = args[i+1], true
			i++
		case strings.HasPrefix(a, "--patch="):
			fl.patch, fl.havePatch = strings.TrimPrefix(a, "--patch="), true
		case a == "--mutations" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			fl.mutations, fl.haveMutations = args[i+1], true
			i++
		case strings.HasPrefix(a, "--mutations="):
			fl.mutations, fl.haveMutations = strings.TrimPrefix(a, "--mutations="), true
		case a == "--bypass" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			fl.bypass, fl.haveBypass = args[i+1], true
			i++
		case strings.HasPrefix(a, "--bypass="):
			fl.bypass, fl.haveBypass = strings.TrimPrefix(a, "--bypass="), true
		case a == "--actor" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			fl.actor = args[i+1]
			i++
		case strings.HasPrefix(a, "--actor="):
			fl.actor = strings.TrimPrefix(a, "--actor=")
		case a == "--poc-exec":
			return nil, t14ArgparseErr(t21ImmunizeUsage, "immunize",
				"argument --poc-exec: expected one argument")
		case a == "--patch":
			return nil, t14ArgparseErr(t21ImmunizeUsage, "immunize",
				"argument --patch: expected one argument")
		case a == "--mutations":
			return nil, t14ArgparseErr(t21ImmunizeUsage, "immunize",
				"argument --mutations: expected one argument")
		case a == "--bypass":
			return nil, t14ArgparseErr(t21ImmunizeUsage, "immunize",
				"argument --bypass: expected one argument")
		case a == "--actor":
			return nil, t14ArgparseErr(t21ImmunizeUsage, "immunize",
				"argument --actor: expected one argument")
		case strings.HasPrefix(a, "-"):
			fl.unknown = append(fl.unknown, immunizeUnk{i, a})
		default:
			fl.pos = append(fl.pos, a)
			fl.posIdx = append(fl.posIdx, i)
		}
	}
	return fl, nil
}

// immunizeRequireArgs enforces the required positionals and flags, then
// reports the remaining unknown tokens in ARGV order.
func immunizeRequireArgs(fl *immunizeFlags) error {
	// argparse checks the subparser's required arguments BEFORE the root
	// parser's "unrecognized arguments" (parse_known_args).
	missing := []string{}
	if len(fl.pos) < 1 {
		missing = append(missing, "campaign")
	}
	if len(fl.pos) < 2 {
		missing = append(missing, "finding")
	}
	if !fl.havePOC {
		missing = append(missing, "--poc-exec")
	}
	if !fl.havePatch {
		missing = append(missing, "--patch")
	}
	if !fl.haveMutations {
		missing = append(missing, "--mutations")
	}
	if len(missing) > 0 {
		return t14ArgparseErr(t21ImmunizeUsage, "immunize",
			"the following arguments are required: %s", strings.Join(missing, ", "))
	}
	// Positionals are assigned greedily; the overflow is unrecognized.
	if len(fl.pos) > 2 {
		for j, t := range fl.pos[2:] {
			fl.unknown = append(fl.unknown, immunizeUnk{fl.posIdx[2+j], t})
		}
		fl.pos = fl.pos[:2]
	}
	if len(fl.unknown) > 0 {
		sort.Slice(fl.unknown, func(i, j int) bool {
			return fl.unknown[i].idx < fl.unknown[j].idx
		})
		toks := make([]string, len(fl.unknown))
		for i, u := range fl.unknown {
			toks[i] = u.tok
		}
		return t14Unrecognized(strings.Join(toks, " "))
	}
	return nil
}

// immunizeBuildOptions applies the actor default and turns the parsed flags
// into the library's Options (mutations split, bypass pointer).
func immunizeBuildOptions(fl *immunizeFlags) immunize.Options {
	if fl.actor == "" {
		fl.actor = "cli" // args.actor or "cli"
	}
	// [m.strip() for m in args.mutations.split(";") if m.strip()]
	parsed := []string{}
	for _, m := range strings.Split(fl.mutations, ";") {
		if s := strings.TrimSpace(m); s != "" {
			parsed = append(parsed, s)
		}
	}
	var bypassPtr *string
	if fl.haveBypass {
		bypassPtr = &fl.bypass
	}
	return immunize.Options{Patch: fl.patch, POCExecID: fl.pocExec,
		Mutations: parsed, Actor: fl.actor, Bypass: bypassPtr}
}

// immunizePrintResult writes the patch-verification outcome and, when a
// bypass was found, the repair instruction.
func immunizePrintResult(out io.Writer, findingID string, f validation.Value) {
	pv := validation.ObjAt(validation.ObjAt(f, "verification"), "patch_verified")
	stateText := "BYPASS FOUND"
	if immunize.IsImmunized(f) {
		stateText = "IMMUNIZED"
	}
	fmt.Fprintf(out, "%s: %s — patch blocks the fork PoC (%s) and %s "+
		"boundary mutations\n", findingID, stateText, validation.ObjStr(pv, "artifact_id"),
		scalarStr(validation.ObjAt(pv, "boundary_mutations_tested")))
	if pyTruthyCLI(validation.ObjAt(pv, "boundary_bypass_found")) {
		fmt.Fprintf(out, "  BYPASS: %s — fix the patch and re-verify; the "+
			"bounty gate fails until it holds\n",
			truncateStr(validation.ObjStr(pv, "bypass"), 80))
	}
}

// truncateStr is Python's s[:n].
func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func init() {
	register(command{ord: 63, name: "immunize",
		line: "immunize <campaign> <f>  verify the patch blocks the FORK PoC",
		run:  runImmunize})
}
