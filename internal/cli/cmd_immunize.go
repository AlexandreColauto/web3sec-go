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
	"sort"
	"strings"

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
	pocExec, patch, mutations, bypass, actor := "", "", "", "", ""
	havePOC, havePatch, haveMutations, haveBypass := false, false, false, false
	var pos []string
	var posIdx []int
	var unknown []immunizeUnk
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--poc-exec" && i+1 < len(args):
			pocExec, havePOC = args[i+1], true
			i++
		case strings.HasPrefix(a, "--poc-exec="):
			pocExec, havePOC = strings.TrimPrefix(a, "--poc-exec="), true
		case a == "--patch" && i+1 < len(args):
			patch, havePatch = args[i+1], true
			i++
		case strings.HasPrefix(a, "--patch="):
			patch, havePatch = strings.TrimPrefix(a, "--patch="), true
		case a == "--mutations" && i+1 < len(args):
			mutations, haveMutations = args[i+1], true
			i++
		case strings.HasPrefix(a, "--mutations="):
			mutations, haveMutations = strings.TrimPrefix(a, "--mutations="), true
		case a == "--bypass" && i+1 < len(args):
			bypass, haveBypass = args[i+1], true
			i++
		case strings.HasPrefix(a, "--bypass="):
			bypass, haveBypass = strings.TrimPrefix(a, "--bypass="), true
		case a == "--actor" && i+1 < len(args):
			actor = args[i+1]
			i++
		case strings.HasPrefix(a, "--actor="):
			actor = strings.TrimPrefix(a, "--actor=")
		case a == "--poc-exec":
			return t14ArgparseErr(t21ImmunizeUsage, "immunize",
				"argument --poc-exec: expected one argument")
		case a == "--patch":
			return t14ArgparseErr(t21ImmunizeUsage, "immunize",
				"argument --patch: expected one argument")
		case a == "--mutations":
			return t14ArgparseErr(t21ImmunizeUsage, "immunize",
				"argument --mutations: expected one argument")
		case a == "--bypass":
			return t14ArgparseErr(t21ImmunizeUsage, "immunize",
				"argument --bypass: expected one argument")
		case a == "--actor":
			return t14ArgparseErr(t21ImmunizeUsage, "immunize",
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
	if !havePOC {
		missing = append(missing, "--poc-exec")
	}
	if !havePatch {
		missing = append(missing, "--patch")
	}
	if !haveMutations {
		missing = append(missing, "--mutations")
	}
	if len(missing) > 0 {
		return t14ArgparseErr(t21ImmunizeUsage, "immunize",
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
	if actor == "" {
		actor = "cli" // args.actor or "cli"
	}
	// [m.strip() for m in args.mutations.split(";") if m.strip()]
	parsed := []string{}
	for _, m := range strings.Split(mutations, ";") {
		if s := strings.TrimSpace(m); s != "" {
			parsed = append(parsed, s)
		}
	}
	var bypassPtr *string
	if haveBypass {
		bypassPtr = &bypass
	}
	c, err := state.Open(root, pos[0])
	if err != nil {
		return err
	}
	o := immunize.Options{Patch: patch, POCExecID: pocExec,
		Mutations: parsed, Actor: actor, Bypass: bypassPtr}
	f, err := immunize.Immunize(c, pos[1], o)
	if err != nil {
		var ie *immunize.InputError
		if errors.As(err, &ie) {
			return t14ExitErr(2, "immunize failed: %s\n", err)
		}
		return err
	}
	pv := objAt(objAt(f, "verification"), "patch_verified")
	stateText := "BYPASS FOUND"
	if immunize.IsImmunized(f) {
		stateText = "IMMUNIZED"
	}
	fmt.Fprintf(r.Out, "%s: %s — patch blocks the fork PoC (%s) and %s "+
		"boundary mutations\n", pos[1], stateText, objStr(pv, "artifact_id"),
		scalarStr(objAt(pv, "boundary_mutations_tested")))
	if pyTruthyCLI(objAt(pv, "boundary_bypass_found")) {
		fmt.Fprintf(r.Out, "  BYPASS: %s — fix the patch and re-verify; the "+
			"bounty gate fails until it holds\n",
			truncateStr(objStr(pv, "bypass"), 80))
	}
	return nil
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
