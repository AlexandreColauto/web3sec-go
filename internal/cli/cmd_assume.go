package cli

// cmd_assume: `webv2 assume <campaign> <finding> <assumption_id> --status S
// [--ref R] [--actor A]` — the operator half of the assumption ladder
// (R3-4, Morph r3 defect 4). The library (findings.AssumptionTransition) has
// always moved assumption status honestly: only the three enum statuses,
// only along legal edges, and every move off UNKNOWN must cite refs that
// RESOLVE IN THE STORE (an evidence item of this finding, a registered
// artifact, or an EXEC record) — a hallucinated citation is a rejection,
// never a warning. What was missing was the VERB: with no CLI surface, a
// refuted blocking assumption could only be narrated. This file adds no
// policy: every refusal is the library's, printed in the move-style
// `assume failed:` handler class.

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// assumeUsage is the verb's pinned usage block (argparse shape, COLUMNS=80;
// this verb is Go-only — the retired twin never had it — so the rendering is
// ours to pin, and this test pins it byte-for-byte).
const assumeUsage = `usage: webv2 assume [-h] --status STATUS [--ref REF] [--actor ACTOR]
                    campaign finding assumption_id
`

// assumptionStatuses is the finding schema's status enum, in schema order —
// the same order the invalid-choice message enumerates.
var assumptionStatuses = []string{"UNKNOWN", "SUPPORTED", "REFUTED"}

// storeRefusalMarker names the evidence-store rejection raised by
// findings.resolveEvidenceRef through AssumptionTransition. The store
// refusal is a refusal of the MOVE (the caller cited a ghost), so the CLI
// prints it in the handler class at exit 2 — while a ghost FINDING or
// ASSUMPTION id stays a plain error at exit 1, exactly like `move` treats a
// finding that does not exist. Text-matched because the library exports no
// sentinel; cmd_assume_test.go pins the full bytes both sides.
const storeRefusalMarker = "does not exist in the campaign evidence store"

func runAssume(root string, args []string, r *Runner) int {
	return t14Dispatch(root, r, func() error { return assumeCmd(root, args, r) })
}

// assumeFlags carries the parsed `assume` command line.
type assumeFlags struct {
	status     string
	refs       []string
	actor      string
	haveStatus bool
	pos        []string
	posIdx     []int
	unknown    []assumeUnk
}

// assumeUnk is one unrecognized argv token with its position.
type assumeUnk struct {
	idx int
	tok string
}

func assumeCmd(root string, args []string, r *Runner) error {
	if helpRequested(r.Out, "assume", args) {
		return nil
	}
	ensureSeams()
	af, err := assumeParseFlags(args)
	if err != nil {
		return err
	}
	if err := assumeRequireArgs(af); err != nil {
		return err
	}
	return assumeApply(root, af, r)
}

// assumeParseFlags scans the raw arguments with the house hand-rolled loop:
// guarded values, --flag=value forms, --ref repeatable.
func assumeParseFlags(args []string) (*assumeFlags, error) {
	af := &assumeFlags{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--status":
			v, ok := flagValue(args, i)
			if !ok {
				return nil, t14ArgparseErr(assumeUsage, "assume",
					"argument --status: expected one argument")
			}
			af.status, af.haveStatus = v, true
			i++
		case strings.HasPrefix(a, "--status="):
			af.status, af.haveStatus = strings.TrimPrefix(a, "--status="), true
		case a == "--ref":
			v, ok := flagValue(args, i)
			if !ok {
				return nil, t14ArgparseErr(assumeUsage, "assume",
					"argument --ref: expected one argument")
			}
			af.refs = append(af.refs, v)
			i++
		case strings.HasPrefix(a, "--ref="):
			af.refs = append(af.refs, strings.TrimPrefix(a, "--ref="))
		case a == "--actor":
			v, ok := flagValue(args, i)
			if !ok {
				return nil, t14ArgparseErr(assumeUsage, "assume",
					"argument --actor: expected one argument")
			}
			af.actor = v
			i++
		case strings.HasPrefix(a, "--actor="):
			af.actor = strings.TrimPrefix(a, "--actor=")
		case strings.HasPrefix(a, "-"):
			return nil, t14Unrecognized(a)
		default:
			af.pos = append(af.pos, a)
			af.posIdx = append(af.posIdx, i)
		}
	}
	// --status is uppercased ONCE, here, so the library's table and the
	// printed line share one spelling (schema enums are uppercase) — but
	// the refusal names what the operator TYPED, like argparse does.
	if af.haveStatus {
		up := strings.ToUpper(af.status)
		if !containsStrCLI(assumptionStatuses, up) {
			return nil, t14ArgparseErr(assumeUsage, "assume",
				"argument --status: invalid choice: %s (choose from %s)",
				validation.PyReprStr(af.status),
				quotedList(assumptionStatuses))
		}
		af.status = up
	}
	return af, nil
}

// assumeRequireArgs fills the positional trio, then the required-flag, in
// argparse's order (positionals are declared first).
func assumeRequireArgs(af *assumeFlags) error {
	var missing []string
	if len(af.pos) < 3 {
		for _, n := range []string{"campaign", "finding", "assumption_id"}[len(af.pos):] {
			missing = append(missing, n)
		}
	}
	if !af.haveStatus {
		missing = append(missing, "--status")
	}
	if len(missing) > 0 {
		return t14ArgparseErr(assumeUsage, "assume",
			"the following arguments are required: %s",
			strings.Join(missing, ", "))
	}
	// Positionals are assigned greedily; the overflow is unrecognized.
	if len(af.pos) > 3 {
		for j, t := range af.pos[3:] {
			af.unknown = append(af.unknown, assumeUnk{af.posIdx[3+j], t})
		}
		af.pos = af.pos[:3]
	}
	if len(af.unknown) > 0 {
		sort.Slice(af.unknown, func(i, j int) bool {
			return af.unknown[i].idx < af.unknown[j].idx
		})
		toks := make([]string, len(af.unknown))
		for i, u := range af.unknown {
			toks[i] = u.tok
		}
		return t14Unrecognized(strings.Join(toks, " "))
	}
	if af.actor == "" {
		af.actor = "cli" // the move default: an unattributed CLI actor is a lie
	}
	return nil
}

// assumeApply opens the campaign, reads the assumption's current status for
// the printed line (the same read the library does first — no second source
// of truth for FROM), then performs the transition.
func assumeApply(root string, af *assumeFlags, r *Runner) error {
	c, err := state.Open(root, af.pos[0])
	if err != nil {
		return err
	}
	finding, err := findings.LoadFinding(c, af.pos[1])
	if err != nil {
		return err
	}
	fromStatus := ""
	for _, a := range validation.ObjAt(finding, "assumptions").A {
		if validation.ObjStr(a, "id") == af.pos[2] {
			fromStatus = validation.ObjStr(a, "status")
			break
		}
	}
	if _, err := findings.AssumptionTransition(c, af.pos[1], af.pos[2],
		af.status, af.refs, af.actor); err != nil {
		if assumeHandlerError(err) {
			return t14ExitErr(2, "assume failed: %s\n", err)
		}
		return err
	}
	fmt.Fprintf(r.Out, "assumption %s: %s -> %s (evidence: %s)\n",
		af.pos[2], fromStatus, af.status, strings.Join(af.refs, ", "))
	return nil
}

// assumeHandlerError is the move-style handler class: IllegalTransition
// (bad status enum, illegal edge, no-refs, the re-open provenance rule) and
// the evidence-store rejection print `assume failed:` at exit 2. Everything
// else — a ghost campaign/finding/assumption id, an unwritable ledger —
// stays main's `error:` line at exit 1.
func assumeHandlerError(err error) bool {
	var it *findings.IllegalTransition
	if errors.As(err, &it) {
		return true
	}
	return strings.Contains(err.Error(), storeRefusalMarker)
}

func init() {
	register(command{ord: 92, name: "assume",
		line: `assume <campaign> <finding> <assumption_id> --status S [--ref R]  set an assumption's status against the store`,
		run:  runAssume})
}
