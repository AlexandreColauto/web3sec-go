package cli

// cmd_verdict: `webv2 verdict <campaign> <finding> --verdict V --reason R` —
// record the hostile-critic verdict with its reasoning (cli.py cmd_verdict
// verbatim: the FULL reasoning is printed — it is persisted in full at
// dedup_meta.critic_reasoning, so truncating the console line would read as
// data loss).

import (
	"fmt"
	"strings"

	"websec/internal/findings"
	"websec/internal/planner"
	"websec/internal/state"
	"websec/internal/validation"
)

var criticVerdicts = []string{"pending", "confirmed", "possible", "disproved",
	"duplicate", "out_of_scope", "informational"}

// triagerOutlooks is the G6 outlook enum: TriagerOutlooks is the SINGLE
// source — never a second hardcoded list.
var triagerOutlooks = findings.TriagerOutlooks()

// verdictArgs carries the parsed flags and positionals of runVerdict.
type verdictArgs struct {
	verdict, reason         string
	outlook, outlookReason  string
	haveVerdict, haveReason bool
	haveOutlook             bool
	pos                     []string
}

// verdictParseFlags is the argparse token scan of runVerdict; a parse
// failure returns the exit code, 0 on success.
func (v *verdictArgs) parseFlags(args []string, root string, r *Runner) int {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--verdict" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			v.verdict, v.haveVerdict = args[i+1], true
			i++
		case strings.HasPrefix(a, "--verdict="):
			v.verdict, v.haveVerdict = strings.TrimPrefix(a, "--verdict="), true
		case a == "--verdict":
			return r.fail(root, argErrf("verdict",
				"argument --verdict: expected one argument"))
		case a == "--reason" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			v.reason, v.haveReason = args[i+1], true
			i++
		case strings.HasPrefix(a, "--reason="):
			v.reason, v.haveReason = strings.TrimPrefix(a, "--reason="), true
		case a == "--reason":
			return r.fail(root, argErrf("verdict",
				"argument --reason: expected one argument"))
		case a == "--outlook" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			v.outlook, v.haveOutlook = args[i+1], true
			i++
		case strings.HasPrefix(a, "--outlook="):
			v.outlook, v.haveOutlook = strings.TrimPrefix(a, "--outlook="), true
		case a == "--outlook":
			return r.fail(root, argErrf("verdict",
				"argument --outlook: expected one argument"))
		case a == "--outlook-reason" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			v.outlookReason = args[i+1]
			i++
		case strings.HasPrefix(a, "--outlook-reason="):
			v.outlookReason = strings.TrimPrefix(a, "--outlook-reason=")
		case a == "--outlook-reason":
			return r.fail(root, argErrf("verdict",
				"argument --outlook-reason: expected one argument"))
		case strings.HasPrefix(a, "-"):
			return r.fail(root, usageErrf("unrecognized arguments: %s", a))
		default:
			v.pos = append(v.pos, a)
		}
		if v.haveVerdict && !containsStrCLI(criticVerdicts, v.verdict) {
			return r.fail(root, argErrf("verdict",
				"argument --verdict: invalid choice: %s (choose from %s)",
				validation.PyReprStr(v.verdict), quotedList(criticVerdicts)))
		}
		if v.haveOutlook && !containsStrCLI(triagerOutlooks, v.outlook) {
			return r.fail(root, argErrf("verdict",
				"argument --outlook: invalid choice: %s (choose from %s)",
				validation.PyReprStr(v.outlook), quotedList(triagerOutlooks)))
		}
	}
	return 0
}

// verdictCheckRequired is argparse's pairing / required-arguments / overflow
// check; a failure returns the exit code, 0 on success.
func (v *verdictArgs) checkRequired(root string, r *Runner) int {
	if (v.outlook == "") != (v.outlookReason == "") {
		return r.fail(root, requiredErrf("verdict", "--outlook", "--outlook-reason"))
	}
	missing := []string{}
	if len(v.pos) < 1 {
		missing = append(missing, "campaign")
	}
	if len(v.pos) < 2 {
		missing = append(missing, "finding")
	}
	if !v.haveVerdict {
		missing = append(missing, "--verdict")
	}
	if !v.haveReason {
		missing = append(missing, "--reason")
	}
	if len(missing) > 0 {
		return r.fail(root, requiredErrf("verdict", missing...))
	}
	if len(v.pos) > 2 {
		return r.fail(root, usageErrf("unrecognized arguments: %s", v.pos[2]))
	}
	return 0
}

// verdictRun opens the campaign, records the verdict (and the optional
// triager outlook) and prints the confirmation.
func (v *verdictArgs) run(root string, r *Runner) int {
	c, err := state.Open(root, v.pos[0])
	if err != nil {
		return r.withErr(root, func() error { return err })
	}
	if _, err := findings.SetCriticVerdict(c, v.pos[1], v.verdict, v.reason); err != nil {
		return r.withErr(root, func() error { return err })
	}
	fmt.Fprintf(r.Out, "critic verdict on %s: %s\n", v.pos[1], v.verdict)
	fmt.Fprintf(r.Out, "  reason: %s\n", v.reason)
	fmt.Fprintln(r.Out, "  (persisted in full at dedup_meta.critic_reasoning)")
	if v.outlook != "" {
		if _, err := findings.SetTriagerOutlook(c, v.pos[1], v.outlook, v.outlookReason); err != nil {
			return r.withErr(root, func() error { return err })
		}
		fmt.Fprintf(r.Out, "  triager outlook: %s — %s\n", v.outlook, v.outlookReason)
	}
	// B4 finding-side twin: the same dismissal-vocabulary scan over the
	// critic's reasoning. Advisory only — verdicts are human judgment, so
	// this warns and never blocks or fails.
	if hits := planner.DismissalHits(v.reason); len(hits) > 0 {
		fmt.Fprintf(r.Out, "  warning: reason uses dismissal vocabulary (%s) — "+
			"advisory only (B4); record the counter-argument or re-check "+
			"the row behind this verdict\n", strings.Join(hits, ", "))
	}
	return 0
}

func runVerdict(root string, args []string, r *Runner) int {
	if helpRequested(r.Out, "verdict", args) {
		return 0
	}

	ensureSeams()
	v := &verdictArgs{}
	if code := v.parseFlags(args, root, r); code != 0 {
		return code
	}
	if code := v.checkRequired(root, r); code != 0 {
		return code
	}
	return v.run(root, r)
}

// quotedList is Python's "', '".join(repr choices): 'a', 'b', 'c'.
func quotedList(items []string) string {
	parts := make([]string, 0, len(items))
	for _, it := range items {
		parts = append(parts, validation.PyReprStr(it))
	}
	return strings.Join(parts, ", ")
}

func init() {
	register(command{ord: 45, name: "verdict",
		line: "verdict <campaign> <finding> --verdict V --reason R [--outlook O --outlook-reason R]",
		run:  runVerdict})
}
