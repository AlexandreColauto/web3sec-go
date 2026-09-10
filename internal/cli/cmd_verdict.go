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

func runVerdict(root string, args []string, r *Runner) int {
	if helpRequested(r.Out, "verdict", args) {
		return 0
	}

	ensureSeams()
	verdict, reason := "", ""
	outlook, outlookReason := "", ""
	haveVerdict, haveReason := false, false
	haveOutlook := false
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--verdict" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			verdict, haveVerdict = args[i+1], true
			i++
		case strings.HasPrefix(a, "--verdict="):
			verdict, haveVerdict = strings.TrimPrefix(a, "--verdict="), true
		case a == "--verdict":
			return r.fail(root, argErrf("verdict",
				"argument --verdict: expected one argument"))
		case a == "--reason" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			reason, haveReason = args[i+1], true
			i++
		case strings.HasPrefix(a, "--reason="):
			reason, haveReason = strings.TrimPrefix(a, "--reason="), true
		case a == "--reason":
			return r.fail(root, argErrf("verdict",
				"argument --reason: expected one argument"))
		case a == "--outlook" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			outlook, haveOutlook = args[i+1], true
			i++
		case strings.HasPrefix(a, "--outlook="):
			outlook, haveOutlook = strings.TrimPrefix(a, "--outlook="), true
		case a == "--outlook":
			return r.fail(root, argErrf("verdict",
				"argument --outlook: expected one argument"))
		case a == "--outlook-reason" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			outlookReason = args[i+1]
			i++
		case strings.HasPrefix(a, "--outlook-reason="):
			outlookReason = strings.TrimPrefix(a, "--outlook-reason=")
		case a == "--outlook-reason":
			return r.fail(root, argErrf("verdict",
				"argument --outlook-reason: expected one argument"))
		case strings.HasPrefix(a, "-"):
			return r.fail(root, usageErrf("unrecognized arguments: %s", a))
		default:
			pos = append(pos, a)
		}
		if haveVerdict && !containsStrCLI(criticVerdicts, verdict) {
			return r.fail(root, argErrf("verdict",
				"argument --verdict: invalid choice: %s (choose from %s)",
				validation.PyReprStr(verdict), quotedList(criticVerdicts)))
		}
		if haveOutlook && !containsStrCLI(triagerOutlooks, outlook) {
			return r.fail(root, argErrf("verdict",
				"argument --outlook: invalid choice: %s (choose from %s)",
				validation.PyReprStr(outlook), quotedList(triagerOutlooks)))
		}
	}
	if (outlook == "") != (outlookReason == "") {
		return r.fail(root, requiredErrf("verdict", "--outlook", "--outlook-reason"))
	}
	missing := []string{}
	if len(pos) < 1 {
		missing = append(missing, "campaign")
	}
	if len(pos) < 2 {
		missing = append(missing, "finding")
	}
	if !haveVerdict {
		missing = append(missing, "--verdict")
	}
	if !haveReason {
		missing = append(missing, "--reason")
	}
	if len(missing) > 0 {
		return r.fail(root, requiredErrf("verdict", missing...))
	}
	if len(pos) > 2 {
		return r.fail(root, usageErrf("unrecognized arguments: %s", pos[2]))
	}
	c, err := state.Open(root, pos[0])
	if err != nil {
		return r.withErr(root, func() error { return err })
	}
	if _, err := findings.SetCriticVerdict(c, pos[1], verdict, reason); err != nil {
		return r.withErr(root, func() error { return err })
	}
	fmt.Fprintf(r.Out, "critic verdict on %s: %s\n", pos[1], verdict)
	fmt.Fprintf(r.Out, "  reason: %s\n", reason)
	fmt.Fprintln(r.Out, "  (persisted in full at dedup_meta.critic_reasoning)")
	if outlook != "" {
		if _, err := findings.SetTriagerOutlook(c, pos[1], outlook, outlookReason); err != nil {
			return r.withErr(root, func() error { return err })
		}
		fmt.Fprintf(r.Out, "  triager outlook: %s — %s\n", outlook, outlookReason)
	}
	// B4 finding-side twin: the same dismissal-vocabulary scan over the
	// critic's reasoning. Advisory only — verdicts are human judgment, so
	// this warns and never blocks or fails.
	if hits := planner.DismissalHits(reason); len(hits) > 0 {
		fmt.Fprintf(r.Out, "  warning: reason uses dismissal vocabulary (%s) — "+
			"advisory only (B4); record the counter-argument or re-check "+
			"the row behind this verdict\n", strings.Join(hits, ", "))
	}
	return 0
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
