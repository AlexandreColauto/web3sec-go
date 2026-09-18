package cli

// cmd_waive: `webv2 waive <campaign> <stage> --reason R --actor A
// [--subject S]` — waive a completion-proof subject ('*' = the whole stage).
// Named actor, written reason, append-only, logged (cli.py cmd_waive
// verbatim; --subject omitted means '*').

import (
	"fmt"
	"sort"
	"strings"

	"websec/internal/completion"
	"websec/internal/state"
	"websec/internal/validation"
)

func runWaive(root string, args []string, r *Runner) int {
	if helpRequested(r.Out, "waive", args) {
		return 0
	}

	ensureSeams()
	subject, reason, actor := "", "", ""
	haveReason, haveActor := false, false
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--subject" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			subject = args[i+1]
			i++
		case strings.HasPrefix(a, "--subject="):
			subject = strings.TrimPrefix(a, "--subject=")
		case a == "--subject":
			return r.fail(root, argErrf("waive",
				"argument --subject: expected one argument"))
		case a == "--reason" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			reason, haveReason = args[i+1], true
			i++
		case strings.HasPrefix(a, "--reason="):
			reason, haveReason = strings.TrimPrefix(a, "--reason="), true
		case a == "--reason":
			return r.fail(root, argErrf("waive",
				"argument --reason: expected one argument"))
		case a == "--actor" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			actor, haveActor = args[i+1], true
			i++
		case strings.HasPrefix(a, "--actor="):
			actor, haveActor = strings.TrimPrefix(a, "--actor="), true
		case a == "--actor":
			return r.fail(root, argErrf("waive",
				"argument --actor: expected one argument"))
		case strings.HasPrefix(a, "-"):
			return r.fail(root, usageErrf("unrecognized arguments: %s", a))
		default:
			pos = append(pos, a)
		}
	}
	missing := []string{}
	if len(pos) < 1 {
		missing = append(missing, "campaign")
	}
	if len(pos) < 2 {
		missing = append(missing, "stage")
	}
	if !haveReason {
		missing = append(missing, "--reason")
	}
	if !haveActor {
		missing = append(missing, "--actor")
	}
	if len(missing) > 0 {
		return r.fail(root, requiredErrf("waive", missing...))
	}
	if len(pos) > 2 {
		return r.fail(root, usageErrf("unrecognized arguments: %s", pos[2]))
	}
	stage := pos[1]
	if !waiveStageKnown(stage) {
		// A typo'd stage records a waiver row nothing ever consults — the
		// proof stays red while `waive` reports success. Refused at exit 2
		// naming the valid list (round-2 contract: a value the verb cannot
		// use is refused, never silently recorded).
		fmt.Fprintf(r.Err, "waive: %s is not a stage the waiver system "+
			"reads — a waiver recorded there would satisfy nothing. Valid: "+
			"%s\n", validation.PyReprStr(stage),
			strings.Join(waiveStages(), ", "))
		return 2
	}
	c, err := state.Open(root, pos[0])
	if err != nil {
		return r.withErr(root, func() error { return err })
	}
	row, err := completion.Waive(c, stage, subject, reason, actor)
	if err != nil {
		return r.withErr(root, func() error { return err })
	}
	fmt.Fprintf(r.Out, "waived %s/%s (actor %s): %s\n", stage,
		validation.ObjStr(row, "subject"), actor, pyHead(reason, 60))
	return 0
}

func init() {
	register(command{ord: 54, name: "waive",
		line: "waive <campaign> <stage> --reason R --actor A",
		run:  runWaive})
}

// waiveCheckStages are the non-stage waiver rails the gate checks read:
// each names a check-level escape hatch, not a pipeline stage (bounty.go's
// waived() readers and the adversarial-game clause).
var waiveCheckStages = []string{"adversarial-game", "accepted-risk",
	"paid-exploitability", "immunization"}

// waiveStages is the full vocabulary a waiver row can land on. R3 (critic):
// it is NOT every pipeline stage — a waiver on a stage whose completion
// proof never calls waiverMap (scope, snapshot, structural-index,
// protocol-model, campaign-planning, chaining, report) satisfies nothing,
// and the typo guard's own sentence ("a waiver recorded there would satisfy
// nothing") makes accepting it a lie. The set below is exactly the stages
// internal/completion/proofs*.go read (discovery, dedup, hostile-review,
// reproduction, maximal-exploitation, independent-verification,
// risk-calibration, mainnet-fork-poc, bounty-gate, learning) plus the gate
// check rails; TestWaiveVocabularyIsReadByProofs pins the pairing against
// the proof source, so the two lists cannot drift.
func waiveStages() []string {
	out := []string{"discovery", "dedup", "hostile-review", "reproduction",
		"maximal-exploitation", "independent-verification", "risk-calibration",
		"mainnet-fork-poc", "bounty-gate", "learning"}
	out = append(out, waiveCheckStages...)
	sort.Strings(out)
	return out
}

// waiveStageKnown reports whether stage is one the waiver system reads.
func waiveStageKnown(stage string) bool {
	for _, s := range waiveStages() {
		if s == stage {
			return true
		}
	}
	return false
}
