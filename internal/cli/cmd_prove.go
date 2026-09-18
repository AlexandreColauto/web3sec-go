package cli

// cmd_prove: `webv2 prove <campaign> [--stage S]` — completion proofs: is a
// stage DONE because its artifacts prove it? (cli.py cmd_prove verbatim;
// with --stage the JSON is printed and the exit code is the proof's own
// done/not-done verdict.)

import (
	"fmt"
	"sort"
	"strings"
	"websec/internal/pipeline"

	"websec/internal/completion"
	"websec/internal/state"
	"websec/internal/validation"
)

// proveRun carries the shared context of the two `prove` output paths.
type proveRun struct {
	root string
	r    *Runner
	c    *state.Campaign
}

func runProve(root string, args []string, r *Runner) int {
	if helpRequested(r.Out, "prove", args) {
		return 0
	}

	ensureSeams()
	stage, haveStage := "", false
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--stage" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			stage, haveStage = args[i+1], true
			i++
		case strings.HasPrefix(a, "--stage="):
			stage, haveStage = strings.TrimPrefix(a, "--stage="), true
		case a == "--stage":
			return r.fail(root, argErrf("prove",
				"argument --stage: expected one argument"))
		case strings.HasPrefix(a, "-"):
			return r.fail(root, usageErrf("unrecognized arguments: %s", a))
		default:
			pos = append(pos, a)
		}
	}
	if len(pos) != 1 {
		return r.fail(root, requiredErrf("prove", "campaign"))
	}
	c, err := state.Open(root, pos[0])
	if err != nil {
		return r.withErr(root, func() error { return err })
	}
	p := &proveRun{root: root, r: r, c: c}
	if haveStage {
		return p.runStage(stage)
	}
	return p.runAll()
}

// runStage is the --stage path: one stage's proof, with the exit code as the
// done/not-done verdict.
func (p *proveRun) runStage(stage string) int {
	// r5 (critic issue 5): "no proof declared" is a statement about a
	// REAL stage; for a typo it is indistinguishable from silence.
	// Membership costs a loop over the canonical table — refuse a
	// non-stage and list what IS a stage.
	if !isKnownStage(stage) {
		fmt.Fprintf(p.r.Err, "prove refused: %q is not a campaign stage; "+
			"stages are: %s\n", stage,
			strings.Join(knownStageIDs(), ", "))
		return 2
	}
	pr, err := completion.ProofStatus(p.c, stage)
	if err != nil {
		return p.r.withErr(p.root, func() error { return err })
	}
	if pr.Kind == validation.Null {
		fmt.Fprintf(p.r.Out, "%s: no completion proof declared "+
			"(deterministic stage without an advisory proof)\n", stage)
		return 0
	}
	p.printRow(stage, pr)
	if !pyTruthyCLI(validation.ObjAt(pr, "done")) {
		return 1
	}
	return 0
}

// runAll is the no--stage path: every stage's proof, sorted by stage id.
func (p *proveRun) runAll() int {
	rows, err := completion.AllProofStatus(p.c)
	if err != nil {
		return p.r.withErr(p.root, func() error { return err })
	}
	ids := make([]string, 0, len(rows.O))
	for _, kv := range rows.O {
		ids = append(ids, kv.K)
	}
	sort.Strings(ids)
	for _, sid := range ids {
		pr, _ := fieldAtCLI(rows, sid)
		if pr.Kind == validation.Null {
			fmt.Fprintf(p.r.Out, "%s (no proof)\n", pyLeft(sid, 26))
			continue
		}
		p.printRow(sid, pr)
	}
	return 0
}

// printRow prints the human-readable proof line shared by both paths.
// feedback-triage A6: the reference dumped the raw proof JSON here — the
// operator asking "is this stage provably done?" got a wall of nested
// dicts. Print the same human-readable line the no--stage view uses; the
// exit code remains the done/not-done verdict (intentional divergence from
// the reference).
func (p *proveRun) printRow(sid string, pr validation.Value) {
	mark := "open "
	if pyTruthyCLI(validation.ObjAt(pr, "done")) {
		mark = "DONE "
	}
	auth := "advisory"
	if pyTruthyCLI(validation.ObjAt(pr, "authoritative")) {
		auth = "authoritative"
	}
	line := fmt.Sprintf("%s %s [%s]", pyLeft(sid, 26), mark, auth)
	if !pyTruthyCLI(validation.ObjAt(pr, "done")) {
		missing := strListCLI(validation.ObjAt(pr, "missing"))
		if len(missing) > 3 {
			missing = missing[:3]
		}
		line += " — " + strings.Join(missing, "; ")
	}
	fmt.Fprintln(p.r.Out, line)
}

// pyLeft is Python's f"{s:26s}": left-aligned, padded to width.
func pyLeft(s string, width int) string {
	if n := width - len([]rune(s)); n > 0 {
		return s + strings.Repeat(" ", n)
	}
	return s
}

func init() {
	register(command{ord: 55, name: "prove",
		line: "prove <campaign> [--stage S]       completion proofs",
		run:  runProve})
}

// isKnownStage / knownStageIDs read the canonical pipeline table — the
// one authority on what a stage is.
func isKnownStage(id string) bool {
	for _, s := range pipeline.Stages {
		if s.ID == id {
			return true
		}
	}
	return false
}

func knownStageIDs() []string {
	out := make([]string, 0, len(pipeline.Stages))
	for _, s := range pipeline.Stages {
		out = append(out, s.ID)
	}
	return out
}
