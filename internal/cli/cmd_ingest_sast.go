package cli

// cmd_ingest_sast: the --from slither|aderyn SAST lane — tool-output
// adapters feeding the SAME orchestrator ingest (moved verbatim from
// cmd_ingest.go).
import (
	"fmt"
	"websec/internal/datasets/aderyn"
	"websec/internal/datasets/slither"
	"websec/internal/orchestrator"
	"websec/internal/state"
	"websec/internal/validation"
)

// sastLane is one tool-output adapter: the JSON->payloads reader plus the
// discovery stage its hypotheses are attributed to. The table is the ONLY
// place a SAST tool is declared — parseIngest's allowlist and the dispatch
// below both read it, so a new tool is one entry, not three edits.
type sastLane struct {
	toPayloads func(validation.Value) ([]validation.Value, error)
	stage      string
}

// sastLanes is the two-entry tool table (slither G1, aderyn I2a).
var sastLanes = map[string]sastLane{
	"slither": {toPayloads: slither.ToPayloads, stage: "sast-slither"},
	"aderyn":  {toPayloads: aderyn.ToPayloads, stage: "sast-aderyn"},
}

// sastTools is the allowlist in argparse declaration order (the `choose from`
// list order is the flag's declaration order, not map order).
var sastTools = []string{"slither", "aderyn"}

// runIngestSast is the SAST lane: tool JSON -> hypothesis payloads -> the
// SAME orchestrator ingest as a model payload. A rejected payload exits 2
// after reporting which check died — detector output is input, not verdict.
// parseIngest has already enforced the --from/--json-file dependency and the
// tool allowlist, so `a.from` always names a sastLanes entry here.
func runIngestSast(root string, c *state.Campaign, a *ingestArgs, r *Runner) error {
	lane := sastLanes[a.from]
	doc, err := t14ReadPayload(a.jsonFile) // existing ordered-JSON reader
	if err != nil {
		return t14ExitErr(2, "%s JSON unparsable: %s\n", a.from, err)
	}
	payloads, err := lane.toPayloads(doc)
	if err != nil {
		return t14ExitErr(2, "%s\n", err)
	}
	orch := orchestrator.New(c)
	stage := a.stage
	if stage == "" {
		stage = lane.stage
	}
	var created []string
	var made []validation.Value
	for _, p := range payloads {
		f, err := orch.Ingest(p, orchestrator.IngestOpts{
			Trajectory: a.trajectory, Stage: stage, Lint: a.lint})
		if err != nil {
			printIngestFailure(r, err)
			return t14ExitErr(2, "")
		}
		created = append(created, validation.ObjStr(f, "finding_id"))
		made = append(made, f)
	}
	// The SAST lane prints the same summary under --lint as a real run (T4:
	// lint prints exactly what ingest would print); the lane's own per-payload
	// refusals above are byte-identical too, because they come from the same
	// pipeline call.
	fmt.Fprintf(r.Out, "%s ingest: %d hypotheses created\n", a.from, len(created))
	for _, id := range created {
		fmt.Fprintf(r.Out, "  %s\n", id)
	}
	// B9: the lane is an `ingest --json-file` success too, so the hygiene note
	// runs here as well — over EVERY hypothesis the lane created, one capped
	// block (the cap is what keeps a detector run's 50 findings from becoming
	// 50 notes). It rides stderr after the summary above; stdout is untouched.
	emitWriteHints(c, made, a.noHints, r.Err)
	return nil
}
