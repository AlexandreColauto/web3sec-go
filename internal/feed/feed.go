package feed

// The non-interactive model-stage handoff (v1.6 Part 1: "the non-interactive
// file-drop handoff is the only sanctioned transport — with stdout/stdin,
// context leaks by construction"). A stage appears here only when its output
// has a real ingest path; a stage that does not is refused by name, never
// silently accepted. The drop file's STEM names the stage, so a file cannot
// masquerade as another stage's output.
//
// This registry lives in its own package, not in internal/pipeline where the
// plan sketched it: pipeline -> boundary is an import CYCLE (boundary ->
// roles -> corpus -> archetypes -> structidx -> orchestrator -> completion ->
// pipeline), and the boundary checks below are exactly what this file exists
// to drive. The stage table it partitions is still pipeline.Stages.

import (
	"fmt"

	"websec/internal/boundary"
	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// strValues is []string -> []validation.Value, for the array fields.
func strValues(in []string) []validation.Value {
	out := make([]validation.Value, 0, len(in))
	for _, s := range in {
		out = append(out, validation.VStr(s))
	}
	return out
}

// FeedStage is one wired stage of the handoff.
type FeedStage struct {
	Stage  string // pipeline stage id (see pipeline.Stages)
	Schema string // the contract the drop file must satisfy, for the error text
	Note   string // one line: what the drop file contains
	Ingest func(c *state.Campaign, doc validation.Value) (string, error)
}

// FeedStages is the wired set, in pipeline order.
var FeedStages = []FeedStage{
	{
		Stage:  "discovery",
		Schema: "model_request + finding",
		Note:   "a stage invocation: the request record (with its declared input set) plus one hypothesis payload",
		Ingest: discoveryIngest("proposer", "hypothesis"),
	},
}

// discoveryIngest binds the model role and response kind a discovery request
// carries. They are a fact about the STAGE, not a claim a drop file makes, and
// the refusal event must carry them: trajectory.schema.json#model_rejected
// fixes that vocabulary, so a refusal the framework writes about itself may
// not be the one event that fails its own contract.
func discoveryIngest(role, kind string) func(*state.Campaign, validation.Value) (string, error) {
	return func(c *state.Campaign, doc validation.Value) (string, error) {
		return ingestDiscovery(c, doc, role, kind)
	}
}

// ingestDiscovery is the discovery stage's ingest path: validate the stage
// INVOCATION before its output is read, then hand the output to the ordinary
// hypothesis ingest.
func ingestDiscovery(c *state.Campaign, doc validation.Value, role, kind string) (string, error) {
	request, err := invocationRequest(c, doc, role, kind)
	if err != nil {
		return "", err
	}
	output := validation.ObjAt(doc, "output")
	if output.Kind != validation.Obj {
		return "", fmt.Errorf("drop file has no output payload")
	}
	f, err := findings.IngestHypothesis(c, output, "model",
		stageOf(request, "discovery"), validation.ObjStr(request, "model_id"))
	if err != nil {
		return "", err
	}
	return validation.ObjStr(f, "finding_id"), nil
}

// invocationRequest validates a drop file's stage invocation and returns the
// request record with its cited set DERIVED from the bundle the file shipped.
// An undeclared or out-of-set input set is refused AND recorded here, on the
// only production path that reaches the boundary check
// (boundary.IngestModelHypothesis has no CLI caller).
func invocationRequest(c *state.Campaign, doc validation.Value,
	role, kind string) (validation.Value, error) {
	request := validation.ObjAt(doc, "request")
	if request.Kind != validation.Obj {
		// A drop with output but no request record IS the
		// undeclared-consumption case non-negotiable 4 is about: refused AND
		// recorded, like the out-of-set refusal below.
		err := fmt.Errorf("drop file has no request record: a stage " +
			"invocation must declare its input artifact set (v1.6 Part 1)")
		return validation.VNull(), refuseInputSet(c,
			refusalRequest(doc, role, kind), err)
	}
	context := validation.ObjAt(doc, "context")
	if context.Kind != validation.Obj {
		return validation.VNull(), fmt.Errorf("drop file has no context " +
			"bundle: the cited artifact set is derived from the bundle, " +
			"never asserted by the file")
	}
	// The hash is checked against the bytes, not trusted: a request whose
	// context_hash does not describe the bundle it shipped is the fabrication
	// this whole path exists to catch.
	if got, want := validation.ObjStr(request, "context_hash"),
		boundary.ContextHash(context); got != want {
		return validation.VNull(), fmt.Errorf(
			"drop file context_hash %s does not describe its bundle (%s)", got, want)
	}
	// DERIVE the cited set; never read it from the file.
	request.O = validation.SetOrAppend(request.O, "context_artifacts",
		validation.VArr(strValues(boundary.BundleArtifacts(context))...))
	if err := boundary.ValidateRequest(request); err != nil {
		return validation.VNull(), refuseInputSet(c, request, err)
	}
	return request, nil
}

// refuseInputSet records a declared-input-set refusal and returns it. The
// ledger write wins: a refusal that could not be recorded is not a refusal an
// auditor can see, so its failure is the error the caller reports.
func refuseInputSet(c *state.Campaign, request validation.Value, err error) error {
	if logErr := boundary.RecordInputSetRefusal(c, request, err.Error()); logErr != nil {
		return logErr
	}
	return err
}

// refusalRequest is the record a bare drop is refused WITH. There is no
// request to log, but the refusal must still be a LEDGER FACT that satisfies
// trajectory.schema.json#model_rejected — that definition fixes the role and
// kind vocabulary and types context_hash as a 64-hex digest — so the stage's
// own role/kind are carried (a fact about the stage, not a claim the file
// makes) and the hash describes the bundle the drop actually shipped (the
// null bundle, when the key is absent).
func refusalRequest(doc validation.Value, role, kind string) validation.Value {
	return validation.VObj(
		validation.KV{K: "role", V: validation.VStr(role)},
		validation.KV{K: "response_schema", V: validation.VStr(kind)},
		validation.KV{K: "context_hash", V: validation.VStr(
			boundary.ContextHash(validation.ObjAt(doc, "context")))})
}

// stageOf reads the stage from the request record, defaulting to the feed
// stage's own name; the drop file's stem already fixed the stage, so this only
// refines the attribution Task 8 records.
func stageOf(request validation.Value, fallback string) string {
	if s := validation.ObjStr(request, "stage"); s != "" {
		return s
	}
	return fallback
}

// FeedStageFor looks a stage up by id.
func FeedStageFor(stage string) (FeedStage, bool) {
	for _, fs := range FeedStages {
		if fs.Stage == stage {
			return fs, true
		}
	}
	return FeedStage{}, false
}

// FeedStageIDs lists the wired stage ids in declaration order.
func FeedStageIDs() []string {
	out := make([]string, 0, len(FeedStages))
	for _, fs := range FeedStages {
		out = append(out, fs.Stage)
	}
	return out
}

// FeedUnwired names every MODEL or MIXED pipeline stage with NO ingest path
// yet, and why. TestFeedStagesPartitionThePipeline requires the wired set and
// this map to partition the model/mixed rows of pipeline.Stages: a stage that
// is in neither has silently dropped out of the handoff, and a model stage
// added to the table without either entry fails the build. Deterministic
// stages are absent by design — code performs them, so there is no output to
// hand back. Delete an entry when its ingest path lands.
var FeedUnwired = map[string]string{
	"protocol-model":           "the protocol model is loaded by `webv2 model <file>`, not by a drop file",
	"campaign-planning":        "the plan is written by `webv2 plan`, which owns its own contract",
	"dedup":                    "candidate dedup verdicts are applied by `webv2 dedup`, which owns its own contract",
	"hostile-review":           "critic verdicts are applied by `webv2 adjudicate`, not by a drop file",
	"reproduction":             "reproduction requests are submitted through `webv2 sequence run`",
	"maximal-exploitation":     "no maximization loop exists yet (Phase 5)",
	"independent-verification": "no independent-verification ingest path exists yet (Phase 5)",
	"mainnet-fork-poc":         "fork PoCs are minted through `webv2 mint --type fork-test`",
	"learning":                 "memory rows are written through `webv2 memory`",
}
