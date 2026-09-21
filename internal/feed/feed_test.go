package feed

// v1.6 Part 1: the drop file is the only sanctioned model-stage transport, and
// a stage with no wired ingest path is refused by name rather than ignored.
//
// The registry lives in this package rather than in internal/pipeline (the
// plan's path) because pipeline -> boundary is an import cycle; the stage
// table it partitions is still pipeline.Stages, so the partition assertion is
// unchanged.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/boundary"
	"websec/internal/pipeline"
	"websec/internal/state"
	"websec/internal/trajectory"
	"websec/internal/validation"
)

// bundle is the context bundle a drop file ships: id-bearing keys plus prose
// that quotes an id, which the derivation must ignore.
func bundle(ids ...string) validation.Value {
	rows := make([]validation.Value, 0, len(ids))
	for _, id := range ids {
		rows = append(rows, validation.VObj(
			validation.KV{K: "artifact_id", V: validation.VStr(id)},
			validation.KV{K: "note", V: validation.VStr("see ART-99999999 for context")}))
	}
	return validation.VObj(
		validation.KV{K: "role", V: validation.VStr("proposer")},
		validation.KV{K: "context", V: validation.VArr(rows...)},
	)
}

// feedOutput is one hypothesis payload — exactly what the `output` key of a
// discovery drop carries.
func feedOutput() validation.Value {
	return validation.VObj(
		validation.KV{K: "title", V: validation.VStr("Attacker drains the vault")},
		validation.KV{K: "root_cause", V: validation.VObj(
			validation.KV{K: "class", V: validation.VStr("economic-invariant")},
			validation.KV{K: "description", V: validation.VStr("the mechanism described in detail")})},
		validation.KV{K: "affected", V: validation.VArr(validation.VObj(
			validation.KV{K: "path", V: validation.VStr("src/V.sol")},
			validation.KV{K: "function", V: validation.VStr("f")}))},
		validation.KV{K: "attacker", V: validation.VObj(
			validation.KV{K: "profile", V: validation.VStr("arbitrary EOA")},
			validation.KV{K: "capabilities", V: validation.VArr()})},
	)
}

// feedDoc is a complete stage invocation: the request record (with its
// declared input set), the context bundle the stage was given, and the output
// payload. context_artifacts is NOT written here — the feed derives it, which
// is the whole point.
func feedDoc(t *testing.T, declared ...string) validation.Value {
	t.Helper()
	return feedDocWithBundle(t, bundle(declared...), declared...)
}

// feedDocWithBundle is feedDoc with a caller-chosen bundle, so a test can ship
// a bundle that cites something the declaration does not cover.
func feedDocWithBundle(t *testing.T, context validation.Value,
	declared ...string) validation.Value {
	t.Helper()
	decl := make([]validation.Value, 0, len(declared))
	for _, id := range declared {
		decl = append(decl, validation.VObj(
			validation.KV{K: "kind", V: validation.VStr("artifact")},
			validation.KV{K: "id", V: validation.VStr(id)}))
	}
	request := validation.VObj(
		validation.KV{K: "role", V: validation.VStr("proposer")},
		validation.KV{K: "model_id", V: validation.VStr("qwen3-14b:local")},
		validation.KV{K: "prompt_version", V: validation.VStr("0123456789abcdef")},
		validation.KV{K: "response_schema", V: validation.VStr("hypothesis")},
		validation.KV{K: "context_hash", V: validation.VStr(boundary.ContextHash(context))},
		validation.KV{K: "input_artifacts", V: validation.VArr(decl...)},
	)
	return validation.VObj(
		validation.KV{K: "request", V: request},
		validation.KV{K: "context", V: context},
		validation.KV{K: "output", V: feedOutput()},
	)
}

func TestFeedStagesPartitionThePipeline(t *testing.T) {
	// Every MODEL or MIXED stage is either wired or explicitly declared
	// unwired with a reason. A stage that is neither has silently dropped out
	// of the handoff, which is the failure this test exists to catch.
	// Deterministic stages are excluded: code performs them, so there is no
	// model output to hand back and no drop file to write.
	modelStages := 0
	for _, s := range pipeline.Stages {
		if s.Kind == "deterministic" {
			refuseWiredDeterministic(t, s)
			continue
		}
		modelStages++
		requireWiredOrDeclared(t, s)
	}
	if modelStages == 0 {
		t.Fatal("no model/mixed stages found — the Stage table moved")
	}
	requireUnwiredReasons(t)
	requireAdvertisedStagesResolve(t)
}

// refuseWiredDeterministic: a deterministic stage must not be wired.
func refuseWiredDeterministic(t *testing.T, s pipeline.Stage) {
	t.Helper()
	if _, wired := FeedStageFor(s.ID); wired {
		t.Fatalf("stage %q is deterministic but wired for a drop file", s.ID)
	}
}

// requireWiredOrDeclared: exactly one of wired / declared-unwired holds.
func requireWiredOrDeclared(t *testing.T, s pipeline.Stage) {
	t.Helper()
	_, wired := FeedStageFor(s.ID)
	_, declared := FeedUnwired[s.ID]
	if wired == declared {
		t.Fatalf("stage %q (%s): wired=%v declared-unwired=%v — exactly one must hold",
			s.ID, s.Kind, wired, declared)
	}
}

// requireUnwiredReasons: every declared-unwired stage carries a reason, and is
// not also wired.
func requireUnwiredReasons(t *testing.T) {
	t.Helper()
	for id, why := range FeedUnwired {
		if why == "" {
			t.Fatalf("stage %q is declared unwired with no reason", id)
		}
		if _, wired := FeedStageFor(id); wired {
			t.Fatalf("stage %q is both wired and declared unwired", id)
		}
	}
}

// requireAdvertisedStagesResolve: FeedStageIDs and FeedStageFor agree.
func requireAdvertisedStagesResolve(t *testing.T) {
	t.Helper()
	for _, id := range FeedStageIDs() {
		if _, ok := FeedStageFor(id); !ok {
			t.Fatalf("FeedStageIDs advertises %q but FeedStageFor refuses it", id)
		}
	}
}

// TestFeedRecordsTheAcceptedInvocation is the I-1 covering test at the package
// level: a drop the feed ACCEPTS leaves its declaration on the ledger as
// exactly one model.request event carrying what the file declared. Before the
// fix the feed validated the declaration and threw it away, so the ledger's
// only model.request writer (boundary.IngestModelHypothesis) had no non-test
// caller and the event never existed on the sanctioned transport.
func TestFeedRecordsTheAcceptedInvocation(t *testing.T) {
	root := t.TempDir()
	c, err := state.Init(root, "Acme", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	fs, _ := FeedStageFor("discovery")
	if _, err := fs.Ingest(c, feedDoc(t, "ART-aaaa1111")); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	evs, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	reqs := []validation.Value{}
	for _, e := range evs {
		if validation.ObjStr(e, "type") == "model.request" {
			reqs = append(reqs, e)
		}
	}
	if len(reqs) != 1 {
		t.Fatalf("model.request events = %d, want exactly 1 for an accepted "+
			"drop (the declaration is a ledger fact)", len(reqs))
	}
	got := boundary.DeclaredInputArtifacts(validation.ObjAt(reqs[0], "data"))
	if len(got) != 1 || got[0] != "ART-aaaa1111" {
		t.Fatalf("input_artifacts = %v, want [ART-aaaa1111] (what the drop declared)", got)
	}
	// The new writer's row must satisfy the contract verify_trajectory
	// re-validates — the framework may not write the one event that turns a
	// healthy campaign red.
	requireTrajectoryOK(t, c)
}

func TestFeedDiscoveryIngestsAHypothesis(t *testing.T) {
	root := t.TempDir()
	c, err := state.Init(root, "Acme", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	doc := feedDoc(t, "ART-aaaa1111")
	fs, ok := FeedStageFor("discovery")
	if !ok {
		t.Fatal("discovery must be wired")
	}
	fid, err := fs.Ingest(c, doc)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if fid == "" {
		t.Fatal("ingest returned no finding id")
	}
	if _, err := os.Stat(filepath.Join(root, "campaigns", c.CampaignID,
		"findings", fid+".json")); err != nil {
		t.Fatalf("finding not written: %v", err)
	}
}

// TestFeedRefusesAnUndeclaredRequest is the production reachability test for
// Task 2's refusal: a drop file whose request record declares nothing, or
// whose BUNDLE cites an artifact outside its declaration, is refused AND
// recorded, on the path an operator actually drives. The second case is the
// one that matters — it is unreachable if the file may assert its own cited
// set, which is why the feed derives it from the bundle instead.
func TestFeedRefusesAnUndeclaredRequest(t *testing.T) {
	root := t.TempDir()
	c, err := state.Init(root, "Acme", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	fs, _ := FeedStageFor("discovery")

	refuseBareDrop(t, c, fs)
	refuseOutOfSetDrop(t, c, fs)
	refuseHashMismatch(t, c, fs)

	// The first two refusals are ledger facts, not stderr lines: the bare drop
	// is the undeclared-consumption case, and the out-of-set drop is the
	// declaration violation. (The hash mismatch is refused before the boundary
	// check, so it logs nothing — a malformed file, not a fabrication attempt.)
	requireRefusalsRecorded(t, c)
}

// TestFeedRefusesAMalformedRecordWithoutRecording is the regression guard for
// the defect fix round 2 found. ValidateRequest fails for TWO reasons, and the
// feed recorded both: the declared-input-set clause (a ledger fact) and the
// request violating the model_request record contract itself (a malformed
// file). The second must be refused with NO event — its role/kind may not be
// model.rejected's vocabulary at all, so the framework's own ledger row would
// violate trajectory.schema.json#model_rejected and turn verify_trajectory red
// on a campaign the framework wrote.
func TestFeedRefusesAMalformedRecordWithoutRecording(t *testing.T) {
	root := t.TempDir()
	c, err := state.Init(root, "Acme", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	fs, _ := FeedStageFor("discovery")

	// (b) the record contract itself: refused, and NOT a ledger fact.
	refuseBadRoleDrop(t, c, fs)
	if n := countRejections(t, c); n != 0 {
		t.Fatalf("model.rejected events after a malformed request record = %d, "+
			"want 0: role %q is not model_rejected's vocabulary, so recording "+
			"it violates trajectory.schema.json#model_rejected", n, "gremlin")
	}
	requireTrajectoryOK(t, c)

	// (a) the declared-input-set clause alone: refused AND recorded.
	refuseOutOfSetDrop(t, c, fs)
	if n := countRejections(t, c); n != 1 {
		t.Fatalf("model.rejected events = %d, want 1 (the out-of-set drop is "+
			"still a ledger fact)", n)
	}
	requireTrajectoryOK(t, c)
}

// refuseBadRoleDrop: a request record whose role is outside model_request's
// enum — a record-contract violation, not a declared-input-set one. The
// request's input_artifacts are derived from a bundle that cites nothing
// outside them, so the input-set clause is satisfied.
func refuseBadRoleDrop(t *testing.T, c *state.Campaign, fs FeedStage) {
	t.Helper()
	doc := feedDoc(t, "ART-aaaa1111")
	req := validation.ObjAt(doc, "request")
	req.O = validation.SetOrAppend(req.O, "role", validation.VStr("gremlin"))
	doc.O = validation.SetOrAppend(doc.O, "request", req)
	_, err := fs.Ingest(c, doc)
	if err == nil {
		t.Fatal("a request record with role gremlin was accepted")
	}
	if strings.Contains(err.Error(), "input artifact set") ||
		strings.Contains(err.Error(), "outside its declared input set") {
		t.Fatalf("err = %v, want the RECORD-CONTRACT refusal, not an "+
			"input-set one (the test would then prove nothing)", err)
	}
}

// refuseBareDrop: no request record at all.
func refuseBareDrop(t *testing.T, c *state.Campaign, fs FeedStage) {
	t.Helper()
	bare := validation.VObj(validation.KV{K: "output", V: feedOutput()})
	if _, err := fs.Ingest(c, bare); err == nil ||
		!strings.Contains(err.Error(), "declare its input artifact set") {
		t.Fatalf("err = %v, want the missing-invocation refusal", err)
	}
}

// refuseOutOfSetDrop: a bundle that cites an artifact the declaration does not
// cover.
func refuseOutOfSetDrop(t *testing.T, c *state.Campaign, fs FeedStage) {
	t.Helper()
	doc := feedDocWithBundle(t, bundle("ART-aaaa1111", "ART-cccc3333"), "ART-aaaa1111")
	if _, err := fs.Ingest(c, doc); err == nil ||
		!strings.Contains(err.Error(), "outside its declared input set") {
		t.Fatalf("err = %v, want the out-of-set refusal", err)
	}
}

// refuseHashMismatch: a request whose context_hash does not describe the
// bundle it shipped.
func refuseHashMismatch(t *testing.T, c *state.Campaign, fs FeedStage) {
	t.Helper()
	lied := feedDoc(t, "ART-aaaa1111")
	req := validation.ObjAt(lied, "request")
	req.O = validation.SetOrAppend(req.O, "context_hash",
		validation.VStr(strings.Repeat("b", 64)))
	lied.O = validation.SetOrAppend(lied.O, "request", req)
	if _, err := fs.Ingest(c, lied); err == nil ||
		!strings.Contains(err.Error(), "does not describe its bundle") {
		t.Fatalf("err = %v, want the context-hash mismatch refusal", err)
	}
}

// requireRefusalsRecorded: exactly the two declaration refusals are ledger
// facts, and they satisfy model_rejected's OWN contract — verify_trajectory
// re-validates every model.* event, so a refusal the framework writes about
// itself may not be the one event that turns a healthy campaign red.
func requireRefusalsRecorded(t *testing.T, c *state.Campaign) {
	t.Helper()
	if n := countRejections(t, c); n != 2 {
		t.Fatalf("model.rejected events = %d, want 2 (the bare drop and the "+
			"out-of-set drop; the hash mismatch logs nothing)", n)
	}
	requireTrajectoryOK(t, c)
}

// countRejections is the number of model.rejected events in the ledger.
func countRejections(t *testing.T, c *state.Campaign) int {
	t.Helper()
	evs, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range evs {
		if validation.ObjStr(e, "type") == "model.rejected" {
			n++
		}
	}
	return n
}

// requireTrajectoryOK: the campaign verifies — no framework-written event may
// violate the contract verify_trajectory re-checks.
func requireTrajectoryOK(t *testing.T, c *state.Campaign) {
	t.Helper()
	report, err := trajectory.VerifyTrajectory(c)
	if err != nil {
		t.Fatal(err)
	}
	if !validation.ObjAt(report, "ok").B {
		t.Fatalf("verify_trajectory = %s, want ok (the refusal events must "+
			"satisfy model_rejected's own contract)",
			validation.CanonCompact(report))
	}
}
