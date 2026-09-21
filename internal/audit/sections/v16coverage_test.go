// v16coverage_test.go pins the v1.6 record-coverage section: the eight fields
// Tasks 2-8 added are written by five code paths and read by none of them, so
// this section is the one place that notices when one of them stops being
// populated. The fixture builds campaigns through state.Init and the REAL
// write paths (findings.IngestHypothesis, the Task 5-8 setters) and
// hand-writes only the states those paths refuse by construction.
package sections

import (
	"fmt"
	"strings"
	"testing"

	"websec/internal/boundary"
	"websec/internal/findings"
	"websec/internal/reviewsession"
	"websec/internal/risk"
	"websec/internal/state"
	"websec/internal/validation"
)

// coverageRow is one finding the fixture ingests plus the v1.6 fields the row
// records on it. A zero value means "the write path recorded nothing", so a
// bare row is a finding the section must count as uncovered.
type coverageRow struct {
	confirmed      bool
	forkDependence string
	originStage    string
	pocTier        string
	facts          int
	factBlock      int64
	replay         bool
	replayCost     float64
	replayCeiling  float64
	// direct writes the row's fields by hand instead of through the setters:
	// the row describes a state the public write paths refuse (see
	// TestV16CoverageFlagsImpossibleRecords).
	direct bool
}

// coverageCampaign builds a campaign with one ingested finding per row.
func coverageCampaign(t *testing.T, rows ...coverageRow) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "Acme", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	for i, row := range rows {
		coverageIngest(t, c, i, row)
	}
	return c
}

// coverageIngest ingests one row's hypothesis and applies the row's fields —
// through the public setters, or directly when the row says so.
func coverageIngest(t *testing.T, c *state.Campaign, i int, row coverageRow) {
	t.Helper()
	f, err := findings.IngestHypothesis(c, coveragePayload(i), "economic",
		row.originStage, "")
	if err != nil {
		t.Fatal(err)
	}
	fid := validation.ObjStr(f, "finding_id")
	if row.direct {
		coverageWriteDirect(t, c, fid, row)
		return
	}
	coverageApplySetters(t, c, fid, row)
}

// coverageApplySetters records the row's v1.6 fields through the write paths
// Tasks 5-8 added: SetForkDependence, RecordFactRead, RecordReplay, AddEvidence.
func coverageApplySetters(t *testing.T, c *state.Campaign, fid string,
	row coverageRow) {
	t.Helper()
	if row.forkDependence != "" {
		if _, err := findings.SetForkDependence(c, fid, row.forkDependence,
			"recorded by the coverage fixture", "operator"); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < row.facts; i++ {
		block := row.factBlock
		if block <= 0 {
			block = 100 // a setter row always pins its read
		}
		if _, err := findings.RecordFactRead(c, fid, coverageFactCommand,
			"1", "ethereum", "operator", block, false); err != nil {
			t.Fatal(err)
		}
	}
	if row.replay {
		if _, err := risk.RecordReplay(c, fid, coverageReplayRecord(row),
			"", "operator"); err != nil {
			t.Fatal(err)
		}
	}
	if row.pocTier != "" {
		if _, err := findings.AddEvidence(c, fid,
			coverageEvidence(row.pocTier)); err != nil {
			t.Fatal(err)
		}
	}
	coverageStampStatus(t, c, fid, row.confirmed)
}

// coverageStampStatus stamps the row's status onto the stored finding.
//
// The status is written DIRECTLY rather than through findings.Transition: the
// CONFIRMED gate is the full clause bundle (exec-backed E4/E5 evidence, a
// critic verdict, the memory check) and this fixture exists to produce the
// DATA the coverage section counts, not to re-prove the gate. The section
// reads status as a fact about the record; the gate keeps its own tests.
func coverageStampStatus(t *testing.T, c *state.Campaign, fid string,
	confirmed bool) {
	t.Helper()
	if !confirmed {
		return
	}
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	f.O = validation.SetOrAppend(f.O, "status", validation.VStr("CONFIRMED"))
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
}

// coverageWriteDirect writes a row's fields the way a hand edit would: the
// finding is loaded, the fields are stamped on it, and the FILE is written —
// no setter, no gate. See the note on TestV16CoverageFlagsImpossibleRecords.
func coverageWriteDirect(t *testing.T, c *state.Campaign, fid string,
	row coverageRow) {
	t.Helper()
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	coverageStampRow(&f, row)
	// The ordinary hand-edit write. The no-op log is deliberate: a hand edit
	// leaves no event, and that absence is exactly what the audit's drift
	// sections exist to see.
	err = findings.SaveThenLog(c, &f, func() error { return nil })
	if err == nil {
		if coverageNeedsSchemaBypass(row) {
			t.Fatal("the finding schema accepted an unpinned deployment " +
				"fact — this fixture's premise (that state survives only in " +
				"pre-guard bytes) no longer holds")
		}
		return
	}
	if !coverageNeedsSchemaBypass(row) {
		t.Fatal(err)
	}
	// The unpinned fact row cannot pass SaveThenLog: deployment_facts.block
	// carries `minimum: 1` in the finding schema, so SaveFinding refuses the
	// very bytes the section exists to catch. That is the point — the state is
	// reachable only from a hand edit or from bytes written before Task 5's
	// schema landed — so the fixture writes the file straight to disk and the
	// section reads the file, not a writer's promise.
	if err := validation.WriteJson(findings.FindingPath(c, fid), f, ""); err != nil {
		t.Fatal(err)
	}
}

// coverageNeedsSchemaBypass reports whether a direct row describes bytes the
// finding schema itself refuses (an unpinned deployment fact).
func coverageNeedsSchemaBypass(row coverageRow) bool {
	return row.facts > 0 && row.factBlock <= 0
}

// coverageStampRow stamps a direct row's fields onto a loaded finding.
func coverageStampRow(f *validation.Value, row coverageRow) {
	if row.confirmed {
		f.O = validation.SetOrAppend(f.O, "status", validation.VStr("CONFIRMED"))
	}
	if row.forkDependence != "" {
		f.O = validation.SetOrAppend(f.O, "fork_dependence",
			validation.VStr(row.forkDependence))
	}
	if row.pocTier != "" {
		ev := validation.ObjAt(*f, "evidence")
		if ev.Kind != validation.Arr {
			ev = validation.VArr()
		}
		ev.A = append(ev.A, coverageEvidence(row.pocTier))
		f.O = validation.SetOrAppend(f.O, "evidence", ev)
	}
	if row.facts > 0 {
		facts := validation.ObjAt(*f, "deployment_facts")
		if facts.Kind != validation.Arr {
			facts = validation.VArr()
		}
		for i := 0; i < row.facts; i++ {
			facts.A = append(facts.A, coverageFactRow(row.factBlock))
		}
		f.O = validation.SetOrAppend(f.O, "deployment_facts", facts)
	}
	if row.replay {
		f.O = validation.SetOrAppend(f.O, "replay", coverageReplayRecord(row))
	}
}

// coverageFactCommand is a recognized read shape (fact_read.go's
// knownReadPattern), so a setter row needs no --read-only attestation.
const coverageFactCommand = "cast call 0xabc balanceOf()"

// coverageFactRow is one deployment_facts row at the given block.
func coverageFactRow(block int64) validation.Value {
	return validation.VObj(
		validation.KV{K: "command", V: validation.VStr(coverageFactCommand)},
		validation.KV{K: "value", V: validation.VStr("1")},
		validation.KV{K: "chain", V: validation.VStr("ethereum")},
		validation.KV{K: "block", V: validation.VInt(block)},
		validation.KV{K: "read_at", V: validation.VStr(state.NowIso())},
		validation.KV{K: "actor", V: validation.VStr("operator")},
		validation.KV{K: "read_only_attested", V: validation.VBool(false)},
	)
}

// coverageEvidence is one evidence item carrying the row's tier. E1/reasoning
// keeps it out of the execution gate (an E4+ item needs a real EXEC record):
// the tier is what the section reads, and a tier on a cheap item is the same
// tier.
func coverageEvidence(tier string) validation.Value {
	return validation.VObj(
		validation.KV{K: "evidence_id", V: validation.VStr(state.NewID("EV", 8))},
		validation.KV{K: "level", V: validation.VStr("E1")},
		validation.KV{K: "type", V: validation.VStr("reasoning")},
		validation.KV{K: "description", V: validation.VStr(
			"the state break, demonstrated on the pinned fork")},
		validation.KV{K: "poc_tier", V: validation.VStr(tier)},
	)
}

// coverageReplayRecord builds the replay block a row describes: a ten-round
// extrapolation whose arithmetic produces exactly the row's cost and ceiling
// (gas = cost/rounds, per-round extraction = ceiling/rounds), so the row reads
// as the record it produces. A row with neither figure gets the profitable
// default.
func coverageReplayRecord(row coverageRow) validation.Value {
	cost, ceiling := row.replayCost, row.replayCeiling
	if cost == 0 && ceiling == 0 {
		cost, ceiling = 50, 10000
	}
	const rounds = 10.0
	return risk.ComputeReplay(2, ceiling/rounds, ceiling, cost/rounds, nil)
}

// coveragePayload is the hypothesis row i ingests. The title carries the row
// index on purpose: ingest folds an identical (title, root_cause, affected)
// digest into its live twin, and the fixture needs one finding per row.
func coveragePayload(i int) validation.Value {
	return validation.VObj(
		validation.KV{K: "title", V: validation.VStr(fmt.Sprintf(
			"Attacker skews the oracle and borrows unbacked funds (row %d)", i))},
		validation.KV{K: "root_cause", V: validation.VObj(
			validation.KV{K: "class", V: validation.VStr("oracle-manipulation")},
			validation.KV{K: "description", V: validation.VStr(
				"the spot price read lets the attacker trade against its own quote")},
		)},
		validation.KV{K: "attacker", V: validation.VObj(
			validation.KV{K: "profile", V: validation.VStr("arbitrary EOA")},
			validation.KV{K: "capabilities", V: validation.VArr()},
		)},
	)
}

func TestV16CoverageCountsWhatTheNewFieldsRecorded(t *testing.T) {
	c := coverageCampaign(t, coverageRow{
		confirmed: true, forkDependence: "real-price-feed",
		originStage: "discovery", pocTier: "existence", facts: 2, replay: true,
	}, coverageRow{confirmed: true}) // a bare finding: nothing recorded
	sec, err := V16Coverage(c)
	if err != nil {
		t.Fatal(err)
	}
	cov := validation.ObjAt(sec, "coverage")
	for _, want := range []struct {
		key string
		got int64
	}{
		{"findings", 2}, {"confirmed", 2},
		{"fork_dependence_set", 1}, {"origin_stage", 1}, {"contributing_stages", 1},
		{"deployment_facts", 1}, {"replay_recorded", 1},
		{"poc_tier_existence", 1}, {"poc_tier_maximized", 0},
	} {
		if got := validation.ObjAt(cov, want.key).I; got != want.got {
			t.Errorf("coverage.%s = %d, want %d", want.key, got, want.got)
		}
	}
	if len(validation.ObjAt(sec, "problems").A) != 0 {
		t.Fatalf("problems = %v, want none: coverage is a measurement, not a verdict",
			validation.ObjAt(sec, "problems"))
	}
}

// TestV16CoverageCountsTheNonFindingFields: review_sessions and the
// input-artifact declaration are not finding fields, and they are the two most
// likely to silently stop being written — a section that read only the six
// finding fields would not notice either.
func TestV16CoverageCountsTheNonFindingFields(t *testing.T) {
	c := coverageCampaign(t, coverageRow{confirmed: true})
	if _, err := reviewsession.Start(c, "operator", []string{"ART-aaaa1111"}); err != nil {
		t.Fatal(err)
	}
	sec, err := V16Coverage(c)
	if err != nil {
		t.Fatal(err)
	}
	cov := validation.ObjAt(sec, "coverage")
	if got := validation.ObjAt(cov, "review_sessions").I; got != 1 {
		t.Fatalf("review_sessions = %d, want 1", got)
	}
	if got := validation.ObjAt(cov, "review_sessions_closed").I; got != 0 {
		t.Fatalf("review_sessions_closed = %d, want 0 (the session is open)", got)
	}
	if got := validation.ObjAt(cov, "model_requests").I; got != 0 {
		t.Fatalf("model_requests = %d, want 0 for a campaign that logged none", got)
	}
}

// TestV16CoverageCountsTheDeclaredInputSets is the other half of the
// non-finding-field coverage: the declaration lives on model.request EVENTS,
// so the section must count the ledger, not the findings. A declaring request
// and a refusal are both recorded through boundary's own writers.
func TestV16CoverageCountsTheDeclaredInputSets(t *testing.T) {
	c := coverageCampaign(t, coverageRow{confirmed: true})
	coverageLogRequest(t, c, coverageRequest("ART-aaaa1111", "ART-aaaa1111"))
	if err := boundary.RecordInputSetRefusal(c,
		coverageRequest("ART-bbbb2222", "ART-aaaa1111"),
		"artifact ART-bbbb2222 is outside the declared input set"); err != nil {
		t.Fatal(err)
	}
	sec, err := V16Coverage(c)
	if err != nil {
		t.Fatal(err)
	}
	cov := validation.ObjAt(sec, "coverage")
	if got := validation.ObjAt(cov, "model_requests").I; got != 1 {
		t.Fatalf("model_requests = %d, want 1", got)
	}
	if got := validation.ObjAt(cov, "requests_declared").I; got != 1 {
		t.Fatalf("requests_declared = %d, want 1", got)
	}
	if got := validation.ObjAt(cov, "model_rejections").I; got != 1 {
		t.Fatalf("model_rejections = %d, want 1", got)
	}
}

// coverageLogRequest records the request the way boundary.logHypothesisRequest
// does — the same call on the same record — so the ledger holds the event the
// real path writes, without a model call.
func coverageLogRequest(t *testing.T, c *state.Campaign, req validation.Value) {
	t.Helper()
	if _, err := c.Log("model.request", nil, &req); err != nil {
		t.Fatal(err)
	}
}

// coverageRequest builds a real model_request (boundary.BuildRequest) whose
// bundle cites cited but whose declaration names declared.
func coverageRequest(cited, declared string) validation.Value {
	bundle := validation.VObj(validation.KV{K: "context", V: validation.VArr(
		validation.VObj(validation.KV{K: "artifact_id", V: validation.VStr(cited)}))})
	decl := validation.VObj(
		validation.KV{K: "kind", V: validation.VStr("artifact")},
		validation.KV{K: "id", V: validation.VStr(declared)})
	return boundary.BuildRequest(bundle, validation.VArr(decl), "proposer",
		"qwen3-14b:local", "0123456789abcdef", "hypothesis")
}

// The three states that must never exist, whatever the coverage numbers say.
//
// These rows are written DIRECTLY — through findings.SaveThenLog on a
// hand-mutated finding, not through the public setters — and that is the
// point, not a shortcut. RecordReplay calls ValidateReplayProfitability and
// RecordFactRead refuses block <= 0, so the write paths cannot produce these
// states at all: that is exactly why the guards were put there. A fixture that
// went through the setters would either fail (the guards hold) or force
// someone to weaken a guard to make a test pass. The states remain reachable
// in the field from data that predates the guard or arrives from an older
// binary, which is what an audit section is for.
func TestV16CoverageFlagsImpossibleRecords(t *testing.T) {
	c := coverageCampaign(t,
		coverageRow{confirmed: true, forkDependence: "real-price-feed",
			pocTier: "maximized", direct: true},
		coverageRow{confirmed: true, replay: true, replayCost: 5000,
			replayCeiling: 1000, direct: true},
		coverageRow{confirmed: true, facts: 1, factBlock: 0, direct: true},
	)
	sec, err := V16Coverage(c)
	if err != nil {
		t.Fatal(err)
	}
	problems := validation.ObjAt(sec, "problems")
	if len(problems.A) != 3 {
		t.Fatalf("problems = %d, want 3: %s", len(problems.A),
			validation.CanonSpaced(problems))
	}
	joined := validation.CanonSpaced(problems)
	for _, want := range []string{"maximized", "unprofitable", "unpinned"} {
		if !strings.Contains(joined, want) {
			t.Errorf("problems do not mention %q: %s", want, joined)
		}
	}
}
