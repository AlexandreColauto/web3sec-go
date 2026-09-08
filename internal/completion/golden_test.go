// Golden vectors for the 13 completion proofs: oracles generated from the
// LIVE Python twin by .scratch/t12/gen-vectors.py across three campaign
// states (empty / partial / complete) plus a waive() replay. Every proof
// bundle is compared as the exact `json.dumps(..., ensure_ascii=False)`
// string Python printed — key order, em-dashes, repr() and slices included.
package completion

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

const pinnedNow = "2026-01-02T03:04:05.000006+00:00"

type scenarioDoc struct {
	CampaignID  string              `json:"campaign_id"`
	WaiveReplay waiveReplay         `json:"waive_replay"`
	Scenarios   map[string]scenario `json:"scenarios"`
}

type waiveReplay struct {
	Rows           []string          `json:"rows"`
	WaiversJSONL   string            `json:"waivers_jsonl"`
	EventsJSONL    string            `json:"events_jsonl"`
	WaiversAll     string            `json:"waivers_all"`
	WaiversByStage map[string]string `json:"waivers_by_stage"`
	Errors         map[string]string `json:"errors"`
}

type scenario struct {
	CampaignID string            `json:"campaign_id"`
	Files      map[string]string `json:"files"`
	Oracle     oracle            `json:"oracle"`
}

type oracle struct {
	AllProofStatus   string            `json:"all_proof_status"`
	Proofs           map[string]string `json:"proofs"`
	AuditStageLedger []string          `json:"audit_stage_ledger"`
	WaiversAll       string            `json:"waivers_all"`
	WaiversByStage   map[string]string `json:"waivers_by_stage"`
	HasProof         map[string]bool   `json:"has_proof"`
}

func loadScenarios(t *testing.T) scenarioDoc {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "scenarios.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc scenarioDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// materialize writes one fixture tree and opens the campaign.
func materialize(t *testing.T, sc scenario) *state.Campaign {
	t.Helper()
	root := t.TempDir()
	base := filepath.Join(root, "campaigns", sc.CampaignID)
	for rel, content := range sc.Files {
		p := filepath.Join(base, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	c, err := state.Open(root, sc.CampaignID)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// ladderFake is the deterministic test double for maximization.load_ladder:
// Python reads <campaign.dir>/ladders/<fid>.json and validates it; the
// fixture ladders are schema-valid, so the read alone is equivalent.
type ladderFake struct{}

func (ladderFake) LoadLadder(c *state.Campaign, findingID string) (validation.Value, error) {
	p := filepath.Join(c.Dir, "ladders", findingID+".json")
	if !fileExists(p) {
		return validation.VNull(), nil
	}
	return validation.ReadJson(p)
}

// forkPocFake is the deterministic test double for fork_poc.fork_poc_evidence
// (rule 5): the ledger-traced branches, minus the sequence-coverage clause
// that needs sequence_poc. The fixtures carry no fork target, so Python takes
// exactly these branches.
type forkPocFake struct{}

func (forkPocFake) ForkPocEvidence(c *state.Campaign,
	finding validation.Value) (validation.Value, *string, error) {
	execs, err := state.AllExecs(c)
	if err != nil {
		return validation.VNull(), nil, err
	}
	byID := map[string]validation.Value{}
	for _, r := range execs {
		byID[objStr(r, "exec_id")] = r
	}
	noEvidence := "no fork-level evidence (E5/E6) — run the PoC on the " +
		"pinned mainnet fork (webv2 exec --profile fork-runner) and mint it " +
		"(webv2 mint --type fork-test)"
	notTraced := "evidence claims fork-level but no E5/E6 item traces to a " +
		"SUCCEEDED fork-runner exec in the ledger — unit-harness " +
		"evidence (E4) proves semantics, not mainnet"
	candidates := []validation.Value{}
	for _, e := range listAt(finding, "evidence") {
		if e.Kind != validation.Obj {
			continue
		}
		if lvl := objStr(e, "level"); lvl == "E5" || lvl == "E6" {
			candidates = append(candidates, e)
		}
	}
	if len(candidates) == 0 {
		return validation.VNull(), &noEvidence, nil
	}
	for _, e := range candidates {
		if objStr(e, "sandbox_profile") != "fork-runner" {
			continue
		}
		rec, ok := byID[objStr(e, "artifact_id")]
		if !ok || objStr(rec, "profile") != "fork-runner" {
			continue
		}
		if exit, ok := fieldAt(rec, "exit_status"); !ok ||
			exit.Kind != validation.Int || exit.I != 0 {
			continue
		}
		return e, nil, nil
	}
	return validation.VNull(), &notTraced, nil
}

func withFakes(t *testing.T) {
	t.Helper()
	SetMaximization(ladderFake{})
	SetForkPocEvidence(forkPocFake{})
	t.Cleanup(func() {
		SetMaximization(nil)
		SetForkPocEvidence(nil)
	})
}

func TestGoldenScenarioProofs(t *testing.T) {
	t.Setenv("WEBV2_NOW", pinnedNow)
	withFakes(t)
	doc := loadScenarios(t)
	if len(doc.Scenarios) != 4 {
		t.Fatalf("want 4 scenarios, got %d", len(doc.Scenarios))
	}
	for _, name := range []string{"empty", "partial", "complete", "small"} {
		sc, ok := doc.Scenarios[name]
		if !ok {
			t.Fatalf("missing scenario %q", name)
		}
		c := materialize(t, sc)
		all, err := AllProofStatus(c)
		if err != nil {
			t.Fatal(err)
		}
		if got := pyJSONDumps(all); got != sc.Oracle.AllProofStatus {
			t.Errorf("%s all_proof_status\n got %s\nwant %s", name, got,
				sc.Oracle.AllProofStatus)
		}
		for _, stage := range proofOrder {
			pr, err := ProofStatus(c, stage)
			if err != nil {
				t.Fatal(err)
			}
			if got := pyJSONDumps(pr); got != sc.Oracle.Proofs[stage] {
				t.Errorf("%s %s\n got %s\nwant %s", name, stage, got,
					sc.Oracle.Proofs[stage])
			}
		}
	}
}

func TestGoldenAuditAndWaivers(t *testing.T) {
	t.Setenv("WEBV2_NOW", pinnedNow)
	withFakes(t)
	doc := loadScenarios(t)
	for _, name := range []string{"empty", "partial", "complete", "small"} {
		sc := doc.Scenarios[name]
		c := materialize(t, sc)
		audit, err := AuditStageLedger(c)
		if err != nil {
			t.Fatal(err)
		}
		if got := pyJSONDumps(strArr(audit)); got !=
			pyJSONDumps(strArr(sc.Oracle.AuditStageLedger)) {
			t.Errorf("%s audit\n got %s\nwant %s", name, got,
				pyJSONDumps(strArr(sc.Oracle.AuditStageLedger)))
		}
		rows, err := Waivers(c, "")
		if err != nil {
			t.Fatal(err)
		}
		if got := pyJSONDumps(validation.VArr(rows...)); got != sc.Oracle.WaiversAll {
			t.Errorf("%s waivers\n got %s\nwant %s", name, got, sc.Oracle.WaiversAll)
		}
		for stage, want := range sc.Oracle.WaiversByStage {
			rows, err := Waivers(c, stage)
			if err != nil {
				t.Fatal(err)
			}
			if got := pyJSONDumps(validation.VArr(rows...)); got != want {
				t.Errorf("%s waivers(%q)\n got %s\nwant %s", name, stage, got, want)
			}
		}
		for stage, want := range sc.Oracle.HasProof {
			if got := HasProof(stage); got != want {
				t.Errorf("%s has_proof(%q) = %v, want %v", name, stage, got, want)
			}
		}
	}
}

func TestGoldenWaiveReplay(t *testing.T) {
	t.Setenv("WEBV2_NOW", pinnedNow)
	t.Setenv("WEBV2_UUID", "task12-completion")
	doc := loadScenarios(t)
	replay := doc.WaiveReplay
	root := t.TempDir()
	c, err := state.Init(root, "Proof Fixture Program",
		state.InitOpts{CampaignID: doc.CampaignID})
	if err != nil {
		t.Fatal(err)
	}
	row1, err := Waive(c, "discovery", "",
		"fixture: the queue was drained by hand — em-dash stays raw",
		"fixture-operator")
	if err != nil {
		t.Fatal(err)
	}
	row2, err := Waive(c, "learning", "F-0000000009",
		"fixture: no memory entry for this run either", "fixture-operator")
	if err != nil {
		t.Fatal(err)
	}
	if len(replay.Rows) != 2 {
		t.Fatalf("want 2 oracle rows, got %d", len(replay.Rows))
	}
	if got := pyJSONDumps(row1); got != replay.Rows[0] {
		t.Errorf("row1\n got %s\nwant %s", got, replay.Rows[0])
	}
	if got := pyJSONDumps(row2); got != replay.Rows[1] {
		t.Errorf("row2\n got %s\nwant %s", got, replay.Rows[1])
	}
	rawWaivers, err := os.ReadFile(WaiversPath(c))
	if err != nil {
		t.Fatal(err)
	}
	if string(rawWaivers) != replay.WaiversJSONL {
		t.Errorf("waivers.jsonl\n got %q\nwant %q", rawWaivers,
			replay.WaiversJSONL)
	}
	rawEvents, err := os.ReadFile(c.EventsPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(rawEvents) != replay.EventsJSONL {
		t.Errorf("events.jsonl\n got %q\nwant %q", rawEvents, replay.EventsJSONL)
	}
	rows, err := Waivers(c, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := pyJSONDumps(validation.VArr(rows...)); got != replay.WaiversAll {
		t.Errorf("waivers_all\n got %s\nwant %s", got, replay.WaiversAll)
	}
	for stage, want := range replay.WaiversByStage {
		rows, err := Waivers(c, stage)
		if err != nil {
			t.Fatal(err)
		}
		if got := pyJSONDumps(validation.VArr(rows...)); got != want {
			t.Errorf("waivers(%q)\n got %s\nwant %s", stage, got, want)
		}
	}
}

func TestGoldenWaiveErrors(t *testing.T) {
	t.Setenv("WEBV2_NOW", pinnedNow)
	doc := loadScenarios(t)
	root := t.TempDir()
	c, err := state.Init(root, "Proof Fixture Program",
		state.InitOpts{CampaignID: doc.CampaignID})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		key                    string
		stage, subject, reason string
		actor                  string
	}{
		{"short_reason", "x", "*", "short", "actor"},
		{"blank_reason", "x", "*", "   ", "actor"},
		{"no_actor", "x", "*", "a long enough reason here", ""},
	}
	if len(cases) != 3 || len(doc.WaiveReplay.Errors) != 3 {
		t.Fatalf("want 3 error cases, got %d/%d", len(cases),
			len(doc.WaiveReplay.Errors))
	}
	for _, tc := range cases {
		_, err := Waive(c, tc.stage, tc.subject, tc.reason, tc.actor)
		if err == nil {
			t.Fatalf("%s: want an error", tc.key)
		}
		if err.Error() != doc.WaiveReplay.Errors[tc.key] {
			t.Errorf("%s\n got %q\nwant %q", tc.key, err.Error(),
				doc.WaiveReplay.Errors[tc.key])
		}
	}
}
