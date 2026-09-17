// invariants_test.go: port of tests/test_invariants.py plus the core
// registry behaviour, verified against vectors generated from the Python twin.
package invariants

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

// ---- fixtures ------------------------------------------------------------

func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

// invCamp is the structured-test `camp` fixture: a pinned target snapshot.
func invCamp(t *testing.T) *state.Campaign {
	t.Helper()
	root := t.TempDir()
	c, err := state.Init(root, "Inv Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "V.sol"),
		[]byte("contract V {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, target, nil, nil); err != nil {
		t.Fatal(err)
	}
	return c
}

// docCamp is conftest's `camp`: a campaign with nothing pinned.
func docCamp(t *testing.T) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "test-program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// modelWithInvariants is tests/test_invariants_structured.py's helper. INV-2
// claims its own verification status — seeding must ignore it.
func modelWithInvariants() validation.Value {
	return validation.VObj(kv("invariants", validation.VArr(
		validation.VObj(
			kv("id", validation.VStr("INV-1")),
			kv("statement", validation.VStr(
				"totalAssets never decreases except via withdraw")),
			kv("severity_if_broken", validation.VStr("critical")),
		),
		validation.VObj(
			kv("id", validation.VStr("INV-2")),
			kv("statement", validation.VStr(
				"fee accumulator cannot be set backwards")),
			kv("severity_if_broken", validation.VStr("high")),
			kv("model_belief", validation.VFloat(0.6)),
			kv("depends_on", validation.VArr(validation.VStr("INV-1"))),
			kv("modified_by", validation.VStr("model-proposer pass 2")),
			kv("status", validation.VStr("CHECKED_AGAINST_CODE")),
		),
	)))
}

// readmeSnap writes text to <snapshot>/README.md and returns the snapshot id.
func readmeSnap(t *testing.T, c *state.Campaign, text string) string {
	t.Helper()
	sid, err := c.ActiveSnapshotIDOrNone()
	if err != nil || sid == nil {
		t.Fatalf("no active snapshot: %v", err)
	}
	p := filepath.Join(c.Dir, "snapshots", *sid, "README.md")
	if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	return *sid
}

// registeredArtifact is the structured test's _registered_artifact helper.
func registeredArtifact(t *testing.T, c *state.Campaign, name, text string) string {
	t.Helper()
	p := filepath.Join(c.ArtifactsDir, name)
	if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RegisterOrRefresh("other", p, "", nil,
		"re-registered (content may have changed)"); err != nil {
		t.Fatal(err)
	}
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range objAt(st, "artifacts").A {
		if strings.HasSuffix(objStr(a, "path"), name) {
			return objStr(a, "artifact_id")
		}
	}
	t.Fatalf("no registered artifact ending in %q", name)
	return ""
}

// findingWithInvariant is _finding_with_invariant: ingest the hypothesis,
// then attach the structured invariant citation and save.
func findingWithInvariant(t *testing.T, c *state.Campaign, invID string) validation.Value {
	t.Helper()
	payload := validation.VObj(
		kv("title", validation.VStr("fee accumulator rewound")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("access-control")),
			kv("description", validation.VStr(
				"unauthorized setter rewinds the accumulator")),
		)),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/V.sol")),
			kv("function", validation.VStr("setFee")),
		))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()),
		)),
	)
	f, err := findings.IngestHypothesis(c, payload, "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	f.O = validation.SetOrAppend(f.O, "security_invariants", validation.VArr(
		validation.VObj(
			kv("id", validation.VStr(invID)),
			kv("statement", validation.VStr(
				"fee accumulator cannot be set backwards")),
		)))
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

var execSeq int

// testExec is the conftest `sandboxed_exec` equivalent (sandbox.register_exec
// lands with P2): it writes the EXEC ledger record directly.
func testExec(t *testing.T, c *state.Campaign, profile, findingID string,
	exitStatus int64, stdout string) validation.Value {
	t.Helper()
	execSeq++
	execID := fmt.Sprintf("EXEC-%010x", execSeq)
	dir := filepath.Join(c.ExecsDir, execID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	stdoutPath := filepath.Join(dir, "stdout.log")
	stderrPath := filepath.Join(dir, "stderr.log")
	if err := os.WriteFile(stdoutPath, []byte(stdout), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stderrPath, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	fidV := validation.VNull()
	if findingID != "" {
		fidV = validation.VStr(findingID)
	}
	rec := validation.VObj(
		kv("exec_id", validation.VStr(execID)),
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("profile", validation.VStr(profile)),
		kv("finding_id", fidV),
		kv("artifact_id", validation.VNull()),
		kv("command", validation.VStr("forge test --match-test test_exploit")),
		kv("exit_status", validation.VInt(exitStatus)),
		kv("stdout_path", validation.VStr(stdoutPath)),
		kv("stderr_path", validation.VStr(stderrPath)),
	)
	if err := validation.WriteJson(filepath.Join(dir, "exec_record.json"),
		rec, ""); err != nil {
		t.Fatal(err)
	}
	return rec
}

// evidenceItem is conftest's `evidence_item` (E4+ tracing to rec).
func evidenceItem(rec validation.Value, level, typ, eid string) validation.Value {
	return validation.VObj(
		kv("evidence_id", validation.VStr(eid)),
		kv("level", validation.VStr(level)),
		kv("type", validation.VStr(typ)),
		kv("description", validation.VStr("reproduction under sandbox")),
		kv("sandbox_profile", objAt(rec, "profile")),
		kv("artifact_id", objAt(rec, "exec_id")),
	)
}

// manualNote is the structured test's level-neutral / rise note item.
func manualNote(eid, level string) validation.Value {
	return validation.VObj(
		kv("evidence_id", validation.VStr(eid)),
		kv("level", validation.VStr(level)),
		kv("type", validation.VStr("manual")),
		kv("description", validation.VStr("reasoning note")),
	)
}

func wantErr(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q does not contain %q", err.Error(), want)
	}
}

// ---- golden helpers ------------------------------------------------------

func goldenBytes(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func goldenValue(t *testing.T, name string) validation.Value {
	t.Helper()
	v, err := validation.ParseOrdered(goldenBytes(t, name))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// wantGolden compares a Value's pretty rendering (the write_json format)
// with the Python twin's bytes.
func wantGolden(t *testing.T, name string, got validation.Value) {
	t.Helper()
	want := string(goldenBytes(t, name))
	if g := validation.DumpIndented(got) + "\n"; g != want {
		t.Errorf("%s mismatch\n got: %s\nwant: %s", name, g, want)
	}
}

// materializeTree writes the doc-scan fixture tree (emitted by the Python
// twin) under dir.
func materializeTree(t *testing.T, dir string) {
	t.Helper()
	var spec struct {
		Files []struct {
			Path string `json:"path"`
			B64  string `json:"b64"`
		} `json:"files"`
	}
	if err := json.Unmarshal(goldenBytes(t, "docscan_tree.json"), &spec); err != nil {
		t.Fatal(err)
	}
	if len(spec.Files) < 10 {
		t.Fatalf("tree spec too small: %d files", len(spec.Files))
	}
	for _, f := range spec.Files {
		raw, err := base64.StdEncoding.DecodeString(f.B64)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, filepath.FromSlash(f.Path))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// ---- ported tests: tests/test_invariants.py ------------------------------

func TestSeedSynthesizesLivenessInvariantForStateMachines(t *testing.T) {
	c := docCamp(t)
	model := validation.VObj(
		kv("state_machines", validation.VArr(validation.VObj(
			kv("name", validation.VStr("rollup")),
			kv("states", validation.VArr(
				validation.VStr("committed"), validation.VStr("finalized"))),
			kv("transitions", validation.VArr()),
		))),
		kv("invariants", validation.VArr(validation.VObj(
			kv("id", validation.VStr("INV-1")),
			kv("statement", validation.VStr("minted == locked")),
			kv("kind", validation.VStr("accounting")),
			kv("severity_if_broken", validation.VStr("critical")),
		))),
	)
	if _, err := SeedFromModel(c, model); err != nil {
		t.Fatal(err)
	}
	links, err := LoadLinks(c)
	if err != nil {
		t.Fatal(err)
	}
	reg := objAt(links, "invariants")
	if len(reg.O) != 2 {
		t.Fatalf("registry size = %d, want 2", len(reg.O))
	}
	live := objAt(reg, "INV-2")
	if objStr(live, "kind") != "liveness" {
		t.Fatalf("synthesized kind = %q, want liveness", objStr(live, "kind"))
	}
	if !strings.Contains(strings.ToLower(objStr(live, "statement")), "rollup") {
		t.Errorf("liveness statement does not name the machine: %q",
			objStr(live, "statement"))
	}
}

func TestSeedNormalizesVerificationStatus(t *testing.T) {
	c := invCamp(t)
	links, err := SeedFromModel(c, modelWithInvariants())
	if err != nil {
		t.Fatal(err)
	}
	reg := objAt(links, "invariants")
	if got := objStr(objAt(reg, "INV-1"), "test_status"); got != "untested" {
		t.Errorf("INV-1 test_status = %q", got)
	}
	if got := objStr(objAt(reg, "INV-2"), "test_status"); got != "untested" {
		t.Errorf("INV-2 test_status = %q", got)
	}
	// the model's self-claim is NOT honored
	if got := objStr(objAt(reg, "INV-1"), "status"); got != "UNVERIFIED" {
		t.Errorf("INV-1 status = %q, want UNVERIFIED", got)
	}
	if got := objStr(objAt(reg, "INV-2"), "status"); got != "UNVERIFIED" {
		t.Errorf("INV-2 status = %q, want UNVERIFIED", got)
	}
	if got := objAt(objAt(reg, "INV-2"), "model_belief").F; got != 0.6 {
		t.Errorf("model_belief = %v, want 0.6", got)
	}
	if got := objAt(objAt(reg, "INV-2"), "depends_on").A; len(got) != 1 ||
		got[0].S != "INV-1" {
		t.Errorf("depends_on = %s, want [INV-1]", validation.PyRepr(
			objAt(objAt(reg, "INV-2"), "depends_on")))
	}
	if got := objStr(objAt(reg, "INV-2"), "source"); got != "model" {
		t.Errorf("INV-2 source = %q, want model", got)
	}
}

func TestSeedDerivesDocumentedSource(t *testing.T) {
	c := invCamp(t)
	readmeSnap(t, c, "# Protocol\nINV-1: totalAssets never decreases except "+
		"via withdraw.\n")
	links, err := SeedFromModel(c, modelWithInvariants())
	if err != nil {
		t.Fatal(err)
	}
	reg := objAt(links, "invariants")
	if got := objStr(objAt(reg, "INV-1"), "source"); got != "documented" {
		t.Errorf("INV-1 source = %q, want documented", got)
	}
	if got := objStr(objAt(reg, "INV-2"), "source"); got != "model" {
		t.Errorf("INV-2 source = %q, want model", got)
	}
}

func TestVerifyRequiresRegisteredArtifact(t *testing.T) {
	c := invCamp(t)
	if _, err := SeedFromModel(c, modelWithInvariants()); err != nil {
		t.Fatal(err)
	}
	_, err := VerifyInvariantStatement(c, "INV-2", "ART-nope")
	wantErr(t, err, "unknown artifact")
	artID := registeredArtifact(t, c, "inv-check.md",
		"checked against src/V.sol L40\n")
	e, err := VerifyInvariantStatement(c, "INV-2", artID)
	if err != nil {
		t.Fatal(err)
	}
	if got := objStr(e, "status"); got != "CHECKED_AGAINST_CODE" {
		t.Errorf("status = %q", got)
	}
	if got := objStr(e, "verified_by"); got != artID {
		t.Errorf("verified_by = %q, want %q", got, artID)
	}
}

func TestContradictSetsStatus(t *testing.T) {
	c := invCamp(t)
	if _, err := SeedFromModel(c, modelWithInvariants()); err != nil {
		t.Fatal(err)
	}
	e, err := ContradictInvariantStatement(c, "INV-1", "src/V.sol#L40")
	if err != nil {
		t.Fatal(err)
	}
	if got := objStr(e, "status"); got != "CONTRADICTED" {
		t.Errorf("status = %q, want CONTRADICTED", got)
	}
	if got := objStr(e, "contradiction"); got != "src/V.sol#L40" {
		t.Errorf("contradiction = %q", got)
	}
}

func TestTestStatusAxisIsOrthogonal(t *testing.T) {
	c := invCamp(t)
	if _, err := SeedFromModel(c, modelWithInvariants()); err != nil {
		t.Fatal(err)
	}
	artID := registeredArtifact(t, c, "fuzz.md", "fuzz run\n")
	e, err := LinkTest(c, "INV-1", artID)
	if err != nil {
		t.Fatal(err)
	}
	if got := objStr(e, "test_status"); got != "held" {
		t.Errorf("test_status = %q, want held", got)
	}
	if got := objStr(e, "status"); got != "UNVERIFIED" {
		t.Errorf("status = %q, want UNVERIFIED (orthogonal axis)", got)
	}
}

func TestReseedRefreshesModelToDocumented(t *testing.T) {
	c := invCamp(t)
	if _, err := SeedFromModel(c, modelWithInvariants()); err != nil {
		t.Fatal(err)
	}
	links, err := LoadLinks(c)
	if err != nil {
		t.Fatal(err)
	}
	if got := objStr(objAt(objAt(links, "invariants"), "INV-2"), "source"); got != "model" {
		t.Fatalf("INV-2 source before = %q, want model", got)
	}
	readmeSnap(t, c, "INV-2: fee accumulator cannot be set backwards.\n")
	links, err = SeedFromModel(c, modelWithInvariants())
	if err != nil {
		t.Fatal(err)
	}
	e := objAt(objAt(links, "invariants"), "INV-2")
	if got := objStr(e, "source"); got != "documented" {
		t.Errorf("INV-2 source after = %q, want documented", got)
	}
	if got := objStr(e, "modified_by"); !strings.Contains(got, "source-refresh") {
		t.Errorf("modified_by = %q, want source-refresh provenance", got)
	}
}

func TestUnknownInvariantErrors(t *testing.T) {
	c := invCamp(t)
	artID := registeredArtifact(t, c, "fuzz.md", "fuzz run\n")
	_, err := LinkFinding(c, "INV-nope", "F-1", false)
	wantErr(t, err, "unknown invariant 'INV-nope'")
	_, err = LinkTest(c, "INV-nope", artID)
	wantErr(t, err, "unknown invariant 'INV-nope'")
	_, err = VerifyInvariantStatement(c, "INV-nope", artID)
	wantErr(t, err, "unknown invariant 'INV-nope'")
	_, err = ContradictInvariantStatement(c, "INV-nope", "x#L1")
	wantErr(t, err, "unknown invariant 'INV-nope'")
}

func TestLinkFindingTracksViolation(t *testing.T) {
	c := invCamp(t)
	if _, err := SeedFromModel(c, modelWithInvariants()); err != nil {
		t.Fatal(err)
	}
	e, err := LinkFinding(c, "INV-1", "F-aaaaaaaaaaaa", true)
	if err != nil {
		t.Fatal(err)
	}
	if got := objStr(e, "test_status"); got != "violated" {
		t.Errorf("test_status = %q, want violated", got)
	}
	if got := objStr(e, "violated_by"); got != "F-aaaaaaaaaaaa" {
		t.Errorf("violated_by = %q", got)
	}
	e, err = LinkFinding(c, "INV-1", "F-aaaaaaaaaaaa", false)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(objAt(e, "findings").A); got != 1 {
		t.Errorf("findings length = %d, want 1 (no duplicates)", got)
	}
}

// ---- byte-exact vectors generated from the Python twin -------------------

// The goldens under testdata/ are produced by scripts/invariants-vectors.py,
// which runs the live Python reference (web3sec-final) and dumps what it
// returned; none of the expectations are hand-written. Re-run that script
// (never hand-edit a golden) whenever a scenario is added.
//
// pinnedNow is the WEBV2_NOW clock pin both twins use for the goldens.
const pinnedNow = "2026-02-01T00:00:00.000000+00:00"

func TestMain(m *testing.M) {
	// The cross-twin goldens (links files, hash-chained event logs) are only
	// byte-comparable when both sides see the same clock.
	os.Setenv("WEBV2_NOW", pinnedNow)
	os.Exit(m.Run())
}

func TestNormalizeInvIDVectors(t *testing.T) {
	vec := goldenValue(t, "normalize_vectors.json")
	if len(vec.A) < 30 {
		t.Fatalf("vector file has %d rows, want >= 30", len(vec.A))
	}
	bad := 0
	for _, row := range vec.A {
		in, want := objStr(row, "in"), objStr(row, "out")
		if got := NormalizeInvID(in); got != want {
			t.Errorf("NormalizeInvID(%q) = %q, want %q", in, got, want)
			bad++
		}
	}
	if bad > 0 {
		t.Fatalf("%d normalize vectors disagreed with CPython", bad)
	}
}

func TestCoverageVectors(t *testing.T) {
	cases := goldenValue(t, "coverage_vectors.json")
	if len(cases.A) < 6 {
		t.Fatalf("coverage vector file has %d rows, want >= 6", len(cases.A))
	}
	for _, tc := range cases.A {
		name := objStr(tc, "name")
		c := docCamp(t)
		if _, err := SaveLinks(c, objAt(tc, "links")); err != nil {
			t.Fatal(err)
		}
		got, err := Coverage(c)
		if err != nil {
			t.Fatal(err)
		}
		want := objAt(tc, "expected")
		if validation.DumpIndented(got) != validation.DumpIndented(want) {
			t.Errorf("coverage[%s]\n got: %s\nwant: %s", name,
				validation.DumpIndented(got), validation.DumpIndented(want))
		}
	}
}

// TestUncoveredCriticalVectors pins the whole filter matrix: severity,
// test-status, missing test_status, missing registry entry, and zero-padded
// ids on both sides.
func TestUncoveredCriticalVectors(t *testing.T) {
	c := docCamp(t)
	if _, err := SaveLinks(c, goldenValue(t, "uncovered_links.json")); err != nil {
		t.Fatal(err)
	}
	got, err := UncoveredCritical(c, goldenValue(t, "uncovered_model.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := goldenValue(t, "uncovered_vectors.json")
	if len(want.A) < 5 {
		t.Fatalf("uncovered vector file has %d rows, want >= 5", len(want.A))
	}
	wantGolden(t, "uncovered_vectors.json", validation.VArr(got...))
}

// scenarioCamp builds the twin campaign for the scripted link scenario: a
// pinned snapshot, a documented INV-1, and two pre-registered artifacts.
func scenarioCamp(t *testing.T) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "vec program",
		state.InitOpts{CampaignID: "C-vec00003"})
	if err != nil {
		t.Fatal(err)
	}
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	st.O = validation.SetOrAppend(st.O, "active_snapshot_id", validation.VStr("SNAPX"))
	st.O = validation.SetOrAppend(st.O, "artifacts", validation.VArr(
		fixedArtifact("OTH-fixed001", filepath.Join(c.ArtifactsDir, "inv-check.md")),
		fixedArtifact("OTH-fixed002", filepath.Join(c.ArtifactsDir, "fuzz.md")),
	))
	if err := validation.WriteJson(c.StatePath, st, "campaign_state"); err != nil {
		t.Fatal(err)
	}
	snapDir := filepath.Join(c.Dir, "snapshots", "SNAPX")
	if err := os.MkdirAll(snapDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snapDir, "README.md"),
		[]byte("INV-1 totalAssets never decreases except via withdraw\n"),
		0o644); err != nil {
		t.Fatal(err)
	}
	return c
}

func fixedArtifact(id, path string) validation.Value {
	return validation.VObj(
		kv("artifact_id", validation.VStr(id)),
		kv("kind", validation.VStr("other")),
		kv("path", validation.VStr(path)),
		kv("registered_at", validation.VStr(pinnedNow)),
		kv("sha256", validation.VNull()),
		kv("snapshot_id", validation.VNull()),
		kv("note", validation.VStr("")),
	)
}

func TestLinkScenarioMatchesPythonTwin(t *testing.T) {
	c := scenarioCamp(t)
	model := goldenValue(t, "scenario_model.json")
	steps := goldenValue(t, "scenario_steps.json")
	if len(steps.A) < 10 {
		t.Fatalf("scenario has %d steps, want >= 10", len(steps.A))
	}
	if n := replayScenario(t, c, steps); n != len(steps.A) {
		t.Fatalf("replayed %d steps, golden has %d", n, len(steps.A))
	}
	compareTwinFile(t, linksPath(c), "scenario_links.json")
	compareTwinFile(t, c.EventsPath, "scenario_events.jsonl")
	cov, err := Coverage(c)
	if err != nil {
		t.Fatal(err)
	}
	wantGolden(t, "scenario_coverage.json", cov)
	unc, err := UncoveredCritical(c, model)
	if err != nil {
		t.Fatal(err)
	}
	wantGolden(t, "scenario_uncovered.json", validation.VArr(unc...))
}

// compareTwinFile asserts a file this package wrote is byte-identical to the
// Python twin's copy.
func compareTwinFile(t *testing.T, path, golden string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(goldenBytes(t, golden)) {
		t.Errorf("%s differs from the Python twin (%s)", path, golden)
	}
}

// scenarioChecker replays the scripted link scenario one step at a time,
// comparing the registry with the golden after each call.
type scenarioChecker struct {
	t     *testing.T
	c     *state.Campaign
	steps validation.Value
	i     int
}

func (s *scenarioChecker) check(label string) {
	s.t.Helper()
	if s.i >= len(s.steps.A) {
		s.t.Fatalf("extra step %q (golden has %d)", label, len(s.steps.A))
	}
	row := s.steps.A[s.i]
	if got := objStr(row, "label"); got != label {
		s.t.Fatalf("step %d label = %q, want %q", s.i, got, label)
	}
	links, err := LoadLinks(s.c)
	if err != nil {
		s.t.Fatal(err)
	}
	if got, want := validation.DumpIndented(links),
		validation.DumpIndented(objAt(row, "links")); got != want {
		s.t.Errorf("links after %q\n got: %s\nwant: %s", label, got, want)
	}
	s.i++
}

func replayScenario(t *testing.T, c *state.Campaign,
	steps validation.Value) int {
	t.Helper()
	s := &scenarioChecker{t: t, c: c, steps: steps}
	if _, err := SeedFromModel(c, goldenValue(t, "scenario_model.json")); err != nil {
		t.Fatal(err)
	}
	s.check("seed")
	if _, err := LinkFinding(c, "INV-2", "F-aaaaaaaaaaaa", true); err != nil {
		t.Fatal(err)
	}
	s.check("link_finding_violated")
	if _, err := LinkFinding(c, "INV-2", "F-aaaaaaaaaaaa", false); err != nil {
		t.Fatal(err)
	}
	s.check("link_finding_dup")
	if _, err := LinkFinding(c, "INV-1", "F-bbbbbbbbbbbb", false); err != nil {
		t.Fatal(err)
	}
	s.check("link_finding_inv1")
	if _, err := LinkTest(c, "INV-2", "OTH-fixed002"); err != nil {
		t.Fatal(err)
	}
	s.check("link_test")
	if _, err := VerifyInvariantStatement(c, "INV-2", "OTH-fixed001"); err != nil {
		t.Fatal(err)
	}
	s.check("verify")
	if _, err := ContradictInvariantStatement(c, "INV-1", "src/V.sol#L40"); err != nil {
		t.Fatal(err)
	}
	s.check("contradict")
	if _, err := VerifyInvariantStatement(c, "INV-3", "OTH-fixed001"); err != nil {
		t.Fatal(err)
	}
	s.check("verify_inv3")
	if _, err := VerifyInvariantStatement(c, "INV-3", "OTH-fixed002"); err != nil {
		t.Fatal(err)
	}
	s.check("verify_inv3_again")
	if _, err := ContradictInvariantStatement(c, "INV-3", "src/V.sol#L1"); err != nil {
		t.Fatal(err)
	}
	s.check("contradict_inv3")
	links, err := LoadLinks(c)
	if err != nil {
		t.Fatal(err)
	}
	links.O = validation.SetOrAppend(links.O, "invariants", setObjKey(
		objAt(links, "invariants"), "INV-4", validation.VObj(
			kv("statement", validation.VStr("legacy claim")),
			kv("status", validation.VStr("held")),
			kv("findings", validation.VArr()),
			kv("tests", validation.VArr()),
			kv("detectors", validation.VArr()))))
	if _, err := SaveLinks(c, links); err != nil {
		t.Fatal(err)
	}
	s.check("legacy_raw")
	if _, err := LinkTest(c, "INV-4", "OTH-fixed002"); err != nil {
		t.Fatal(err)
	}
	s.check("legacy_migrated")
	if _, err := LoadLinks(c); err != nil {
		t.Fatal(err)
	}
	s.check("legacy_second_read")
	return s.i
}

func TestConstantsMatchPythonTwin(t *testing.T) {
	wantStatuses := []string{"untested", "violated", "held", "untestable"}
	if len(Statuses) != len(wantStatuses) {
		t.Fatalf("Statuses = %v, want %v", Statuses, wantStatuses)
	}
	for i, s := range wantStatuses {
		if Statuses[i] != s {
			t.Errorf("Statuses[%d] = %q, want %q", i, Statuses[i], s)
		}
	}
	wantVerif := []string{"UNVERIFIED", "CHECKED_AGAINST_CODE", "CONTRADICTED"}
	if len(VerificationStatuses) != len(wantVerif) {
		t.Fatalf("VerificationStatuses = %v, want %v", VerificationStatuses,
			wantVerif)
	}
	for i, s := range wantVerif {
		if VerificationStatuses[i] != s {
			t.Errorf("VerificationStatuses[%d] = %q, want %q", i,
				VerificationStatuses[i], s)
		}
	}
}

func TestLoadLinksDefaultsToEmptyRegistry(t *testing.T) {
	c := docCamp(t)
	links, err := LoadLinks(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(links.O) != 1 || !hasKey(links, "invariants") {
		t.Fatalf("fresh links = %s, want only an invariants key",
			validation.DumpIndented(links))
	}
	if got := len(objAt(links, "invariants").O); got != 0 {
		t.Errorf("registry size = %d, want 0", got)
	}
	if _, err := os.Stat(linksPath(c)); err == nil {
		t.Errorf("load_links created the registry file; it must not")
	}
	p, err := SaveLinks(c, links)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Errorf("save_links did not write %s: %v", p, err)
	}
}

// ---- per-machine liveness coverage (Task 3, the G-01 gap) ----------------

// livenessMachinesModel is the Task 3 fixture literal: three modeled state
// machines (vault-lifecycle, relay, staking) and three model invariants, so a
// zero-coverage seed synthesizes its template as INV-4. The plan sketch called
// this `modelWithInvariants()`, but that shared fixture carries no
// state_machines — and a dozen unrelated tests depend on its exact shape — so
// the literal is spelled out here instead of widening the shared fixture.
func livenessMachinesModel() validation.Value {
	return validation.VObj(
		kv("state_machines", validation.VArr(
			validation.VObj(kv("name", validation.VStr("vault-lifecycle"))),
			validation.VObj(kv("name", validation.VStr("relay"))),
			validation.VObj(kv("name", validation.VStr("staking"))),
		)),
		kv("invariants", validation.VArr(
			validation.VObj(
				kv("id", validation.VStr("INV-1")),
				kv("statement", validation.VStr(
					"totalAssets never decreases except via withdraw")),
				kv("kind", validation.VStr("accounting")),
				kv("severity_if_broken", validation.VStr("critical")),
			),
			validation.VObj(
				kv("id", validation.VStr("INV-2")),
				kv("statement", validation.VStr(
					"fee accumulator cannot be set backwards")),
				kv("kind", validation.VStr("accounting")),
				kv("severity_if_broken", validation.VStr("high")),
			),
			validation.VObj(
				kv("id", validation.VStr("INV-3")),
				kv("statement", validation.VStr(
					"paused relay cannot permanently strand withdrawals")),
				kv("kind", validation.VStr("security")),
				kv("severity_if_broken", validation.VStr("high")),
			),
		)),
	)
}

// livenessModelCovering is livenessMachinesModel with its first invariant
// turned into a kind=liveness entry whose applies_to is the single named
// machine — the partial-coverage shape the gate must refuse.
func livenessModelCovering(machine string) validation.Value {
	model := livenessMachinesModel()
	invs := objAt(model, "invariants")
	first := invs.A[0]
	first.O = validation.SetOrAppend(first.O, "kind",
		validation.VStr("liveness"))
	first.O = validation.SetOrAppend(first.O, "applies_to",
		validation.VArr(validation.VStr(machine)))
	invs.A[0] = first
	model.O = validation.SetOrAppend(model.O, "invariants", invs)
	return model
}

// TestPartialLivenessCoverageRefused pins the G-01 law: liveness coverage is
// per MACHINE, not per model. A registry whose liveness invariants cover some
// state machines but not all is refused at load, naming the uncovered ones.
// Before this gate the global "a liveness kind is registered somewhere" check
// let two covered machines hide a third uncovered one.
func TestPartialLivenessCoverageRefused(t *testing.T) {
	c := invCamp(t)
	_, err := SeedFromModel(c, livenessModelCovering("vault-lifecycle"))
	wantErr(t, err, "protocol model: state machine(s) relay, staking have no "+
		"liveness invariant (one per machine — stage 37)")
	if err != nil && strings.Contains(err.Error(), "vault-lifecycle") {
		t.Errorf("refusal names the COVERED machine: %v", err)
	}
	// The refusal is issued before any write, so it must leave no partial
	// registry state and no template event behind.
	links, lerr := LoadLinks(c)
	if lerr != nil {
		t.Fatal(lerr)
	}
	if got := len(objAt(links, "invariants").O); got != 0 {
		t.Errorf("refused load left %d registry entries, want 0", got)
	}
	if _, serr := os.Stat(linksPath(c)); serr == nil {
		t.Errorf("refused load wrote the registry file")
	}
	events, eerr := c.Events()
	if eerr != nil {
		t.Fatal(eerr)
	}
	for _, e := range events {
		if objStr(e, "type") == "invariants.liveness_template" {
			t.Errorf("refused load logged a liveness template event")
		}
	}
}

// TestZeroLivenessStillSynthesizes pins the other half of the law: a model
// with state machines and NO liveness coverage keeps the existing synthesis
// path, unchanged (one template naming every machine, here INV-4).
func TestZeroLivenessStillSynthesizes(t *testing.T) {
	c := invCamp(t)
	links, err := SeedFromModel(c, livenessMachinesModel())
	if err != nil {
		t.Fatal(err)
	}
	if objStr(objAt(objAt(links, "invariants"), "INV-4"), "synthesized") != "liveness-template" {
		t.Fatalf("template synthesis regressed")
	}
}

// TestFullLivenessCoverageNeedsNoTemplate pins the third branch of the law:
// when every machine already carries a liveness invariant, seeding neither
// synthesizes nor refuses — and re-seeding stays idempotent (no INV-5).
func TestFullLivenessCoverageNeedsNoTemplate(t *testing.T) {
	c := invCamp(t)
	model := livenessMachinesModel()
	invs := objAt(model, "invariants")
	invs.A = append(invs.A, validation.VObj(
		kv("id", validation.VStr("INV-4")),
		kv("statement", validation.VStr(
			"every state machine can advance to its terminal state")),
		kv("kind", validation.VStr("liveness")),
		kv("applies_to", validation.VArr(
			validation.VStr("vault-lifecycle"),
			validation.VStr("relay"),
			validation.VStr("staking"))),
		kv("severity_if_broken", validation.VStr("critical")),
	))
	model.O = validation.SetOrAppend(model.O, "invariants", invs)
	links, err := SeedFromModel(c, model)
	if err != nil {
		t.Fatalf("full coverage refused: %v", err)
	}
	if got := objStr(objAt(objAt(links, "invariants"), "INV-4"),
		"synthesized"); got != "" {
		t.Errorf("full coverage synthesized a template (synthesized=%q)", got)
	}
	links, err = SeedFromModel(c, model)
	if err != nil {
		t.Fatalf("re-seed with full coverage refused: %v", err)
	}
	if hasKey(objAt(links, "invariants"), "INV-5") {
		t.Errorf("re-seed synthesized a duplicate template (INV-5)")
	}
}
