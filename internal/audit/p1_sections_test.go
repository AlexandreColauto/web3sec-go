// P1 audit-parity vectors: every expected value here was produced by the
// LIVE Python twin (web3sec-final) via .scratch/t15/gen_vectors.py and is
// committed in testdata/p1_audit_vectors.json. Each scenario ships the exact
// campaign files the Python audit ran on, so the Go twin audits byte-identical
// state/log bytes; the pretty-printed section oracles are
// json.dumps(section, indent=2, ensure_ascii=False) and are compared against
// validation.DumpIndented (same rendering, same key order).
//
// Python emits one section the Go twin does not implement yet
// (sequence_coverage, section 12, reserved by the P0 plan for a later
// phase): the full-report parity check asserts that exact delta and strips
// only that section from the summary line.
package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"websec/internal/audit/sections"
	"websec/internal/floors"
	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/validation"
)

// kv is the keyed constructor the test fixtures use (non-test code uses
// validation.KV{...}).
func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

type p1Vectors struct {
	PinnedNow  string               `json:"pinned_now"`
	UUIDSeed   string               `json:"uuid_seed"`
	CampaignID string               `json:"campaign_id"`
	Sections   []string             `json:"sections"`
	Scenarios  map[string]p1Fixture `json:"scenarios"`
}

type p1Fixture struct {
	Files          map[string]string          `json:"files"`
	BaselinesFiles map[string]string          `json:"baselines_files"`
	Fingerprints   map[string]json.RawMessage `json:"fingerprints"`
	Sections       map[string]string          `json:"sections"`
	SummaryLine    string                     `json:"summary_line"`
	FullReport     string                     `json:"full_report"`
	Raises         string                     `json:"raises"`
}

func loadP1Vectors(t *testing.T) p1Vectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "p1_audit_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vec p1Vectors
	if err := json.Unmarshal(raw, &vec); err != nil {
		t.Fatal(err)
	}
	if len(vec.Scenarios) == 0 || vec.CampaignID == "" {
		t.Fatalf("vector file is empty: %d scenarios", len(vec.Scenarios))
	}
	return vec
}

func (v p1Vectors) fixture(t *testing.T, name string) p1Fixture {
	t.Helper()
	sc, ok := v.Scenarios[name]
	if !ok {
		t.Fatalf("no scenario %q in testdata/p1_audit_vectors.json", name)
	}
	return sc
}

// materializeP1 writes the scenario's campaign files verbatim and opens the
// campaign (Python's own bytes, so the audit input is identical).
func materializeP1(t *testing.T, vec p1Vectors, sc p1Fixture) *state.Campaign {
	t.Helper()
	root := t.TempDir()
	base := filepath.Join(root, "campaigns", vec.CampaignID)
	for rel, content := range sc.Files {
		p := filepath.Join(base, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	c, err := state.Open(root, vec.CampaignID)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// fixtureForkdiff is the deterministic test double for forkdiff: the
// baselines dir is the materialized fixture and the fingerprint is the one
// the LIVE Python T0 parser produced for that same src tree.
type fixtureForkdiff struct {
	dir string
	fps map[string]validation.Value
}

func (f fixtureForkdiff) BaselinesDir(*state.Campaign) string { return f.dir }

func (f fixtureForkdiff) FingerprintTree(root string) (validation.Value, error) {
	name := filepath.Base(filepath.Dir(root))
	fp, ok := f.fps[name]
	if !ok {
		return validation.VNull(), fmt.Errorf("no fixture fingerprint for %q", name)
	}
	return fp, nil
}

// useBaselines materializes the scenario's baselines fixture and wires the
// seam to it (restored on cleanup).
func useBaselines(t *testing.T, sc p1Fixture) {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range sc.BaselinesFiles {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fps := map[string]validation.Value{}
	for name, raw := range sc.Fingerprints {
		fp, err := validation.ParseOrdered(raw)
		if err != nil {
			t.Fatal(err)
		}
		fps[name] = fp
	}
	sections.SetForkdiff(fixtureForkdiff{dir: dir, fps: fps})
	t.Cleanup(func() { sections.SetForkdiff(nil) })
}

func auditScenario(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	Setup()
	report, err := AuditCampaign(c)
	if err != nil {
		t.Fatal(err)
	}
	return report
}

// sectionVal is one named section of a report.
func sectionVal(t *testing.T, report validation.Value, name string) validation.Value {
	t.Helper()
	secs := objAt(report, "sections")
	for _, s := range secs.O {
		if s.K == name {
			return s.V
		}
	}
	t.Fatalf("report has no section %q", name)
	return validation.Value{}
}

// assertSectionOracle compares one section to its Python rendering.
func assertSectionOracle(t *testing.T, report validation.Value, name, oracle string) {
	t.Helper()
	got := validation.DumpIndented(sectionVal(t, report, name))
	if got != oracle {
		t.Errorf("section %s mismatch\n got: %s\nwant: %s", name, got, oracle)
	}
}

// assertScenarioSections compares every oracle section of a fixture.
func assertScenarioSections(t *testing.T, report validation.Value, sc p1Fixture) {
	t.Helper()
	names := make([]string, 0, len(sc.Sections))
	for name := range sc.Sections {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) == 0 {
		t.Fatal("fixture carries no section oracles")
	}
	for _, name := range names {
		assertSectionOracle(t, report, name, sc.Sections[name])
	}
}

// pythonSummaryWithoutSeqCoverage drops the one section the Go twin does not
// implement yet (sequence_coverage, Python's section 12, reserved for a
// later phase), so the remaining summary text is compared byte-for-byte.
func pythonSummaryWithoutSeqCoverage(line string) string {
	parts := strings.Split(line, ", ")
	kept := make([]string, 0, len(parts))
	for _, p := range parts {
		if strings.HasPrefix(p, "sequence_coverage=") {
			continue
		}
		kept = append(kept, p)
	}
	if len(kept) != len(parts)-1 {
		return line // no sequence_coverage token: compare verbatim
	}
	return strings.Join(kept, ", ")
}

func assertSummaryOracle(t *testing.T, report validation.Value, pythonLine string) {
	t.Helper()
	if pythonLine == "" {
		t.Fatal("fixture carries no summary_line oracle")
	}
	got, want := AuditSummaryLine(report), pythonSummaryWithoutSeqCoverage(pythonLine)
	if got != want {
		t.Errorf("summary mismatch\n got: %s\nwant: %s", got, want)
	}
	if !strings.Contains(pythonLine, "sequence_coverage=") {
		t.Errorf("python summary has no sequence_coverage token: %q", pythonLine)
	}
}

// pythonSectionOrder is the section order of a Python full report (the
// contractual emission order).
func pythonSectionOrder(t *testing.T, fullReport string) []string {
	t.Helper()
	rep, err := validation.ParseOrdered([]byte(fullReport))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, kv := range objAt(rep, "sections").O {
		out = append(out, kv.K)
	}
	if len(out) < 14 {
		t.Fatalf("python report has %d sections, want >= 14", len(out))
	}
	return out
}

// goSectionOrder is Python's order minus the one unported section.
func goSectionOrder(pythonOrder []string) []string {
	out := make([]string, 0, len(pythonOrder))
	for _, name := range pythonOrder {
		if name == "sequence_coverage" {
			continue
		}
		out = append(out, name)
	}
	return out
}

func TestAuditRegistryOrderMatchesPython(t *testing.T) {
	Setup()
	vec := loadP1Vectors(t)
	sc := vec.fixture(t, "parity_p1")
	want := goSectionOrder(pythonSectionOrder(t, sc.FullReport))
	if got := SectionNames(); !reflect.DeepEqual(got, want) {
		t.Fatalf("SectionNames() = %v\nwant %v", got, want)
	}
	if len(want) != 13 {
		t.Fatalf("want 13 registered sections, got %d", len(want))
	}
}

func TestP1EmptyCampaignSectionsMatchPython(t *testing.T) {
	vec := loadP1Vectors(t)
	sc := vec.fixture(t, "empty")
	report := auditScenario(t, materializeP1(t, vec, sc))
	assertScenarioSections(t, report, sc)
	assertSummaryOracle(t, report, sc.SummaryLine)
	flags := sectionOKFlags(report)
	for _, name := range vec.Sections {
		if !flags[name] {
			t.Errorf("section %s not ok on a fresh campaign: %s", name,
				validation.DumpIndented(sectionVal(t, report, name)))
		}
	}
	if !reportOK(report) {
		t.Errorf("fresh campaign not ok: %v", flags)
	}
}

// sectionProblems is one section's problems array as strings.
func sectionProblems(t *testing.T, report validation.Value, name string) []string {
	t.Helper()
	return arrStr(sectionVal(t, report, name), "problems")
}

func TestFloorPolicyScenariosMatchPython(t *testing.T) {
	vec := loadP1Vectors(t)
	names := []string{"floor_clean", "floor_hand_edited", "floor_drifted",
		"floor_clear_only"}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			sc := vec.fixture(t, name)
			report := auditScenario(t, materializeP1(t, vec, sc))
			assertSectionOracle(t, report, "floor_policy",
				sc.Sections["floor_policy"])
			sec := sectionVal(t, report, "floor_policy")
			probs := arrStr(sec, "problems")
			if got := objAt(sec, "ok").B; got != (len(probs) == 0) {
				t.Errorf("ok=%v with %d problems", got, len(probs))
			}
			if name == "floor_hand_edited" && len(probs) != 2 {
				t.Errorf("hand-edited policy yields %d problems, want 2", len(probs))
			}
			if name == "floor_clear_only" && objAt(sec, "checked").I != 2 {
				t.Errorf("clear-only checked = %v, want 2", objAt(sec, "checked").I)
			}
		})
	}
}

// TestFloorPolicyPopulatedViaAPI drives the ported floors package, then
// compares the section to the Python twin's answer for the same operations.
func TestFloorPolicyPopulatedViaAPI(t *testing.T) {
	vec := loadP1Vectors(t)
	sc := vec.fixture(t, "floor_clean")
	c := apiCampaign(t)
	if _, err := floors.SetFloorPolicy(c, "access-control", "E2", "auditor",
		"reviewed the access control table"); err != nil {
		t.Fatal(err)
	}
	if _, err := floors.SetFloorPolicy(c, "oracle-manipulation", "E3", "auditor",
		"oracle risk reviewed twice"); err != nil {
		t.Fatal(err)
	}
	if err := floors.ClearFloorPolicy(c, "oracle-manipulation", "auditor",
		"superseded by the E2 evidence ladder"); err != nil {
		t.Fatal(err)
	}
	report := auditScenario(t, c)
	assertSectionOracle(t, report, "floor_policy", sc.Sections["floor_policy"])
	if probs := sectionProblems(t, report, "floor_policy"); len(probs) != 0 {
		t.Errorf("clean policy flagged: %v", probs)
	}
	if got := objAt(sectionVal(t, report, "floor_policy"), "checked").I; got != 4 {
		t.Errorf("checked = %d, want 4 (1 row + 3 events)", got)
	}
}

func TestStageCompletionsScenariosMatchPython(t *testing.T) {
	vec := loadP1Vectors(t)
	names := []string{"stage_advisory", "stage_done_clean",
		"stage_model_problem"}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			sc := vec.fixture(t, name)
			report := auditScenario(t, materializeP1(t, vec, sc))
			assertSectionOracle(t, report, "stage_completions",
				sc.Sections["stage_completions"])
			sec := sectionVal(t, report, "stage_completions")
			if got := objAt(sec, "checked").I; got != 13 {
				t.Errorf("checked = %d, want 13 (len(CP.PROOFS))", got)
			}
			probs := arrStr(sec, "problems")
			advisory := arrStr(sec, "advisory")
			if got := objAt(sec, "ok").B; got != (len(probs) == 0) {
				t.Errorf("ok=%v with %d problems", got, len(probs))
			}
			if name == "stage_advisory" && (len(advisory) != 1 || len(probs) != 0) {
				t.Errorf("advisory=%v problems=%v, want 1 advisory 0 problems",
					advisory, probs)
			}
			if name == "stage_model_problem" && len(probs) != 1 {
				t.Errorf("problems=%v, want the model-stage paper-over", probs)
			}
		})
	}
}

// TestStageCompletionsViaAPI completes a pipeline stage with the ported
// state API and compares to the Python twin's answer for the same write.
func TestStageCompletionsViaAPI(t *testing.T) {
	vec := loadP1Vectors(t)
	sc := vec.fixture(t, "stage_done_clean")
	c := apiCampaign(t)
	if err := c.SetStage("dedup", "done", validation.VNull(), nil); err != nil {
		t.Fatal(err)
	}
	report := auditScenario(t, c)
	assertSectionOracle(t, report, "stage_completions",
		sc.Sections["stage_completions"])
	sec := sectionVal(t, report, "stage_completions")
	if probs := arrStr(sec, "problems"); len(probs) != 0 {
		t.Errorf("done stage flagged: %v", probs)
	}
	if adv := arrStr(sec, "advisory"); len(adv) != 0 {
		t.Errorf("advisory=%v, want empty for a satisfied proof", adv)
	}
}

// apiCampaign is a fresh campaign built through the ported Go API (the
// cross-twin build path the populated-section tests use).
func apiCampaign(t *testing.T) *state.Campaign {
	t.Helper()
	Setup()
	c, err := state.Init(t.TempDir(), "Acme",
		state.InitOpts{CampaignID: "C-apibuild01"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// parseOracle decodes one pretty section oracle back into a Value.
func parseOracle(t *testing.T, oracle string) validation.Value {
	t.Helper()
	v, err := validation.ParseOrdered([]byte(oracle))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestBaselinesScenariosMatchPython(t *testing.T) {
	vec := loadP1Vectors(t)
	names := []string{"baselines_absent_dir", "baselines_clean",
		"baselines_mismatch", "baselines_missing_on_disk",
		"baselines_not_listed", "baselines_malformed",
		"baselines_meta_not_object"}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			sc := vec.fixture(t, name)
			useBaselines(t, sc)
			report := auditScenario(t, materializeP1(t, vec, sc))
			assertSectionOracle(t, report, "baselines",
				sc.Sections["baselines"])
			sec := sectionVal(t, report, "baselines")
			probs := arrStr(sec, "problems")
			if got := objAt(sec, "ok").B; got != (len(probs) == 0) {
				t.Errorf("ok=%v with %d problems", got, len(probs))
			}
			if name == "baselines_clean" && objAt(sec, "checked").I != 1 {
				t.Errorf("clean baseline checked = %v, want 1",
					objAt(sec, "checked").I)
			}
		})
	}
}

// TestBaselinesUnreadableJSONTextIsHostSpecific pins the one baselines
// divergence: the problem text embeds the host JSON decoder's message
// (CPython JSONDecodeError vs Go encoding/json), so the ported prefix is
// compared byte-for-byte and the embedded tail is host-specific.
func TestBaselinesUnreadableJSONTextIsHostSpecific(t *testing.T) {
	vec := loadP1Vectors(t)
	cases := map[string]string{
		"baselines_unreadable":          "baseline manifest unreadable (manifest.json): ",
		"baselines_unreadable_baseline": "baseline 'acme-vault': unreadable (",
	}
	for name, prefix := range cases {
		t.Run(name, func(t *testing.T) {
			sc := vec.fixture(t, name)
			useBaselines(t, sc)
			report := auditScenario(t, materializeP1(t, vec, sc))
			got := sectionProblems(t, report, "baselines")
			oracle := arrStr(parseOracle(t, sc.Sections["baselines"]), "problems")
			if len(got) != 1 || len(oracle) != 1 {
				t.Fatalf("problems = %v / oracle %v, want one each", got, oracle)
			}
			if !strings.HasPrefix(got[0], prefix) {
				t.Errorf("go problem %q lacks the ported prefix %q", got[0], prefix)
			}
			if !strings.HasPrefix(oracle[0], prefix) {
				t.Errorf("python oracle %q lacks the ported prefix %q",
					oracle[0], prefix)
			}
		})
	}
}

func TestInvariantVerificationScenariosMatchPython(t *testing.T) {
	vec := loadP1Vectors(t)
	names := []string{"inv_clean", "inv_no_verified_by",
		"inv_unknown_artifact", "inv_no_event"}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			sc := vec.fixture(t, name)
			report := auditScenario(t, materializeP1(t, vec, sc))
			assertSectionOracle(t, report, "invariant_verification",
				sc.Sections["invariant_verification"])
			sec := sectionVal(t, report, "invariant_verification")
			probs := arrStr(sec, "problems")
			if got := objAt(sec, "checked").I; got != 1 {
				t.Errorf("checked = %d, want 1 registry entry", got)
			}
			if got := objAt(sec, "ok").B; got != (len(probs) == 0) {
				t.Errorf("ok=%v with %d problems", got, len(probs))
			}
		})
	}
}

// TestInvariantVerificationViaAPI registers an artifact and verifies an
// invariant through the ported invariants API, then compares to the Python
// twin's answer for the same writes.
func TestInvariantVerificationViaAPI(t *testing.T) {
	vec := loadP1Vectors(t)
	sc := vec.fixture(t, "inv_clean")
	c := apiCampaign(t)
	p := filepath.Join(c.ArtifactsDir, "evidence.md")
	if err := os.WriteFile(p, []byte("checked against code\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	artID, err := c.RegisterArtifact("other", p, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	entry := validation.VObj(
		kv("test_status", validation.VStr("untested")),
		kv("status", validation.VStr("UNVERIFIED")),
	)
	links := validation.VObj(kv("invariants", validation.VObj(kv("INV-1", entry))))
	if err := validation.WriteJson(filepath.Join(c.ArtifactsDir,
		"invariant_links.json"), links, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := invariants.VerifyInvariantStatement(c, "INV-1", artID); err != nil {
		t.Fatal(err)
	}
	report := auditScenario(t, c)
	assertSectionOracle(t, report, "invariant_verification",
		sc.Sections["invariant_verification"])
	if probs := sectionProblems(t, report, "invariant_verification"); len(probs) != 0 {
		t.Errorf("verified invariant flagged: %v", probs)
	}
}

// staticRelations / failingRelations are the deterministic relations seam
// doubles (the P3 module is not ported; the wiring is what is under test).
type staticRelations struct{ sec validation.Value }

func (s staticRelations) VerifyRelations(*state.Campaign) (validation.Value, error) {
	return s.sec, nil
}

type failingRelations struct{}

func (failingRelations) VerifyRelations(*state.Campaign) (validation.Value, error) {
	return validation.VNull(), errors.New("boom")
}

// staticProbeSurface / failingProbeSurface are the probe-surface doubles.
type staticProbeSurface struct{ sec validation.Value }

func (s staticProbeSurface) AuditSurface(*state.Campaign) (validation.Value, error) {
	return s.sec, nil
}

type failingProbeSurface struct{}

func (failingProbeSurface) AuditSurface(*state.Campaign) (validation.Value, error) {
	return validation.VNull(), errors.New("boom")
}

func TestRelationsSeam(t *testing.T) {
	vec := loadP1Vectors(t)
	sc := vec.fixture(t, "empty")
	// (a) the default seam reproduces Python's empty-campaign section.
	report := auditScenario(t, materializeP1(t, vec, sc))
	assertSectionOracle(t, report, "relations", sc.Sections["relations"])
	// (b) a populated section from the seam passes through unchanged.
	populated := validation.VObj(
		kv("checked", validation.VInt(2)),
		kv("problems", validation.VArr(validation.VStr("REL-1: drift"))),
		kv("ok", validation.VBool(false)),
	)
	sections.SetRelations(staticRelations{sec: populated})
	t.Cleanup(func() { sections.SetRelations(nil) })
	got := sectionVal(t, auditScenario(t, materializeP1(t, vec, sc)), "relations")
	if validation.DumpIndented(got) != validation.DumpIndented(populated) {
		t.Errorf("relations passthrough = %s", validation.DumpIndented(got))
	}
	// (c) Python does not guard section 7: a raise escapes audit_campaign.
	sections.SetRelations(failingRelations{})
	if _, err := AuditCampaign(materializeP1(t, vec, sc)); err == nil ||
		err.Error() != "boom" {
		t.Errorf("relations error = %v, want boom (Python's ValueError escapes)", err)
	}
}

func TestProbeSurfaceSeam(t *testing.T) {
	vec := loadP1Vectors(t)
	sc := vec.fixture(t, "empty")
	// (a) default = Python's no-surface dict (note text included).
	report := auditScenario(t, materializeP1(t, vec, sc))
	assertSectionOracle(t, report, "probe_surface", sc.Sections["probe_surface"])
	// (b) a populated section from the seam passes through unchanged.
	populated := validation.VObj(
		kv("checked", validation.VInt(3)),
		kv("problems", validation.VArr()),
		kv("ok", validation.VBool(true)),
		kv("rederived_rows", validation.VInt(3)),
	)
	sections.SetProbeSurfaceAudit(staticProbeSurface{sec: populated})
	t.Cleanup(func() { sections.SetProbeSurfaceAudit(nil) })
	got := sectionVal(t, auditScenario(t, materializeP1(t, vec, sc)), "probe_surface")
	if validation.DumpIndented(got) != validation.DumpIndented(populated) {
		t.Errorf("probe_surface passthrough = %s", validation.DumpIndented(got))
	}
	// (c) a raise becomes Python's degraded entry, byte-for-byte.
	failed := vec.fixture(t, "probe_surface_failed")
	sections.SetProbeSurfaceAudit(failingProbeSurface{})
	report = auditScenario(t, materializeP1(t, vec, failed))
	assertSectionOracle(t, report, "probe_surface",
		failed.Sections["probe_surface"])
	sec := sectionVal(t, report, "probe_surface")
	if objAt(sec, "ok").B {
		t.Errorf("degraded probe surface section must be ok=false")
	}
	if objAt(sec, "checked").Kind != validation.Null {
		t.Errorf("degraded checked = %v, want null", objAt(sec, "checked"))
	}
}

// TestP1FullReportParity is the cross-twin check: the P1-shaped campaign
// (init + floor policy + stage completion + invariant + baseline) is
// materialized from the Python twin's own files, audited, and the full
// report is compared section-for-section against the LIVE Python report.
// The only permitted delta is Python's section 12 (sequence_coverage), which
// the P0 plan reserves for a later phase.
func TestP1FullReportParity(t *testing.T) {
	vec := loadP1Vectors(t)
	for _, name := range []string{"parity_p1", "parity_p1_problem"} {
		t.Run(name, func(t *testing.T) {
			sc := vec.fixture(t, name)
			useBaselines(t, sc)
			report := auditScenario(t, materializeP1(t, vec, sc))
			py := parseOracle(t, sc.FullReport)
			if got := objStr(report, "campaign_id"); got != objStr(py, "campaign_id") {
				t.Fatalf("campaign_id = %q, want %q", got, objStr(py, "campaign_id"))
			}
			var pythonOnly []string
			shared := 0
			for _, kv := range objAt(py, "sections").O {
				if kv.K == "sequence_coverage" {
					pythonOnly = append(pythonOnly, kv.K)
					continue
				}
				shared++
				assertSectionOracle(t, report, kv.K, validation.DumpIndented(kv.V))
			}
			if !reflect.DeepEqual(pythonOnly, []string{"sequence_coverage"}) {
				t.Errorf("python-only sections = %v, want [sequence_coverage]", pythonOnly)
			}
			if shared != 13 {
				t.Errorf("shared sections = %d, want 13", shared)
			}
			if reportOK(report) != (objAt(py, "ok").Kind == validation.Bool &&
				objAt(py, "ok").B) {
				t.Errorf("overall ok disagrees with the Python twin")
			}
			assertSummaryOracle(t, report, sc.SummaryLine)
			// one whole-report comparison: canonical JSON of the Go report
			// must equal the Python report minus the unported section.
			got := validation.CanonCompact(report)
			want := validation.CanonCompact(withoutSection(py, "sequence_coverage"))
			if got != want {
				t.Errorf("full report mismatch\n got: %s\nwant: %s", got, want)
			}
		})
	}
}

// withoutSection drops one named section from a report (the documented
// sequence_coverage delta).
func withoutSection(report validation.Value, name string) validation.Value {
	out := make([]validation.KV, 0, len(report.O))
	for _, top := range report.O {
		if top.K != "sections" {
			out = append(out, top)
			continue
		}
		secs := make([]validation.KV, 0, len(top.V.O))
		for _, s := range top.V.O {
			if s.K != name {
				secs = append(secs, s)
			}
		}
		out = append(out, validation.KV{K: top.K, V: validation.VObj(secs...)})
	}
	return validation.VObj(out...)
}
