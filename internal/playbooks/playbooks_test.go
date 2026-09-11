// playbooks_test.go: 1:1 ports of tests/test_playbooks.py (the loader /
// validation half). The three model-role stage tests and the proposer-bundle
// directive test target adapter/model_boundary/roles — unported P3 interface
// modules — and are listed as deviations in the task report.
package playbooks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/pipeline"
	"websec/internal/validation"
)

var shippedClasses = []string{
	"access-control", "bridge-message", "economic-invariant",
	"frontend-injection", "infra-boundary", "oracle-manipulation",
	"precision-rounding", "reentrancy",
	"share-price-inflation", "upgrade-initializer",
}

// useDir points the loader at dir for one test.
func useDir(t *testing.T, dir string) {
	t.Helper()
	prev := PlaybooksDir
	SetPlaybooksDir(dir)
	t.Cleanup(func() { SetPlaybooksDir(prev) })
}

// writePB is _write_pb: a tmp playbooks dir holding one class file.
func writePB(t *testing.T, text string) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "playbooks")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "share-price-inflation.yaml"),
		[]byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	return d
}

// shippedText reads one shipped playbook from the embedded pack.
func shippedText(t *testing.T, name string) string {
	t.Helper()
	prev := PlaybooksDir
	SetPlaybooksDir("")
	defer SetPlaybooksDir(prev)
	raw, err := readFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestAvailablePlaybooksAreExactlyTheShippedTen(t *testing.T) {
	got, err := AvailablePlaybooks()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != strings.Join(shippedClasses, ",") {
		t.Fatalf("available_playbooks() = %v, want %v", got, shippedClasses)
	}
	if len(got) != 10 {
		t.Fatalf("expected 10 shipped playbooks, got %d", len(got))
	}
}

func TestShippedPlaybooksLoadAndValidate(t *testing.T) {
	for _, cls := range shippedClasses {
		t.Run(cls, func(t *testing.T) {
			pb, found, err := PlaybookForClass(cls)
			if err != nil {
				t.Fatalf("playbook_for_class(%q): %v", cls, err)
			}
			if !found {
				t.Fatalf("playbook_for_class(%q) = miss, want a playbook", cls)
			}
			if got := objAt(pb, "bug_class"); got.Kind != validation.Str || got.S != cls {
				t.Fatalf("bug_class = %v, want %q", got, cls)
			}
			if objAt(pb, "title").Kind != validation.Str {
				t.Fatal("playbook carries no title string")
			}
		})
	}
}

func TestMissingPlaybookIsANormalMiss(t *testing.T) {
	pb, found, err := PlaybookForClass("no-such-class")
	if err != nil {
		t.Fatalf("missing playbook must not error: %v", err)
	}
	if found {
		t.Fatalf("found = true for a missing class (value %v)", pb)
	}
	if pb.Kind != validation.Null {
		t.Fatalf("miss value = %v, want None", pb)
	}
}

func TestPlaybookForClassIsTraversalSafe(t *testing.T) {
	// The _CLASS_RE guard pins the router's input shape; the shaped paths are
	// planted on disk so the guard is pinned by BEHAVIOR, not by the repo's
	// file layout.
	base := t.TempDir()
	d := filepath.Join(base, "playbooks")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	shipped := shippedText(t, "access-control.yaml")
	plant := func(path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// "../etc/passwd" escapes the playbooks dir one level: plant it outside.
	plant(filepath.Join(base, "etc", "passwd.yaml"),
		strings.Replace(shipped, "bug_class: access-control",
			"bug_class: passwd", 1))
	plant(filepath.Join(d, "a", "b.yaml"),
		strings.Replace(shipped, "bug_class: access-control",
			"bug_class: b", 1))
	plant(filepath.Join(d, "UPPER.yaml"), shipped)
	// the positive control: the same tree does serve the class it names.
	plant(filepath.Join(d, "access-control.yaml"), shipped)
	useDir(t, d)
	for _, bad := range []string{"../etc/passwd", "UPPER", "a/b"} {
		pb, found, err := PlaybookForClass(bad)
		if err != nil {
			t.Fatalf("playbook_for_class(%q) errored: %v", bad, err)
		}
		if found {
			t.Fatalf("playbook_for_class(%q) resolved to %v, want a miss", bad, pb)
		}
	}
	// positive control: the same tree does serve the class it names.
	if _, found, _ := PlaybookForClass("access-control"); !found {
		t.Fatal("control: access-control must resolve from the planted pack")
	}
}

func TestTamperedPlaybookFailsLoud(t *testing.T) {
	d := writePB(t, "bug_class: broken-class\ntitle: short\n")
	useDir(t, d)
	if _, _, err := PlaybookForClass("share-price-inflation"); err == nil {
		t.Fatal("schema-invalid playbook must fail loud")
	} else if !strings.Contains(err.Error(), "playbook validation failed") {
		t.Fatalf("error = %v, want a schema failure", err)
	}
}

func TestUnparseablePlaybookFailsLoud(t *testing.T) {
	d := writePB(t, "bug_class: broken-class\n  bad: [indentation\n")
	useDir(t, d)
	_, _, err := PlaybookForClass("share-price-inflation")
	if err == nil {
		t.Fatal("unparseable playbook must fail loud")
	}
	if !strings.Contains(err.Error(), "not valid YAML") {
		t.Fatalf("error = %v, want a YAML failure", err)
	}
}

func TestAvailablePlaybooksSkipBrokenFiles(t *testing.T) {
	d := writePB(t, "bug_class: broken-class\ntitle: short\n")
	useDir(t, d)
	got, err := AvailablePlaybooks()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("available_playbooks() = %v, want []", got)
	}
}

func TestAvailablePlaybooksFailsLoudOnFilenameClassMismatch(t *testing.T) {
	d := filepath.Join(t.TempDir(), "playbooks")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	shipped := shippedText(t, "access-control.yaml")
	if err := os.WriteFile(filepath.Join(d, "wrong-name.yaml"),
		[]byte(shipped), 0o644); err != nil {
		t.Fatal(err)
	}
	useDir(t, d)
	_, err := AvailablePlaybooks()
	if err == nil {
		t.Fatal("a filename/class mismatch must fail loud")
	}
	msg := err.Error()
	if !strings.Contains(msg, "wrong-name.yaml") {
		t.Fatalf("error %q does not name the file", msg)
	}
	if !strings.Contains(msg, "access-control") {
		t.Fatalf("error %q does not name the declared class", msg)
	}
}

func TestModelRoleStagesAreNotPipelineStages(t *testing.T) {
	// Model-role stages are invoked via the boundary, not the deterministic
	// stage graph: pipeline.STAGE_DEPS must not reference them.
	graph := map[string]bool{}
	for id, deps := range pipeline.StageDeps {
		graph[id] = true
		for _, d := range deps {
			graph[d] = true
		}
	}
	for _, stage := range []string{"model-proposer", "model-critic",
		"model-reproducer"} {
		if graph[stage] {
			t.Fatalf("%s leaked into the pipeline stage graph — model-role "+
				"stages are boundary-invoked, not deterministic pipeline stages",
				stage)
		}
	}
	if len(pipeline.StageDeps) == 0 {
		t.Fatal("control: STAGE_DEPS must not be empty")
	}
}

// ---- adversarial-simulation mode (spec §4.1) -----------------------------

// simPB is _sim_pb_yaml: a minimal valid simulation-mode playbook.
const simPB = `
bug_class: share-price-inflation
title: Simulation-mode fixture playbook
description: >-
  Fixture playbook for adversarial-simulation loader checks; not a real prior.
investigation_mode: adversarial-simulation
invariants:
  - id: INV-SPI-PRORATA
    statement: Depositors receive shares pro-rata to assets at entry.
assumption_templates:
  - id: AT-SPI-FIXTURE
    type: economic
    statement: Fixture assumption template for loader tests only.
    blocking: true
hunt_order:
  - step: 1
    tool_id: fixture-tool
    purpose: Fixture hunt step for loader tests only.
simulation:
  actors:
    - name: attacker
      behavior_class: adversarial
      capital: dust entry plus large off-path inflow
      behavior: profit-maximizing
    - name: victim
      behavior_class: benign-rational
      capital: real deposit at documented terms
      behavior: deposits because the mechanism is documented as fair
  action_space: deposit, withdraw, redeem, direct ERC20 transfer to vault
  ordering_freedoms: cross-tx order of entry, inflow, deposit, redemption
  expectation_violated: INV-SPI-PRORATA
`

func TestSimulationModePlaybookLoads(t *testing.T) {
	useDir(t, writePB(t, simPB))
	pb, found, err := PlaybookForClass("share-price-inflation")
	if err != nil || !found {
		t.Fatalf("load: found=%v err=%v", found, err)
	}
	if got := objAt(pb, "investigation_mode"); got.Kind != validation.Str ||
		got.S != "adversarial-simulation" {
		t.Fatalf("investigation_mode = %v", got)
	}
	sim := objAt(pb, "simulation")
	if got := objAt(sim, "expectation_violated"); got.S != "INV-SPI-PRORATA" {
		t.Fatalf("expectation_violated = %v", got)
	}
}

func TestModeWithoutSimulationBlockFails(t *testing.T) {
	text := simPB[:strings.Index(simPB, "simulation:")]
	useDir(t, writePB(t, text))
	if _, _, err := PlaybookForClass("share-price-inflation"); err == nil {
		t.Fatal("adversarial-simulation without a simulation block must fail")
	}
}

func TestSimulationBlockWithoutModeFails(t *testing.T) {
	text := strings.Replace(simPB,
		"investigation_mode: adversarial-simulation\n", "", 1)
	useDir(t, writePB(t, text))
	if _, _, err := PlaybookForClass("share-price-inflation"); err == nil {
		t.Fatal("a simulation block without the mode must fail")
	}
}

func TestDuplicateActorNamesFail(t *testing.T) {
	text := strings.Replace(simPB, "    - name: victim\n", "    - name: attacker\n", 1)
	useDir(t, writePB(t, text))
	_, _, err := PlaybookForClass("share-price-inflation")
	if err == nil {
		t.Fatal("duplicate actor names must fail")
	}
	if !strings.Contains(err.Error(), "duplicate actor") {
		t.Fatalf("error = %v, want a duplicate-actor failure", err)
	}
}

func TestAllAdversarialCastFails(t *testing.T) {
	text := strings.Replace(simPB, "      behavior_class: benign-rational\n",
		"      behavior_class: adversarial\n", 1)
	useDir(t, writePB(t, text))
	_, _, err := PlaybookForClass("share-price-inflation")
	if err == nil {
		t.Fatal("an all-adversarial cast must fail")
	}
	if !strings.Contains(err.Error(), "at least one") {
		t.Fatalf("error = %v, want the cast-composition failure", err)
	}
}

func TestExpectationUnknownInvariantFails(t *testing.T) {
	text := strings.Replace(simPB, "  expectation_violated: INV-SPI-PRORATA",
		"  expectation_violated: INV-NOT-DECLARED", 1)
	useDir(t, writePB(t, text))
	_, _, err := PlaybookForClass("share-price-inflation")
	if err == nil {
		t.Fatal("an expectation naming no declared invariant must fail")
	}
	if !strings.Contains(err.Error(), "must name an invariant id") {
		t.Fatalf("error = %v, want the expectation-reference failure", err)
	}
}

func TestCuratedInvariantIDsIsUnionOverPlaybooks(t *testing.T) {
	expected := map[string]bool{}
	classes, err := AvailablePlaybooks()
	if err != nil {
		t.Fatal(err)
	}
	for _, cls := range classes {
		pb, found, perr := PlaybookForClass(cls)
		if perr != nil || !found {
			t.Fatalf("playbook %s: found=%v err=%v", cls, found, perr)
		}
		for _, inv := range listAt(pb, "invariants") {
			if id := objAt(inv, "id"); id.Kind == validation.Str {
				expected[id.S] = true
			}
		}
	}
	got := CuratedInvariantIDs()
	if len(got) != len(expected) {
		t.Fatalf("curated ids = %v, want %d entries", got, len(expected))
	}
	for _, id := range got {
		if !expected[id] {
			t.Fatalf("curated id %q is not declared by any playbook", id)
		}
	}
	if !containsStr(got, "INV-RE-CEI-ORDERING") {
		t.Fatalf("INV-RE-CEI-ORDERING missing from %v", got)
	}
	for _, id := range got {
		if len(id) > 4 && allDigits(id[4:]) {
			t.Fatalf("curated id %q has a bare numeric target-doc shape", id)
		}
	}
}

func TestShippedSimulationPlaybooksCarryModeAndExpectation(t *testing.T) {
	cases := map[string]string{
		"share-price-inflation": "INV-SPI-PRORATA",
		"economic-invariant":    "INV-EI-NO-PROFIT-AT-OTHERS-EXPENSE",
	}
	for cls, expectation := range cases {
		t.Run(cls, func(t *testing.T) {
			pb, found, err := PlaybookForClass(cls)
			if err != nil || !found {
				t.Fatalf("load: found=%v err=%v", found, err)
			}
			if got := objAt(pb, "investigation_mode"); got.S != "adversarial-simulation" {
				t.Fatalf("investigation_mode = %v", got)
			}
			sim := objAt(pb, "simulation")
			classes := map[string]bool{}
			for _, a := range listAt(sim, "actors") {
				classes[objAt(a, "behavior_class").S] = true
			}
			if !classes["adversarial"] || !classes["benign-rational"] ||
				len(classes) != 2 {
				t.Fatalf("actor classes = %v", classes)
			}
			if got := objAt(sim, "expectation_violated").S; got != expectation {
				t.Fatalf("expectation_violated = %q, want %q", got, expectation)
			}
			ids := map[string]bool{}
			for _, inv := range listAt(pb, "invariants") {
				ids[objAt(inv, "id").S] = true
			}
			if !ids[expectation] {
				t.Fatalf("expectation %q is not among the declared invariants %v",
					expectation, sortedKeys(ids))
			}
		})
	}
}

// ---- embed byte-identity -------------------------------------------------

// The former twin byte-identity acceptance check moved to
// assets.TestAssetPackManifest (committed SHA-256 manifest, no external tree).

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
