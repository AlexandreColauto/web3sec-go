// corpus_test.go: the L6a tripwires over the VENDORED minicertora corpus.
//
// The vendored tree under testdata/minicertora-corpus/ is data, not code:
// eight target directories copied VERBATIM from
// /home/xand/Projects/minicertora/minicertora/corpus/targets/, pinned by
// VENDOR.json (upstream path + git sha + per-file sha256). These tests assert
// SELF-CONSISTENCY only — recorded hashes equal the bytes on disk, the
// expected.json envelopes conform to the vocabulary the tool documents
// (verdicts, reason codes, solc pin, tool flags). They never exec the
// minicertora binary and never assert tool behavior; the live tripwire is an
// operator script (scorecard, Task 5).
//
// testdata/ is read directly from the package directory (Go tests may) — it
// is git-tracked but NOT a go:embed pack, so it does not ride
// assets/testdata/asset_manifest.json. assets/ tests stay unaffected.
package harness

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const corpusTestdataDir = "testdata/minicertora-corpus"

// corpusTargets is the pinned vendoring set: exactly these eight slugs and no
// others. Adding a ninth target is a deliberate revendoring act (update the
// list, VENDOR.json and the sha pin together).
var corpusTargets = []string{
	"access-control-mint",
	"invariant-cap",
	"packed-storage-rejected",
	"privilege-escalation",
	"reentrancy-double-payout",
	"rounding-drain",
	"tx-origin-auth",
	"wrap-unchecked",
}

// corpusUpstreamSHA is the upstream commit vendored on 2026-09-12
// (`git -C /home/xand/Projects/minicertora rev-parse HEAD`). Pinned as a
// literal so an upstream move is a conscious revendoring, never a silent
// drift; the self-consistency test compares VENDOR.json against it.
const corpusUpstreamSHA = "5a35567d0aaa79005006825a7a10b964f6fe4e4e"

type vendorFile struct {
	Files map[string]string `json:"files"` // rel name -> "sha256:<hex>"
}

type vendorManifest struct {
	Upstream    string                `json:"upstream"`
	UpstreamSHA string                `json:"upstream_sha"`
	Vendored    string                `json:"vendored"`
	Targets     map[string]vendorFile `json:"targets"`
}

func readVendorManifest(t *testing.T) vendorManifest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(corpusTestdataDir, "VENDOR.json"))
	if err != nil {
		t.Fatalf("read VENDOR.json: %v", err)
	}
	var man vendorManifest
	if err := json.Unmarshal(raw, &man); err != nil {
		t.Fatalf("parse VENDOR.json: %v", err)
	}
	return man
}

func sha256HexOf(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func containsString(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

// TestCorpusVendoringSelfConsistent walks the vendored tree and checks it
// against VENDOR.json in both directions: every vendored file's bytes hash to
// its recorded sha256, no directory or file is unlisted, and no record is
// stale. It also pins the provenance envelope (upstream path, sha format,
// vendoring date) and the file census (8 targets, 33 files).
func TestCorpusVendoringSelfConsistent(t *testing.T) {
	man := readVendorManifest(t)

	if man.Upstream != "/home/xand/Projects/minicertora" {
		t.Errorf("upstream = %q, want /home/xand/Projects/minicertora", man.Upstream)
	}
	if man.Vendored != "2026-09-12" {
		t.Errorf("vendored = %q, want 2026-09-12", man.Vendored)
	}
	if man.UpstreamSHA != corpusUpstreamSHA {
		t.Errorf("upstream_sha = %q, want the pinned %q", man.UpstreamSHA, corpusUpstreamSHA)
	}
	if len(man.UpstreamSHA) != 40 {
		t.Errorf("upstream_sha %q is not a 40-char git sha", man.UpstreamSHA)
	} else if _, err := hex.DecodeString(man.UpstreamSHA); err != nil {
		t.Errorf("upstream_sha %q is not hex: %v", man.UpstreamSHA, err)
	}
	if len(man.Targets) != 8 {
		t.Fatalf("VENDOR.json lists %d targets, want 8", len(man.Targets))
	}
	for _, name := range corpusTargets {
		if _, ok := man.Targets[name]; !ok {
			t.Errorf("target %q missing from VENDOR.json", name)
		}
	}
	for name := range man.Targets {
		if !containsString(corpusTargets, name) {
			t.Errorf("VENDOR.json lists unlisted target %q", name)
		}
	}

	dirs, err := os.ReadDir(corpusTestdataDir)
	if err != nil {
		t.Fatalf("read %s: %v", corpusTestdataDir, err)
	}
	onDisk := map[string]bool{}
	total := 0
	for _, d := range dirs {
		if !d.IsDir() {
			continue // VENDOR.json itself, and nothing else
		}
		onDisk[d.Name()] = true
		rec, ok := man.Targets[d.Name()]
		if !ok {
			t.Fatalf("directory %q is not listed in VENDOR.json", d.Name())
		}
		remaining := map[string]string{}
		for rel, sum := range rec.Files {
			remaining[rel] = sum
		}
		entries, err := os.ReadDir(filepath.Join(corpusTestdataDir, d.Name()))
		if err != nil {
			t.Fatalf("read target %q: %v", d.Name(), err)
		}
		for _, f := range entries {
			if f.IsDir() {
				t.Errorf("unexpected subdirectory %s/%s", d.Name(), f.Name())
				continue
			}
			total++
			rel := f.Name()
			want, listed := remaining[rel]
			if !listed {
				t.Errorf("unlisted vendored file %s/%s", d.Name(), rel)
				continue
			}
			delete(remaining, rel)
			got := "sha256:" + sha256HexOf(t, filepath.Join(corpusTestdataDir, d.Name(), rel))
			if got != want {
				t.Errorf("%s/%s sha256 = %s, want %s", d.Name(), rel, got, want)
			}
		}
		for rel := range remaining {
			t.Errorf("VENDOR.json lists %s/%s but the file is missing", d.Name(), rel)
		}
	}
	for name := range man.Targets {
		if !onDisk[name] {
			t.Errorf("VENDOR.json lists target %q but the directory is missing", name)
		}
	}
	if total != 33 {
		t.Errorf("vendored corpus holds %d files, want 33", total)
	}
}

// corpusRule is the per-rule envelope of the vendored expected.json files
// (shape pinned in the plan's source-of-truth pointers; extra keys the
// envelopes carry — replay, essential_witness, notes — are not asserted here).
type corpusRule struct {
	RuleID                     string   `json:"rule_id"`
	ExpectedVerdict            string   `json:"expected_verdict"`
	ExpectedReasonCode         *string  `json:"expected_reason_code"`
	ExpectedAssumptionsInclude []string `json:"expected_assumptions_include"`
	ExpectedInvariant          *struct {
		PerFunction     map[string]string `json:"per_function"`
		Init            *string           `json:"init"`
		WitnessFunction *string           `json:"witness_function"`
	} `json:"expected_invariant"`
}

type corpusExpected struct {
	Target            string       `json:"target"`
	BugClass          string       `json:"bug_class"`
	Sol               string       `json:"sol"`
	Spec              string       `json:"spec"`
	Solc              string       `json:"solc"`
	ToolFlags         []string     `json:"tool_flags"`
	Status            string       `json:"status"`
	ExpectedErrorCode *string      `json:"expected_error_code"`
	Rules             []corpusRule `json:"rules"`
}

func readCorpusExpected(t *testing.T, target string) corpusExpected {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(corpusTestdataDir, target, "expected.json"))
	if err != nil {
		t.Fatalf("read %s/expected.json: %v", target, err)
	}
	var exp corpusExpected
	if err := json.Unmarshal(raw, &exp); err != nil {
		t.Fatalf("parse %s/expected.json: %v", target, err)
	}
	return exp
}

// TestCorpusExpectationsConform asserts the vocabulary conformance of every
// vendored envelope: the solc pin, the mandatory --loop-bound flag, the
// target/sol/spec self-naming, and — per rule — a documented verdict with an
// empty-or-closed-set reason code. Three targets are `unwritable` (an honest
// refusal carries expected_error_code, not rules); the rest are `expected`.
func TestCorpusExpectationsConform(t *testing.T) {
	verdicts := []string{"PROVEN", "VIOLATED", "UNKNOWN"}
	for _, target := range corpusTargets {
		t.Run(target, func(t *testing.T) {
			exp := readCorpusExpected(t, target)
			if exp.Target != target {
				t.Errorf("target = %q, want %q", exp.Target, target)
			}
			if exp.BugClass == "" {
				t.Error("bug_class is empty")
			}
			if exp.Solc != "0.8.36" {
				t.Errorf("solc = %q, want the vendored pin 0.8.36", exp.Solc)
			}
			if !containsString(exp.ToolFlags, "--loop-bound") {
				t.Errorf("tool_flags %v lacks --loop-bound", exp.ToolFlags)
			}
			for _, rel := range []string{exp.Sol, exp.Spec} {
				if _, err := os.Stat(filepath.Join(corpusTestdataDir, target, rel)); err != nil {
					t.Errorf("referenced file %q: %v", rel, err)
				}
			}
			switch exp.Status {
			case "expected":
				if len(exp.Rules) == 0 {
					t.Error("status expected but no rules")
				}
			case "unwritable":
				// An honest refusal: the target documents WHY it cannot be
				// written, with a closed-set reason code and no rules.
				if exp.ExpectedErrorCode == nil || !IsReasonCode(*exp.ExpectedErrorCode) {
					t.Errorf("unwritable target carries expected_error_code %v, want a closed-set code",
						exp.ExpectedErrorCode)
				}
			default:
				// Deviation from the plan's `status=="expected"` literal:
				// the shipped corpus has three `unwritable` envelopes
				// (rounding-drain, reentrancy-double-payout,
				// packed-storage-rejected). The CODE wins; the plan's
				// intent — every envelope conforms — is kept.
				t.Errorf("status = %q, want expected or unwritable", exp.Status)
			}
			for i, r := range exp.Rules {
				if r.RuleID == "" {
					t.Errorf("rule %d: empty rule_id", i)
				}
				if !containsString(verdicts, r.ExpectedVerdict) {
					t.Errorf("rule %q: verdict %q not in %v", r.RuleID, r.ExpectedVerdict, verdicts)
				}
				if r.ExpectedReasonCode != nil {
					if !IsReasonCode(*r.ExpectedReasonCode) {
						t.Errorf("rule %q: reason code %q outside the closed set",
							r.RuleID, *r.ExpectedReasonCode)
					}
				}
			}
		})
	}
}

// TestCorpusInvariantCapPinned pins the invariant-cap envelope verbatim: the
// one target whose rule is an `invariant` declaration (cap.mspec:
// `invariant cap_respected() { assert total <= cap; }`) must record a PROVEN
// verdict with NO reason code and the full induction detail. The verdict is
// PROVEN exactly because the tool's `bounds.loop_bound_exhaustive` is true
// (Task 4's semantics): the unrolling proved its bound on every path and both
// entrypoints preserve the invariant.
func TestCorpusInvariantCapPinned(t *testing.T) {
	exp := readCorpusExpected(t, "invariant-cap")
	if exp.Status != "expected" {
		t.Fatalf("status = %q, want expected", exp.Status)
	}
	if len(exp.Rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(exp.Rules))
	}
	r := exp.Rules[0]
	// The rule id IS the invariant declaration name in cap.mspec.
	if r.RuleID != "cap_respected" {
		t.Errorf("rule_id = %q, want cap_respected", r.RuleID)
	}
	if r.ExpectedVerdict != "PROVEN" {
		t.Errorf("expected_verdict = %q, want PROVEN", r.ExpectedVerdict)
	}
	if r.ExpectedReasonCode != nil {
		t.Errorf("expected_reason_code = %q, want null (PROVEN carries no refusal)", *r.ExpectedReasonCode)
	}
	if r.ExpectedInvariant == nil {
		t.Fatal("expected_invariant missing")
	}
	wantPerFunction := map[string]string{"deposit": "proved", "setCap": "proved"}
	if len(r.ExpectedInvariant.PerFunction) != len(wantPerFunction) {
		t.Errorf("per_function = %v, want %v", r.ExpectedInvariant.PerFunction, wantPerFunction)
	}
	for fn, want := range wantPerFunction {
		if got := r.ExpectedInvariant.PerFunction[fn]; got != want {
			t.Errorf("per_function[%q] = %q, want %q", fn, got, want)
		}
	}
	if r.ExpectedInvariant.Init == nil || *r.ExpectedInvariant.Init != "proved" {
		t.Errorf("init = %v, want proved", r.ExpectedInvariant.Init)
	}
	if r.ExpectedInvariant.WitnessFunction != nil {
		t.Errorf("witness_function = %q, want null (nothing to witness when PROVEN)",
			*r.ExpectedInvariant.WitnessFunction)
	}
	wantAssumptions := []string{
		"entry-bound-at-internal-implementation",
		"invariant-init-checked",
		"invariant-init-from-zeroed-storage",
		"invariant-one-step-induction",
		"invariant-state-getters-not-checked",
	}
	got := append([]string(nil), r.ExpectedAssumptionsInclude...)
	sort.Strings(got)
	sort.Strings(wantAssumptions)
	if strings.Join(got, "\n") != strings.Join(wantAssumptions, "\n") {
		t.Errorf("expected_assumptions_include = %v, want %v",
			r.ExpectedAssumptionsInclude, wantAssumptions)
	}
}

// TestReasonCodeSetIsTwentyFive pins the exported closed set: the 25 names of
// corpus/runner.py::REASON_CODES (copied here as literals, so a revendored
// runner.py that moves the set trips this test) are exactly the members of
// dispositionOf, and anything else — including a near-miss — is rejected.
func TestReasonCodeSetIsTwentyFive(t *testing.T) {
	codes := []string{
		"assertion-violated", "expect-revert-violated", "tool-error", "vacuous-rule",
		"malformed-spec", "solver-timeout", "rejected-feature", "unsupported-opcode",
		"unsupported-storage-layout", "external-call-abstraction",
		"unrecognized-dispatcher", "path-limit-reached", "solver-disagreement",
		"summary-unverified", "invariant-uninitialized",
		"invariant-unchecked-functions", "vacuous-block", "unsupported-feature",
		"modelling-inconsistency", "multi-call-ambiguous-call-site",
		"multi-call-inner-arg-unsupported", "multi-call-stmt-between-calls",
		"loop-bound-may-be-exceeded", "unresolved-phi-source",
		"unresolved-branch-cond",
	}
	if len(codes) != 25 {
		t.Fatalf("code list has %d entries, want 25", len(codes))
	}
	trueCount := 0
	seen := map[string]bool{}
	for _, code := range codes {
		if seen[code] {
			t.Errorf("duplicate code %q in the hard-listed slice", code)
			continue
		}
		seen[code] = true
		if !IsReasonCode(code) {
			t.Errorf("IsReasonCode(%q) = false, want true", code)
			continue
		}
		trueCount++
	}
	if trueCount != 25 {
		t.Errorf("IsReasonCode accepted %d of the 25 pinned codes", trueCount)
	}
	// The map itself is the closed set: no extra rows may sneak past the
	// hard-listed slice above.
	if len(dispositionOf) != 25 {
		t.Errorf("dispositionOf holds %d entries, want 25", len(dispositionOf))
	}
	for _, bad := range []string{"nope-code", "", "assertion-violated ", "ASSERTION-VIOLATED"} {
		if IsReasonCode(bad) {
			t.Errorf("IsReasonCode(%q) = true, want false", bad)
		}
	}
}
