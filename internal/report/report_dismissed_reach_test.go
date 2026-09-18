package report

// report_dismissed_reach_test.go — G14b: the "Dismissed with strong
// reaching" subsection. Presence-gated (the additive convention): it renders
// only when a terminal-dismissal finding (DISPROVED, OUT_OF_SCOPE,
// INFORMATIONAL or DUPLICATE — never SUPERSEDED) is reached by a high-risk
// probe row, joined by file overlap (no id-level link exists).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// reachSurface is the MORPH-style probe surface: one high-risk row about
// Rollup, one high-risk row about FarAway (which no finding touches).
const reachSurface = `{"rows": [
 {"row_id": "r1reach00001", "probe": "assertion-strength",
  "tier": 0, "assertion_gap": 4,
  "contract": "Rollup", "consumer": "commitBatch", "consumer_line": 45,
  "asserter": "finalizeBatch", "asserter_line": 66},
 {"row_id": "r2far00000002", "probe": "assertion-strength",
  "tier": 0, "assertion_gap": 4,
  "contract": "FarAway", "consumer": "doThing", "consumer_line": 7,
  "asserter": "setupThing", "asserter_line": 3}
]}`

// reachIndex resolves both surface contracts to files.
const reachIndex = `{"nodes": [
 {"id": "FarAway.sol#FarAway", "kind": "contract", "name": "FarAway",
  "path": "FarAway.sol"},
 {"id": "Rollup.sol#Rollup", "kind": "contract", "name": "Rollup",
  "path": "Rollup.sol"}
]}`

// reachWriteArtifacts installs the surface (+ optionally the index) under
// the campaign's artifacts dir, the way `probes run --emit` would.
func reachWriteArtifacts(t *testing.T, camp *state.Campaign,
	withIndex bool) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(camp.ArtifactsDir,
		"probe_surface.json"), []byte(reachSurface), 0o644); err != nil {
		t.Fatal(err)
	}
	if withIndex {
		if err := os.WriteFile(filepath.Join(camp.ArtifactsDir,
			"structural_index.json"), []byte(reachIndex), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// reachFinding ingests a hypothesis on the given file/contract/class — the
// mkBareHypothesis shape with a caller-chosen affected anchor — and returns
// its finding id.
func reachFinding(t *testing.T, camp *state.Campaign, title, path,
	contract, class string) string {
	t.Helper()
	f, err := findings.IngestHypothesis(camp, validation.VObj(
		kv("title", validation.VStr(title)),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr(class)),
			kv("description", validation.VStr(
				"the reach fixture mechanism")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr(path)),
			kv("contract", validation.VStr(contract)),
			kv("function", validation.VStr("reached"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()))),
		kv("capabilities", validation.VObj(
			kv("granted", validation.VArr()),
			kv("required", validation.VArr()))),
	), "code", "test", "")
	if err != nil {
		t.Fatal(err)
	}
	return validation.ObjStr(f, "finding_id")
}

// reachDismiss sets a finding's status the way this package's other tests
// write terminal states.
func reachDismiss(t *testing.T, camp *state.Campaign, fid, status string) {
	t.Helper()
	f, err := findings.LoadFinding(camp, fid)
	if err != nil {
		t.Fatal(err)
	}
	f = setField(f, "status", validation.VStr(status))
	if err := findings.SaveFinding(camp, &f); err != nil {
		t.Fatal(err)
	}
}

// reachSection slices the subsection out of a rendered report (to the next
// ## section, or the end of the report).
func reachSection(t *testing.T, text string) string {
	t.Helper()
	i := strings.Index(text, "### Dismissed with strong reaching")
	if i < 0 {
		t.Fatalf("no dismissed-with-reach section:\n%s", text)
	}
	sec := text[i:]
	if j := strings.Index(sec, "\n## "); j != -1 {
		sec = sec[:j]
	}
	return sec
}

// TestDismissedWithStrongReaching pins the MORPH-style fixture: two
// dismissed findings plus high-risk rows where exactly one finding is
// reached — the section bytes name the hit, and the non-reaching finding
// and row stay out.
func TestDismissedWithStrongReaching(t *testing.T) {
	camp := clusterCamp(t)
	reachWriteArtifacts(t, camp, true)
	hit := reachFinding(t, camp, "the dismissed Rollup claim",
		"src/Rollup.sol", "Rollup", "logic-error")
	reachDismiss(t, camp, hit, "DISPROVED")
	miss := reachFinding(t, camp, "the dismissed Other claim",
		"src/Other.sol", "Other", "logic-error")
	reachDismiss(t, camp, miss, "OUT_OF_SCOPE")

	sec := reachSection(t, mustGenerate(t, camp))

	want := "### Dismissed with strong reaching\n" +
		"\n" +
		"- `" + hit + "` (DISPROVED, class logic-error): reached by " +
		"high-risk row `r1reach00001` (tier 0, assertion_gap 4)\n" +
		"reach joined by file overlap (no id-level link exists).\n" +
		"\n"
	if sec != want {
		t.Fatalf("section bytes mismatch\n got: %q\nwant: %q", sec, want)
	}
	if strings.Contains(sec, miss) {
		t.Fatalf("the non-reaching dismissal must stay out:\n%s", sec)
	}
	if strings.Contains(sec, "r2far00000002") {
		t.Fatalf("the non-reaching row must stay out:\n%s", sec)
	}
}

// TestDismissedWithStrongReachingAbsentNoRows pins the (b) gate: dismissed
// findings with no probe surface gain no bytes.
func TestDismissedWithStrongReachingAbsentNoRows(t *testing.T) {
	camp := clusterCamp(t)
	dead := reachFinding(t, camp, "disproved with no rows about",
		"src/Rollup.sol", "Rollup", "logic-error")
	reachDismiss(t, camp, dead, "DISPROVED")

	text := mustGenerate(t, camp)
	if strings.Contains(text, "Dismissed with strong reaching") {
		t.Fatalf("no surface means no reach section:\n%s", text)
	}
	if !strings.Contains(text, "## Dismissed candidates (with reasons)") {
		t.Fatalf("the dismissed block itself must still render:\n%s", text)
	}
}

// TestDismissedWithStrongReachingAbsentNoDismissals pins the (a) gate: a
// probe surface with no dismissed findings gains no bytes.
func TestDismissedWithStrongReachingAbsentNoDismissals(t *testing.T) {
	camp := clusterCamp(t)
	reachWriteArtifacts(t, camp, true)
	reachFinding(t, camp, "still a live hypothesis",
		"src/Rollup.sol", "Rollup", "logic-error")

	text := mustGenerate(t, camp)
	if strings.Contains(text, "Dismissed with strong reaching") {
		t.Fatalf("no dismissals means no reach section:\n%s", text)
	}
}

// TestDismissedWithStrongReachingIgnoresSuperseded pins the correction
// boundary: a SUPERSEDED finding a high-risk row reaches is corrected, not
// dismissed, so the section stays out.
func TestDismissedWithStrongReachingIgnoresSuperseded(t *testing.T) {
	camp := clusterCamp(t)
	reachWriteArtifacts(t, camp, true)
	old := reachFinding(t, camp, "the superseded Rollup claim",
		"src/Rollup.sol", "Rollup", "logic-error")
	reachDismiss(t, camp, old, "SUPERSEDED")

	text := mustGenerate(t, camp)
	if strings.Contains(text, "Dismissed with strong reaching") {
		t.Fatalf("supersession must not arm the reach section:\n%s", text)
	}
}
