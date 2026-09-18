package briefing

// R45A (P3): four readers in this file turned a stat/ReadJson error into
// "no artifact / no model", so `chmod 000 protocol_model.json` made the brief
// cockpit silently DROP whole sections — exit 0, nothing said. Each fold is
// fixed the same way: only os.IsNotExist is absence (the honest shapes below
// stay byte-identical), every other error is a read failure this code could
// not perform, and it is DISCLOSED by name and errno rather than rendered as
// absence. The section value itself is still not fabricated.
//
//   - chArtifact (:325): the critical-hunt artifacts. The disclosure goes into
//     the top-level problems block — the one diagnostic list the cockpit
//     prints (cmd_brief: "problems:") — while the section-local
//     critical_hunt.problems keeps its existing malformed-input semantics.
//   - TrackedSurfaces / ChainAssumptions: their signature IS the display list
//     the cockpit prints, so the disclosure is a named UNAVAILABLE line in
//     that list, rendered exactly where the block would have been.
//   - criticalityBlock: a model that could not be read omitted the section
//     silently, and a structural index that could not be read ranked every
//     component against a FABRICATED empty index. Both now disclose.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// r45aChmodFile makes a FILE unreadable and proves it (the directory helper
// r43aChmod proves the same for directories): under a uid that ignores mode
// bits the test skips instead of asserting a refusal it cannot create.
func r45aChmodFile(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod 000 %s: %v", path, err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o644) })
	if _, err := os.ReadFile(path); err == nil {
		t.Skipf("cannot create an unreadable file here (%s stayed readable)", path)
	}
}

// r45aWriteModel writes the smallest model TrackedSurfaces renders a line for.
func r45aWriteModel(t *testing.T, c *state.Campaign) string {
	t.Helper()
	p := filepath.Join(c.ArtifactsDir, "protocol_model.json")
	raw := `{"protocol_id":"p","name":"Probe","contracts":[],"actors":[],` +
		`"assets":[],"relations":[],"components":[{"kind":"frontend",` +
		`"path":"app/","trust":"untrusted","in_scope":true,"paid_for":true}]}`
	if err := os.WriteFile(p, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// r45aWriteIndex writes an index the criticality block can rank against.
func r45aWriteIndex(t *testing.T, c *state.Campaign) string {
	t.Helper()
	p := filepath.Join(c.ArtifactsDir, "structural_index.json")
	if err := os.WriteFile(p, []byte(`{"nodes":[],"edges":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// r45aTopProblem reports whether the top-level problems block carries a line
// naming every substring (the block the cockpit prints).
func r45aTopProblem(b validation.Value, subs ...string) bool {
	for _, p := range validation.ObjAt(b, "problems").A {
		if p.Kind != validation.Str {
			continue
		}
		hit := true
		for _, sub := range subs {
			if !strings.Contains(p.S, sub) {
				hit = false
				break
			}
		}
		if hit {
			return true
		}
	}
	return false
}

// TestR45aBriefDisclosesUnreadableModel: `chmod 000 protocol_model.json` used
// to drop the tracked-surfaces block, the assumption block and criticality
// with exit 0 and no disclosure anywhere.
func TestR45aBriefDisclosesUnreadableModel(t *testing.T) {
	c := r43aCampaign(t, "C-r45abrief1")
	r45aChmodFile(t, r45aWriteModel(t, c))

	surfaces := TrackedSurfaces(c)
	if len(surfaces) != 1 || !strings.Contains(surfaces[0], "UNAVAILABLE") ||
		!strings.Contains(surfaces[0], "protocol_model.json") ||
		!strings.Contains(surfaces[0], "permission denied") {
		t.Fatalf("tracked surfaces must disclose the read failure: %q", surfaces)
	}
	lines := ChainAssumptions(c)
	if len(lines) != 1 || !strings.Contains(lines[0], "UNAVAILABLE") {
		t.Fatalf("the assumption table must disclose the read failure: %q", lines)
	}

	b, err := BuildBrief(c, false, nil)
	if err != nil {
		t.Fatalf("a read failure must be disclosed, not abort the cockpit: %v", err)
	}
	if !r45aTopProblem(b, "protocol_model.json", "could not be read",
		"permission denied") {
		t.Fatalf("problems = %v, want a named protocol_model.json read failure",
			validation.ObjAt(b, "problems"))
	}
	ts := validation.ObjAt(b, "tracked_surfaces")
	if len(ts.A) != 1 || !strings.Contains(ts.A[0].S, "UNAVAILABLE") {
		t.Fatalf("tracked_surfaces = %v, want the UNAVAILABLE line", ts)
	}
	al := validation.ObjAt(b, "chain_assumption_lines")
	if len(al.A) != 1 || !strings.Contains(al.A[0].S, "UNAVAILABLE") {
		t.Fatalf("chain_assumption_lines = %v, want the UNAVAILABLE line", al)
	}
	// No ranking is invented from a model that was never read.
	if validation.HasKey(b, "criticality") {
		t.Fatalf("criticality must not be computed from an unread model: %v",
			validation.ObjAt(b, "criticality"))
	}
}

// TestR45aBriefDisclosesUnreadableStructuralIndex: the index fold used to be
// the worst of the four — the ranking ran against a fabricated empty index,
// so a component that EXISTS could be reported uncovered from structure the
// brief never read.
func TestR45aBriefDisclosesUnreadableStructuralIndex(t *testing.T) {
	c := r43aCampaign(t, "C-r45abrief2")
	r45aWriteModel(t, c)
	indexPath := r45aWriteIndex(t, c)

	// Control: a readable index renders the section.
	ok, err := BuildBrief(c, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !validation.HasKey(ok, "criticality") {
		t.Fatalf("a readable model+index renders criticality: %v",
			validation.ObjAt(ok, "criticality"))
	}

	r45aChmodFile(t, indexPath)
	b, err := BuildBrief(c, false, nil)
	if err != nil {
		t.Fatalf("a read failure must be disclosed, not abort the cockpit: %v", err)
	}
	if !r45aTopProblem(b, "structural_index.json", "could not be read",
		"permission denied") {
		t.Fatalf("problems = %v, want a named structural_index.json read failure",
			validation.ObjAt(b, "problems"))
	}
	if validation.HasKey(b, "criticality") {
		t.Fatalf("criticality must not be ranked against an unread index: %v",
			validation.ObjAt(b, "criticality"))
	}
	// The disclosure is not duplicated: the critical-hunt reader of the same
	// file (chArtifact, via ChAmplifiers) names the identical failure, and the
	// problems block carries the sentence once.
	seen := 0
	for _, p := range validation.ObjAt(b, "problems").A {
		if strings.Contains(p.S, "structural_index.json could not be read") {
			seen++
		}
	}
	if seen != 1 {
		t.Fatalf("problems = %v, want exactly one structural_index.json "+
			"disclosure", validation.ObjAt(b, "problems"))
	}
	// The section that reader feeds still falls back to its documented empty
	// shape (the fold was never about the shape, only about the silence).
	amps := validation.ObjAt(validation.ObjAt(b, "critical_hunt"), "amplifiers")
	if got := validation.ObjAt(amps, "detected"); got.Kind != validation.Obj || len(got.O) != 0 {
		t.Fatalf("amplifiers detected = %v, want the empty shape", got)
	}
}

// TestR45aBriefDisclosesUnreadableHuntArtifact pins the chArtifact fold on a
// file ONLY that reader touches: fork_diff.json feeds no other section, so
// before the fix its failure was silence in the cockpit.
func TestR45aBriefDisclosesUnreadableHuntArtifact(t *testing.T) {
	c := r43aCampaign(t, "C-r45abrief5")
	r45aWriteModel(t, c)
	fork := filepath.Join(c.ArtifactsDir, "fork_diff.json")
	if err := os.WriteFile(fork, []byte(`{"snapshot_id":null,`+
		`"extra_selectors":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	r45aChmodFile(t, fork)

	b, err := BuildBrief(c, false, nil)
	if err != nil {
		t.Fatalf("a read failure must be disclosed, not abort the cockpit: %v", err)
	}
	if !r45aTopProblem(b, "fork_diff.json", "could not be read",
		"permission denied") {
		t.Fatalf("problems = %v, want a named fork_diff.json read failure",
			validation.ObjAt(b, "problems"))
	}
	// The section is still omitted (Python's shape: a null fork_diff) — only
	// the silence was the bug.
	if got := validation.ObjAt(validation.ObjAt(b, "critical_hunt"), "fork_diff"); got.Kind != validation.Null {
		t.Fatalf("fork_diff = %v, want null (section omitted, now disclosed)", got)
	}
}

// TestR45aAbsenceStaysAbsentAndSilent pins the honest shapes: a campaign with
// no artifacts at all renders exactly as before (no sections, and — the point
// of the fix — no read-failure disclosure invented for a file that is simply
// not there).
func TestR45aAbsenceStaysAbsentAndSilent(t *testing.T) {
	c := r43aCampaign(t, "C-r45abrief3")

	if got := TrackedSurfaces(c); len(got) != 0 {
		t.Fatalf("an absent model renders no surfaces: %q", got)
	}
	if got := ChainAssumptions(c); len(got) != 0 {
		t.Fatalf("an absent model renders no assumption lines: %q", got)
	}
	b, err := BuildBrief(c, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"tracked_surfaces", "chain_assumption_lines",
		"criticality"} {
		if validation.HasKey(b, key) {
			t.Fatalf("absent artifacts must not create %s: %v", key,
				validation.ObjAt(b, key))
		}
	}
	if r45aTopProblem(b, "could not be read") {
		t.Fatalf("absence is not a read failure: %v", validation.ObjAt(b, "problems"))
	}
}

// TestR45aComponentFreeModelStaysSilent: a model that exists and carries no
// components is the OTHER honest silent shape (presence-gating), and it must
// not acquire a disclosure either.
func TestR45aComponentFreeModelStaysSilent(t *testing.T) {
	c := r43aCampaign(t, "C-r45abrief4")
	p := filepath.Join(c.ArtifactsDir, "protocol_model.json")
	if err := os.WriteFile(p, []byte(`{"protocol_id":"p","components":[]}`),
		0o644); err != nil {
		t.Fatal(err)
	}
	if got := TrackedSurfaces(c); len(got) != 0 {
		t.Fatalf("a component-free model renders no surfaces: %q", got)
	}
	b, err := BuildBrief(c, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if validation.HasKey(b, "tracked_surfaces") || validation.HasKey(b, "chain_assumption_lines") {
		t.Fatalf("a component-free model must add no block")
	}
	if r45aTopProblem(b, "could not be read") {
		t.Fatalf("a readable model is not a read failure: %v", validation.ObjAt(b, "problems"))
	}
	if !validation.HasKey(b, "criticality") {
		t.Fatal("a readable model still renders criticality")
	}
}
