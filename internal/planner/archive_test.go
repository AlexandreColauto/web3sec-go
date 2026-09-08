// Port of tests/test_plan_rebuild.py's planner half (B1/D1): validate_plan
// (the write-time checks WITHOUT touching disk) and archive_plan (the
// immutable superseded-plan record). The CLI/Orchestrator half is recorded in
// internal/orchestrator's golden oracles and, for the CLI itself, is T14's job.
package planner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// vaCampaign is the recorded campaign: id pinned so paths and sha256 match
// testdata/oracles.json's archive_plan section.
func vaCampaign(t *testing.T) *state.Campaign {
	t.Helper()
	t.Setenv("WEBV2_NOW", "2026-09-09T12:00:00.000000+00:00")
	c, err := state.Init(t.TempDir(), "T9 va", state.InitOpts{
		CampaignID: "C-09bb627b59"})
	if err != nil {
		t.Fatalf("init campaign: %v", err)
	}
	return c
}

// seedlessPlan is the oracle's pre-seed plan (no lenses).
func seedlessPlan(campaign *state.Campaign) validation.Value {
	return validation.VObj(
		kv("campaign_id", validation.VStr(campaign.CampaignID)),
		kv("created_at", validation.VStr("2026-09-09T12:00:00.000000+00:00")),
		kv("priorities", validation.VArr(validation.VObj(
			kv("id", validation.VStr("Q-001")),
			kv("question", validation.VStr("Can an unprivileged caller "+
				"drain the vault?")),
			kv("risk", validation.VFloat(0.5)),
			kv("trajectories", validation.VArr(validation.VStr("code"))),
		))),
	)
}

// TestValidatePlanSeedsWithoutTouchingDisk is validate_plan's contract: the
// returned plan carries the canonical lenses and nothing was written.
func TestValidatePlanSeedsWithoutTouchingDisk(t *testing.T) {
	root := oracles(t)
	want := at(t, root, "validate_plan")
	camp := vaCampaign(t)
	got, err := ValidatePlan(camp, seedlessPlan(camp))
	if err != nil {
		t.Fatalf("validate_plan: %v", err)
	}
	requireJSON(t, "seeded plan", got, objAt(want, "seeded"))
	_, statErr := os.Stat(filepath.Join(camp.ArtifactsDir,
		"campaign_plan.json"))
	requireJSON(t, "plan on disk", validation.VBool(statErr == nil),
		objAt(want, "plan_exists"))
	if n := len(listOf(got, "lenses")); n != 4 {
		t.Fatalf("seeded %d lenses, want 4", n)
	}
}

// TestValidatePlanRejectsNonCanonicalClass pins the ValueError text (the same
// check save_plan used to run inline).
func TestValidatePlanRejectsNonCanonicalClass(t *testing.T) {
	root := oracles(t)
	want := at(t, root, "validate_plan")
	camp := vaCampaign(t)
	bad := seedlessPlan(camp)
	bad.O = setOrAppend(bad.O, "priorities", validation.VArr(validation.VObj(
		kv("id", validation.VStr("Q-001")),
		kv("question", validation.VStr("Can an unprivileged caller drain "+
			"the vault?")),
		kv("risk", validation.VFloat(0.5)),
		kv("trajectories", validation.VArr(validation.VStr("code"))),
		kv("bug_class", validation.VStr("vibes-based")),
	)))
	_, err := ValidatePlan(camp, bad)
	requireErr(t, "validate_plan bad class", err, objAt(want, "error"))
	if _, statErr := os.Stat(filepath.Join(camp.ArtifactsDir,
		"campaign_plan.json")); !os.IsNotExist(statErr) {
		t.Fatalf("validate_plan wrote a plan file (stat err=%v)", statErr)
	}
}

// TestArchivePlanByteIdenticalAndRegistered is archive_plan's happy path: a
// byte-for-byte copy at version 0001, registered as kind plan.superseded with
// one plan.superseded event carrying the contract fields.
func TestArchivePlanByteIdenticalAndRegistered(t *testing.T) {
	root := oracles(t)
	want := at(t, root, "archive_plan")
	camp := vaCampaign(t)
	if _, err := SavePlan(camp, DefaultPlanFixture(t, camp)); err != nil {
		t.Fatalf("save plan: %v", err)
	}
	planPath := filepath.Join(camp.ArtifactsDir, "campaign_plan.json")
	outgoing, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatal(err)
	}
	dest, err := ArchivePlan(camp, ArchiveOpts{})
	if err != nil {
		t.Fatalf("archive plan: %v", err)
	}
	requireJSON(t, "dest", validation.VStr(dest),
		validation.VStr(realRoot(t, camp, objStr(want, "dest1"))))
	archived, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !sameBytes(archived, outgoing) {
		t.Fatalf("archive is not byte-identical")
	}
	requireJSON(t, "byte_identical", validation.VBool(true),
		objAt(want, "byte_identical"))
	events, err := camp.Events()
	if err != nil {
		t.Fatal(err)
	}
	last := events[len(events)-1]
	requireJSON(t, "event type", objAt(last, "type"),
		objAt(at(t, root, "archive_plan", "event"), "type"))
	requireJSON(t, "event data", normalizePaths(objAt(last, "data"),
		camp.Root), objAt(at(t, root, "archive_plan", "event"), "data"))
	st, err := camp.State()
	if err != nil {
		t.Fatal(err)
	}
	rows := []validation.Value{}
	for _, a := range listOf(st, "artifacts") {
		if objStr(a, "kind") == "plan.superseded" {
			rows = append(rows, projectArtifact(a))
		}
	}
	requireJSON(t, "artifact rows", validation.VArr(rows...),
		validation.VArr(at(t, root, "archive_plan", "artifacts").A[0]))
}

// TestArchivePlanMonotonicAndNeverReusesANumber deletes a MIDDLE archive and
// asserts the next version is still one past the highest.
func TestArchivePlanMonotonicAndNeverReusesANumber(t *testing.T) {
	root := oracles(t)
	want := at(t, root, "archive_plan")
	camp := vaCampaign(t)
	dest1, dest2, dest3 := "", "", ""
	for i := 0; i < 3; i++ {
		if _, err := SavePlan(camp, DefaultPlanFixture(t, camp)); err != nil {
			t.Fatalf("save plan %d: %v", i, err)
		}
		dest, err := ArchivePlan(camp, ArchiveOpts{})
		if err != nil {
			t.Fatalf("archive %d: %v", i, err)
		}
		switch i {
		case 0:
			dest1 = dest
		case 1:
			dest2 = dest
		case 2:
			dest3 = dest
		}
		if i == 1 {
			if err := os.Remove(dest1); err != nil { // middle archive gone
				t.Fatal(err)
			}
		}
	}
	requireJSON(t, "dest2", validation.VStr(dest2),
		validation.VStr(realRoot(t, camp, objStr(want, "dest2"))))
	requireJSON(t, "dest3", validation.VStr(dest3),
		validation.VStr(realRoot(t, camp, objStr(want, "dest3"))))
	got := []string{}
	for _, p := range SupersededPaths(camp) {
		got = append(got, strings.ReplaceAll(p, camp.Root, "<ROOT>"))
	}
	requireJSON(t, "superseded_paths", strArr(got),
		objAt(want, "superseded_paths"))
	if len(got) != 2 {
		t.Fatalf("expected 2 surviving archives, got %d", len(got))
	}
}

// TestArchivePlanMissingPlanRaises pins the fail-loud text: an archive of a
// plan that is not there never writes an empty record.
func TestArchivePlanMissingPlanRaises(t *testing.T) {
	root := oracles(t)
	want := objAt(at(t, root, "archive_plan"), "missing_error")
	t.Setenv("WEBV2_NOW", "2026-09-09T12:00:00.000000+00:00")
	camp, err := state.Init(t.TempDir(), "T9 va2", state.InitOpts{
		CampaignID: "C-f41b989d19"})
	if err != nil {
		t.Fatalf("init campaign: %v", err)
	}
	dest, err := ArchivePlan(camp, ArchiveOpts{})
	requireErr(t, "archive missing", err, validation.VObj(
		kv("msg", validation.VStr(strings.ReplaceAll(objStr(want, "msg"),
			"<ROOT>", camp.Root)))))
	if dest != "" {
		t.Fatalf("dest = %q, want empty", dest)
	}
	if got := SupersededPaths(camp); len(got) != 0 {
		t.Fatalf("SupersededPaths = %v, want none", got)
	}
}

// DefaultPlanFixture is the recorded default plan (a 4-priority bootstrap).
func DefaultPlanFixture(t *testing.T, camp *state.Campaign) validation.Value {
	t.Helper()
	plan, err := DefaultPlanFromModel(camp, validation.VObj())
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	return plan
}

// realRoot maps the oracle's <ROOT> placeholder back to the temp tree.
func realRoot(t *testing.T, camp *state.Campaign, s string) string {
	t.Helper()
	return strings.ReplaceAll(s, "<ROOT>", camp.Root)
}

// projectArtifact is the oracle's recorded artifact projection.
func projectArtifact(a validation.Value) validation.Value {
	out := []validation.KV{}
	for _, key := range []string{"kind", "path", "note", "sha256",
		"snapshot_id"} {
		if v, ok := fieldAt(a, key); ok {
			out = append(out, kv(key, v))
		}
	}
	return validation.VObj(out...)
}

// strsOf renders a JSON array of strings.
func strsOf(v validation.Value) []string {
	out := []string{}
	for _, item := range v.A {
		out = append(out, pyStr(item))
	}
	return out
}

// normalizePaths rewrites the temp root back to the oracle's <ROOT>
// placeholder (or the reverse), for path-bearing values.
func normalizePaths(v validation.Value, root string) validation.Value {
	switch v.Kind {
	case validation.Str:
		return validation.VStr(strings.ReplaceAll(v.S, root, "<ROOT>"))
	case validation.Obj:
		out := make([]validation.KV, 0, len(v.O))
		for _, item := range v.O {
			out = append(out, kv(item.K, normalizePaths(item.V, root)))
		}
		return validation.VObj(out...)
	case validation.Arr:
		out := make([]validation.Value, 0, len(v.A))
		for _, item := range v.A {
			out = append(out, normalizePaths(item, root))
		}
		return validation.VArr(out...)
	}
	return v
}

// sameBytes is bytes.Equal without importing bytes.
func sameBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
