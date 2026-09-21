package findings

import (
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

func TestForkDependenceDrivesExistenceFunding(t *testing.T) {
	none := validation.VObj(validation.KV{K: "fork_dependence", V: validation.VStr("none")})
	if ForkDependent(none) {
		t.Fatal("fork_dependence=none must not be fork-dependent")
	}
	if ExistenceFundingRequired(none, true) {
		t.Fatal("a fork-independent hypothesis needs no existence tranche")
	}
	feed := validation.VObj(validation.KV{K: "fork_dependence",
		V: validation.VStr("real-price-feed")})
	if !ForkDependent(feed) {
		t.Fatal("fork_dependence=real-price-feed must be fork-dependent")
	}
	if ExistenceFundingRequired(feed, false) {
		t.Fatal("E4 must be satisfied before existence funding (v1.6 §2.2)")
	}
	if !ExistenceFundingRequired(feed, true) {
		t.Fatal("E4-satisfied + fork-dependent = existence funding")
	}
	// Absent means unknown, and unknown is not 'none'.
	if !ForkDependent(validation.VObj()) {
		t.Fatal("an unrecorded fork_dependence must default to dependent, not to none")
	}
}

func TestSetForkDependenceRequiresAReason(t *testing.T) {
	c, fid := factCampaign(t) // the Task 5 fixture
	if _, err := SetForkDependence(c, fid, "none", "", "operator"); err == nil ||
		!strings.Contains(err.Error(), "--reason") {
		t.Fatalf("err = %v, want the reason refusal", err)
	}
	if _, err := SetForkDependence(c, fid, "oracle-ish", "because", "operator"); err == nil ||
		!strings.Contains(err.Error(), "fork_dependence must be one of") {
		t.Fatalf("err = %v, want the enum refusal", err)
	}
	f, err := SetForkDependence(c, fid, "none", "the harness mocks the feed", "operator")
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	if got := validation.ObjStr(f, "fork_dependence"); got != "none" {
		t.Fatalf("fork_dependence = %q", got)
	}
}

// TestIngestAttributesTheOriginStage: ingest records the authoring stage and
// its default contributing set, and OMITS both — never invents "unknown" —
// when the caller names no stage (v1.6 Part 1/C2).
func TestIngestAttributesTheOriginStage(t *testing.T) {
	c, fid := factCampaign(t) // ingests with stage "discovery"
	f, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(f, "origin_stage"); got != "discovery" {
		t.Fatalf("origin_stage = %q, want discovery", got)
	}
	stages := validation.ObjAt(f, "contributing_stages")
	if stages.Kind != validation.Arr || len(stages.A) != 1 ||
		stages.A[0].S != "discovery" {
		t.Fatalf("contributing_stages = %v, want the origin stage alone", stages)
	}
	c2, err := state.Init(t.TempDir(), "Acme", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	unstaged, err := IngestHypothesis(c2, hypoPayload(), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := fieldAt(unstaged, "origin_stage"); ok {
		t.Fatal(`an unstaged ingest must leave origin_stage absent, not "unknown"`)
	}
	if _, ok := fieldAt(unstaged, "contributing_stages"); ok {
		t.Fatal("an unstaged ingest must leave contributing_stages absent")
	}
}
