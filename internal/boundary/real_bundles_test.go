package boundary

import (
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/roles"
	"websec/internal/state"
	"websec/internal/validation"
)

// The cited set is derived by matching KEY NAMES, so a key the role builders
// rename silently stops being collected — the same failure the id-shape
// pattern had, one level up. These tests therefore run the walk against what
// the builders REALLY emit, never against a hand-built bundle that mirrors
// what someone believed they emit.

// everyIDString collects every string under a key ending in _id/_ids, at any
// depth. It is the SUPERSET rule: BundleArtifacts may legitimately collect
// less (the campaign's own id is not an input artifact), never more.
func everyIDString(v validation.Value, out *[]string) {
	switch v.Kind {
	case validation.Obj:
		for _, kv := range v.O {
			if strings.HasSuffix(kv.K, "_id") || strings.HasSuffix(kv.K, "_ids") {
				stringsUnder(kv.V, out)
			}
			everyIDString(kv.V, out)
		}
	case validation.Arr:
		for _, e := range v.A {
			everyIDString(e, out)
		}
	}
}

func stringsUnder(v validation.Value, out *[]string) {
	switch v.Kind {
	case validation.Str:
		if s := strings.TrimSpace(v.S); s != "" {
			*out = append(*out, s)
		}
	case validation.Obj:
		for _, kv := range v.O {
			stringsUnder(kv.V, out)
		}
	case validation.Arr:
		for _, e := range v.A {
			stringsUnder(e, out)
		}
	}
}

func sortedUnique(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// realCampaignWithAFinding is a campaign that can build all three contexts:
// a pinned snapshot, a registered artifact, and one finding at POSSIBLE with
// a recorded evidence item.
func realCampaignWithAFinding(t *testing.T) (*state.Campaign, string) {
	t.Helper()
	c := newCamp(t)
	pin(t, c)
	artPath := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(artPath, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RegisterArtifact("policy", artPath, "", nil); err != nil {
		t.Fatal(err)
	}
	f := mustIngest(t, c, validHypothesis())
	fid := validation.ObjStr(f, "finding_id")
	floorEvidence(t, c, fid, "E2")
	if _, err := findings.Transition(c, fid, "POSSIBLE", "triage", "", "",
		false); err != nil {
		t.Fatal(err)
	}
	return c, fid
}

func assertCitedSetIsComplete(t *testing.T, name string, bundle validation.Value,
	campaignID string) {
	t.Helper()
	var all []string
	everyIDString(bundle, &all)
	want := []string{}
	for _, id := range sortedUnique(all) {
		if id != campaignID {
			want = append(want, id)
		}
	}
	got := sortedUnique(BundleArtifacts(bundle))
	if !slices.Equal(got, want) {
		t.Fatalf("%s: BundleArtifacts = %q, want every _id/_ids string the "+
			"builder emitted (minus the campaign's own id) = %q", name, got, want)
	}
}

// TestBundleArtifactsMatchesTheRealProposer is the proposer half.
func TestBundleArtifactsMatchesTheRealProposer(t *testing.T) {
	c, _ := realCampaignWithAFinding(t)
	b, err := roles.BuildProposerContext(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertCitedSetIsComplete(t, "proposer", b, c.CampaignID)
}

// TestBundleArtifactsMatchesTheRealCriticAndReproducer is the other half: the
// two builders that cite findings and evidence items.
func TestBundleArtifactsMatchesTheRealCriticAndReproducer(t *testing.T) {
	c, fid := realCampaignWithAFinding(t)
	critic, err := roles.BuildCriticContext(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	assertCitedSetIsComplete(t, "critic", critic, c.CampaignID)
	repro, err := roles.BuildReproducerContext(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	assertCitedSetIsComplete(t, "reproducer", repro, c.CampaignID)
}
