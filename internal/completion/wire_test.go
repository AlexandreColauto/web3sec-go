// Wiring tests: wire.go's init() is the only thing that makes the ported
// proofs reachable from the scheduler and the bounty gate, so both seams are
// asserted through the real consumers (pipeline.run's proof-driven
// auto-completion, bounty.check11's stage waiver) rather than by inspecting
// package variables.
package completion

import (
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/bounty"
	"websec/internal/invariants"
	"websec/internal/pipeline"
	"websec/internal/protocolgraph"
	"websec/internal/state"
	"websec/internal/validation"
)

// noOrch is an orchestrator stub: the deterministic stages this test needs
// are pre-marked done, so none of its methods is ever called.
type noOrch struct{}

func (noOrch) Scope() (validation.Value, error)                { return validation.VObj(), nil }
func (noOrch) BuildStructuralIndex() (validation.Value, error) { return validation.VObj(), nil }
func (noOrch) RunDedup() (validation.Value, error)             { return validation.VObj(), nil }
func (noOrch) Chaining() (validation.Value, error)             { return validation.VObj(), nil }
func (noOrch) CalibrateAll() (validation.Value, error)         { return validation.VObj(), nil }
func (noOrch) BountyGateAll() (validation.Value, error)        { return validation.VObj(), nil }
func (noOrch) Plan() (validation.Value, error)                 { return validation.VObj(), nil }
func (noOrch) ReproductionQueue() (validation.Value, error)    { return validation.VObj(), nil }

func strPtr(s string) *string { return &s }

// seededCampaign is a campaign whose protocol-model proof HOLDS: a valid
// model plus the invariant registry seeded from it.
func seededCampaign(t *testing.T, id string) *state.Campaign {
	t.Helper()
	root := t.TempDir()
	c, err := state.Init(root, "Wiring Program",
		state.InitOpts{CampaignID: id})
	if err != nil {
		t.Fatal(err)
	}
	model := validation.VObj(
		validation.KV{K: "protocol_id", V: validation.VStr("vault")},
		validation.KV{K: "name", V: validation.VStr("Vault")},
		validation.KV{K: "snapshot_id", V: validation.VStr("unpinned")},
		validation.KV{K: "chains", V: validation.VArr(validation.VStr("ethereum"))},
		validation.KV{K: "contracts", V: validation.VArr(validation.VObj(
			validation.KV{K: "name", V: validation.VStr("Vault")},
			validation.KV{K: "path", V: validation.VStr("Vault.sol")},
			validation.KV{K: "role", V: validation.VStr("core")},
			validation.KV{K: "in_scope", V: validation.VBool(true)},
		))},
		validation.KV{K: "actors", V: validation.VArr(validation.VObj(
			validation.KV{K: "id", V: validation.VStr("user")},
			validation.KV{K: "kind", V: validation.VStr("EOA")},
			validation.KV{K: "trust", V: validation.VStr("externally-owned")},
		))},
		validation.KV{K: "assets", V: validation.VArr(validation.VObj(
			validation.KV{K: "id", V: validation.VStr("share")},
			validation.KV{K: "kind", V: validation.VStr("share")},
		))},
		validation.KV{K: "relations", V: validation.VArr()},
		validation.KV{K: "invariants", V: validation.VArr(validation.VObj(
			validation.KV{K: "id", V: validation.VStr("INV-1")},
			validation.KV{K: "statement", V: validation.VStr(
				"invariant 1 must hold under every reachable state")},
			validation.KV{K: "applies_to", V: validation.VArr(validation.VStr("Vault"))},
			validation.KV{K: "kind", V: validation.VStr("economic")},
			validation.KV{K: "severity_if_broken", V: validation.VStr("high")},
		))},
	)
	if _, err := protocolgraph.SaveModel(c, model, ""); err != nil {
		t.Fatal(err)
	}
	loaded, err := protocolgraph.LoadModel(c,
		filepath.Join(c.ArtifactsDir, "protocol_model.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := invariants.SeedFromModel(c, loaded); err != nil {
		t.Fatal(err)
	}
	return c
}

// TestWiringPipelineAutoCompletes drives pipeline.run over a handler-less
// model stage whose proof holds: without completion's init the stage would
// be blocked with "no completion proof declared".
func TestWiringPipelineAutoCompletes(t *testing.T) {
	t.Setenv("WEBV2_NOW", pinnedNow)
	c := seededCampaign(t, "C-wire000001")
	for _, sid := range []string{"scope", "snapshot", "structural-index"} {
		if err := c.SetStage(sid, "done", validation.VStr(""),
			strPtr("deterministic")); err != nil {
			t.Fatal(err)
		}
	}
	proof, err := ProofStatus(c, "protocol-model")
	if err != nil {
		t.Fatal(err)
	}
	if !pyTruthyBigNonEmpty(objAt(proof, "done")) {
		t.Fatalf("fixture proof does not hold: %s", pyJSONDumps(proof))
	}
	p := pipeline.New(c, noOrch{}, nil)
	until := "protocol-model"
	if _, err := p.Run(pipeline.RunOpts{Until: &until}); err != nil {
		t.Fatal(err)
	}
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	entry := objAt(objAt(st, "stages"), "protocol-model")
	if got := objStr(entry, "status"); got != "done" {
		t.Fatalf("protocol-model status = %q, want done (%s)", got,
			pyJSONDumps(entry))
	}
	if got := objStr(entry, "note"); got != "auto-completed: completion proof holds" {
		t.Errorf("note = %q, want the proof-driven note", got)
	}
	if got := objStr(entry, "executor"); got != "derived" {
		t.Errorf("executor = %q, want derived", got)
	}
}

// TestWiringBountyWaiverSeam runs the real gate twice: the mainnet-fork-poc
// check must flip from fail to waived only because bounty's waiver seam is
// bound to Waivers by wire.go.
func TestWiringBountyWaiverSeam(t *testing.T) {
	t.Setenv("WEBV2_NOW", pinnedNow)
	c := seededCampaign(t, "C-wire000002")
	fid := "F-0000000001"
	f := validation.VObj(
		validation.KV{K: "finding_id", V: validation.VStr(fid)},
		validation.KV{K: "campaign_id", V: validation.VStr(c.CampaignID)},
		validation.KV{K: "title", V: validation.VStr("wiring fixture finding")},
		validation.KV{K: "status", V: validation.VStr("CONFIRMED")},
		validation.KV{K: "created_at", V: validation.VStr(pinnedNow)},
		validation.KV{K: "updated_at", V: validation.VStr(pinnedNow)},
	)
	if err := validation.WriteJson(
		filepath.Join(c.FindingsDir, fid+".json"), f, ""); err != nil {
		t.Fatal(err)
	}
	row := func() validation.Value {
		t.Helper()
		b, err := bounty.EvaluateBountyGate(c, fid, validation.VObj(), false)
		if err != nil {
			t.Fatal(err)
		}
		for _, chk := range listAt(b, "policy_checks") {
			if objStr(chk, "check") == "mainnet-fork-poc" {
				return chk
			}
		}
		t.Fatal("no mainnet-fork-poc check row")
		return validation.VNull()
	}
	if got := objStr(row(), "result"); got != "fail" {
		t.Fatalf("unwaived mainnet-fork-poc = %q, want fail", got)
	}
	if _, err := Waive(c, "mainnet-fork-poc", "*",
		"wiring test: the fork PoC is waived for this campaign", "tester"); err != nil {
		t.Fatal(err)
	}
	got := row()
	if result := objStr(got, "result"); result != "pass" {
		t.Fatalf("waived mainnet-fork-poc = %q, want pass (%s)", result,
			pyJSONDumps(got))
	}
	if detail := objStr(got, "detail"); !strings.Contains(detail, "waived by") {
		t.Errorf("detail = %q, want a waived-by line", detail)
	}
}

// TestDiscoveryWaiverWorksBeforeThePlan pins r12 issue 4: the proof
// returned "no plan" BEFORE ever reading the waiver map, so `waive
// discovery --subject '*'` recorded a row that satisfied nothing — the
// R3 typo guard passes (discovery consults waiverMap) yet the waiver was
// inert. The no-plan leg now consults the waiver and says who waived.
func TestDiscoveryWaiverWorksBeforeThePlan(t *testing.T) {
	root := t.TempDir()
	c, err := state.Init(root, "Waive Program",
		state.InitOpts{CampaignID: "C-wire000003"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Waive(c, "discovery", "*",
		"operator-driven plan-free discovery", "alice"); err != nil {
		t.Fatal(err)
	}
	res, err := Proofs["discovery"](c)
	if err != nil {
		t.Fatal(err)
	}
	if objAt(res, "done").Kind != validation.Bool || !objAt(res, "done").B {
		t.Fatalf("a stage-wide waiver must open the no-plan leg: %v", res)
	}
	if n := objStr(res, "note"); n != "no plan — waived by alice" {
		t.Fatalf("the note must name the waiver actor, got %q", n)
	}
}
