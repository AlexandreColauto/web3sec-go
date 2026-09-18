package planner

// recon_binding_test.go — FIX-C: the FIX-8 recon stamps are bound to their
// evidence. A prescreen from a snapshot the campaign is not pinned to is not
// the campaign's recon; a sinks stamp that names another campaign (or no
// campaign — a pre-binding stamp) is not this campaign's recon; and a sinks
// run over a different tree than the prescreen's is not the recon the L-04
// attestation reconciles over. Every refusal names the rerun command; the
// honest path — re-run the owed recon — stays cheap.

import (
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// pinActive pins sid as the campaign's active snapshot (the real
// state.PinSnapshot write path, with a minimal schema-valid snapshot doc).
func pinActive(t *testing.T, c *state.Campaign, sid string) {
	t.Helper()
	snap := validation.VObj(
		kv("snapshot_id", validation.VStr(sid)),
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("created_at", validation.VStr("2026-09-09T12:00:00.000000+00:00")),
		kv("source", validation.VObj(
			kv("ladder", validation.VStr("no-vcs")),
			kv("content_hash", validation.VStr("deadbeefcafe")),
		)),
	)
	if _, err := c.PinSnapshot(snap); err != nil {
		t.Fatalf("pin snapshot: %v", err)
	}
}

// rewriteSinksStamp edits the sinks stamp on disk the way an operator's text
// editor would — the state file is operator-writable, and that is exactly
// the tamper the gate must catch.
func rewriteSinksStamp(t *testing.T, c *state.Campaign,
	mutate func(validation.Value) validation.Value) {
	t.Helper()
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	recon := validation.ObjAt(st, "recon")
	stamp := validation.ObjAt(recon, "sinks")
	if stamp.Kind != validation.Obj {
		t.Fatalf("no sinks stamp to rewrite: %s", validation.CanonCompact(recon))
	}
	stamp = mutate(stamp)
	recon.O = validation.SetOrAppend(recon.O, "sinks", stamp)
	st.O = validation.SetOrAppend(st.O, "recon", recon)
	if err := validation.WriteJson(c.StatePath, st, "campaign_state"); err != nil {
		t.Fatal(err)
	}
}

// TestReconGateStalePrescreen: the prescreen artifact's snapshot_id must be
// the campaign's active pin — the staleness comparison runPrescreen itself
// makes. A re-pin without a re-run refuses with both ids and the rerun
// command; re-running the prescreen against the (unchanged) pin clears it.
func TestReconGateStalePrescreen(t *testing.T) {
	c := newCampaign(t, "recon-stale")
	reconOnRecord(t, c)
	pinActive(t, c, "S-currentpin001")

	err := checkReconStamps(c)
	if err == nil {
		t.Fatal("stale prescreen accepted")
	}
	msg := err.Error()
	for _, want := range []string{
		"S-0123456789abcdef", "S-currentpin001",
		"webv2 prescreen " + c.CampaignID + " --src SRC",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal missing %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "webv2 sinks "+c.CampaignID) {
		t.Errorf("refusal demands the sinks run that is on record:\n%s", msg)
	}

	// the honest exit: the prescreen re-run against the same pin. The
	// planner cannot run the verb (import cycle), so the fixture artifact
	// carries the pin's id — the gate sees the same thing.
	if err := validation.WriteJson(filepath.Join(c.ArtifactsDir,
		"archetype_prescreen.json"),
		jsonValue(t, `{"snapshot_id":"S-currentpin001"}`), ""); err != nil {
		t.Fatal(err)
	}
	if err := checkReconStamps(c); err != nil {
		t.Fatalf("fresh prescreen refused: %v", err)
	}
}

// TestReconGateForeignStamp: a sinks stamp naming another campaign — the
// state file is operator-writable, so this is the copy-and-hope cheat — is
// refused with the rerun command; so is a legacy stamp that names no campaign
// at all.
func TestReconGateForeignStamp(t *testing.T) {
	c := newCampaign(t, "recon-foreign")
	reconOnRecord(t, c)

	rewriteSinksStamp(t, c, func(stamp validation.Value) validation.Value {
		stamp.O = validation.SetOrAppend(stamp.O, "campaign_id",
			validation.VStr("C-othercampaign"))
		return stamp
	})
	err := checkReconStamps(c)
	if err == nil {
		t.Fatal("foreign-campaign stamp accepted")
	}
	msg := err.Error()
	for _, want := range []string{
		"C-othercampaign", c.CampaignID,
		"webv2 sinks " + c.CampaignID + " --src SRC",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal missing %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "webv2 prescreen "+c.CampaignID) {
		t.Errorf("refusal demands the prescreen that is on record:\n%s", msg)
	}

	// a stamp written before the campaign binding existed cannot be bound
	// to this campaign either — it is refused the same way
	c2 := newCampaign(t, "recon-legacy-stamp")
	reconOnRecord(t, c2)
	rewriteSinksStamp(t, c2, func(stamp validation.Value) validation.Value {
		stamp.O = dropKey(stamp.O, "campaign_id")
		return stamp
	})
	err = checkReconStamps(c2)
	if err == nil || !strings.Contains(err.Error(),
		"does not name the campaign it ran under") {
		t.Fatalf("unbound legacy stamp accepted: %v", err)
	}
	if !strings.Contains(err.Error(),
		"webv2 sinks "+c2.CampaignID+" --src SRC") {
		t.Fatalf("refusal does not name the rerun command: %v", err)
	}
}

// rewritePrescreenArtifact rewrites the prescreen artifact the way an
// operator moving files between campaigns would — the artifacts directory is
// operator-writable, and that is exactly the copy-and-hope cheat the FIX-E
// binding must catch.
func rewritePrescreenArtifact(t *testing.T, c *state.Campaign,
	mutate func(validation.Value) validation.Value) {
	t.Helper()
	p := filepath.Join(c.ArtifactsDir, "archetype_prescreen.json")
	rep, err := validation.ReadJson(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := validation.WriteJson(p, mutate(rep), ""); err != nil {
		t.Fatal(err)
	}
}

// TestReconGateForeignPrescreen pins the FIX-E binding symmetry: the sinks
// half refuses a foreign-campaign stamp, so the prescreen half must too. A
// prescreen artifact naming another campaign is refused with the rerun
// command; a pre-binding artifact (no campaign_id) stays accepted — its
// snapshot_id binding is its whole evidence.
func TestReconGateForeignPrescreen(t *testing.T) {
	c := newCampaign(t, "recon-foreign-pre")
	reconOnRecord(t, c)
	rewritePrescreenArtifact(t, c, func(rep validation.Value) validation.Value {
		rep.O = validation.SetOrAppend(rep.O, "campaign_id",
			validation.VStr("C-othercampaign"))
		return rep
	})
	err := checkReconStamps(c)
	if err == nil {
		t.Fatal("foreign-campaign prescreen accepted")
	}
	msg := err.Error()
	for _, want := range []string{
		"C-othercampaign", c.CampaignID,
		"webv2 prescreen " + c.CampaignID + " --src SRC",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal missing %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "webv2 sinks "+c.CampaignID) {
		t.Errorf("refusal demands the sinks run that is on record:\n%s", msg)
	}

	// a pre-binding artifact — the fixtures every pre-FIX-E test seeds —
	// carries no campaign_id and stays accepted
	c2 := newCampaign(t, "recon-legacy-pre")
	reconOnRecord(t, c2)
	if err := checkReconStamps(c2); err != nil {
		t.Fatalf("pre-binding prescreen refused: %v", err)
	}
}

// TestReconGateSameTreeAssumption: when both verbs stamped their src, the
// sinks run must have seen the tree the prescreen saw — the attestation
// reconciles divergence rows both recon runs read together. Matching trees
// pass.
func TestReconGateSameTreeAssumption(t *testing.T) {
	c := newCampaign(t, "recon-trees")
	reconOnRecord(t, c)
	if err := c.StampRecon("prescreen", "src"); err != nil {
		t.Fatal(err)
	}
	if err := checkReconStamps(c); err != nil {
		t.Fatalf("matching trees refused: %v", err)
	}

	// the sinks run went over a different tree than the prescreen: refused
	// with both trees and both rerun commands
	c2 := newCampaign(t, "recon-trees-bad")
	reconOnRecord(t, c2)
	if err := c2.StampRecon("prescreen", "other-tree"); err != nil {
		t.Fatal(err)
	}
	err := checkReconStamps(c2)
	if err == nil {
		t.Fatal("cross-tree recon accepted")
	}
	msg := err.Error()
	for _, want := range []string{
		"other-tree", "src",
		"webv2 prescreen " + c2.CampaignID + " --src SRC",
		"webv2 sinks " + c2.CampaignID + " --src SRC",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal missing %q:\n%s", want, msg)
		}
	}
}
