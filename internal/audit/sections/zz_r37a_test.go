package sections

// r37a: the projection check for artifact.refreshed refs was ORDER-BLIND —
// any refreshed id absent from the state was accused ("log records
// artifact.refreshed for X but the state has no such artifact"), but a
// SANCTIONED artifact-prune retires the row while the log keeps the trail
// (register -> refresh -> pruned). The honest repro sequence audited RED
// with a false accusation, and no sanctioned heal existed (re-registering
// mints a different id; doctor and reconcile touch nothing relevant; only
// a forbidden hand-edit of campaign_state.json greened the campaign).
//
// These tests pin the full decision matrix with REAL verbs wherever the
// verbs can produce the sequence, and forged events (c.Log) exactly where
// the verbs cannot (the impossible rows must refuse loudly).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// zzr37aCampaign inits a campaign with a registrable file and returns the
// campaign plus the file path.
func zzr37aCampaign(t *testing.T) (*state.Campaign, string) {
	t.Helper()
	root := t.TempDir()
	c, err := state.Init(root, "C-r37a", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "artifact.txt")
	if err := os.WriteFile(file, []byte("version-one"), 0o644); err != nil {
		t.Fatal(err)
	}
	return c, file
}

// zzr37aProblems runs the projection section and returns its problem
// strings (failing the test if the section itself errors).
func zzr37aProblems(t *testing.T, c *state.Campaign) []string {
	t.Helper()
	sec, err := Projection(c)
	if err != nil {
		t.Fatal(err)
	}
	var msgs []string
	for _, p := range objAt(sec, "problems").A {
		msgs = append(msgs, p.S)
	}
	return msgs
}

// zzr37aRegister registers path and returns the minted artifact id.
func zzr37aRegister(t *testing.T, c *state.Campaign, path string) string {
	t.Helper()
	id, err := c.RegisterArtifact("other", path, "r37a repro", nil)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// TestZZR37aRefreshedThenPrunedAuditsGreen is the auditor's exact repro at
// the state layer: register a file, rewrite it EXTERNALLY (outside every
// verb), reconcile the mutation with artifact-refresh, then retire the row
// with artifact-prune. The refresh event's id is then legitimately absent
// from the state — the log's own artifact.pruned event is why — so the
// audit must be GREEN with the rung and the trail intact, not red with the
// old false accusation.
func TestZZR37aRefreshedThenPrunedAuditsGreen(t *testing.T) {
	c, file := zzr37aCampaign(t)
	id := zzr37aRegister(t, c, file)

	// External rewrite: the file mutates outside the verb surface.
	if err := os.WriteFile(file, []byte("version-two-external"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Sanctioned reconcile of the mutation...
	if _, err := c.RefreshArtifact(id, "external rewrite detected", ""); err != nil {
		t.Fatal(err)
	}
	// ...then the sanctioned retire.
	if _, err := c.PruneArtifact(id, "retire test"); err != nil {
		t.Fatal(err)
	}

	// The trail: registered -> refreshed -> pruned, in that order.
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, e := range events {
		switch objStr(e, "type") {
		case "artifact.registered", "artifact.refreshed", "artifact.pruned":
			kinds = append(kinds, objStr(e, "type"))
		}
	}
	want := "artifact.registered artifact.refreshed artifact.pruned"
	if strings.Join(kinds, " ") != want {
		t.Fatalf("trail = %q, want %q", strings.Join(kinds, " "), want)
	}

	msgs := zzr37aProblems(t, c)
	joined := strings.Join(msgs, "\n")
	for _, m := range msgs {
		if strings.Contains(m, "but the state has no such artifact") {
			t.Fatalf("the sanctioned prune must not be accused:\n%s", joined)
		}
		if strings.Contains(m, "artifact.pruned") || strings.Contains(m, "artifact.refreshed") {
			t.Fatalf("history must not be flagged:\n%s", joined)
		}
	}
}

// TestZZR37aPrunedThenReRegisteredUnderNewId: after a prune, re-registering
// the same path mints a DIFFERENT id (fresh uuid stream), so the old id's
// prune stays history and the new id has its own registered event and row.
// Both ids must audit green.
func TestZZR37aPrunedThenReRegisteredUnderNewId(t *testing.T) {
	c, file := zzr37aCampaign(t)
	oldID := zzr37aRegister(t, c, file)
	if _, err := c.PruneArtifact(oldID, "retire before re-register"); err != nil {
		t.Fatal(err)
	}
	newID := zzr37aRegister(t, c, file)
	if newID == oldID {
		t.Fatalf("re-register must mint a NEW id, got %s again", newID)
	}
	msgs := zzr37aProblems(t, c)
	if len(msgs) != 0 {
		t.Fatalf("old prune + new registration must audit green, got:\n%s",
			strings.Join(msgs, "\n"))
	}
}

// TestZZR37aRefreshAfterPruneRefusedLoudly: a refresh event for an id
// AFTER its artifact.pruned event is impossible through the verbs (prune
// removes the row, refresh requires it, and a re-register mints a new id),
// so the log below can only be hand-forged. The false accusation must not
// become a silent skip either: this refuses LOUDLY with its own message,
// never the generic one.
func TestZZR37aRefreshAfterPruneRefusedLoudly(t *testing.T) {
	c, file := zzr37aCampaign(t)
	id := zzr37aRegister(t, c, file)
	if _, err := c.PruneArtifact(id, "retire, then someone forges a refresh"); err != nil {
		t.Fatal(err)
	}
	// Forge: no verb can emit a refreshed event for a pruned row.
	if _, err := c.Log("artifact.refreshed", &id, nil); err != nil {
		t.Fatal(err)
	}
	msgs := zzr37aProblems(t, c)
	joined := strings.Join(msgs, "\n")
	if !strings.Contains(joined,
		"log records artifact.refreshed for "+validation.PyReprStr(id)+" after its artifact.pruned event") {
		t.Fatalf("the impossible refresh must be refused loudly, got:\n%s", joined)
	}
	if strings.Contains(joined, "but the state has no such artifact") {
		t.Fatalf("the generic message must not double-accuse here:\n%s", joined)
	}
}

// TestZZR37aPruneWithoutRegistrationRefused: a prune for an id the ledger
// never registered is a forged trail — prune retires a REGISTERED row —
// and stays a problem.
func TestZZR37aPruneWithoutRegistrationRefused(t *testing.T) {
	c, _ := zzr37aCampaign(t)
	ghost := "GHO-00000000"
	data := validation.VObj(
		validation.KV{K: "kind", V: validation.VStr("other")},
		validation.KV{K: "path", V: validation.VStr("nowhere.txt")},
		validation.KV{K: "reason", V: validation.VStr("forged")},
	)
	if _, err := c.Log("artifact.pruned", &ghost, &data); err != nil {
		t.Fatal(err)
	}
	msgs := zzr37aProblems(t, c)
	joined := strings.Join(msgs, "\n")
	if !strings.Contains(joined,
		"log records artifact.pruned for "+validation.PyReprStr(ghost)+" but no artifact.registered event for it") {
		t.Fatalf("a never-registered prune must stay a problem, got:\n%s", joined)
	}
}

// TestZZR37aStateRowSurvivingPruneRefused: the row is pruned (removed from
// the state, event on the log) and then hand-restored into
// campaign_state.json. The sanctioned heal re-registers under a NEW id, so
// a surviving row is a hand-edit and stays a problem.
func TestZZR37aStateRowSurvivingPruneRefused(t *testing.T) {
	c, file := zzr37aCampaign(t)
	id := zzr37aRegister(t, c, file)
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	var row validation.Value
	for _, a := range objAt(st, "artifacts").A {
		if objStr(a, "artifact_id") == id {
			row = a
		}
	}
	if row.Kind != validation.Obj {
		t.Fatalf("row for %s not found in state", id)
	}
	if _, err := c.PruneArtifact(id, "retire, then hand-restore the row"); err != nil {
		t.Fatal(err)
	}
	// Hand-edit: put the pruned row back (exactly what the RUNBOOK forbids).
	st, err = c.State()
	if err != nil {
		t.Fatal(err)
	}
	arts := objAt(st, "artifacts")
	arts.A = append(arts.A, row)
	st.O = validation.SetOrAppend(st.O, "artifacts", arts)
	if err := c.SaveState(st); err != nil {
		t.Fatal(err)
	}
	msgs := zzr37aProblems(t, c)
	joined := strings.Join(msgs, "\n")
	if !strings.Contains(joined,
		"state lists artifact "+validation.PyReprStr(id)+" but the log records artifact.pruned for it") {
		t.Fatalf("a row that survived its own prune must stay a problem, got:\n%s", joined)
	}
}

// TestZZR37aGenericMessageStillFires: the genuinely-broken case — a
// refresh with NO prune and NO state row — must keep its original
// accusation; the order-aware heal did not silence it.
func TestZZR37aGenericMessageStillFires(t *testing.T) {
	c, file := zzr37aCampaign(t)
	id := zzr37aRegister(t, c, file)
	if _, err := c.RefreshArtifact(id, "refresh, then vanish the row", ""); err != nil {
		t.Fatal(err)
	}
	// Hand-edit: drop the row while the refresh event stays on the log.
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	var kept []validation.Value
	for _, a := range objAt(st, "artifacts").A {
		if objStr(a, "artifact_id") != id {
			kept = append(kept, a)
		}
	}
	st.O = validation.SetOrAppend(st.O, "artifacts", validation.VArr(kept...))
	if err := c.SaveState(st); err != nil {
		t.Fatal(err)
	}
	msgs := zzr37aProblems(t, c)
	joined := strings.Join(msgs, "\n")
	if !strings.Contains(joined,
		"log records artifact.refreshed for "+validation.PyReprStr(id)+" but the state has no such artifact") {
		t.Fatalf("the genuine orphan-refresh must still be accused, got:\n%s", joined)
	}
}
