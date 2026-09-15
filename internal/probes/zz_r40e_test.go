package probes

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/structidx"
	"websec/internal/validation"
)

// ---------------------------------------------------------------------------
// r40e — unwind-on-refusal for the probes package, pinned against the honest
// refusal an operator can always hit: grow the ledger a few events, then cut
// campaigns/<C>/events.jsonl to a shorter PREFIX so the state mirror is
// LONGER than the log — the next append refuses with
// "events.jsonl holds N event(s) but the state projection mirrors M ...
// run webv2 doctor".
//
// Two campaign TRUTH artifacts are written here:
//   - campaign_state.probe_blanks (the blank attestations, written by
//     set_blank). Section 13's blank check re-derives them from the ledger
//     and red-lines an attested axis with NO probes.blank event as
//     "hand-edited", so the refusal must put the state bytes back.
//   - artifacts/probe_surface.json (written by run_probes from a fresh
//     index). Its registration appends artifact.registered / refreshed —
//     whose refresh pins the NEW bytes' sha256 — so a refused append used to
//     leave the rebuilt surface on disk while the registry row unwound to
//     the OLD sha: audit section 2 "content hash mismatch".
// ---------------------------------------------------------------------------

// r40eSha is the sha256 of one file (or "absent").
func r40eSha(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "absent"
	}
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// r40eEventCount counts one event type in the ledger.
func r40eEventCount(t *testing.T, c *state.Campaign, eventType string) int {
	t.Helper()
	evts, err := c.Events()
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	n := 0
	for _, e := range evts {
		if vStr(e, "type") == eventType {
			n++
		}
	}
	return n
}

// r40eCutLedger grows the ledger a few events, then cuts events.jsonl to a
// shorter prefix so the state mirror is LONGER than the log. Returns the
// full bytes (the sanctioned out-of-band repair).
func r40eCutLedger(t *testing.T, c *state.Campaign) []byte {
	t.Helper()
	for i := 0; i < 3; i++ {
		data := validation.VObj(kv("note", validation.VStr("r40e ledger growth")))
		if _, err := c.Log("note.added", nil, &data); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(c.EventsPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) < 3 {
		t.Fatalf("ledger too short to cut: %d line(s)", len(lines))
	}
	if err := os.WriteFile(c.EventsPath,
		[]byte(strings.Join(lines[:len(lines)-1], "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return raw
}

// r40eAuditProblems is audit section 13's problem list for the campaign,
// joined (the in-package audit is the real section body, so this is the
// oracle — not a restatement).
func r40eAuditProblems(t *testing.T, c *state.Campaign) string {
	t.Helper()
	sec, err := NewProbeSurfaceAudit().AuditSurface(c)
	if err != nil {
		t.Fatalf("AuditSurface: %v", err)
	}
	items := []string{}
	for _, p := range vList(sec, "problems") {
		items = append(items, p.S)
	}
	return strings.Join(items, " | ")
}

// r40eSurfaceCamp builds the t29 fixture and materialises BOTH artifacts the
// section reads: artifacts/structural_index.json (so the surface is not
// stale) and artifacts/probe_surface.json.
func r40eSurfaceCamp(t *testing.T, cid string) (*state.Campaign, validation.Value) {
	t.Helper()
	root := t.TempDir()
	t29CopyTree(t, filepath.Join(t29ProbesDir, "accumulator", "blind"),
		filepath.Join(root, "acc"))
	t29CopyTree(t, filepath.Join(t29ProbesDir, "short_circuit", "clean"),
		filepath.Join(root, "guard"))
	camp, err := state.Init(t.TempDir(), "r40e probes",
		state.InitOpts{CampaignID: cid})
	if err != nil {
		t.Fatal(err)
	}
	idx, err := structidx.IndexSnapshot(camp, root, structidx.DefaultBackend)
	if err != nil {
		t.Fatal(err)
	}
	if err := validation.WriteJson(filepath.Join(camp.ArtifactsDir,
		"structural_index.json"), idx, "structural_index"); err != nil {
		t.Fatal(err)
	}
	surface, err := BuildSurface(idx, validation.VNull(), 12, 40, 3, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := validation.WriteJson(filepath.Join(camp.ArtifactsDir,
		"probe_surface.json"), surface, "probe_surface"); err != nil {
		t.Fatal(err)
	}
	return camp, surface
}

// TestR40ERefusedSetBlankRestoresStateBytes pins set_blank: the attestation
// and its probes.blank event land together or not at all, and section 13
// keeps reading the same verdict.
func TestR40ERefusedSetBlankRestoresStateBytes(t *testing.T) {
	camp, surface := r40eSurfaceCamp(t, "C-r40eblank0001")
	acc := t29Axis(t, surface, "accumulator-basis-skew")
	if vStr(acc, "status") != "blind" {
		t.Fatalf("fixture axis is %q, want blind", vStr(acc, "status"))
	}
	key := vStr(vList(acc, "blind")[0], "key")
	// The cut itself moves the state MIRROR (the growth events project into
	// it), so the snapshot of the r16 law is taken after it: what must not
	// move is campaign_state across the refused append.
	raw := r40eCutLedger(t, camp)
	stateBefore := r40eSha(t, camp.StatePath)
	auditBefore := r40eAuditProblems(t, camp)
	_, err := SetBlank(camp, "L-01", key, "checked the caller by hand", "operator")
	if err == nil || !strings.Contains(err.Error(), "state projection mirrors") {
		t.Fatalf("ledger-door set_blank err = %v (want the projection refusal)",
			err)
	}
	if got := r40eSha(t, camp.StatePath); got != stateBefore {
		t.Fatalf("the refused attestation rewrote campaign_state (an "+
			"attestation with no probes.blank event — what section 13 reads "+
			"as hand-edited):\n before %s\n after  %s", stateBefore, got)
	}
	if got := r40eAuditProblems(t, camp); got != auditBefore {
		t.Fatalf("section 13 changed across the refusal:\n before %s\n after  %s",
			auditBefore, got)
	}
	if got := r40eEventCount(t, camp, "probes.blank"); got != 0 {
		t.Fatalf("probes.blank events = %d, want 0", got)
	}
	blanks, err := CampaignBlanks(camp)
	if err != nil {
		t.Fatal(err)
	}
	if _, attested := blanks["accumulator-skew"]; attested {
		t.Fatal("the refused attestation is still readable through " +
			"CampaignBlanks — the store did not unwind")
	}
	// Repair, then the honest retry: one attestation, one event, audit green.
	if err := os.WriteFile(camp.EventsPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	entry, err := SetBlank(camp, "L-01", key, "checked the caller by hand",
		"operator")
	if err != nil {
		t.Fatalf("retry on a repaired ledger: %v", err)
	}
	if vStr(entry, "probe_axis") != "accumulator-skew" {
		t.Fatalf("retry recorded %s", vStr(entry, "probe_axis"))
	}
	if got := r40eEventCount(t, camp, "probes.blank"); got != 1 {
		t.Fatalf("probes.blank events after the retry = %d, want 1", got)
	}
	if got := r40eAuditProblems(t, camp); got != "" {
		t.Fatalf("section 13 red after the honest attestation: %s", got)
	}
}

// TestR40ERefusedRunProbesRestoresSurfaceBytes pins run_probes: the rebuilt
// surface, its registry row and its probes.run event land together or not at
// all — the refused rebuild leaves the PREVIOUS surface, coherent with the
// row that is still registered for it.
func TestR40ERefusedRunProbesRestoresSurfaceBytes(t *testing.T) {
	camp, _ := r40eSurfaceCamp(t, "C-r40erun000001")
	// A healthy first run with different knobs, so the refused rebuild would
	// demonstrably CHANGE the bytes.
	idx, err := CampaignIndex(camp)
	if err != nil || idx == nil {
		t.Fatalf("fixture index: %v", err)
	}
	if _, err := RunProbes(camp, *idx, validation.VNull(), 12, 40, 3); err != nil {
		t.Fatalf("honest first run: %v", err)
	}
	path := filepath.Join(camp.ArtifactsDir, "probe_surface.json")
	before := r40eSha(t, path)
	auditBefore := r40eAuditProblems(t, camp)
	raw := r40eCutLedger(t, camp)
	if _, err := RunProbes(camp, *idx, validation.VNull(), 8, 20, 2); err == nil ||
		!strings.Contains(err.Error(), "state projection mirrors") {
		t.Fatalf("ledger-door run_probes err = %v (want the projection "+
			"refusal)", err)
	}
	if got := r40eSha(t, path); got != before {
		t.Fatalf("the refused rebuild left the new surface on disk while its "+
			"event was refused:\n before %s\n after  %s", before, got)
	}
	if got := r40eAuditProblems(t, camp); got != auditBefore {
		t.Fatalf("section 13 changed across the refusal:\n before %s\n after  %s",
			auditBefore, got)
	}
	if got := r40eEventCount(t, camp, "probes.run"); got != 1 {
		t.Fatalf("probes.run events = %d, want 1 (only the honest first run)", got)
	}
	// Repair, then the honest retry: the rebuild lands once.
	if err := os.WriteFile(camp.EventsPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := RunProbes(camp, *idx, validation.VNull(), 8, 20, 2); err != nil {
		t.Fatalf("retry on a repaired ledger: %v", err)
	}
	if got := r40eSha(t, path); got == before {
		t.Fatal("the retry did not rebuild the surface")
	}
	if got := r40eEventCount(t, camp, "probes.run"); got != 2 {
		t.Fatalf("probes.run events after the retry = %d, want 2", got)
	}
	if got := r40eAuditProblems(t, camp); got != "" {
		t.Fatalf("section 13 red after the honest rebuild: %s", got)
	}
}

// TestR40EHealthyProbeWritesStillWork is the happy-path guard.
func TestR40EHealthyProbeWritesStillWork(t *testing.T) {
	camp, surface := r40eSurfaceCamp(t, "C-r40ehappy0001")
	acc := t29Axis(t, surface, "accumulator-basis-skew")
	key := vStr(vList(acc, "blind")[0], "key")
	if _, err := SetBlank(camp, "L-01", key, "checked the caller by hand",
		"operator"); err != nil {
		t.Fatalf("honest set_blank refused: %v", err)
	}
	if got := r40eAuditProblems(t, camp); got != "" {
		t.Fatalf("section 13 red: %s", got)
	}
	idx, err := CampaignIndex(camp)
	if err != nil || idx == nil {
		t.Fatalf("fixture index: %v", err)
	}
	if _, err := RunProbes(camp, *idx, validation.VNull(), 12, 40, 3); err != nil {
		t.Fatalf("honest run_probes refused: %v", err)
	}
	if n := r40eEventCount(t, camp, "probes.run"); n != 1 {
		t.Fatalf("probes.run events = %d, want 1", n)
	}
}
