package planner

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// ---------------------------------------------------------------------------
// r40e — unwind-on-refusal for the planner package, pinned against the honest
// refusal an operator can always hit: grow the ledger a few events, then cut
// campaigns/<C>/events.jsonl to a shorter PREFIX so the state mirror is
// LONGER than the log — the next append refuses with
// "events.jsonl holds N event(s) but the state projection mirrors M ...
// run webv2 doctor".
//
// The plan file is campaign TRUTH (the queue, the lens/attestation gates and
// audit read it), so a decided status flip that lands while its plan.* event
// is REFUSED is a decision the ledger never recorded. Every one of these
// verbs writes the plan and THEN appends (SavePlan -> Log), and the artifact
// registration inside SavePlan appends its own event first
// (artifact.registered / artifact.refreshed, whose data pins the new bytes'
// sha256) — which is where the reachable refusal actually lands.
//
// The pins below are the audit predicate restated (a registered row's sha256
// must equal its file's sha256, audit section 2 — internal/audit/sections/
// artifacts.go:62) plus the verify verdict, compared before/after.
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

// r40eArtifactRow is the campaign_state row registered for path (suffix
// match), or null.
func r40eArtifactRow(t *testing.T, c *state.Campaign, suffix string) validation.Value {
	t.Helper()
	st, err := c.State()
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	for _, a := range validation.ObjAt(st, "artifacts").A {
		if strings.HasSuffix(validation.ObjStr(a, "path"), suffix) {
			return a
		}
	}
	return validation.VNull()
}

// r40eAuditMismatch is audit section 2's artifacts check for one path,
// restated: "" when the registered row's sha256 equals the file's, else the
// problem sentence (or a "no row" note, which is audit's normal
// unregistered-bytes case).
func r40eAuditMismatch(t *testing.T, c *state.Campaign, path string) string {
	t.Helper()
	row := r40eArtifactRow(t, c, filepath.Base(path))
	if row.Kind != validation.Obj {
		return ""
	}
	stored := validation.ObjStr(row, "sha256")
	if stored == "" {
		return "registered without a sha256"
	}
	if got := r40eSha(t, path); got != stored {
		return "content hash mismatch (stored " + stored[:12] +
			"..., actual " + got[:12] + "...)"
	}
	return ""
}

// r40eVerifyProblems is the verify verdict's problem list (the mirror/chain
// verdict must be unchanged by a refused write).
func r40eVerifyProblems(t *testing.T, c *state.Campaign) string {
	t.Helper()
	v, err := c.VerifyLog()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return strings.Join(v.Problems, " | ")
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
		if validation.ObjStr(e, "type") == eventType {
			n++
		}
	}
	return n
}

// r40eCutLedger grows the ledger a few events, then cuts events.jsonl to a
// shorter prefix so the state mirror is LONGER than the log. Returns the
// full bytes (the sanctioned out-of-band repair: restore the cut tail, what
// `webv2 doctor` reconstructs).
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

// r40ePlanCamp seeds one campaign whose plan file is already a registered
// living artifact (the state mark_answered / mark_lens / archive_run in).
func r40ePlanCamp(t *testing.T, tag string) (*state.Campaign, validation.Value) {
	t.Helper()
	t.Setenv("WEBV2_NOW", "2026-01-01T00:00:00.000000+00:00")
	c := newCampaign(t, tag)
	plan := maPlan(t, "plan_probe_rows.json")
	if _, err := SavePlan(c, plan); err != nil {
		t.Fatalf("seed SavePlan: %v", err)
	}
	return c, maPlan(t, "plan_probe_rows.json")
}

// TestR40ERefusedMarkAnsweredRestoresPlanBytes pins the named SavePlan->Log
// pair at mark_answered: the closure's status flip and its
// plan.priority_status event land together or not at all, and the plan file
// stays coherent with its registry row (audit section 2 green).
func TestR40ERefusedMarkAnsweredRestoresPlanBytes(t *testing.T) {
	c, plan := r40ePlanCamp(t, "r40e-ma")
	// A LATER clock: only a half-land would stamp a new updated_at.
	t.Setenv("WEBV2_NOW", "2026-01-02T00:00:00.000000+00:00")
	path := planPath(c)
	before := r40eSha(t, path)
	rowBefore := validation.ObjStr(r40eArtifactRow(t, c, "campaign_plan.json"), "sha256")
	if rowBefore != before {
		t.Fatalf("fixture is not coherent: file %s row %s", before, rowBefore)
	}
	if got := r40eAuditMismatch(t, c, path); got != "" {
		t.Fatalf("fixture starts audit-red: %s", got)
	}
	raw := r40eCutLedger(t, c)
	// The cut IS a verify problem; what must not change is the verdict from
	// here on (the refused closure adds no second one).
	verifyBefore := r40eVerifyProblems(t, c)
	reason := "checked by hand: commitBatch re-derives the slots"
	_, err := MarkAnswered(c, plan, "Q-001", "answered",
		AnsweredOpts{Reason: &reason})
	if err == nil || !strings.Contains(err.Error(), "state projection mirrors") {
		t.Fatalf("ledger-door mark_answered err = %v (want the projection "+
			"refusal)", err)
	}
	if got := r40eSha(t, path); got != before {
		t.Fatalf("the refused closure rewrote the plan file (the flip "+
			"without its event):\n before %s\n after  %s", before, got)
	}
	if got := validation.ObjStr(r40eArtifactRow(t, c, "campaign_plan.json"), "sha256"); got != rowBefore {
		t.Fatalf("the refused closure moved the registry row: %s -> %s",
			rowBefore, got)
	}
	if got := r40eAuditMismatch(t, c, path); got != "" {
		t.Fatalf("audit section 2 mismatch after the refusal: %s", got)
	}
	if got := r40eVerifyProblems(t, c); got != verifyBefore {
		t.Fatalf("verify verdict changed across the refusal:\n before %s\n after  %s",
			verifyBefore, got)
	}
	if got := r40eEventCount(t, c, "plan.priority_status"); got != 0 {
		t.Fatalf("plan.priority_status events = %d, want 0", got)
	}
	// Repair, then the honest retry: the closure lands exactly once, and the
	// registration follows the new bytes.
	if err := os.WriteFile(c.EventsPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := MarkAnswered(c, plan, "Q-001", "answered",
		AnsweredOpts{Reason: &reason}); err != nil {
		t.Fatalf("retry on a repaired ledger: %v", err)
	}
	if got := r40eEventCount(t, c, "plan.priority_status"); got != 1 {
		t.Fatalf("plan.priority_status events after the retry = %d, want 1", got)
	}
	after := r40eSha(t, path)
	if after == before {
		t.Fatal("the retry did not rewrite the plan")
	}
	if got := validation.ObjStr(r40eArtifactRow(t, c, "campaign_plan.json"), "sha256"); got != after {
		t.Fatalf("row sha %s != file sha %s after the retry", got, after)
	}
	if got := r40eAuditMismatch(t, c, path); got != "" {
		t.Fatalf("audit section 2 mismatch after the retry: %s", got)
	}
}

// TestR40ERefusedMarkLensRestoresPlanBytes pins the same door at mark_lens:
// a closed lens (an attestation the gates read) must not survive a refused
// plan.lens_status.
func TestR40ERefusedMarkLensRestoresPlanBytes(t *testing.T) {
	c, plan := r40ePlanCamp(t, "r40e-lens")
	t.Setenv("WEBV2_NOW", "2026-01-02T00:00:00.000000+00:00")
	path := planPath(c)
	before := r40eSha(t, path)
	raw := r40eCutLedger(t, c)
	verifyBefore := r40eVerifyProblems(t, c)
	_, err := MarkLens(c, plan, "L-01", "answered", LensOpts{
		Reason: strPtr("the invariant holds on every reachable path"),
		Actor:  "operator"})
	if err == nil || !strings.Contains(err.Error(), "state projection mirrors") {
		t.Fatalf("ledger-door mark_lens err = %v (want the projection refusal)",
			err)
	}
	if got := r40eSha(t, path); got != before {
		t.Fatalf("the refused attestation rewrote the plan file:\n before %s\n after  %s",
			before, got)
	}
	if got := r40eAuditMismatch(t, c, path); got != "" {
		t.Fatalf("audit section 2 mismatch after the refusal: %s", got)
	}
	if got := r40eVerifyProblems(t, c); got != verifyBefore {
		t.Fatalf("verify verdict changed across the refusal:\n before %s\n after  %s",
			verifyBefore, got)
	}
	if got := r40eEventCount(t, c, "plan.lens_status"); got != 0 {
		t.Fatalf("plan.lens_status events = %d, want 0", got)
	}
	if err := os.WriteFile(c.EventsPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := MarkLens(c, plan, "L-01", "answered", LensOpts{
		Reason: strPtr("the invariant holds on every reachable path"),
		Actor:  "operator"}); err != nil {
		t.Fatalf("retry on a repaired ledger: %v", err)
	}
	if got := r40eEventCount(t, c, "plan.lens_status"); got != 1 {
		t.Fatalf("plan.lens_status events after the retry = %d, want 1", got)
	}
	if got := r40eSha(t, path); got == before {
		t.Fatal("the retry did not rewrite the plan")
	}
}

// TestR40ERefusedArchiveLeavesNoOrphanCopy pins the archive site: the
// byte-identical copy, its artifact.registered row and the plan.superseded
// event land together or not at all. Without the door the refused rebuild
// left an unregistered, unrecorded archive that the NEXT rebuild minted
// again at the next version.
func TestR40ERefusedArchiveLeavesNoOrphanCopy(t *testing.T) {
	c, _ := r40ePlanCamp(t, "r40e-archive")
	raw := r40eCutLedger(t, c)
	_, err := ArchivePlan(c, ArchiveOpts{Reason: "r40e rebuild"})
	if err == nil || !strings.Contains(err.Error(), "state projection mirrors") {
		t.Fatalf("ledger-door archive err = %v (want the projection refusal)",
			err)
	}
	if got := SupersededPaths(c); len(got) != 0 {
		t.Fatalf("the refused archive left %v — an unregistered copy with no "+
			"event", got)
	}
	if got := r40eEventCount(t, c, "plan.superseded"); got != 0 {
		t.Fatalf("plan.superseded events = %d, want 0", got)
	}
	if err := os.WriteFile(c.EventsPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	dest, err := ArchivePlan(c, ArchiveOpts{Reason: "r40e rebuild"})
	if err != nil {
		t.Fatalf("retry on a repaired ledger: %v", err)
	}
	got := SupersededPaths(c)
	if len(got) != 1 || got[0] != dest {
		t.Fatalf("archives after the retry = %v, want [%s]", got, dest)
	}
	if a, b := r40eSha(t, dest), r40eSha(t, planPath(c)); a != b {
		t.Fatalf("archive is not a byte-identical copy: %s vs %s", a, b)
	}
	if n := r40eEventCount(t, c, "plan.superseded"); n != 1 {
		t.Fatalf("plan.superseded events after the retry = %d, want 1", n)
	}
	if got := r40eAuditMismatch(t, c, dest); got != "" {
		t.Fatalf("audit section 2 mismatch on the archive: %s", got)
	}
}

// TestR40EHealthyPlanWritesStillWork is the happy-path guard: the door must
// not turn an honest write into a refusal, and the event ORDER the golden
// oracles pin (artifact registration before the decision event) is unchanged.
func TestR40EHealthyPlanWritesStillWork(t *testing.T) {
	c, plan := r40ePlanCamp(t, "r40e-happy")
	reason := "checked by hand: commitBatch re-derives the slots"
	if _, err := MarkAnswered(c, plan, "Q-001", "answered",
		AnsweredOpts{Reason: &reason}); err != nil {
		t.Fatalf("honest mark_answered refused: %v", err)
	}
	if n := r40eEventCount(t, c, "plan.priority_status"); n != 1 {
		t.Fatalf("plan.priority_status events = %d, want 1", n)
	}
	types := []string{}
	evts, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range evts {
		types = append(types, validation.ObjStr(e, "type"))
	}
	artIdx, decidedIdx := -1, -1
	for i, ty := range types {
		if (ty == "artifact.registered" || ty == "artifact.refreshed") && artIdx < 0 {
			artIdx = i
		}
		if ty == "plan.priority_status" {
			decidedIdx = i
		}
	}
	if artIdx < 0 || decidedIdx < 0 || artIdx > decidedIdx {
		t.Fatalf("event order changed: %v", types)
	}
	if got := r40eAuditMismatch(t, c, planPath(c)); got != "" {
		t.Fatalf("audit section 2 mismatch: %s", got)
	}
}
