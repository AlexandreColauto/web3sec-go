package learning

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
// r40d — unwind-on-refusal pin for the learning package's whole-file writers
// (memory rows + the sanctioned strip). The honest refusal an operator can
// always hit: grow the ledger, then cut events.jsonl to a shorter PREFIX so
// the state mirror is LONGER than the log — the next Log refuses with
// "events.jsonl holds N event(s) but the state projection mirrors M".
//
// Before r40 QueueMemory/ApproveMemory/RejectMemory/StripCampaignMemoryField
// wrote their JSON files and then logged with no restore: a refused event
// left a queued/approved/rejected row (or a destructively stripped set of
// rows) on disk that the ledger never recorded — the inbox gate, the human
// approval gate and the audit trail all read the file as truth. The pin: the
// artifact bytes are sha256-identical across the refusal (or absent), the
// event counts do not move, and the honest path still lands.
// ---------------------------------------------------------------------------

// r40dSha is the sha256 of one file (or "absent"), the byte-identity pin.
func r40dSha(t *testing.T, path string) string {
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

// r40dMemoryDigest hashes the memory dir's MEM-*.json listing (sorted,
// "name:sha" lines; "empty" when none) — the dir-level identity pin.
func r40dMemoryDigest(t *testing.T, dir string) string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "MEM-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		return "empty"
	}
	lines := make([]string, 0, len(matches))
	for _, p := range matches {
		lines = append(lines, filepath.Base(p)+":"+r40dSha(t, p))
	}
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])
}

// r40dEventCount counts the ledger's anchors of one event type.
func r40dEventCount(t *testing.T, c *state.Campaign, eventType string) int {
	t.Helper()
	raw, err := os.ReadFile(c.EventsPath)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	return strings.Count(string(raw), `"`+eventType+`"`)
}

// r40dCutLedger grows the ledger a few events, then cuts events.jsonl to a
// shorter prefix so the state mirror is LONGER than the log. Returns the
// full bytes (the sanctioned out-of-band repair: restore the cut tail).
func r40dCutLedger(t *testing.T, c *state.Campaign) []byte {
	t.Helper()
	for i := 0; i < 3; i++ {
		data := validation.VObj(kv("note",
			validation.VStr("r40d ledger growth")))
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

// TestR40DRefusedQueueLeavesNoMemoryFile pins QueueMemory: a refused
// memory.queued must leave the inbox empty — no row the ledger never
// recorded, and the retry after the heal must not duplicate it.
func TestR40DRefusedQueueLeavesNoMemoryFile(t *testing.T) {
	c := newCampaign(t, "r40d-queue")
	raw := r40dCutLedger(t, c)
	before := r40dMemoryDigest(t, c.MemoryDir)
	if before != "empty" {
		t.Fatalf("fixture is not the sharp case: memory dir = %s", before)
	}
	_, err := QueueMemory(c, QueueOpts{Kind: "confirmed", Status: "CONFIRMED",
		Pattern: "r40d memory pattern (long enough)", EvidenceSummary: "r40d evidence"})
	if err == nil || !strings.Contains(err.Error(), "state projection mirrors") {
		t.Fatalf("queue err = %v (want the projection refusal)", err)
	}
	if got := r40dMemoryDigest(t, c.MemoryDir); got != "empty" {
		t.Fatalf("refused queue left a memory row with no event:\n"+
			" before %s\n after  %s", before, got)
	}
	// Repair, then the honest retry lands exactly one row with its event.
	if err := os.WriteFile(c.EventsPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	mem, err := QueueMemory(c, QueueOpts{Kind: "confirmed", Status: "CONFIRMED",
		Pattern: "r40d memory pattern (long enough)", EvidenceSummary: "r40d evidence"})
	if err != nil {
		t.Fatalf("retry on a repaired ledger: %v", err)
	}
	if got := r40dMemoryDigest(t, c.MemoryDir); got == "empty" {
		t.Fatal("retry wrote nothing")
	}
	if n := len(strings.Split(r40dMemoryDigest(t, c.MemoryDir), "\n")); n != 1 {
		t.Fatalf("retry left %d memory row(s), want 1 — the candidate was "+
			"queued twice for one event", n)
	}
	if got := r40dEventCount(t, c, "memory.queued"); got != 1 {
		t.Fatalf("memory.queued events = %d, want 1", got)
	}
	if validation.ObjStr(mem, "promotion_status") != "pending" {
		t.Fatalf("promotion_status = %q, want pending",
			validation.ObjStr(mem, "promotion_status"))
	}
}

// TestR40DRefusedApproveAndRejectRestoreRowBytes pins ApproveMemory and
// RejectMemory: the promotion-status flip is the human gate's state; a
// refused event must leave the row byte-identical and still pending.
func TestR40DRefusedApproveAndRejectRestoreRowBytes(t *testing.T) {
	c := newCampaign(t, "r40d-gate")
	rowPath := func(id string) string {
		return filepath.Join(c.MemoryDir, id+".json")
	}
	// Two honest queues (rows on disk, events in the ledger).
	mustQueue(t, c, QueueOpts{Kind: "confirmed", Status: "DISPROVED",
		Pattern: "r40d disprove pattern", EvidenceSummary: "r40d evidence"})
	mustQueue(t, c, QueueOpts{Kind: "confirmed", Status: "CONFIRMED",
		Pattern: "r40d confirm pattern", EvidenceSummary: "r40d evidence"})
	rows, err := AllMemory(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("fixture: %d rows, want 2", len(rows))
	}
	var approveID, rejectID string
	for _, r := range rows {
		if validation.ObjStr(r, "status") == "DISPROVED" {
			approveID = validation.ObjStr(r, "memory_id") // rejection_class default ok
		} else {
			rejectID = validation.ObjStr(r, "memory_id")
		}
	}
	raw := r40dCutLedger(t, c)
	approveBefore := r40dSha(t, rowPath(approveID))
	rejectBefore := r40dSha(t, rowPath(rejectID))

	if _, err := ApproveMemory(c, approveID, "alex"); err == nil ||
		!strings.Contains(err.Error(), "state projection mirrors") {
		t.Fatalf("approve err = %v (want the projection refusal)", err)
	}
	if got := r40dSha(t, rowPath(approveID)); got != approveBefore {
		t.Fatalf("refused approve moved the row bytes (the flip without "+
			"its event):\n before %s\n after  %s", approveBefore, got)
	}
	if _, err := RejectMemory(c, rejectID, "r40d written rejection reason",
		"invalid-hypothesis"); err == nil ||
		!strings.Contains(err.Error(), "state projection mirrors") {
		t.Fatalf("reject err = %v (want the projection refusal)", err)
	}
	if got := r40dSha(t, rowPath(rejectID)); got != rejectBefore {
		t.Fatalf("refused reject moved the row bytes (the flip without "+
			"its event):\n before %s\n after  %s", rejectBefore, got)
	}

	// Repair, then both honest flips land.
	if err := os.WriteFile(c.EventsPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ApproveMemory(c, approveID, "alex"); err != nil {
		t.Fatalf("retry approve: %v", err)
	}
	if _, err := RejectMemory(c, rejectID, "r40d written rejection reason",
		"invalid-hypothesis"); err != nil {
		t.Fatalf("retry reject: %v", err)
	}
	approved, err := validation.ReadJson(rowPath(approveID))
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(approved, "promotion_status") != "human-approved" ||
		validation.ObjStr(approved, "approved_by") != "alex" {
		t.Fatalf("approved row = %v", approved)
	}
	rejected, err := validation.ReadJson(rowPath(rejectID))
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(rejected, "promotion_status") != "rejected" {
		t.Fatalf("rejected row promotion_status = %q, want rejected",
			validation.ObjStr(rejected, "promotion_status"))
	}
	if got := r40dEventCount(t, c, "memory.approved"); got != 1 {
		t.Fatalf("memory.approved events = %d, want 1", got)
	}
	if got := r40dEventCount(t, c, "memory.rejected"); got != 1 {
		t.Fatalf("memory.rejected events = %d, want 1", got)
	}
}

// TestR40DRefusedStripRestoresRowBytes pins StripCampaignMemoryField: the
// strip is destructive and sanctioned ONLY by its event, so a refused
// memory.field-stripped must leave every target row byte-identical.
func TestR40DRefusedStripRestoresRowBytes(t *testing.T) {
	root := t.TempDir()
	a, err := state.Init(root, "r40d-strip", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	stripRow(t, a, "MEM-legacy0001", true, "CONFIRMED")
	stripRow(t, a, "MEM-legacy0002", true, "CONFIRMED")
	digestBefore := r40dMemoryDigest(t, a.MemoryDir)
	raw := r40dCutLedger(t, a)

	if _, err := StripCampaignMemoryField(root, "rag_doc_id", "operator",
		"r40d: schema retirement stranded campaign rows"); err == nil ||
		!strings.Contains(err.Error(), "state projection mirrors") {
		t.Fatalf("strip err = %v (want the projection refusal)", err)
	}
	if got := r40dMemoryDigest(t, a.MemoryDir); got != digestBefore {
		t.Fatalf("refused strip moved the row bytes (rows stripped with "+
			"no event):\n before %s\n after  %s", digestBefore, got)
	}
	// Repair, then the honest strip lands with its event.
	if err := os.WriteFile(a.EventsPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := StripCampaignMemoryField(root, "rag_doc_id", "operator",
		"r40d: schema retirement stranded campaign rows")
	if err != nil {
		t.Fatalf("retry strip: %v", err)
	}
	if got := validation.ObjAt(out, "total_stripped").I; got != 2 {
		t.Fatalf("total_stripped = %d, want 2", got)
	}
	if got := r40dEventCount(t, a, "memory.field-stripped"); got != 1 {
		t.Fatalf("memory.field-stripped events = %d, want 1", got)
	}
	for _, id := range []string{"MEM-legacy0001", "MEM-legacy0002"} {
		row, err := validation.ReadJson(filepath.Join(a.MemoryDir, id+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := fieldAt(row, "rag_doc_id"); ok {
			t.Fatalf("%s still holds rag_doc_id after the honest strip", id)
		}
	}
}
