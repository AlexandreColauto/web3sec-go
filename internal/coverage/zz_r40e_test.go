package coverage

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"websec/internal/audit/sections"
	"websec/internal/state"
	"websec/internal/validation"
)

// ---------------------------------------------------------------------------
// r40e — unwind-on-refusal for coverage.record_sweep, pinned against the
// honest refusal an operator can always hit: grow the ledger a few events,
// then cut campaigns/<C>/events.jsonl to a shorter PREFIX so the state mirror
// is LONGER than the log — the next append refuses with
// "events.jsonl holds N event(s) but the state projection mirrors M ...
// run webv2 doctor".
//
// coverage.json is campaign TRUTH (the uncovered-critical gates, the funnel
// accounting and every report read it), so a sweep row that lands while its
// coverage.sweep event is REFUSED is a disposition the ledger never
// recorded — and the retry after the heal writes a SECOND row for the one
// event. The door (saveThenLog) restores the pre-write bytes exactly.
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

// r40eAuditSection2 runs audit section 2 itself (Artifacts), the registry
// ->disk integrity section, and returns its problems joined.
func r40eAuditSection2(t *testing.T, c *state.Campaign) string {
	t.Helper()
	sec, err := sections.Artifacts(c)
	if err != nil {
		t.Fatalf("sections.Artifacts: %v", err)
	}
	items := []string{}
	for _, p := range validation.ObjAt(sec, "problems").A {
		items = append(items, p.S)
	}
	return strings.Join(items, " | ")
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

// r40eSweepCase is the first record_sweep oracle case that succeeds, with
// its seed, contract, trajectory and option tail.
func r40eSweepCase(t *testing.T) (validation.Value, string, string, string, SweepOpts) {
	t.Helper()
	doc := readTest(t, "oracle_sweeps.json")
	for _, c := range casesOf(t, doc) {
		if validation.ObjAt(c, "error").Kind == validation.Obj {
			continue
		}
		return c, validation.ObjStr(c, "label"), validation.ObjStr(c, "seed"),
			validation.ObjStr(c, "contract"), SweepOpts{
				EntryPointsReviewed: validation.ObjAt(c, "entry_points_reviewed").I,
				FunctionsReviewed:   validation.ObjAt(c, "functions_reviewed").I,
				Complete:            validation.ObjAt(c, "complete").B,
			}
	}
	t.Fatal("no successful record_sweep oracle case")
	return validation.VNull(), "", "", "", SweepOpts{}
}

// TestR40ERefusedRecordSweepRestoresLedgerBytes pins the sweep: the row and
// its coverage.sweep event land together or not at all, and the retry after
// the heal writes ONE row, never two.
func TestR40ERefusedRecordSweepRestoresLedgerBytes(t *testing.T) {
	t.Setenv("WEBV2_NOW", pinnedNow)
	c, label, seed, contract, opts := r40eSweepCase(t)
	camp := seedCampaign(t, label, seed)
	path := Path(camp)
	before := r40eSha(t, path)
	raw := r40eCutLedger(t, camp)
	auditBefore := r40eAuditSection2(t, camp)
	if _, err := RecordSweep(camp, contract, "code", opts); err == nil ||
		!strings.Contains(err.Error(), "state projection mirrors") {
		t.Fatalf("ledger-door record_sweep err = %v (want the projection "+
			"refusal)", err)
	}
	if got := r40eSha(t, path); got != before {
		t.Fatalf("the refused sweep rewrote the coverage ledger (the row "+
			"without its event):\n before %s\n after  %s", before, got)
	}
	if got := r40eEventCount(t, camp, "coverage.sweep"); got != 0 {
		t.Fatalf("coverage.sweep events = %d, want 0", got)
	}
	if got := r40eAuditSection2(t, camp); got != auditBefore {
		t.Fatalf("audit section 2 changed across the refusal:\n before %s\n after  %s",
			auditBefore, got)
	}
	// Repair, then the honest retry: exactly one row and one event.
	if err := os.WriteFile(camp.EventsPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	row, err := RecordSweep(camp, contract, "code", opts)
	if err != nil {
		t.Fatalf("retry on a repaired ledger: %v", err)
	}
	if got := r40eEventCount(t, camp, "coverage.sweep"); got != 1 {
		t.Fatalf("coverage.sweep events after the retry = %d, want 1", got)
	}
	if r40eSha(t, path) == before {
		t.Fatal("the retry did not rewrite the coverage ledger")
	}
	if got := r40eAuditSection2(t, camp); got != "" {
		t.Fatalf("audit section 2 red after the honest retry: %s", got)
	}
	// The retry reproduces the Python twin's recorded row and file exactly.
	wantCanon(t, label, row, validation.ObjStr(c, "result"))
	wantFile(t, label, path, validation.ObjStr(c, "file"))
}

// TestR40EHealthyRecordSweepStillWorks is the happy-path guard: the door
// must not turn an honest sweep into a refusal.
func TestR40EHealthyRecordSweepStillWorks(t *testing.T) {
	t.Setenv("WEBV2_NOW", pinnedNow)
	c, label, seed, contract, opts := r40eSweepCase(t)
	camp := seedCampaign(t, label, seed)
	row, err := RecordSweep(camp, contract, "code", opts)
	if err != nil {
		t.Fatalf("honest record_sweep refused: %v", err)
	}
	if got := r40eEventCount(t, camp, "coverage.sweep"); got != 1 {
		t.Fatalf("coverage.sweep events = %d, want 1", got)
	}
	wantCanon(t, label, row, validation.ObjStr(c, "result"))
	wantFile(t, label, Path(camp), validation.ObjStr(c, "file"))
}
