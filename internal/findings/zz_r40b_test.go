package findings

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
// r40b — unwind-on-refusal for the two findings writers the r17/r18 sweeps
// missed, pinned against the honest refusal an operator can always hit:
// grow the ledger, then cut events.jsonl to a shorter PREFIX so the state
// mirror is LONGER than the log — the next Log refuses with
// "events.jsonl holds N event(s) but the state projection mirrors M".
//
// P2-1: a refused ingest left F-<id>.json on disk with 0 events (a live
// HYPOTHESIS the ledger never recorded); the retry after the heal ingested
// the payload AGAIN — two findings, one event.
// P3: RecordMitigationScan was a byte-for-byte twin of the ackscan door the
// r18 sweep migrated to SaveThenLog; the scan stamp without its event let a
// re-scan read as already covered.
// ---------------------------------------------------------------------------

// r40bSha is the sha256 of one file (or "absent"), the byte-identity pin.
func r40bSha(t *testing.T, path string) string {
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

// r40bFindingsDigest hashes the findings dir's F-*.json listing (sorted,
// "name:sha" lines; "empty" when none) — the file-presence pin for the
// ingest refusal.
func r40bFindingsDigest(t *testing.T, dir string) string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "F-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		return "empty"
	}
	lines := make([]string, 0, len(matches))
	for _, p := range matches {
		lines = append(lines, filepath.Base(p)+":"+r40bSha(t, p))
	}
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])
}

// r40bFindingFiles counts the F-*.json files on disk.
func r40bFindingFiles(t *testing.T, dir string) int {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "F-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	return len(matches)
}

// r40bEventCount counts the ledger's anchors of one event type.
func r40bEventCount(t *testing.T, c *state.Campaign, eventType string) int {
	t.Helper()
	raw, err := os.ReadFile(c.EventsPath)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	return strings.Count(string(raw), `"`+eventType+`"`)
}

// r40bCutLedger grows the ledger a few events, then cuts events.jsonl to a
// shorter prefix so the state mirror is LONGER than the log. Returns the
// full bytes (the sanctioned out-of-band repair: restore the cut tail) and
// panics via t.Fatal on any error.
func r40bCutLedger(t *testing.T, c *state.Campaign) []byte {
	t.Helper()
	for i := 0; i < 3; i++ {
		data := validation.VObj(kv("note",
			validation.VStr("r40b ledger growth")))
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

// TestR40BRefusedIngestLeavesNoFindingAndRetryDoesNotDouble pins P2-1.
func TestR40BRefusedIngestLeavesNoFindingAndRetryDoesNotDouble(t *testing.T) {
	c := ingestCamp(t)
	raw := r40bCutLedger(t, c)
	digestBefore := r40bFindingsDigest(t, c.FindingsDir)
	if digestBefore != "empty" {
		t.Fatalf("fixture is not the sharp case: findings dir = %s",
			digestBefore)
	}
	_, err := IngestHypothesis(c, hypoPayload(), "code", "", "")
	if err == nil || !strings.Contains(err.Error(), "state projection mirrors") {
		t.Fatalf("ledger-door ingest err = %v (want the projection refusal)",
			err)
	}
	// The finding file must NOT be on disk with zero events behind it.
	if got := r40bFindingsDigest(t, c.FindingsDir); got != "empty" {
		t.Fatalf("refused ingest left a live finding with no event:\n"+
			" before %s\n after  %s", digestBefore, got)
	}
	// Out-of-band repair (the cut tail restored — what `webv2 doctor`
	// reconstructs), then the retry: exactly ONE finding with its event,
	// never two findings with one event.
	if err := os.WriteFile(c.EventsPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := IngestHypothesis(c, hypoPayload(), "code", "", "")
	if err != nil {
		t.Fatalf("retry on a repaired ledger: %v", err)
	}
	if objStr(f, "finding_id") == "" {
		t.Fatal("retry returned a finding with no id")
	}
	if got := r40bFindingsDigest(t, c.FindingsDir); got == "empty" {
		t.Fatal("retry wrote nothing")
	}
	if n := r40bFindingFiles(t, c.FindingsDir); n != 1 {
		t.Fatalf("retry left %d finding file(s), want 1 — the payload was "+
			"ingested twice with one event", n)
	}
	if got := r40bEventCount(t, c, "finding.ingested"); got != 1 {
		t.Fatalf("finding.ingested events = %d, want 1", got)
	}
}

// TestR40BRefusedMitigationScanRestoresFindingBytes pins P3: the
// mitigation-scanned save without its event must unwind, byte for byte.
func TestR40BRefusedMitigationScanRestoresFindingBytes(t *testing.T) {
	// The clock pin makes the half-land deterministic: the ingest stamps
	// updated_at under day 1; the pre-fix half-land re-stamped it under
	// day 2, so the pre-fix bytes provably moved.
	t.Setenv("WEBV2_NOW", "2026-01-01T00:00:00.000000+00:00")
	c := ingestCamp(t)
	f, err := IngestHypothesis(c, hypoPayload(kv("affected",
		validation.VArr(validation.VObj(
			kv("path", validation.VStr("V.sol")),
			kv("lines", validation.VArr(validation.VInt(1))))))),
		"code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	id := objStr(f, "finding_id")
	// NOTE: ingestHypothesis itself runs a fail-open RecordMitigationScan,
	// so the ledger already holds one anchor — count the DELTA.
	eventsBaseline := r40bEventCount(t, c, "finding.mitigation_scanned")
	raw := r40bCutLedger(t, c)
	before := r40bSha(t, FindingPath(c, id))
	if before == "absent" {
		t.Fatal("fixture is not the sharp case: no finding file")
	}
	// A LATER clock: only a half-land would move the file's bytes.
	t.Setenv("WEBV2_NOW", "2026-01-02T00:00:00.000000+00:00")
	if _, err := RecordMitigationScan(c, id); err == nil ||
		!strings.Contains(err.Error(), "state projection mirrors") {
		t.Fatalf("ledger-door mitigscan err = %v (want the projection "+
			"refusal)", err)
	}
	if got := r40bSha(t, FindingPath(c, id)); got != before {
		t.Fatalf("finding bytes changed across the refused mitigation "+
			"scan (the stamp without its event):\n before %s\n after  %s",
			before, got)
	}
	if got := r40bEventCount(t, c, "finding.mitigation_scanned"); got != eventsBaseline {
		t.Fatalf("finding.mitigation_scanned events = %d, want %d (the "+
			"refusal must add none)", got, eventsBaseline)
	}
	// Repair, then the honest retry lands exactly once.
	if err := os.WriteFile(c.EventsPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := RecordMitigationScan(c, id); err != nil {
		t.Fatalf("retry on a repaired ledger: %v", err)
	}
	if got := r40bEventCount(t, c, "finding.mitigation_scanned"); got != eventsBaseline+1 {
		t.Fatalf("finding.mitigation_scanned events after the retry = %d, "+
			"want %d", got, eventsBaseline+1)
	}
}

// TestR40BRefusedIngestStillIngestsHappily is the happy-path guard: the
// unwind must not turn a real ingest into a refusal.
func TestR40BRefusedIngestStillIngestsHappily(t *testing.T) {
	c := ingestCamp(t)
	f, err := IngestHypothesis(c, hypoPayload(), "code", "", "")
	if err != nil {
		t.Fatalf("honest ingest refused: %v", err)
	}
	if objStr(f, "status") != "HYPOTHESIS" {
		t.Fatalf("status = %q, want HYPOTHESIS", objStr(f, "status"))
	}
	if got := r40bEventCount(t, c, "finding.ingested"); got != 1 {
		t.Fatalf("finding.ingested events = %d, want 1", got)
	}
}
