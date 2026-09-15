package pricing

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// ---------------------------------------------------------------------------
// r40b P2-2 — a refused `price set` used to leave a ghost row: SaveTable
// wrote prices.json and only THEN logged price.set with a plain return err.
// Unlike the findings half-lands the audit DOES see this one
// ("PRICING: PRC-xxxx: prices.json carries a row the log never priced"),
// but nothing can repair it — a retry adds a SECOND row for the same asset,
// doctor repairs projections only, and no verb removes a price row.
// Pinned against the honest refusal an operator can always hit: grow the
// ledger, then cut events.jsonl to a shorter PREFIX so the state mirror is
// LONGER than the log — the next Log refuses with
// "events.jsonl holds N event(s) but the state projection mirrors M".
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

// r40bPriceSetEvents counts the ledger's price.set anchors.
func r40bPriceSetEvents(t *testing.T, c *state.Campaign) int {
	t.Helper()
	raw, err := os.ReadFile(c.EventsPath)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	return strings.Count(string(raw), `"price.set"`)
}

// r40bCutLedger grows the ledger a few events, then cuts events.jsonl to a
// shorter prefix so the state mirror is LONGER than the log. Returns the
// full bytes (the sanctioned out-of-band repair: restore the cut tail).
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

// TestR40BRefusedSetPriceLeavesTableByteIdentical pins P2-2.
func TestR40BRefusedSetPriceLeavesTableByteIdentical(t *testing.T) {
	c := priceCamp(t)
	tablePath := path(c)
	// One honest row first: prices.json exists and the ghost would be an
	// APPENDED row, not the whole file.
	if _, err := SetPrice(c, "ETH", 1000.0, "coinmetrics", "", "op"); err != nil {
		t.Fatal(err)
	}
	eventsBaseline := r40bPriceSetEvents(t, c)
	raw := r40bCutLedger(t, c)
	before := r40bSha(t, tablePath)
	if before == "absent" {
		t.Fatal("fixture is not the sharp case: no prices.json")
	}
	_, err := SetPrice(c, "WETH", 2.0, "coinmetrics", "", "op")
	if err == nil || !strings.Contains(err.Error(), "state projection mirrors") {
		t.Fatalf("ledger-door price set err = %v (want the projection refusal)",
			err)
	}
	// prices.json must be byte-identical: no ghost row the audit red-lines
	// and no verb can remove.
	if got := r40bSha(t, tablePath); got != before {
		t.Fatalf("refused price set left a ghost row:\n before %s\n after  %s",
			before, got)
	}
	if got := r40bPriceSetEvents(t, c); got != eventsBaseline {
		t.Fatalf("price.set events after the refusal = %d, want %d (the "+
			"refusal must add none)", got, eventsBaseline)
	}
	table, err := LoadTable(c)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(objAt(table, "prices").A); n != 1 {
		t.Fatalf("rows after the refusal = %d, want 1 (the honest ETH row)", n)
	}
	// Repair (restore the cut tail), then the retry lands exactly ONE new
	// row for the one event — not a second WETH row on top of a ghost.
	if err := os.WriteFile(c.EventsPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	row, err := SetPrice(c, "WETH", 2.0, "coinmetrics", "", "op")
	if err != nil {
		t.Fatalf("retry on a repaired ledger: %v", err)
	}
	table, err = LoadTable(c)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(objAt(table, "prices").A); n != 2 {
		t.Fatalf("rows after the retry = %d, want 2 (ETH + exactly one WETH)", n)
	}
	for _, r := range objAt(table, "prices").A {
		if objStr(r, "asset") == "WETH" &&
			objStr(r, "price_id") != objStr(row, "price_id") {
			t.Fatal("the ghost row survived the retry")
		}
	}
	if got := r40bPriceSetEvents(t, c); got != eventsBaseline+1 {
		t.Fatalf("price.set events after the retry = %d, want %d",
			got, eventsBaseline+1)
	}
}

// TestR40BRefusedSetPriceOnEmptyTablePinsAbsence: the same refusal with no
// pre-existing prices.json must not leave the file behind at all — the
// restore of "did not exist" is the file's absence, never an empty one.
func TestR40BRefusedSetPriceOnEmptyTablePinsAbsence(t *testing.T) {
	c := priceCamp(t)
	tablePath := path(c)
	raw := r40bCutLedger(t, c)
	if _, err := os.Stat(tablePath); !os.IsNotExist(err) {
		t.Fatalf("fixture is not the sharp case: prices.json exists: %v", err)
	}
	if _, err := SetPrice(c, "ETH", 1.0, "coinmetrics", "", "op"); err == nil ||
		!strings.Contains(err.Error(), "state projection mirrors") {
		t.Fatalf("ledger-door price set err = %v (want the projection refusal)",
			err)
	}
	if got := r40bSha(t, tablePath); got != "absent" {
		t.Fatalf("refused price set created prices.json (sha %s); the "+
			"pre-write state was its absence", got)
	}
	if err := os.WriteFile(c.EventsPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := SetPrice(c, "ETH", 1.0, "coinmetrics", "", "op"); err != nil {
		t.Fatalf("retry on a repaired ledger: %v", err)
	}
	if got := r40bPriceSetEvents(t, c); got != 1 {
		t.Fatalf("price.set events after the retry = %d, want 1", got)
	}
}
