package sections

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/pricing"
	"websec/internal/state"
	"websec/internal/validation"
)

func ptCamp(t *testing.T) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "PriceAuditTarget", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestPriceTableSection pins r4 issue 1 end to end: presence-gated skip,
// clean pass over an honest table, and the usd hand-edit caught as drift.
func TestPriceTableSection(t *testing.T) {
	c := ptCamp(t)
	if _, err := PriceTable(c); err != ErrSkip {
		t.Fatalf("never-priced campaign must ErrSkip, got %v", err)
	}
	row, err := pricing.SetPrice(c, "ETH", 3000.0,
		"coingecko 2026-09-13 snapshot", "2026-09-13", "op")
	if err != nil {
		t.Fatal(err)
	}
	rep, err := PriceTable(c)
	if err != nil {
		t.Fatalf("priced campaign renders: %v", err)
	}
	if !objAt(rep, "ok").B {
		t.Fatalf("honest table must pass: %s", validation.DumpsOrdered(rep, false))
	}
	// Hand-edit the file the way no command ever would: usd -> 1.0.
	p := filepath.Join(c.Dir, "prices.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := validation.ParseOrdered(raw)
	if err != nil {
		t.Fatal(err)
	}
	rows := objAt(doc, "prices")
	rows.A[0].O = validation.SetOrAppend(rows.A[0].O, "usd",
		validation.VFloat(1.0))
	doc.O = validation.SetOrAppend(doc.O, "prices", rows)
	if err := os.WriteFile(p, []byte(validation.DumpsOrdered(doc, false)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err = PriceTable(c)
	if err != nil {
		t.Fatal(err)
	}
	body := validation.DumpsOrdered(rep, false)
	if objAt(rep, "ok").B || !strings.Contains(body, "edited outside the ledger") {
		t.Fatalf("usd drift must be named: %s", body)
	}
	if !strings.Contains(body, objStr(row, "price_id")) {
		t.Fatalf("the offending price_id must appear: %s", body)
	}
	// Ghost row (file-only) and missing row (log-only) each name themselves.
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	rep, err = PriceTable(c)
	if err != nil {
		t.Fatal(err)
	}
	if objAt(rep, "ok").B || !strings.Contains(validation.DumpsOrdered(rep, false),
		"prices.json is missing entirely") {
		t.Fatalf("missing file with price events must fail: %s",
			validation.DumpsOrdered(rep, false))
	}
}
