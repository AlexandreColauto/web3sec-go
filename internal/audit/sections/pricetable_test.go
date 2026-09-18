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
	if !validation.ObjAt(rep, "ok").B {
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
	rows := validation.ObjAt(doc, "prices")
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
	if validation.ObjAt(rep, "ok").B || !strings.Contains(body, "edited outside the ledger") {
		t.Fatalf("usd drift must be named: %s", body)
	}
	if !strings.Contains(body, validation.ObjStr(row, "price_id")) {
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
	if validation.ObjAt(rep, "ok").B || !strings.Contains(validation.DumpsOrdered(rep, false),
		"prices.json is missing entirely") {
		t.Fatalf("missing file with price events must fail: %s",
			validation.DumpsOrdered(rep, false))
	}
}

// TestPriceTableWatchesModule pins r5 issue 8: set_by is log-catchable, so
// a hand-edited attribution must drift too — while the twin's raw-vs-stripped
// actor asymmetry never false-positives.
func TestPriceTableWatchesModule(t *testing.T) {
	c := ptCamp(t)
	if _, err := pricing.SetPrice(c, "ETH", 1500.0,
		"coingecko snapshot", "2026-09-13", "  Ada Lovelace  "); err != nil {
		t.Fatal(err)
	}
	rep, err := PriceTable(c)
	if err != nil {
		t.Fatal(err)
	}
	if !validation.ObjAt(rep, "ok").B {
		t.Fatalf("raw-vs-stripped actor is the DESIGN, not drift: %s",
			validation.DumpsOrdered(rep, false))
	}
	p := filepath.Join(c.Dir, "prices.json")
	raw, _ := os.ReadFile(p)
	doc, _ := validation.ParseOrdered(raw)
	rows := validation.ObjAt(doc, "prices")
	rows.A[0].O = validation.SetOrAppend(rows.A[0].O, "set_by",
		validation.VStr("Mallory"))
	doc.O = validation.SetOrAppend(doc.O, "prices", rows)
	if err := os.WriteFile(p,
		[]byte(validation.DumpsOrdered(doc, true)), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err = PriceTable(c)
	if err != nil {
		t.Fatal(err)
	}
	body := validation.DumpsOrdered(rep, false)
	if validation.ObjAt(rep, "ok").B || !strings.Contains(body, "set_by") ||
		!strings.Contains(body, "Mallory") {
		t.Fatalf("attribution edit must drift: %s", body)
	}
}
