package sections

// R45A (P3): section 15's table reader folded EVERY validation.ReadJson error
// into (nil, false) — "prices.json is not there". So `chmod 000 prices.json`
// made the audit print TWO false absence claims about a file the operator is
// looking at: "<price_id>: the log priced this id but prices.json has no such
// row" and "price events exist but prices.json is missing entirely". The
// sibling `webv2 price <C> table` verb already refuses (pricing.LoadTable
// propagates the same read error); this reader now agrees with it: only
// os.IsNotExist is absence, anything else refuses naming the file and the
// errno, so the audit section fails instead of inventing an absence.
//
// The honest shapes stay byte-identical: a campaign that never priced
// anything still returns ErrSkip, and a prices.json that is genuinely gone
// still renders the two absence claims above (pinned below).

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/pricing"
	"websec/internal/state"
	"websec/internal/validation"
)

// r45aPriced seeds one honest row (file + price.set event) and returns the
// table path.
func r45aPriced(t *testing.T) (*state.Campaign, string) {
	t.Helper()
	c := ptCamp(t)
	if _, err := pricing.SetPrice(c, "ETH", 3000.0,
		"coingecko 2026-09-13 snapshot", "2026-09-13", "op"); err != nil {
		t.Fatal(err)
	}
	return c, filepath.Join(c.Dir, "prices.json")
}

func TestR45aPriceTableRefusesUnreadableTable(t *testing.T) {
	c, p := r45aPriced(t)
	r44cChmod(t, p)

	_, err := PriceTable(c)
	if err == nil {
		t.Fatal("an unreadable prices.json was certified as a priced table")
	}
	if errors.Is(err, ErrSkip) {
		t.Fatalf("a read failure is not presence-gating: %v", err)
	}
	if !strings.Contains(err.Error(), "cannot be read") ||
		!strings.Contains(err.Error(), p) ||
		!strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("refusal must name the table and the errno: %v", err)
	}
	if strings.Contains(err.Error(), "no such row") ||
		strings.Contains(err.Error(), "missing entirely") {
		t.Fatalf("a file that exists must not be reported absent: %v", err)
	}
}

// TestR45aPriceTableRefusesNonFileTable: prices.json replaced by a directory
// (EISDIR) — ReadJson cannot read it, and that is not absence.
func TestR45aPriceTableRefusesNonFileTable(t *testing.T) {
	c, p := r45aPriced(t)
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}

	_, err := PriceTable(c)
	if err == nil {
		t.Fatal("a directory in place of prices.json was read as a table")
	}
	if !strings.Contains(err.Error(), p) ||
		!strings.Contains(err.Error(), "is a directory") {
		t.Fatalf("refusal must name the table and EISDIR: %v", err)
	}
}

// TestR45aPriceTableRefusesTornTable: the file is readable but is not a
// document — also a read failure, not an absence.
func TestR45aPriceTableRefusesTornTable(t *testing.T) {
	c, p := r45aPriced(t)
	if err := os.WriteFile(p, []byte("{ not json\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := PriceTable(c)
	if err == nil {
		t.Fatal("a torn prices.json was certified as a priced table")
	}
	if !strings.Contains(err.Error(), "cannot be read") ||
		!strings.Contains(err.Error(), p) {
		t.Fatalf("refusal must name the table: %v", err)
	}
}

// TestR45aPriceTableAbsenceStaysAbsent pins today's wording for genuine
// absence, byte for byte.
func TestR45aPriceTableAbsenceStaysAbsent(t *testing.T) {
	// Never priced anything: no file, no price.set events -> ErrSkip.
	c := ptCamp(t)
	sec, err := PriceTable(c)
	if !errors.Is(err, ErrSkip) {
		t.Fatalf("never-priced campaign must still ErrSkip: %v, %v", sec, err)
	}

	// Priced, then the file is genuinely removed: the two absence claims.
	c2, p := r45aPriced(t)
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	rep, err := PriceTable(c2)
	if err != nil {
		t.Fatalf("a genuinely absent table must render, not refuse: %v", err)
	}
	body := validation.DumpsOrdered(rep, false)
	if !strings.Contains(body, "prices.json has no such row") ||
		!strings.Contains(body, "prices.json is missing entirely") {
		t.Fatalf("genuine absence keeps its wording: %s", body)
	}
}
