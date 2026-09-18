package pricing

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// PORT-NOTE tests/test_budget.py and tests/test_metrics.py contain no
// function that calls pricing.* — nothing to port from them (see report).

const pinnedNow = "2026-01-01T00:00:00.000000+00:00"

// priceCamp is the `camp` fixture for the pricing functions.
func priceCamp(t *testing.T) *state.Campaign {
	t.Helper()
	t.Setenv("WEBV2_NOW", pinnedNow)
	c, err := state.Init(t.TempDir(), "Acme Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var prcID = regexp.MustCompile(`^PRC-[0-9a-f]{8}$`)

func TestLoadTableEmpty(t *testing.T) {
	c := priceCamp(t)
	table, err := LoadTable(c)
	if err != nil {
		t.Fatal(err)
	}
	// CanonSpaced sorts keys; the insertion order is pinned separately.
	want := `{"campaign_id": "` + c.CampaignID + `", "prices": [], ` +
		`"updated_at": null}`
	if got := validation.CanonSpaced(table); got != want {
		t.Errorf("LoadTable = %s; want %s", got, want)
	}
	if table.O[0].K != "campaign_id" || table.O[1].K != "updated_at" ||
		table.O[2].K != "prices" {
		t.Errorf("key order = %v", table.O)
	}
	if validation.ObjAt(table, "prices").Kind != validation.Arr {
		t.Errorf("prices kind = %c", validation.ObjAt(table, "prices").Kind)
	}
	if _, err := os.Stat(filepath.Join(c.Dir, "prices.json")); err == nil {
		t.Error("load_table must not create the file")
	}
}

// TestSetPriceRow pins the row + the on-disk table (Python twin output with
// the PRC id interpolated — the id stream is process-global).
func TestSetPriceRow(t *testing.T) {
	c := priceCamp(t)
	row, err := SetPrice(c, " eth ", 2345.5, " coinmetrics ", " 2026-01-01 ", " op ")
	if err != nil {
		t.Fatal(err)
	}
	pid := validation.ObjAt(row, "price_id").S
	if !prcID.MatchString(pid) {
		t.Errorf("price_id = %q; want PRC-<8 hex>", pid)
	}
	wantRow := `{"as_of": "2026-01-01", "asset": "ETH", "price_id": "` + pid +
		`", "set_at": "` + pinnedNow + `", "set_by": "op", ` +
		`"source": "coinmetrics", "usd": 2345.5}`
	if got := validation.CanonSpaced(row); got != wantRow {
		t.Errorf("row = %s; want %s", got, wantRow)
	}
	wantFile := `{
  "campaign_id": "` + c.CampaignID + `",
  "updated_at": "` + pinnedNow + `",
  "prices": [
    {
      "price_id": "` + pid + `",
      "asset": "ETH",
      "usd": 2345.5,
      "source": "coinmetrics",
      "as_of": "2026-01-01",
      "set_by": "op",
      "set_at": "` + pinnedNow + `"
    }
  ]
}
`
	raw, err := os.ReadFile(filepath.Join(c.Dir, "prices.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != wantFile {
		t.Errorf("prices.json:\n%s\nwant:\n%s", raw, wantFile)
	}
}

// TestSetPriceEventKeepsRawActor: the log data carries the RAW actor while
// the row stores the stripped one (Python logs the kwarg).
func TestSetPriceEventKeepsRawActor(t *testing.T) {
	c := priceCamp(t)
	row, err := SetPrice(c, "eth", 1.0, "coinmetrics", "", " op ")
	if err != nil {
		t.Fatal(err)
	}
	pid := validation.ObjAt(row, "price_id").S
	evs, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	var found int
	for _, e := range evs {
		if validation.ObjStr(e, "type") != "price.set" {
			continue
		}
		found++
		if validation.ObjStr(e, "ref") != pid {
			t.Errorf("ref = %q; want %q", validation.ObjStr(e, "ref"), pid)
		}
		want := `{"actor":" op ","asset":"ETH","source":"coinmetrics","usd":1.0}`
		if got := validation.CanonCompact(validation.ObjAt(e, "data")); got != want {
			t.Errorf("data = %s; want %s", got, want)
		}
	}
	if found != 1 {
		t.Errorf("price.set events = %d; want 1", found)
	}
	if validation.ObjAt(row, "set_by").S != "op" {
		t.Errorf("set_by = %q; want stripped", validation.ObjAt(row, "set_by").S)
	}
}

func TestSetPriceAppendOnly(t *testing.T) {
	c := priceCamp(t)
	first, err := SetPrice(c, "ETH", 1000.0, "coinmetrics", "", "op")
	if err != nil {
		t.Fatal(err)
	}
	second, err := SetPrice(c, "ETH", 2000.0, "coinmetrics", "", "op")
	if err != nil {
		t.Fatal(err)
	}
	table, err := LoadTable(c)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(validation.ObjAt(table, "prices").A); n != 2 {
		t.Fatalf("rows = %d; want 2 (append-only)", n)
	}
	got1, err := PriceRow(c, validation.ObjAt(first, "price_id").S)
	if err != nil {
		t.Fatal(err)
	}
	got2, err := PriceRow(c, validation.ObjAt(second, "price_id").S)
	if err != nil {
		t.Fatal(err)
	}
	if got1 == nil || got2 == nil {
		t.Fatal("both rows must stay addressable")
	}
	if validation.ObjAt(*got1, "usd").F != 1000.0 || validation.ObjAt(*got2, "usd").F != 2000.0 {
		t.Errorf("usd = %v / %v", validation.ObjAt(*got1, "usd").F, validation.ObjAt(*got2, "usd").F)
	}
}

func TestPriceRowMiss(t *testing.T) {
	c := priceCamp(t)
	row, err := PriceRow(c, "PRC-nope")
	if err != nil {
		t.Fatal(err)
	}
	if row != nil {
		t.Errorf("unknown id -> %v; want nil", row)
	}
	if _, err := SetPrice(c, "ETH", 1.0, "coinmetrics", "", "op"); err != nil {
		t.Fatal(err)
	}
	row, err = PriceRow(c, "PRC-nope")
	if err != nil || row != nil {
		t.Errorf("unknown id after a row exists -> (%v, %v)", row, err)
	}
}

func TestSetPriceErrors(t *testing.T) {
	c := priceCamp(t)
	cases := []struct {
		name                 string
		asset, source, actor string
		usd                  float64
		want                 string
	}{
		{"empty-asset", "", "s", "a", 1.0, "asset symbol required"},
		{"blank-asset", "   ", "s", "a", 1.0, "asset symbol required"},
		{"zero-usd", "ETH", "s", "a", 0, "usd must be a positive number, got 0.0"},
		{"negative-usd", "ETH", "s", "a", -1.5,
			"usd must be a positive number, got -1.5"},
		{"no-source", "ETH", "", "a", 1.0,
			"a price needs a source and a named actor — 'web search mid-run' " +
				"is not a source"},
		{"no-actor", "ETH", "s", "", 1.0,
			"a price needs a source and a named actor — 'web search mid-run' " +
				"is not a source"},
	}
	for _, c2 := range cases {
		_, err := SetPrice(c, c2.asset, c2.usd, c2.source, "", c2.actor)
		if err == nil || err.Error() != c2.want {
			t.Errorf("%s: err = %v; want %q", c2.name, err, c2.want)
		}
	}
	if _, err := os.Stat(filepath.Join(c.Dir, "prices.json")); err == nil {
		t.Error("a rejected price must not write the table")
	}
}

// TestSetPriceFullCaseMapping: Python's str.upper() is the FULL Unicode
// mapping (ß -> SS), not strings.ToUpper's per-rune simple one.
func TestSetPriceFullCaseMapping(t *testing.T) {
	c := priceCamp(t)
	row, err := SetPrice(c, "ß", 1.0, "coinmetrics", "", "op")
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjAt(row, "asset").S; got != "SS" {
		t.Errorf("asset = %q; want SS", got)
	}
	row, err = SetPrice(c, "ﬁat", 1.0, "coinmetrics", "", "op")
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjAt(row, "asset").S; got != "FIAT" {
		t.Errorf("asset = %q; want FIAT", got)
	}
}

// TestSetPriceStripsPythonWhitespace: Python's str.strip() also trims
// U+001C-U+001F, which unicode.IsSpace does not.
func TestSetPriceStripsPythonWhitespace(t *testing.T) {
	c := priceCamp(t)
	row, err := SetPrice(c, "\x1ceth\x1c", 1.0, "\x1fcoinmetrics\x1f", "", "op")
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjAt(row, "asset").S; got != "ETH" {
		t.Errorf("asset = %q; want ETH", got)
	}
	if got := validation.ObjAt(row, "source").S; got != "coinmetrics" {
		t.Errorf("source = %q", got)
	}
}

func TestSaveTableStampsAndValidates(t *testing.T) {
	c := priceCamp(t)
	table, err := LoadTable(c)
	if err != nil {
		t.Fatal(err)
	}
	p, err := SaveTable(c, &table)
	if err != nil {
		t.Fatal(err)
	}
	if p != filepath.Join(c.Dir, "prices.json") {
		t.Errorf("path = %q", p)
	}
	if validation.ObjAt(table, "campaign_id").S != c.CampaignID {
		t.Errorf("caller table not stamped: %s", validation.CanonSpaced(table))
	}
	if validation.ObjAt(table, "updated_at").S != pinnedNow {
		t.Errorf("updated_at = %q", validation.ObjAt(table, "updated_at").S)
	}
	back, err := LoadTable(c)
	if err != nil {
		t.Fatal(err)
	}
	if validation.CanonSpaced(back) != validation.CanonSpaced(table) {
		t.Errorf("round trip = %s", validation.CanonSpaced(back))
	}
}

func TestSaveTableRejectsInvalid(t *testing.T) {
	c := priceCamp(t)
	bad := validation.VObj(
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("updated_at", validation.VStr(pinnedNow)),
		kv("prices", validation.VArr(validation.VObj(
			kv("price_id", validation.VStr("PRC-abc123")),
			kv("asset", validation.VStr("ETH")),
			kv("usd", validation.VInt(0)),
			kv("source", validation.VStr("coinmetrics")),
			kv("as_of", validation.VStr("2026-01-01")),
			kv("set_by", validation.VStr("op")),
			kv("set_at", validation.VStr(pinnedNow))))),
	)
	_, err := SaveTable(c, &bad)
	if err == nil {
		t.Fatal("usd=0 must fail price_table validation")
	}
	var se *validation.SchemaError
	if !errors.As(err, &se) {
		t.Fatalf("err = %v; want *validation.SchemaError", err)
	}
	if !strings.Contains(err.Error(), "price_table") {
		t.Errorf("message = %q; want the schema name", err.Error())
	}
}

func TestLoadTableRejectsCorruptFile(t *testing.T) {
	c := priceCamp(t)
	if err := os.WriteFile(filepath.Join(c.Dir, "prices.json"),
		[]byte("{\"campaign_id\": \"C-x\", \"updated_at\": null}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTable(c); err == nil {
		t.Fatal("a table without prices must fail validation")
	}
	if _, err := PriceRow(c, "PRC-x"); err == nil {
		t.Error("price_row must surface the validation failure")
	}
}

func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}
