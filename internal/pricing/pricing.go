// Package pricing is the port of webv2/pricing.py: the campaign asset-price
// table (policy-as-data for E7 reproducibility).
//
// Run-1 lesson: E7 forces USD numbers, but with no campaign price reference
// the operator web-searched an ETH mid-price mid-run — the quantification
// became unreproducible. Prices are now first-class campaign data: every row
// carries value + source + as_of + named actor; E7 impact numbers cite a
// price_basis (a price_id); the report renders the basis beside every USD
// figure; the bounty gate fails USD numbers with no basis.
package pricing

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"websec/internal/state"
	"websec/internal/validation"
)

// tableName is _TABLE.
const tableName = "prices.json"

// pyUpper is Python's str.upper(): the FULL Unicode case mapping (ß -> SS,
// ﬁ -> FI), not strings.ToUpper's per-rune simple mapping.
var pyUpper = cases.Upper(language.Und)

// path is _path: <campaign dir>/prices.json.
func path(campaign *state.Campaign) string {
	return filepath.Join(campaign.Dir, tableName)
}

// LoadTable is load_table: the campaign price table, or the empty default
// when no row has ever been recorded.
func LoadTable(campaign *state.Campaign) (validation.Value, error) {
	p := path(campaign)
	if _, err := os.Stat(p); err != nil {
		return validation.VObj(
			validation.KV{K: "campaign_id",
				V: validation.VStr(campaign.CampaignID)},
			validation.KV{K: "updated_at", V: validation.VNull()},
			validation.KV{K: "prices", V: validation.VArr()},
		), nil
	}
	table, err := validation.ReadJson(p)
	if err != nil {
		return validation.VNull(), err
	}
	if err := validation.Validate(table, "price_table", 1); err != nil {
		return validation.VNull(), err
	}
	return table, nil
}

// SaveTable is save_table: stamp campaign_id + updated_at, validate, write.
// The caller's table is mutated in place, as Python's dict is.
func SaveTable(campaign *state.Campaign, table *validation.Value) (string, error) {
	table.O = validation.SetOrAppend(table.O, "campaign_id",
		validation.VStr(campaign.CampaignID))
	table.O = validation.SetOrAppend(table.O, "updated_at", validation.VStr(nowIso()))
	if err := validation.Validate(*table, "price_table", 1); err != nil {
		return "", err
	}
	p := path(campaign)
	if err := validation.WriteJson(p, *table, ""); err != nil {
		return "", err
	}
	return p, nil
}

// saveTableThenLog is the pricing sibling of the state package's
// AppendJsonlThenLog and the findings package's SaveThenLog (r40b P2-2):
// a prices.json row written while its price.set event was REFUSED is a
// ghost row the audit red-lines permanently — a retry adds a SECOND row
// for the same asset, doctor repairs projections only, and no verb
// removes a price row. So the file's bytes are snapshotted before the
// write, and a refused log restores those exact bytes — or removes a
// file that did not exist yet, never creating an empty one. A FAILED
// restore means the row bytes are still AHEAD of the refused event; name
// both failures so no caller can report a clean unwind that never
// happened.
func saveTableThenLog(campaign *state.Campaign, table *validation.Value,
	log func() error) error {
	p := path(campaign)
	prevRaw, perr := os.ReadFile(p)
	had := perr == nil
	if perr != nil && !os.IsNotExist(perr) {
		return perr
	}
	restore := func() error {
		if had {
			return os.WriteFile(p, prevRaw, 0o644)
		}
		if rerr := os.Remove(p); rerr != nil && !os.IsNotExist(rerr) {
			return rerr
		}
		return nil
	}
	if _, err := SaveTable(campaign, table); err != nil {
		return err
	}
	if err := log(); err != nil {
		if rerr := restore(); rerr != nil {
			return fmt.Errorf("%w (UNWIND ALSO FAILED: %v — %s holds "+
				"post-write bytes with no event; repair by hand before "+
				"continuing)", err, rerr, tableName)
		}
		return err
	}
	return nil
}

// SetPrice is set_price: record one price row. Rows are append-only per
// asset: the newest is effective, older rows stay for reproducing past
// quantifications.
func SetPrice(campaign *state.Campaign, asset string, usd float64, source,
	asOf, actor string) (validation.Value, error) {
	if asset == "" || pyStrip(asset) == "" {
		return validation.VNull(), errors.New("asset symbol required")
	}
	if usd <= 0 {
		return validation.VNull(), fmt.Errorf(
			"usd must be a positive number, got %s", validation.PythonFloat(usd))
	}
	if source == "" || actor == "" {
		return validation.VNull(), errors.New("a price needs a source and a " +
			"named actor — 'web search mid-run' is not a source")
	}
	table, err := LoadTable(campaign)
	if err != nil {
		return validation.VNull(), err
	}
	row := validation.VObj(
		validation.KV{K: "price_id",
			V: validation.VStr("PRC-" + idTail(state.NewID("x", 8)))},
		validation.KV{K: "asset",
			V: validation.VStr(pyUpper.String(pyStrip(asset)))},
		validation.KV{K: "usd", V: validation.VFloat(usd)},
		validation.KV{K: "source", V: validation.VStr(pyStrip(source))},
		validation.KV{K: "as_of",
			V: validation.VStr(pyStrip(asOfOrNow(asOf)))},
		validation.KV{K: "set_by", V: validation.VStr(pyStrip(actor))},
		validation.KV{K: "set_at", V: validation.VStr(nowIso())},
	)
	prices := objAt(table, "prices")
	prices.A = append(prices.A, row)
	table.O = validation.SetOrAppend(table.O, "prices", prices)
	// r40b P2-2: the row without its price.set event is a ghost the audit
	// can never repair. Unwind.
	data := validation.VObj(
		validation.KV{K: "asset", V: objAt(row, "asset")},
		validation.KV{K: "usd", V: objAt(row, "usd")},
		validation.KV{K: "source", V: objAt(row, "source")},
		// The log keeps the RAW actor; only the row stores the stripped one.
		validation.KV{K: "actor", V: validation.VStr(actor)},
	)
	ref := objStr(row, "price_id")
	if err := saveTableThenLog(campaign, &table, func() error {
		_, lerr := campaign.Log("price.set", &ref, &data)
		return lerr
	}); err != nil {
		return validation.VNull(), err
	}
	return row, nil
}

// PriceRow is price_row: the matching row, or nil when the id is unknown.
func PriceRow(campaign *state.Campaign, priceID string) (*validation.Value,
	error) {
	table, err := LoadTable(campaign)
	if err != nil {
		return nil, err
	}
	for _, r := range objAt(table, "prices").A {
		if objStr(r, "price_id") == priceID {
			row := r
			return &row, nil
		}
	}
	return nil, nil
}

// asOfOrNow is `as_of or now_iso()`.
func asOfOrNow(asOf string) string {
	if asOf == "" {
		return nowIso()
	}
	return asOf
}

// idTail is new_id(prefix, n).split("-")[1].
func idTail(id string) string {
	parts := strings.SplitN(id, "-", 2)
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

// objAt is d.get(key) as a Value: a missing key reads as Null.
func objAt(v validation.Value, key string) validation.Value {
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V
		}
	}
	return validation.VNull()
}

// objStr is a string field's value ("" when absent/non-string).
func objStr(v validation.Value, key string) string {
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V.S
		}
	}
	return ""
}

// pyStrip is Python's str.strip() with no argument.
func pyStrip(s string) string {
	return strings.TrimFunc(s, pySpace)
}

// pySpace is Py_UNICODE_ISSPACE: the Unicode White_Space property plus the
// ASCII file separators U+001C-U+001F (Python's str.isspace() says true
// there, unicode.IsSpace does not).
func pySpace(r rune) bool {
	if r >= 0x1c && r <= 0x1f {
		return true
	}
	return unicode.IsSpace(r)
}

// nowIso is now_iso (mirrors state.nowIso, unexported there). The WEBV2_NOW
// golden-suite clock pin is honored identically.
func nowIso() string {
	if v := os.Getenv("WEBV2_NOW"); v != "" {
		return v
	}
	now := time.Now().UTC()
	return fmt.Sprintf("%s.%06d+00:00",
		now.Format("2006-01-02T15:04:05"), now.Nanosecond()/1000)
}
