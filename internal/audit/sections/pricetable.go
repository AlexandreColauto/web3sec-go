// Section 15: the price table — prices.json lives OUTSIDE the event chain,
// but every mutation of it was logged (price.set names its price_id, asset,
// usd, source). This section reconciles the FILE against the log's LAST
// decision per price_id: a hand-edited figure, a ghost row the log never
// priced, or a priced row the file lost is drift — caught exactly like a
// hand-edited floor policy (r4: the money path must not be the unwatched
// path). PRESENCE-GATED like `eval`: a campaign that never priced anything
// (no file, no price.set events) returns ErrSkip and renders nothing, so
// the golden audit surface of unpriced campaigns is unchanged.
package sections

import (
	"fmt"
	"path/filepath"

	"websec/internal/state"
	"websec/internal/validation"
)

// PriceTable is the PRICING section: {checked, problems, ok} or ErrSkip.
func PriceTable(c *state.Campaign) (validation.Value, error) {
	events, err := c.Events()
	if err != nil {
		return validation.Value{}, err
	}
	var priceEvents []validation.Value
	for _, e := range events {
		if objStr(e, "type") == "price.set" {
			priceEvents = append(priceEvents, e)
		}
	}
	tablePath := filepath.Join(c.Dir, "prices.json")
	rows, fileFound := readPriceRows(tablePath)
	if !fileFound && len(priceEvents) == 0 {
		return validation.Value{}, ErrSkip // never priced anything
	}
	// Log order = decision order: the LAST price.set per id governs.
	type logged struct {
		data validation.Value
	}
	last := map[string]logged{}
	var order []string
	for _, e := range priceEvents {
		rv := objAt(e, "ref")
		id := ""
		if rv.Kind == validation.Str {
			id = rv.S
		}
		if id == "" {
			continue
		}
		if _, seen := last[id]; !seen {
			order = append(order, id)
		}
		last[id] = logged{objAt(e, "data")}
	}
	var problems []validation.Value
	have := map[string]bool{}
	for _, row := range rows {
		id := objStr(row, "price_id")
		have[id] = true
		lg, ok := last[id]
		if !ok {
			problems = append(problems, validation.VStr(fmt.Sprintf(
				"PRICING: %s: prices.json carries a row the log never "+
					"priced (ghost price_id)", id)))
			continue
		}
		for _, field := range []string{"asset", "usd", "source"} {
			got := objAt(row, field)
			want := objAt(lg.data, field)
			if !pyEqual(got, want) {
				problems = append(problems, validation.VStr(fmt.Sprintf(
					"PRICING: %s: %s is %s in prices.json but the last "+
						"price.set logged %s — the table was edited "+
						"outside the ledger", id, field,
					validation.PyRepr(got),
					validation.PyRepr(want))))
			}
		}
	}
	for _, id := range order {
		if !have[id] {
			problems = append(problems, validation.VStr(fmt.Sprintf(
				"PRICING: %s: the log priced this id but prices.json has "+
					"no such row", id)))
		}
	}
	if !fileFound {
		problems = append(problems, validation.VStr(
			"PRICING: price events exist but prices.json is missing "+
				"entirely"))
	}
	return validation.VObj(
		KV("checked", validation.VInt(int64(len(rows)+len(priceEvents)))),
		KV("problems", validation.VArr(problems...)),
		KV("ok", validation.VBool(len(problems) == 0)),
	), nil
}

// readPriceRows loads the table file if present: rows, found.
func readPriceRows(path string) ([]validation.Value, bool) {
	doc, err := validation.ReadJson(path)
	if err != nil {
		return nil, false
	}
	return listOf(objAt(doc, "prices")), true
}
