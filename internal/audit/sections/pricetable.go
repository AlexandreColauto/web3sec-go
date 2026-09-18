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
	"os"
	"path/filepath"
	"strings"

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
		if validation.ObjStr(e, "type") == "price.set" {
			priceEvents = append(priceEvents, e)
		}
	}
	tablePath := filepath.Join(c.Dir, "prices.json")
	rows, fileFound, err := readPriceRows(tablePath)
	if err != nil {
		return validation.Value{}, err
	}
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
		rv := validation.ObjAt(e, "ref")
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
		last[id] = logged{validation.ObjAt(e, "data")}
	}
	var problems []validation.Value
	have := map[string]bool{}
	for _, row := range rows {
		id := validation.ObjStr(row, "price_id")
		have[id] = true
		lg, ok := last[id]
		if !ok {
			problems = append(problems, validation.VStr(fmt.Sprintf(
				"PRICING: %s: prices.json carries a row the log never "+
					"priced (ghost price_id)", id)))
			continue
		}
		for _, field := range []string{"asset", "usd", "source"} {
			got := validation.ObjAt(row, field)
			want := validation.ObjAt(lg.data, field)
			if !pyEqual(got, want) {
				problems = append(problems, validation.VStr(fmt.Sprintf(
					"PRICING: %s: %s is %s in prices.json but the last "+
						"price.set logged %s — the table was edited "+
						"outside the ledger", id, field,
					validation.PyRepr(got), validation.PyRepr(want))))
			}
		}
		// set_by: the log keeps the RAW actor, the row the stripped one
		// (pricing's own asymmetry) — stripped-vs-stripped, so ordinary
		// whitespace never false-positives but "Mallory" does (r5).
		rowBy, logBy := validation.ObjStr(row, "set_by"), validation.ObjStr(lg.data, "actor")
		if pyStripStr(rowBy) != pyStripStr(logBy) {
			problems = append(problems, validation.VStr(fmt.Sprintf(
				"PRICING: %s: set_by is %s in prices.json but the last "+
					"price.set logged %s — the table was edited outside "+
					"the ledger", id, validation.PyRepr(validation.VStr(rowBy)),
				validation.PyRepr(validation.VStr(logBy)))))
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
//
// r45a: the old body returned (nil, false) for EVERY ReadJson error — "the
// file is not there" — so `chmod 000 prices.json` made this section print TWO
// false absence claims (the log's row "has no such row", and prices.json
// "missing entirely") about a file the operator is looking at. Only
// os.IsNotExist is absence; anything else (EACCES, EISDIR, ENOTDIR, a torn
// document) is a read failure and REFUSES, naming the file and the errno, so
// the audit section fails instead of inventing an absence. This is the
// semantics `webv2 price <C> table` already has (pricing.LoadTable propagates
// the same read error).
func readPriceRows(path string) ([]validation.Value, bool, error) {
	doc, err := validation.ReadJson(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil // genuinely no table file: absence is a fact
		}
		return nil, false, fmt.Errorf("the price table %s cannot be read: %v",
			path, err)
	}
	return listOf(validation.ObjAt(doc, "prices")), true, nil
}

// pyStripStr is Python str.strip() on a CLI-visible string.
func pyStripStr(s string) string { return strings.TrimSpace(s) }
