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
	priceEvents, err := priceCollectEvents(c)
	if err != nil {
		return validation.Value{}, err
	}
	tablePath := filepath.Join(c.Dir, "prices.json")
	rows, fileFound, err := readPriceRows(tablePath)
	if err != nil {
		return validation.Value{}, err
	}
	if !fileFound && len(priceEvents) == 0 {
		return validation.Value{}, ErrSkip // never priced anything
	}
	pt := &priceAudit{c: c, priceEvents: priceEvents, rows: rows,
		fileFound: fileFound, have: map[string]bool{}}
	pt.priceBuildLastMap()
	pt.priceCheckRows()
	pt.priceCheckMissing()
	return validation.VObj(
		KV("checked", validation.VInt(int64(len(rows)+len(priceEvents)))),
		KV("problems", validation.VArr(pt.problems...)),
		KV("ok", validation.VBool(len(pt.problems) == 0)),
	), nil
}

// priceAudit carries the price table reconciliation's shared state: the
// log's price.set events, the file's rows, whether the file was found,
// the row ids the file holds, the accumulated problems, and the log's
// last decision per price_id in first-seen order.
type priceAudit struct {
	c           *state.Campaign
	priceEvents []validation.Value
	rows        []validation.Value
	fileFound   bool
	have        map[string]bool
	problems    []validation.Value
	last        map[string]priceLogged
	order       []string
}

// priceLogged is one price_id's governing decision: the event's data
// object.
type priceLogged struct {
	data validation.Value
}

// priceCollectEvents reads the event log once and keeps the price.set
// decisions, in log order.
func priceCollectEvents(c *state.Campaign) ([]validation.Value, error) {
	events, err := c.Events()
	if err != nil {
		return nil, err
	}
	var priceEvents []validation.Value
	for _, e := range events {
		if validation.ObjStr(e, "type") == "price.set" {
			priceEvents = append(priceEvents, e)
		}
	}
	return priceEvents, nil
}

// priceBuildLastMap folds the log to the LAST price.set per price_id, in
// first-seen order.
func (pt *priceAudit) priceBuildLastMap() {
	// Log order = decision order: the LAST price.set per id governs.
	pt.last = map[string]priceLogged{}
	for _, e := range pt.priceEvents {
		rv := validation.ObjAt(e, "ref")
		id := ""
		if rv.Kind == validation.Str {
			id = rv.S
		}
		if id == "" {
			continue
		}
		if _, seen := pt.last[id]; !seen {
			pt.order = append(pt.order, id)
		}
		pt.last[id] = priceLogged{validation.ObjAt(e, "data")}
	}
}

// priceCheckRows polices each file row against the log's last decision
// for it: ghost ids, drifted fields, set_by.
func (pt *priceAudit) priceCheckRows() {
	for _, row := range pt.rows {
		id := validation.ObjStr(row, "price_id")
		pt.have[id] = true
		lg, ok := pt.last[id]
		if !ok {
			pt.problems = append(pt.problems, validation.VStr(fmt.Sprintf(
				"PRICING: %s: prices.json carries a row the log never "+
					"priced (ghost price_id)", id)))
			continue
		}
		for _, field := range []string{"asset", "usd", "source"} {
			got := validation.ObjAt(row, field)
			want := validation.ObjAt(lg.data, field)
			if !pyEqual(got, want) {
				pt.problems = append(pt.problems, validation.VStr(fmt.Sprintf(
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
			pt.problems = append(pt.problems, validation.VStr(fmt.Sprintf(
				"PRICING: %s: set_by is %s in prices.json but the last "+
					"price.set logged %s — the table was edited outside "+
					"the ledger", id, validation.PyRepr(validation.VStr(rowBy)),
				validation.PyRepr(validation.VStr(logBy)))))
		}
	}
}

// priceCheckMissing reports the mirror direction: a price_id the log
// priced that the file lost, and a table missing entirely.
func (pt *priceAudit) priceCheckMissing() {
	for _, id := range pt.order {
		if !pt.have[id] {
			pt.problems = append(pt.problems, validation.VStr(fmt.Sprintf(
				"PRICING: %s: the log priced this id but prices.json has "+
					"no such row", id)))
		}
	}
	if !pt.fileFound {
		pt.problems = append(pt.problems, validation.VStr(
			"PRICING: price events exist but prices.json is missing "+
				"entirely"))
	}
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
