// The cost-projection mirror law: costs.jsonl rows and cost.recorded ledger events must describe the same spend, both directions.
package costs

import (
	"fmt"
	"strconv"
	"websec/internal/state"
	"websec/internal/validation"
)

// CostMirrorProblems is the ONE cost-projection law: costs.jsonl rows
// and cost.recorded ledger events must describe the same spend, both
// directions. The audit (sections.Projection) reports these; the
// ENFORCEMENT side (BudgetStatus) refuses to price a campaign over
// them (r15: a ghost row halted pipelines on spend the audit
// simultaneously called forged — the gate and the truth reader each
// trusted their own file). Presence-gated: quiet campaigns and fully
// consistent ones return nothing.
func CostMirrorProblems(c *state.Campaign) []string {
	m := &mirrorProblems{
		c:     c,
		byID:  map[string]mirrorLedger{},
		count: map[string]int{},
		sum:   map[string]float64{},
		kinds: map[string]map[string]bool{},
	}
	costEvts, done := m.mirrorLoadEvents()
	if done {
		return m.problems
	}
	rows, done := m.mirrorLoadRows()
	if done {
		return m.problems
	}
	if len(costEvts) == 0 && len(rows) == 0 {
		return nil
	}
	m.mirrorFoldLedger(costEvts)
	m.mirrorFoldRows(rows)
	m.mirrorCompare()
	return m.problems
}

// mirrorProblems carries CostMirrorProblems' cross-check state: the
// ledger's per-id aggregate and the file's per-id aggregate, compared in
// both directions by mirrorCompare.
type mirrorProblems struct {
	c        *state.Campaign
	problems []string
	byID     map[string]mirrorLedger
	count    map[string]int
	sum      map[string]float64
	kinds    map[string]map[string]bool
}

// mirrorLedger is the per-cost-id aggregate of the ledger's
// cost.recorded events: event count, summed amounts, every kind seen.
type mirrorLedger struct {
	n     int
	sum   float64
	kinds map[string]bool
}

// mirrorLoadEvents reads the ledger and keeps the cost.recorded events
// (with their refs). It reports done when the ledger is unreadable and
// the problem has been recorded.
func (m *mirrorProblems) mirrorLoadEvents() ([]validation.Value, bool) {
	evts, err := m.c.Events()
	if err != nil {
		// r17 P2: an UNREADABLE ledger is strictly worse than a damaged
		// mirror — returning nil here priced spend off the rows alone
		// while verify screamed red ("cost: $42.00 spent" on a GARBAGE
		// log). "The ledger verdict belongs to verify" justified
		// silence, not authority to evaluate spend against nothing.
		m.problems = append(m.problems, "the event ledger is unreadable, so recorded "+
			"costs cannot be cross-checked: "+err.Error())
		return nil, true
	}
	var costEvts []validation.Value
	refs := map[string]bool{}
	for _, e := range evts {
		if validation.ObjStr(e, "type") == "cost.recorded" {
			costEvts = append(costEvts, e)
			refs[validation.ObjStr(e, "ref")] = true
		}
	}
	return costEvts, false
}

// mirrorLoadRows reads costs.jsonl; it reports done when the file is
// unreadable and the problem has been recorded.
func (m *mirrorProblems) mirrorLoadRows() ([]validation.Value, bool) {
	rows, rerr := LoadCosts(m.c)
	if rerr != nil {
		m.problems = append(m.problems,
			fmt.Sprintf("costs.jsonl unreadable: %v", rerr))
		return nil, true
	}
	return rows, false
}

// mirrorFoldLedger aggregates the ledger's cost.recorded events per cost
// id, flagging events that carry no ref.
// r16 P1-1: the law is about SPEND, not id-existence — comparing
// cost_id strings alone let one appended duplicate-id row double the
// booked amount (audit PASS while budget priced phantom money) and
// let an amount rewrite hide under its own id. Per id the ledger and
// the file must agree on COUNT and on the SUM of amounts (and every
// kind the id carries): twin stores legitimately repeat an id across
// rows — uuid4 is per-row but the pinned fixtures prove identity is
// not the invariant — so equality is aggregated, and that catches
// inflation, dodging, and edits alike.
func (m *mirrorProblems) mirrorFoldLedger(costEvts []validation.Value) {
	for _, e := range costEvts {
		id := validation.ObjStr(e, "ref")
		if id == "" {
			m.problems = append(m.problems, "a cost.recorded event carries no ref — "+
				"spend the ledger cannot attribute")
			continue
		}
		l := m.byID[id]
		l.n++
		if a := validation.ObjAt(validation.ObjAt(e, "data"), "amount_usd"); a.Kind == validation.Flt ||
			a.Kind == validation.Int {
			f, _ := numberValue(a)
			l.sum += f
		}
		if l.kinds == nil {
			l.kinds = map[string]bool{}
		}
		if k := validation.ObjStr(validation.ObjAt(e, "data"), "kind"); k != "" {
			l.kinds[k] = true
		}
		m.byID[id] = l
	}
}

// mirrorFoldRows aggregates costs.jsonl's rows per cost id, flagging
// rows that carry no cost_id.
func (m *mirrorProblems) mirrorFoldRows(rows []validation.Value) {
	for _, r := range rows {
		id := validation.ObjStr(r, "cost_id")
		if id == "" {
			m.problems = append(m.problems, "costs.jsonl has a row with no cost_id — "+
				"spend that cannot be attributed cannot be audited")
			continue
		}
		m.count[id]++
		if a := validation.ObjAt(r, "amount_usd"); a.Kind == validation.Flt ||
			a.Kind == validation.Int {
			f, _ := numberValue(a)
			m.sum[id] += f
		}
		if m.kinds[id] == nil {
			m.kinds[id] = map[string]bool{}
		}
		if k := validation.ObjStr(r, "kind"); k != "" {
			m.kinds[id][k] = true
		}
	}
}

// mirrorCompare cross-checks the two aggregates in both directions:
// every ledger id must exist in the file with the same count, the same
// summed amount, and the same kinds; every file id must exist in the
// ledger.
func (m *mirrorProblems) mirrorCompare() {
	for id, l := range m.byID {
		if m.count[id] == 0 {
			m.problems = append(m.problems, fmt.Sprintf("the ledger records cost %s (%s) "+
				"but costs.jsonl has no row for it", id,
				pyReprValue(validation.VFloat(l.sum))))
			continue
		}
		if m.count[id] != l.n {
			m.problems = append(m.problems, fmt.Sprintf(
				"costs.jsonl carries %d rows for cost %s but the ledger "+
					"recorded %d — spend was duplicated or events lost",
				m.count[id], id, l.n))
			continue
		}
		if m.sum[id] != l.sum {
			m.problems = append(m.problems, fmt.Sprintf(
				"costs.jsonl books $%s under cost %s but the ledger "+
					"events sum to $%s — the recorded amounts were "+
					"edited in the file", format2(m.sum[id]), id,
				format2(l.sum)))
			continue
		}
		for k := range l.kinds {
			if !m.kinds[id][k] {
				m.problems = append(m.problems, fmt.Sprintf(
					"the ledger says cost %s was kind %s but no costs.jsonl "+
						"row for it is — the recorded kind was edited", id, k))
			}
		}
	}
	for id := range m.count {
		if _, ok := m.byID[id]; !ok {
			m.problems = append(m.problems, fmt.Sprintf("costs.jsonl row(s) for cost %s "+
				"were never recorded in the ledger — ghost spend inflates "+
				"the budget silently; costs are owed through `webv2 cost`, "+
				"not by editing the file", id))
		}
	}
}

// sameSpend compares ledger vs row numbers the way Python's == would
// across int/float (1 == 1.0), and treats any non-number as unequal to
// a number. Null vs Null is equal (a cost recorded without an amount
// matches a row without one).
func sameSpend(a, b validation.Value) bool {
	if a.Kind == validation.Null && b.Kind == validation.Null {
		return true
	}
	an, aok := numberValue(a)
	bn, bok := numberValue(b)
	if aok && bok {
		return an == bn
	}
	return false
}

func numberValue(v validation.Value) (float64, bool) {
	switch v.Kind {
	case validation.Flt:
		return v.F, true
	case validation.Int:
		return float64(v.I), true
	}
	return 0, false
}

// pyReprValue renders a number for a message (None, 10.0, 4).
func pyReprValue(v validation.Value) string {
	if v.Kind == validation.Null {
		return "None"
	}
	f, ok := numberValue(v)
	if !ok {
		return validation.PyRepr(v)
	}
	if v.Kind == validation.Int {
		return validation.IntText(v)
	}
	return validation.PythonFloat(f)
}

// format2 renders a money figure for messages (2 decimals, plain).
func format2(f float64) string {
	return strconv.FormatFloat(f, 'f', 2, 64)
}
