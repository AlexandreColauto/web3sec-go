// assumptions_render.go: G10 table rendering — the shared display
// projection fed by AssumptionTable (Task 2) and consumed by BOTH the
// briefing block and the report block, so the two can never drift apart.
//
// Pure function, no IO, no campaign handle (the Task 2 AssumptionTable
// pattern): the renderers own presence-gating (the Task 4 law — render
// only when len(rows) > 0 AND (any row carries a non-null detail OR
// len(gaps) > 0), so a chains-only legacy model renders NOTHING).
package protocolgraph

import (
	"websec/internal/validation"
)

// declaredNone is the null-detail marker: a missing assumption renders as
// declared state, never as an empty string and never as "None".
const declaredNone = "declared: none"

// detailOrNone renders one table cell: the pyStr value when present, the
// declared-none marker when null/absent.
func detailOrNone(v validation.Value) string {
	if v.Kind == validation.Null {
		return declaredNone
	}
	return pyStr(v)
}

// RenderAssumptionLines is the per-hop assumption table display: one line
// per AssumptionTable row plus one per gap, rows first in table order then
// gaps in table order:
//
//   - <chain>: finality=<v|declared: none> confirmations=<n|declared: none>
//     messenger=<v|declared: none> separator=<v|declared: none>
//   - ASSUMPTION GAP <hop> <chain>: <reason>
//
// Only these four columns render — validator_set/threshold stay in the
// projection (AssumptionTable rows) for future use, not in the line. The
// gap reason renders verbatim. Labels use pyStr (strings render raw).
func RenderAssumptionLines(rows, gaps []validation.Value) []string {
	out := []string{}
	for _, r := range rows {
		out = append(out, "- "+pyStr(objAt(r, "chain"))+
			": finality="+detailOrNone(objAt(r, "finality"))+
			" confirmations="+detailOrNone(objAt(r, "confirmation_depth"))+
			" messenger="+detailOrNone(objAt(r, "messenger"))+
			" separator="+detailOrNone(objAt(r, "separator")))
	}
	for _, g := range gaps {
		out = append(out, "- ASSUMPTION GAP "+pyStr(objAt(g, "hop"))+
			" "+pyStr(objAt(g, "chain"))+": "+pyStr(objAt(g, "reason")))
	}
	return out
}
