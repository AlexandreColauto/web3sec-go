// Measurement gate checks: price basis (check8) and claim drift (check9)
// — every USD figure names its row, and the claim matches the measurement.

package bounty

import (
	"sort"
	"strings"

	"websec/internal/findings"
	"websec/internal/validation"
)

// check8 is price basis (G) — every USD figure must name the price row it was
// computed from.
func (g *gate) check8() error {
	ei := validation.ObjAt(g.f, "economic_impact")
	var usdKeys []string
	for _, kv := range ei.O {
		if strings.HasSuffix(kv.K, "_usd") && kv.V.Kind != validation.Null {
			usdKeys = append(usdKeys, kv.K)
		}
	}
	if len(usdKeys) == 0 {
		return nil
	}
	sort.Strings(usdKeys)
	basis := validation.ObjAt(ei, "price_basis")
	row := validation.VNull()
	if pyTruthyBigNonEmpty(basis) && basis.Kind == validation.Str {
		var err error
		row, err = priceRowFunc(g.campaign, basis.S)
		if err != nil {
			return err
		}
	}
	if row.Kind != validation.Obj {
		g.add("e7-price-basis", "fail", "USD figures "+validation.PyListRepr(usdKeys)+
			" carry no resolvable price_basis "+validation.PyRepr(basis), "")
		g.blockers = append(g.blockers,
			"USD figures without a resolvable price basis")
		return nil
	}
	detail := validation.PyStr(basis) + " -> " + validation.PyStr(validation.ObjAt(row, "asset")) + " @ $" +
		validation.PyStr(validation.ObjAt(row, "usd")) + " (" +
		headRunes(validation.PyStr(validation.ObjAt(row, "source")), 40) + ")"
	g.add("e7-price-basis", "pass", detail, "")
	return nil
}

// check9 is claim drift (C) — the claim must not contradict the measurement.
func (g *gate) check9() error {
	drifts, err := findings.ClaimDriftProblems(g.f)
	if err != nil {
		return err
	}
	if len(drifts) > 0 {
		g.add("claim-drift", "fail", drifts[0], "")
		g.blockers = append(g.blockers,
			"claim contradicts measured extraction_ratio")
		return nil
	}
	g.add("claim-drift", "pass", "", "")
	return nil
}
