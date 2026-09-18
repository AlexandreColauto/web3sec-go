// coverage_summary.go: build_summary — the one-glance numbers stamped into
// the ledger (contract/status counts, invariants, surfaces).
package coverage

import (
	"strconv"

	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/validation"
)

// BuildSummary is build_summary: the one-glance numbers, stamped into the
// ledger. index is accepted for signature parity; Python never reads it.
func BuildSummary(c *state.Campaign, index, model validation.Value) (validation.Value, error) {
	_ = index
	cov, err := Load(c)
	if err != nil {
		return validation.VNull(), err
	}
	invCov, err := invariants.Coverage(c)
	if err != nil {
		return validation.VNull(), err
	}
	rows, err := reqKey(cov, "contracts")
	if err != nil {
		return validation.VNull(), err
	}
	analyzed, unknown, err := summaryStatusCounts(rows.A)
	if err != nil {
		return validation.VNull(), err
	}
	invText, invRatio, err := invariantText(invCov)
	if err != nil {
		return validation.VNull(), err
	}
	priv, err := surfaceText(cov, "privilege_paths")
	if err != nil {
		return validation.VNull(), err
	}
	oracle, err := surfaceText(cov, "oracle_surfaces")
	if err != nil {
		return validation.VNull(), err
	}
	summary := validation.VObj(
		kv("contracts_analyzed", validation.VStr(
			strconv.Itoa(analyzed)+"/"+strconv.Itoa(len(rows.A)))),
		kv("contracts_unknown", validation.VInt(int64(unknown))),
		kv("entry_points", validation.VStr(sumField(rows.A, "entry_points_reviewed").text()+
			"/"+sumField(rows.A, "entry_points_total").text())),
		kv("functions", validation.VStr(sumField(rows.A, "functions_reviewed").text()+
			"/"+sumField(rows.A, "functions_total").text())),
		kv("invariants", validation.VStr(invText)),
		kv("invariant_coverage_ratio", invRatio),
		kv("privilege_paths", validation.VStr(priv)),
		kv("oracle_surfaces", validation.VStr(oracle)),
		kv("unknown_note", validation.VStr(
			"contracts with status 'unknown' are NOT secure — they are unexamined")),
	)
	cov.O = validation.SetOrAppend(cov.O, "summary", summary)
	if _, err := Save(c, &cov); err != nil {
		return validation.VNull(), err
	}
	return summary, nil
}

// summaryStatusCounts is contracts_analyzed / contracts_unknown.
func summaryStatusCounts(rows []validation.Value) (int, int, error) {
	analyzed, unknown := 0, 0
	for _, row := range rows {
		status, err := reqKey(row, "status")
		if err != nil {
			return 0, 0, err
		}
		switch status.S {
		case "swept", "in-progress":
			analyzed++
		case "unknown":
			unknown++
		}
	}
	return analyzed, unknown, nil
}

// invariantText is f"{statuses['held'] + statuses['violated']}/{total}" plus
// the test coverage ratio from the invariants module.
func invariantText(invCov validation.Value) (string, validation.Value, error) {
	statuses, err := reqKey(invCov, "statuses")
	if err != nil {
		return "", validation.VNull(), err
	}
	held, err := reqKey(statuses, "held")
	if err != nil {
		return "", validation.VNull(), err
	}
	violated, err := reqKey(statuses, "violated")
	if err != nil {
		return "", validation.VNull(), err
	}
	total, err := reqKey(invCov, "total")
	if err != nil {
		return "", validation.VNull(), err
	}
	ratio, err := reqKey(invCov, "test_coverage_ratio")
	if err != nil {
		return "", validation.VNull(), err
	}
	done := numOrZero(held).add(numOrZero(violated)).text()
	return done + "/" + numOrZero(total).text(), ratio, nil
}

// sumField is sum(c.get(k, 0) or 0 for c in contracts), keeping Python's
// int/float result type.
func sumField(rows []validation.Value, key string) pynum {
	acc := numInt(0)
	for _, row := range rows {
		acc = acc.add(numOrZero(validation.ObjAt(row, key)))
	}
	return acc
}

// surfaceText is f"{surfaces[s]['reviewed']}/{surfaces[s]['total']}".
func surfaceText(cov validation.Value, surface string) (string, error) {
	surfaces, err := reqKey(cov, "surfaces")
	if err != nil {
		return "", err
	}
	row, err := reqKey(surfaces, surface)
	if err != nil {
		return "", err
	}
	reviewed, err := reqKey(row, "reviewed")
	if err != nil {
		return "", err
	}
	total, err := reqKey(row, "total")
	if err != nil {
		return "", err
	}
	return numOrZero(reviewed).text() + "/" + numOrZero(total).text(), nil
}
