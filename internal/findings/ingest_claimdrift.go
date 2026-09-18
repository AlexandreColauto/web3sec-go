// ingest_claimdrift.go: claim_drift_problems — the claim-vs-measurement
// check over the extraction figures a finding's title claims.
package findings

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"websec/internal/validation"
)

var (
	// claimPctRe is r"(\d+(?:\.\d+)?)\s*%" — the trailing class is
	// Python's str whitespace (Go \s + \v, NEL, file separators, and the
	// Unicode space separators). The control chars are embedded as real
	// characters because RE2 has no \u escape.
	claimPctRe = regexp.MustCompile(`(\d+(?:\.\d+)?)` +
		"[\\s\\v\u0085\u001c\u001d\u001e\u001f\\p{Z}]*%")
	// claimHalfRe is r"\bhalf\b" IGNORECASE with Unicode word boundaries.
	claimHalfRe = regexp.MustCompile(`(?i)(?:^|[^\p{L}\p{N}\p{Pc}])half` +
		`(?:$|[^\p{L}\p{N}\p{Pc}])`)
)

// ClaimDriftProblems is claim_drift_problems: the claim-vs-measurement
// check (C).
func ClaimDriftProblems(finding validation.Value) ([]string, error) {
	ratio, ok := pyFloat(validation.ObjAt(validation.ObjAt(finding, "economic_impact"),
		"extraction_ratio"))
	if !ok || !(ratio > 0 && ratio <= 1) {
		return nil, nil
	}
	titleV := validation.ObjAt(finding, "title")
	if titleV.Kind != validation.Str {
		return nil, nil
	}
	var claimed []float64
	for _, m := range claimPctRe.FindAllStringSubmatch(titleV.S, -1) {
		f, err := strconv.ParseFloat(m[1], 64)
		if err != nil {
			return nil, err
		}
		claimed = append(claimed, f/100.0)
	}
	if len(claimed) == 0 && claimHalfRe.MatchString(titleV.S) {
		claimed = []float64{0.5}
	}
	if len(claimed) == 0 {
		return nil, nil
	}
	for _, c := range claimed {
		if math.Abs(c-ratio) <= 0.05 {
			return nil, nil
		}
	}
	closest := claimed[0]
	for _, c := range claimed[1:] {
		if math.Abs(c-ratio) < math.Abs(closest-ratio) {
			closest = c
		}
	}
	return []string{fmt.Sprintf(
		"claim says %.0f%% extraction (closest figure in the title) but "+
			"measured extraction_ratio is %.0f%% — make the claim and the "+
			"measurement agree", closest*100, ratio*100)}, nil
}

// pyFloat is isinstance(v, (int, float)) as a float64 (bool included, as in
// Python; a big-int can never satisfy 0 < x <= 1, so it is rejected).
func pyFloat(v validation.Value) (float64, bool) {
	switch v.Kind {
	case validation.Int:
		if v.Big != "" {
			return 0, false
		}
		return float64(v.I), true
	case validation.Flt:
		return v.F, true
	case validation.Bool:
		if v.B {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}
