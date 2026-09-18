// Policy loading, scope matching, exclusions, accepted risks and severity
// rules: the bounty policy proper.

package bounty

import (
	"fmt"
	"path/filepath"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// LoadPolicy is load_policy: read + schema-validate a program policy.
func LoadPolicy(path string) (validation.Value, error) {
	policy, err := validation.ReadJson(path)
	if err != nil {
		return validation.VNull(), err
	}
	if err := validation.Validate(policy, "bounty_policy", 1); err != nil {
		return validation.VNull(), err
	}
	return policy, nil
}

// SavePolicy is save_policy: validate, then write to *path (default
// <campaign.dir>/bounty_policy.json) and return the path written. A nil or
// empty path selects the campaign default.
func SavePolicy(campaign *state.Campaign, policy validation.Value,
	path *string) (string, error) {
	if err := validation.Validate(policy, "bounty_policy", 1); err != nil {
		return "", err
	}
	p := filepath.Join(campaign.Dir, "bounty_policy.json")
	if path != nil && *path != "" {
		p = *path
	}
	if err := validation.WriteJson(p, policy, ""); err != nil {
		return "", err
	}
	return p, nil
}

// InScope is in_scope: substring scope match on contract name / path /
// address. The bool is the match; the string is the human-facing why.
func InScope(policy validation.Value, target string) (bool, string, error) {
	t := pyLower.String(target)
	for _, s := range validation.ObjAt(policy, "scope").A {
		needleV, ok := fieldAt(s, "target")
		if !ok {
			return false, "", fmt.Errorf("%s", validation.PyReprStr("target"))
		}
		needle := pyLower.String(needleV.S)
		if needle != "" && strings.Contains(t, needle) {
			return true, "matched scope entry " + validation.PyRepr(needleV), nil
		}
	}
	return false, validation.PyReprStr(target) + " matches no scope entry", nil
}

// textHit is _text_hit: substring match, case-insensitive by default.
func textHit(text, pattern string, caseSensitive bool) bool {
	if caseSensitive {
		return strings.Contains(text, pattern)
	}
	return strings.Contains(pyLower.String(text), pyLower.String(pattern))
}

// ExclusionHit is exclusion_hit: the first exclusion whose pattern matches
// class/title/desc/mechanism, or Null (Python None).
func ExclusionHit(policy, finding validation.Value) (validation.Value, error) {
	root := validation.ObjAt(finding, "root_cause")
	haystacks := strings.Join([]string{
		validation.ObjStr(root, "class"),
		validation.ObjStr(finding, "title"),
		validation.ObjStr(root, "description"),
		validation.ObjStr(root, "mechanism"),
	}, " \n")
	for _, ex := range validation.ObjAt(policy, "exclusions").A {
		pattern, ok := fieldAt(ex, "pattern")
		if !ok {
			return validation.VNull(), fmt.Errorf("%s", validation.PyReprStr("pattern"))
		}
		if textHit(haystacks, pattern.S, pyTruthyBigNonEmpty(validation.ObjAt(ex, "case_sensitive"))) {
			return ex, nil
		}
	}
	return validation.VNull(), nil
}

// AcceptedRiskHit is accepted_risk_hit: the first accepted_risks entry whose
// pattern matches class/title/desc/mechanism (the same haystack and text
// semantics as exclusions), or Null. Accepted risks are the program's
// "we know, we accept, we do not pay" channel (IMPROVEMENTS A1).
func AcceptedRiskHit(policy, finding validation.Value) (validation.Value, error) {
	root := validation.ObjAt(finding, "root_cause")
	haystacks := strings.Join([]string{
		validation.ObjStr(root, "class"),
		validation.ObjStr(finding, "title"),
		validation.ObjStr(root, "description"),
		validation.ObjStr(root, "mechanism"),
	}, " \n")
	for _, ar := range validation.ObjAt(policy, "accepted_risks").A {
		pattern, ok := fieldAt(ar, "pattern")
		if !ok {
			return validation.VNull(), fmt.Errorf("%s", validation.PyReprStr("pattern"))
		}
		if textHit(haystacks, pattern.S, pyTruthyBigNonEmpty(validation.ObjAt(ar, "case_sensitive"))) {
			return ar, nil
		}
	}
	return validation.VNull(), nil
}

// severityRank orders the band names for the accepted-risk min_severity cap
// (0 = no severity assigned — the acceptance still applies).
func severityRank(sev string) int {
	switch sev {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "critical":
		return 4
	}
	return 0
}

// SeverityFor is severity_for: deterministic severity from policy rules — the
// highest severity whose match block is satisfied by the finding. The
// severity is "" for Python None.
func SeverityFor(policy, finding validation.Value) (string, string, error) {
	impact := validation.ObjAt(finding, "economic_impact")
	class := validation.ObjStr(validation.ObjAt(finding, "root_cause"), "class")
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		for _, rule := range validation.ObjAt(policy, "severity_rules").A {
			sevV, ok := fieldAt(rule, "severity")
			if !ok {
				return "", "", fmt.Errorf("%s", validation.PyReprStr("severity"))
			}
			if sevV.S != sev {
				continue
			}
			m := validation.ObjAt(rule, "match")
			if bc := validation.ObjAt(m, "bug_classes"); pyTruthyBigNonEmpty(bc) && !inStringList(bc, class) {
				continue
			}
			if br := validation.ObjAt(m, "blast_radius"); pyTruthyBigNonEmpty(br) &&
				!inStringList(br, validation.ObjStr(impact, "blast_radius")) {
				continue
			}
			if minUsd := validation.ObjAt(m, "min_extractable_usd"); minUsd.Kind != validation.Null {
				got, okGot := pyFloat(validation.ObjAt(impact, "extractable_usd"))
				floor, okFloor := pyFloat(minUsd)
				if !okGot {
					got = 0
				}
				if !okFloor || got < floor {
					continue
				}
			}
			if pyTruthyBigNonEmpty(validation.ObjAt(m, "require_invariant_violation")) &&
				!pyTruthyBigNonEmpty(validation.ObjAt(validation.ObjAt(finding, "invariant"), "violation_demonstrated")) {
				continue
			}
			return sev, "matched severity rule for " + sev, nil
		}
	}
	return "", "no severity rule matched", nil
}

// inStringList is `needle in list` for a JSON array of strings.
func inStringList(list validation.Value, needle string) bool {
	for _, e := range list.A {
		if e.Kind == validation.Str && e.S == needle {
			return true
		}
	}
	return false
}
