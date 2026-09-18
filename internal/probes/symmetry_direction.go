package probes

import (
	"regexp"
)

// ---- directions -----------------------------------------------------------

// symmetryDirection is one (name, pattern) pair. Order decides: "drop" is a
// recovery word and must win over the generic withdrawal verbs.
type symmetryDirection struct {
	name string
	re   *regexp.Regexp
}

var symmetryDirectionTable = []symmetryDirection{
	{"drop", regexp.MustCompile(`(?i)^(_?on)?drop`)},
	{"recover", regexp.MustCompile(
		`(?i)^(refund|recover|rescue|emergency|claim|withdraw.*fail|force.*withdraw)`)},
	{"withdrawal", regexp.MustCompile(
		`(?i)^(_?withdraw|unstake|unlock|exit|redeem|release|_?burn)`)},
	{"deposit", regexp.MustCompile(
		`(?i)^(_?deposit|stake|lock|join|supply|_?mint|bridge|provide|add.*liquidity)`)},
}

// symmetryDirectionOf is the direction a function name serves, or "other"
// when it moves custody without matching a known verb.
func symmetryDirectionOf(function string) string {
	for _, d := range symmetryDirectionTable {
		if d.re.MatchString(function) {
			return d.name
		}
	}
	return "other"
}
