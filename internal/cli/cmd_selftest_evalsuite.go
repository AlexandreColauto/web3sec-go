// cmd_selftest_evalsuite.go: the --full eval-suite self-check — the scorer
// proof that the gold suite self-scores with total recall and zero FP.
package cli

import (
	"fmt"
	"math"
	"strings"

	"websec/assets"
	"websec/internal/evalscore"
	"websec/internal/validation"
	"websec/internal/wilson"
)

// --- --full: eval-suite self-score --------------------------------------

// evalNotExploitable is the gold outcome that inverts the hit rule (a
// clean control scores iff it carries zero live findings).
const evalNotExploitable = "confirmed-not-exploitable"

// checkEvalsuiteSelfcheck is the --full scorer proof: it builds live
// findings synthetically from each gold case (one finding per
// confirmed-exploitable case, class + gold location basename; empty
// slices for the ES16/ES17 controls) and scores the whole suite with
// evalscore.ScoreSuite, failing unless recall is total and FP is zero.
// No docker, no detector: a scorer that scores the suite against itself
// proves the data, not the detector.
func checkEvalsuiteSelfcheck() (bool, string) {
	restore := pinSelftestClock()
	defer restore()
	cases, err := assets.LoadEvalCases()
	if err != nil {
		return false, "evalsuite: " + err.Error()
	}
	var programs []string
	seen := map[string]bool{}
	live := map[string][]validation.Value{}
	for _, cs := range cases {
		prog := validation.ObjStr(validation.ObjAt(cs, "program"), "program")
		gold := validation.ObjAt(cs, "gold")
		if !seen[prog] {
			seen[prog] = true
			programs = append(programs, prog)
		}
		if _, ok := live[prog]; !ok {
			live[prog] = []validation.Value{}
		}
		if validation.ObjStr(gold, "outcome") == evalNotExploitable {
			continue
		}
		path := ""
		for _, l := range validation.ObjAt(gold, "locations").A {
			if f := validation.ObjStr(l, "file"); f != "" {
				if i := strings.LastIndex(f, "/"); i >= 0 {
					f = f[i+1:]
				}
				path = f
				break
			}
		}
		live[prog] = append(live[prog], validation.VObj(
			validation.KV{K: "root_cause", V: validation.VObj(
				validation.KV{K: "class", V: validation.VStr(validation.ObjStr(gold, "bug_class"))})},
			validation.KV{K: "affected", V: validation.VArr(validation.VObj(
				validation.KV{K: "path", V: validation.VStr(path)}))},
		))
	}
	r := evalscore.ScoreSuite(programs, live, cases)
	if r.Hits != r.GoldTotal || r.FP != 0 {
		return false, fmt.Sprintf("self-score %d/%d hits, %d FP (want %d/%d, 0 FP)",
			r.Hits, r.GoldTotal, r.FP, r.GoldTotal, r.GoldTotal)
	}
	lo, hi := wilson.Interval(r.Hits, r.GoldTotal)
	return true, fmt.Sprintf("ok: gold suite self-scores %d/%d "+
		"(95%% CI %.1f–%.1f%%) — scorer semantics proven, NOT a detector claim",
		r.Hits, r.GoldTotal,
		math.Round(lo*1000)/10, math.Round(hi*1000)/10)
}
