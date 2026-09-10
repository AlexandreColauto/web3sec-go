package cli

// cmd_rank: `webv2 rank <campaign>` — the A3 acceptance-ranked table: the
// operator-facing answer to "which findings matter". Every live finding is
// scored with the deterministic acceptance score (severity band + evidence
// level + critic verdict − ack/accepted-risk demotions + reversibility),
// qualified findings first (score descending, or severity band when the
// policy's submission_budget.rank_by says so), disqualified (critic
// rejected) named below the table.
//
// Read-only: the score is recomputed from recorded fields; nothing is
// written. `webv2 gate <CID>` is what persists the score onto the findings.

import (
	"fmt"
	"sort"
	"strings"

	"websec/internal/bounty"
	"websec/internal/findings"
	"websec/internal/risk"
	"websec/internal/state"
	"websec/internal/validation"
)

const rankUsage = `usage: webv2 rank [-h] campaign
`

func runRank(root string, args []string, r *Runner) int {
	return t14Dispatch(root, r, func() error { return rankCmd(root, args, r) })
}

func rankCmd(root string, args []string, r *Runner) error {
	ensureSeams()
	var pos []string
	var posIdx []int
	var unknown []immunizeUnk
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case strings.HasPrefix(a, "-"):
			unknown = append(unknown, immunizeUnk{i, a})
		default:
			pos = append(pos, a)
			posIdx = append(posIdx, i)
		}
	}
	missing := []string{}
	if len(pos) < 1 {
		missing = append(missing, "campaign")
	}
	if len(missing) > 0 {
		return t14ArgparseErr(rankUsage, "rank",
			"the following arguments are required: %s", strings.Join(missing, ", "))
	}
	if len(pos) > 1 {
		for j, t := range pos[1:] {
			unknown = append(unknown, immunizeUnk{posIdx[1+j], t})
		}
		pos = pos[:1]
	}
	if len(unknown) > 0 {
		sort.Slice(unknown, func(i, j int) bool {
			return unknown[i].idx < unknown[j].idx
		})
		toks := make([]string, len(unknown))
		for i, u := range unknown {
			toks[i] = u.tok
		}
		return t14Unrecognized(strings.Join(toks, " "))
	}
	c, err := state.Open(root, pos[0])
	if err != nil {
		return err
	}
	live, err := findings.LoadLiveFindings(c)
	if err != nil {
		return err
	}
	// the policy's submission_budget.rank_by, when the campaign is scoped
	rankBy := "acceptance"
	var budgetNote string
	st, err := c.State()
	if err != nil {
		return err
	}
	if p := objStr(st, "policy_path"); p != "" {
		if policy, perr := bounty.LoadPolicy(p); perr == nil {
			if sb := objAt(policy, "submission_budget"); sb.Kind ==
				validation.Obj {
				if rb := objStr(sb, "rank_by"); rb == "severity" {
					rankBy = "severity"
				}
				if mf := objAt(sb, "max_findings"); mf.Kind == validation.Int &&
					mf.I > 0 {
					budgetNote = fmt.Sprintf(
						", submission budget %d", mf.I)
				}
			}
		}
	}
	entries := risk.AcceptanceRanking(live, rankBy)
	if len(entries) == 0 {
		fmt.Fprintln(r.Out, "no live findings to rank")
		return nil
	}
	keyName := "acceptance"
	if rankBy == "severity" {
		keyName = "severity"
	}
	fmt.Fprintf(r.Out, "acceptance ranking — %d live finding(s) "+
		"(key: %s%s)\n", len(entries), keyName, budgetNote)
	// A campaign with no policy is UNSCORED: the ranking is a severity order,
	// not a submission order. Say so rather than let it read as advice.
	if p := objStr(st, "policy_path"); p == "" {
		fmt.Fprint(r.Out, rankUnscopedNote)
	}
	fmt.Fprintln(r.Out, "  #  id  score  band  evidence  critic  title")
	i := 0
	var dq []string
	for _, e := range entries {
		if e.Disqualified {
			dq = append(dq, rankID(e))
			continue
		}
		i++
		fmt.Fprintf(r.Out, "  %d  %s  %s  %s  %s  %s  %s\n",
			i, rankID(e), rankScore(e), rankBand(e), rankEvidence(e),
			rankCritic(e), rankTitle(e))
	}
	if len(dq) > 0 {
		fmt.Fprintf(r.Out, "disqualified (critic disproved): %s\n",
			strings.Join(dq, ", "))
	}
	return nil
}

// rankUnscopedNote is the loud line an unscoped campaign prints above its
// ranking: a severity order is not a submission order.
const rankUnscopedNote = "  scope: NO POLICY LOADED — ranked without acceptance " +
	"scores, submission budget or accepted-risks checks; run `webv2 scope` with " +
	"--policy before treating this as a submission order\n"

func rankID(e risk.AcceptanceEntry) string {
	return objStr(e.Finding, "finding_id")
}

func rankScore(e risk.AcceptanceEntry) string {
	s := risk.ScoreText(e.Score)
	if e.AckDemoted {
		s += " -ack"
	}
	if e.RiskDemoted {
		s += " -risk"
	}
	return s
}

func rankBand(e risk.AcceptanceEntry) string {
	riskObj := asDictCLI(objAt(e.Finding, "risk"))
	b := objStr(asDictCLI(objAt(riskObj, "validated")), "band")
	if b == "" {
		b = "—"
	}
	return b
}

func rankEvidence(e risk.AcceptanceEntry) string {
	l, err := findings.FindingLevel(e.Finding)
	if err != nil {
		return "—"
	}
	return l
}

func rankCritic(e risk.AcceptanceEntry) string {
	v := objStr(objAt(e.Finding, "verification"), "critic_verdict")
	if v == "" {
		return "—"
	}
	return v
}

func rankTitle(e risk.AcceptanceEntry) string {
	t := objStr(e.Finding, "title")
	if len(t) > 44 {
		t = t[:44] + "…"
	}
	return t
}

func init() {
	register(command{ord: 70, name: "rank",
		line: "rank <campaign>  acceptance-ranked table — which findings matter",
		run:  runRank})
}
