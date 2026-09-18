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
	"io"
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
	if helpRequested(r.Out, "rank", args) {
		return nil
	}

	ensureSeams()
	rp, err := rankParseArgs(args)
	if err != nil {
		return err
	}
	c, err := state.Open(root, rp.pos[0])
	if err != nil {
		return err
	}
	live, err := findings.LoadLiveFindings(c)
	if err != nil {
		return err
	}
	pv, err := rankLoadPolicyView(c)
	if err != nil {
		return err
	}
	actionable, heldBack := rankActionable(live)
	entries := rankComputeEntries(actionable, pv.rankBy, pv.policy)
	if len(entries) == 0 {
		if heldBack > 0 {
			fmt.Fprintf(r.Out, "no candidate findings to rank (%d "+
				"disproof/informational row(s): outcomes, not "+
				"candidates — the scorecard still counts them)\n",
				heldBack)
			return nil
		}
		fmt.Fprintln(r.Out, "no live findings to rank")
		return nil
	}
	rankPrintTable(r.Out, entries, heldBack, pv)
	return nil
}

// rankParsed carries the parsed `rank` command line: the collected
// positionals and the unrecognized tokens still to be checked.
type rankParsed struct {
	pos     []string
	posIdx  []int
	unknown []immunizeUnk
}

// rankParseArgs scans the raw arguments with cli.py's hand-rolled loop.
func rankParseArgs(args []string) (*rankParsed, error) {
	rp := &rankParsed{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case strings.HasPrefix(a, "-"):
			rp.unknown = append(rp.unknown, immunizeUnk{i, a})
		default:
			rp.pos = append(rp.pos, a)
			rp.posIdx = append(rp.posIdx, i)
		}
	}
	missing := []string{}
	if len(rp.pos) < 1 {
		missing = append(missing, "campaign")
	}
	if len(missing) > 0 {
		return nil, t14ArgparseErr(rankUsage, "rank",
			"the following arguments are required: %s", strings.Join(missing, ", "))
	}
	if len(rp.pos) > 1 {
		for j, t := range rp.pos[1:] {
			rp.unknown = append(rp.unknown, immunizeUnk{rp.posIdx[1+j], t})
		}
		rp.pos = rp.pos[:1]
	}
	if len(rp.unknown) > 0 {
		sort.Slice(rp.unknown, func(i, j int) bool {
			return rp.unknown[i].idx < rp.unknown[j].idx
		})
		toks := make([]string, len(rp.unknown))
		for i, u := range rp.unknown {
			toks[i] = u.tok
		}
		return nil, t14Unrecognized(strings.Join(toks, " "))
	}
	return rp, nil
}

// rankPolicyView carries the policy-derived settings one rank run uses: the
// campaign state, the ranking key, the budget note and the hoisted policy.
type rankPolicyView struct {
	st         validation.Value
	rankBy     string
	budgetNote string
	policy     validation.Value
}

// rankLoadPolicyView reads the campaign state and resolves the policy's
// rank_by key and submission-budget note.
func rankLoadPolicyView(c *state.Campaign) (rankPolicyView, error) {
	// the policy's submission_budget.rank_by, when the campaign is scoped
	pv := rankPolicyView{rankBy: "acceptance", policy: validation.VNull()}
	st, err := c.State()
	if err != nil {
		return pv, err
	}
	pv.st = st
	// policy is hoisted: the budget read below and the G3 priors gate
	// both resolve from the one loaded policy (absent/unloadable = VNull
	// = today's behavior for both).
	if p := validation.ObjStr(st, "policy_path"); p != "" {
		if loaded, perr := bounty.LoadPolicy(p); perr == nil {
			pv.policy = loaded
		}
	}
	if sb := validation.ObjAt(pv.policy, "submission_budget"); sb.Kind ==
		validation.Obj {
		if rb := validation.ObjStr(sb, "rank_by"); rb == "severity" {
			pv.rankBy = "severity"
		}
		if mf := validation.ObjAt(sb, "max_findings"); mf.Kind == validation.Int &&
			mf.I > 0 {
			pv.budgetNote = fmt.Sprintf(
				", submission budget %d", mf.I)
		}
	}
	return pv, nil
}

// rankActionable filters the live findings down to the rankable rows,
// reporting how many DISPROVED / INFORMATIONAL rows were held back.
func rankActionable(live []validation.Value) ([]validation.Value, int) {
	// r5 (critic): rank answers "which findings MATTER". A DISPROVED or
	// INFORMATIONAL row stays in the ledger (the calibration law counts
	// disproofs as outcomes) but is not a candidate — a disproved row is
	// an ANSWER, not a question. Say what was held back, never silently.
	actionable := make([]validation.Value, 0, len(live))
	heldBack := 0
	for _, f := range live {
		if st := validation.ObjStr(f, "status"); st == "DISPROVED" ||
			st == "INFORMATIONAL" {
			heldBack++
			continue
		}
		actionable = append(actionable, f)
	}
	return actionable, heldBack
}

// rankComputeEntries runs the acceptance ranking, applying the policy-gated
// G3 priors when they are enabled.
func rankComputeEntries(actionable []validation.Value, rankBy string,
	policy validation.Value) []risk.AcceptanceEntry {
	entries := risk.AcceptanceRanking(actionable, rankBy)
	if bounty.PriorsEnabled(policy) {
		// G3 wPrior, policy-gated OFF by default: a store failure
		// resolves to nil priors, which rank bit-identically to the
		// plain path above — the flag degrades to today's order, never
		// to an error.
		priors, global, _ := risk.AcceptancePriors(risk.DefaultMinN)
		entries = risk.AcceptanceRankingWithPriors(actionable, rankBy,
			priors, global)
	}
	return entries
}

// rankPrintTable writes the held-back note, the ranking header and the
// qualified rows, then names the critic-disqualified ids below the table.
func rankPrintTable(out io.Writer, entries []risk.AcceptanceEntry,
	heldBack int, pv rankPolicyView) {
	if heldBack > 0 {
		fmt.Fprintf(out, "held back: %d disproof/informational row(s) "+
			"— outcomes, not candidates (scorecard still counts them)\n",
			heldBack)
	}
	keyName := "acceptance"
	if pv.rankBy == "severity" {
		keyName = "severity"
	}
	fmt.Fprintf(out, "acceptance ranking — %d live finding(s) "+
		"(key: %s%s)\n", len(entries), keyName, pv.budgetNote)
	// A campaign with no policy is UNSCORED: the ranking is a severity order,
	// not a submission order. Say so rather than let it read as advice.
	if p := validation.ObjStr(pv.st, "policy_path"); p == "" {
		fmt.Fprint(out, rankUnscopedNote)
	}
	fmt.Fprintln(out, "  #  id  score  band  evidence  critic  title")
	i := 0
	var dq []string
	for _, e := range entries {
		if e.Disqualified {
			dq = append(dq, rankID(e))
			continue
		}
		i++
		fmt.Fprintf(out, "  %d  %s  %s  %s  %s  %s  %s\n",
			i, rankID(e), rankScore(e), rankBand(e), rankEvidence(e),
			rankCritic(e), rankTitle(e))
	}
	if len(dq) > 0 {
		fmt.Fprintf(out, "disqualified (critic disproved): %s\n",
			strings.Join(dq, ", "))
	}
}

// rankUnscopedNote is the loud line an unscoped campaign prints above its
// ranking: a severity order is not a submission order.
const rankUnscopedNote = "  scope: NO POLICY LOADED — ranked without acceptance " +
	"scores, submission budget or accepted-risks checks; run `webv2 scope` with " +
	"--policy before treating this as a submission order\n"

func rankID(e risk.AcceptanceEntry) string {
	return validation.ObjStr(e.Finding, "finding_id")
}

func rankScore(e risk.AcceptanceEntry) string {
	s := risk.ScoreText(e.Score)
	if e.AckDemoted {
		s += " -ack"
	}
	if e.RiskDemoted {
		s += " -risk"
	}
	// the G3 prior marker rides the AckDemoted presence pattern: absent
	// when the term is zero, so policy-off output never moves.
	if e.PriorFactor != 0 {
		s += " +prior"
	}
	return s
}

func rankBand(e risk.AcceptanceEntry) string {
	riskObj := asDictCLI(validation.ObjAt(e.Finding, "risk"))
	b := validation.ObjStr(asDictCLI(validation.ObjAt(riskObj, "validated")), "band")
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
	v := validation.ObjStr(validation.ObjAt(e.Finding, "verification"), "critic_verdict")
	if v == "" {
		return "—"
	}
	return v
}

func rankTitle(e risk.AcceptanceEntry) string {
	t := validation.ObjStr(e.Finding, "title")
	// Runes, not bytes: a byte slice through a multi-byte character emits
	// invalid UTF-8 to the terminal.
	if r := []rune(t); len(r) > 44 {
		t = string(r[:44]) + "…"
	}
	return t
}

func init() {
	register(command{ord: 70, name: "rank",
		line: "rank <campaign>  acceptance-ranked table — which findings matter",
		run:  runRank})
}
