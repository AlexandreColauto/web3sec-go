// cmd_adjudicate: `webv2 adjudicate <campaign> [finding] [--verdict V]
// [--severity S] [--basis B] [--assumption TEXT] [--exec EXEC] [--actor A]
// [--reason R] [--json]` — the command surface of the NON-GOLD
// adjudication (internal/evalscore/adjudicate.go; campaign_state key
// "eval_adjudications").
//
// WHY: the eval join scores every live finding that anchors no gold case as
// a false positive, which conflates three states of the world — the finding
// is wrong, the finding is real and the gold dataset does not contain it, or
// the finding is real only if an unresolved assumption holds. Without a
// recorded third verdict an honest campaign and a sloppy one read the same
// in the precision line. This verb is how the verdict, its basis and the
// actor who made it get written down, so the adjusted precision the audit
// section prints can be audited later.
//
// Two modes, decided by the optional positional `finding`: with it, record
// one row (evalscore.Record validates the row, refuses a finding that is not
// live, REPLACES any prior row for the same finding and logs
// "eval.adjudicated"); without it, list the rows the store holds. The tally
// printed after a record is the SAME accounting the audit section renders —
// evalscore.Score/ScoreSuiteWith is the single ledger, and this file adds no
// bucket of its own.

package cli

import (
	"fmt"
	"strings"

	"websec/assets"
	"websec/internal/evalscore"
	"websec/internal/state"
	"websec/internal/validation"
)

const adjudicateUsage = `usage: webv2 adjudicate [-h] [--json] [--verdict V] [--severity S]
                        [--basis B] [--assumption TEXT] [--exec EXEC]
                        [--actor A] [--reason R] [--gold FILE] campaign
                        [finding]
`

// adjudicateHelp is the argparse-style help block. The verb is Go-only, so
// the prose is ours; the wrapping follows argparse's 80-column house style
// (cmd_p3_args), and it teaches the three verdicts in one sentence each.
const adjudicateHelp = adjudicateUsage + `
record or list the NON-GOLD adjudications for a campaign's live findings: one
row per finding that anchors no gold case, with the verdict, the basis it
rests on, and the actor who judged it. The eval join calls every unanchored
live finding a false positive; a recorded verdict is what separates a real bug
the gold dataset does not contain from a wrong one.

positional arguments:
  campaign              campaign id
  finding               the live finding id (F-...); omit to list the rows

options:
  -h, --help            show this help message and exit
  --json                emit the rows as JSON
  --verdict V           additional-true-positive: the finding is real and the
                        gold dataset does not contain it; false-positive: the
                        finding is wrong; assumption-gated: the finding is
                        real only if the named assumption holds
  --severity S          tbd | low | medium | high | critical (default: tbd)
  --basis B             dataset-cross-check | author-review | reproduction |
                        code-argument
  --assumption TEXT     the assumption that must hold; required with the
                        assumption-gated verdict, and meaningful only there
  --exec EXEC           the exec record the verdict rests on
  --actor A             who judged the finding
  --reason R            why, in at least 10 written characters
  --gold FILE           score the tally against an operator-supplied gold pack
                        (a JSON array of evaluation_case rows, plus its sha256
                        sidecar when one sits beside it) instead of the
                        embedded suite — an ANSWER KEY.
                        grading-time; not part of a campaign run

A row REPLACES the prior row for the same finding. The eval section's
adjusted precision is printed from these rows: a finding adjudicated
additional-true-positive or assumption-gated leaves the false-positive
penalty, and the remaining penalty is what "adjudicated true or gated"
excludes.
`

// adjudicateArgs is the parsed command line. finding == "" means LIST mode
// (the optional positional was omitted).
type adjudicateArgs struct {
	campaign   string
	finding    string
	asJSON     bool
	verdict    string
	severity   string
	basis      string
	assumption string
	exec       string
	actor      string
	reason     string
	// gold is the operator-supplied pack FILE ("" = the embedded suite); it
	// is a grading-time input for the tally, never part of a campaign run.
	gold string
}

// adjudicateRequired is the record-mode requirement, in argparse's
// declaration order: the option names as the `vals` slice indexes them.
var adjudicateRequired = []int{0, 2, 5, 6} // --verdict, --basis, --actor, --reason

func runAdjudicate(root string, args []string, r *Runner) int {
	return t14Dispatch(root, r, func() error {
		return adjudicateCmd(root, args, r)
	})
}

func adjudicateCmd(root string, args []string, r *Runner) error {
	a, err := parseAdjudicate(args, r)
	if err != nil || a == nil {
		return err
	}
	c, err := t14Open(root, a.campaign)
	if err != nil {
		return err
	}
	if a.finding == "" {
		return adjudicateList(c, r, a.asJSON, a.gold)
	}
	return adjudicateRecord(c, r, a)
}

// parseAdjudicate is the argparse layer. It uses the shared argSpec so the
// value-consuming flags carry the house looksLikeOption guard (`--verdict
// --json` is "expected one argument", never a verdict named "--json") and
// the error text is the pinned argparse one.
//
// The finding positional is OPTIONAL — list mode is precisely its absence,
// and every argSpec positional is required — so the spec is built with one
// positional and deferExtras: the first leftover non-option token IS the
// finding, and anything else is argparse's "unrecognized arguments". The
// required-option check runs BEFORE the extras report, which is argparse's
// precedence (cmd_p3_args steps 4 and 5).
func parseAdjudicate(args []string, r *Runner) (*adjudicateArgs, error) {
	sp := &argSpec{
		prog:  "adjudicate",
		usage: adjudicateUsage,
		vals: []*valOpt{
			{name: "--verdict"},
			{name: "--severity"},
			{name: "--basis"},
			{name: "--assumption"},
			{name: "--exec"},
			{name: "--actor"},
			{name: "--reason"},
			// --gold is declared LAST so adjudicateRequired's indexes into
			// this slice (0, 2, 5, 6) keep naming the same options.
			{name: "--gold"},
		},
		flags: []*boolOpt{{name: "--json"}},
		pos:   []*posOpt{{name: "campaign"}},
	}
	sp.deferExtras = true
	if err := sp.parse(args); err != nil {
		return nil, err
	}
	if sp.helpSeen {
		fmt.Fprint(r.Out, adjudicateHelp)
		return nil, nil
	}
	a := &adjudicateArgs{campaign: sp.pos[0].val, asJSON: sp.flags[0].set,
		gold: sp.vals[7].val}
	var unrecognized []string
	for _, tok := range sp.extras {
		if looksLikeOption(tok) || a.finding != "" {
			unrecognized = append(unrecognized, tok)
			continue
		}
		a.finding = tok
	}
	if a.finding != "" {
		var missing []string
		for _, i := range adjudicateRequired {
			if !sp.vals[i].seen {
				missing = append(missing, sp.vals[i].name)
			}
		}
		if len(missing) > 0 {
			return nil, t14ArgparseErr(adjudicateUsage, "adjudicate",
				"the following arguments are required: %s",
				strings.Join(missing, ", "))
		}
		a.verdict = sp.vals[0].val
		a.severity = sp.vals[1].val
		if a.severity == "" {
			// The honest default for a verdict that does not re-rate the
			// finding (evalscore.Severities[0]).
			a.severity = "tbd"
		}
		a.basis = sp.vals[2].val
		a.assumption = sp.vals[3].val
		a.exec = sp.vals[4].val
		a.actor = sp.vals[5].val
		a.reason = sp.vals[6].val
	}
	if len(unrecognized) > 0 {
		return nil, t14Unrecognized(strings.Join(unrecognized, " "))
	}
	return a, nil
}

// adjudicateRecord writes one row and shows the operator the score move.
// Every rejection (unknown finding id, bad verdict, short reason, an
// assumption on a non-gated verdict, ...) comes from evalscore.Record and
// exits 1 through the generic `error: {e}` handler.
func adjudicateRecord(c *state.Campaign, r *Runner, a *adjudicateArgs) error {
	rec, err := evalscore.Record(c, evalscore.Adjudication{
		Finding: a.finding, Verdict: a.verdict, Severity: a.severity,
		Basis: a.basis, Assumption: a.assumption, Exec: a.exec,
		Reason: a.reason, Actor: a.actor,
	})
	if err != nil {
		return err
	}
	led, err := loadAdjudicateLedger(c, a.gold)
	if err != nil {
		return err
	}
	if a.asJSON {
		fmt.Fprintln(r.Out,
			validation.DumpIndentedASCII(adjudicateValue(c.CampaignID, led)))
		return nil
	}
	fmt.Fprintf(r.Out, "adjudicated %s as %s (%s) by %s\n", rec.Finding,
		rec.Verdict, rec.Basis, rec.Actor)
	for _, line := range adjudicateTallyLines(led) {
		fmt.Fprintln(r.Out, line)
	}
	return nil
}

// adjudicateList prints the stored rows, one per line, in Load's order (the
// state array's own order: oldest row first, a replaced row moved to the
// end), space-aligned to the widest cell of each column.
//
// The rows are worth listing even when the join could not run, so the join's
// unavailability is a trailing line, not a reason to refuse the listing.
func adjudicateList(c *state.Campaign, r *Runner, asJSON bool, goldPath string) error {
	led, err := loadAdjudicateLedger(c, goldPath)
	if err != nil {
		return err
	}
	if asJSON {
		fmt.Fprintln(r.Out,
			validation.DumpIndentedASCII(adjudicateValue(c.CampaignID, led)))
		return nil
	}
	if len(led.rows) == 0 {
		fmt.Fprintln(r.Out, "no adjudications recorded")
	} else {
		for _, line := range adjudicateTable(led.rows) {
			fmt.Fprintln(r.Out, line)
		}
	}
	if led.joinNote != "" {
		fmt.Fprintln(r.Out, led.joinNote)
	}
	// The provenance of the suite the tally was computed against: without it
	// an operator grading a held-out target cannot tell which answer key the
	// numbers below came from.
	if led.goldPath != "" {
		fmt.Fprintln(r.Out, goldPackProvenance(led.goldPath, led.goldDigest,
			led.goldVerified))
	}
	return nil
}

// adjudicateJoinUnavailable names the one reason the join produced no report
// that the operator must act on: the campaign_state projection no longer
// validates, so there is no program key to join on and every counter below
// would be a confident zero. It is the text line and the --json `note`.
const adjudicateJoinUnavailable = "eval join unavailable: campaign state does not validate"

// adjudicateLedger is the one accounting this verb and the '## eval' audit
// section both read: the stored rows plus the eval join's own split of the
// campaign's unanchored findings. Nothing here recomputes a bucket — a
// second accounting is exactly how the tally an operator sees and the
// precision a report prints would drift apart.
type adjudicateLedger struct {
	rep  evalscore.Report
	rows []evalscore.Adjudication
	// goldPath/goldDigest/goldVerified are the operator-supplied pack this
	// tally was computed against; goldPath == "" means the embedded suite
	// and the provenance line is absent (presence-gated).
	goldPath     string
	goldDigest   string
	goldVerified bool
	// joinNote is set iff the join could not run because the state file does
	// not validate; it is "" both when the join ran and when evalscore.Score
	// reported ok=false for a reason that is not a defect. Consumers read it
	// BEFORE any counter: a note means the counters are absent, never zero.
	joinNote string
}

// loadAdjudicateLedger reads the rows and scores the campaign.
//
// ok=false from evalscore.Score has two causes, and they are not the same
// thing to report. When the campaign's program matches no suite case, every
// unanchored counter is honestly zero and every stored row is stale: the
// tally says so (the stale line appears exactly when the rows apply to no
// unanchored finding), the scorecard prints the same "no gold case" sentence
// and nothing here might be invented — that is not an error either, because
// the rows are still worth listing. When the STATE FILE fails its schema,
// by contrast, the join never ran at all: the Report is the zero value, and
// printing "unanchored: 0" plus an empty adjusted precision would dress a
// broken campaign_state up as a measurement. That case is named in joinNote
// and the counters are withheld (adjudicateList, adjudicateTallyLines and
// adjudicateValue all read joinNote first). goldPath, when given, is the
// operator-supplied pack that REPLACES the embedded suite for this tally (an
// answer key loaded at grading time); a bad pack is a fail-loud error, not a
// silently smaller suite.
func loadAdjudicateLedger(c *state.Campaign, goldPath string) (adjudicateLedger, error) {
	rows, err := evalscore.Load(c)
	if err != nil {
		return adjudicateLedger{}, err
	}
	var cases []validation.Value
	led := adjudicateLedger{rows: rows, goldPath: goldPath}
	if goldPath != "" {
		pack, err := evalscore.OpenGoldPack(goldPath)
		if err != nil {
			return adjudicateLedger{}, err
		}
		cases, led.goldDigest, led.goldVerified =
			pack.Cases, pack.Digest, pack.Verified
	} else {
		emb, err := assets.LoadEvalCases()
		if err != nil {
			return adjudicateLedger{}, err
		}
		cases = emb
	}
	rep, ok := evalscore.Score(c, cases)
	led.rep = rep
	if !ok {
		// The state read is the discriminator: Score reads the same file
		// through (*state.Campaign).State, which schema-validates, so a
		// failure here is exactly the "the join could not run" case above.
		if _, err := c.State(); err != nil {
			led.joinNote = adjudicateJoinUnavailable
		}
	}
	return led, nil
}

// adjudicateTallyLines is the standing tally printed after a record: the
// three lines the '## eval' section renders, minus the markdown bullet, plus
// the stale and refused-row lines when they apply. Every NUMBER comes from
// the one evalscore accounting, so keep the wording in step with
// internal/audit/sections/eval.go if either changes.
//
// When the ledger carries a joinNote the join did not run, so the note line
// REPLACES the counters — a broken state file has no unanchored count, and
// printing zeroes for one would be a fabricated reading.
//
// The provenance line, when --gold was given, comes FIRST: it names the
// suite every number below was computed against.
func adjudicateTallyLines(led adjudicateLedger) []string {
	var out []string
	if led.goldPath != "" {
		out = append(out, goldPackProvenance(led.goldPath, led.goldDigest,
			led.goldVerified))
	}
	if led.joinNote != "" {
		return append(out, led.joinNote)
	}
	rep := led.rep
	adjudicated := rep.Additional + rep.FalsePositives + rep.Gated
	lines := []string{
		fmt.Sprintf("non-gold adjudications: %d of %d unanchored findings "+
			"adjudicated (additional-true-positive %d, false-positive %d, "+
			"assumption-gated %d)", adjudicated, rep.Unanchored,
			rep.Additional, rep.FalsePositives, rep.Gated),
		"adjusted precision (denominator excludes findings adjudicated " +
			"true or gated): " + rep.AdjustedPrecisionLine,
		fmt.Sprintf("unadjudicated unanchored findings: %d",
			rep.Unadjudicated),
	}
	if rep.StaleAdjudications > 0 {
		lines = append(lines, fmt.Sprintf("stale adjudications (rows that "+
			"apply to no unanchored finding): %d", rep.StaleAdjudications))
	}
	// Rows the state file holds that evalscore.Validate refuses. Presence-
	// gated like the stale line: with every row well formed the operator sees
	// exactly the lines they saw before this counter existed.
	if rep.InvalidAdjudications > 0 {
		lines = append(lines, fmt.Sprintf("invalid adjudication rows "+
			"(refused by validation): %d", rep.InvalidAdjudications))
	}
	return append(out, lines...)
}

// adjudicateCellEscaper renders the control characters a table row cannot
// carry: a newline or carriage return becomes the two-character \n and \r,
// a tab becomes \t.
var adjudicateCellEscaper = strings.NewReplacer(
	"\n", `\n`,
	"\r", `\r`,
	"\t", `\t`,
)

// adjudicateCell escapes one table cell before it is measured and printed.
// WHY: adjudicateTable pads every column but the last, so a raw newline in
// any cell would print a second, unlabelled line — the row would read as two
// rows, and the first would look like a complete record. A tab does the same
// damage to a terminal. The escaped form is what the widths are measured on,
// so escaping here (rather than trimming) keeps the columns aligned; the
// --json projection keeps the real bytes, because this is a rendering
// concern only.
func adjudicateCell(s string) string { return adjudicateCellEscaper.Replace(s) }

// adjudicateSeverity is the severity column's DISPLAY default. The schema
// does not require a severity, so a hand-written row may omit the key while
// Record stores "tbd" for the same logical case; an empty cell would make
// two rows that mean the same thing look different depending on who wrote
// them. Display only — the stored row is never rewritten.
func adjudicateSeverity(a evalscore.Adjudication) string {
	if a.Severity == "" {
		return "tbd"
	}
	return a.Severity
}

// adjudicateTable renders the list-mode rows: the six cells, each padded to
// the widest cell of its column (the usageText idiom), the last column left
// unpadded so no line carries trailing spaces. Every cell is escaped first,
// so one stored row is always exactly one printed line.
func adjudicateTable(rows []evalscore.Adjudication) []string {
	cells := make([][]string, 0, len(rows))
	widths := make([]int, 6)
	for _, a := range rows {
		row := []string{adjudicateCell(a.Finding), adjudicateCell(a.Verdict),
			adjudicateCell(adjudicateSeverity(a)), adjudicateCell(a.Basis),
			adjudicateCell(a.Actor), adjudicateCell(a.Reason)}
		for i, s := range row {
			if len(s) > widths[i] {
				widths[i] = len(s)
			}
		}
		cells = append(cells, row)
	}
	out := make([]string, 0, len(cells))
	for _, row := range cells {
		var b strings.Builder
		for i, s := range row {
			if i > 0 {
				b.WriteString("  ")
			}
			if i == len(row)-1 {
				b.WriteString(s)
				continue
			}
			fmt.Fprintf(&b, "%-*s", widths[i], s)
		}
		out = append(out, b.String())
	}
	return out
}

// adjudicateValue is the --json projection, one object for either mode, keys
// in a fixed order. The row shape matches the audit section's
// `adjudications` value exactly (finding, verdict, severity, basis,
// assumption only when set, exec only when set, actor, reason), and the
// optional `stale_adjudications` key is omitted when zero — the same
// presence-gate discipline the section uses, so a zero-row campaign has no
// zero-valued defaults anywhere.
//
// When the join could not run (led.joinNote set) the object is the campaign
// id, the rows, and the `note` naming why — the scorecard's eval-value idiom
// — and NO counter is emitted: a zero-valued `unanchored` or an empty
// `adjusted_precision` would read as a measurement of a broken state file.
func adjudicateValue(campaignID string, led adjudicateLedger) validation.Value {
	rows := make([]validation.Value, 0, len(led.rows))
	for _, a := range led.rows {
		row := []validation.KV{
			{K: "finding", V: validation.VStr(a.Finding)},
			{K: "verdict", V: validation.VStr(a.Verdict)},
			{K: "severity", V: validation.VStr(adjudicateSeverity(a))},
			{K: "basis", V: validation.VStr(a.Basis)},
		}
		if a.Assumption != "" {
			row = append(row, validation.KV{K: "assumption",
				V: validation.VStr(a.Assumption)})
		}
		if a.Exec != "" {
			row = append(row, validation.KV{K: "exec",
				V: validation.VStr(a.Exec)})
		}
		row = append(row,
			validation.KV{K: "actor", V: validation.VStr(a.Actor)},
			validation.KV{K: "reason", V: validation.VStr(a.Reason)})
		rows = append(rows, validation.VObj(row...))
	}
	out := []validation.KV{
		{K: "campaign_id", V: validation.VStr(campaignID)},
		{K: "adjudications", V: validation.VArr(rows...)},
	}
	if led.joinNote != "" {
		out = append(out, validation.KV{K: "note",
			V: validation.VStr(led.joinNote)})
		out = append(out, goldPackKV(led.goldPath, led.goldDigest,
			led.goldVerified)...)
		return validation.VObj(out...)
	}
	rep := led.rep
	out = append(out,
		validation.KV{K: "adjusted_precision", V: validation.VStr(rep.AdjustedPrecisionLine)},
		validation.KV{K: "unanchored", V: validation.VInt(int64(rep.Unanchored))},
		validation.KV{K: "additional_true_positive", V: validation.VInt(int64(rep.Additional))},
		validation.KV{K: "false_positive", V: validation.VInt(int64(rep.FalsePositives))},
		validation.KV{K: "assumption_gated", V: validation.VInt(int64(rep.Gated))},
		validation.KV{K: "unadjudicated", V: validation.VInt(int64(rep.Unadjudicated))},
	)
	if rep.StaleAdjudications > 0 {
		out = append(out, validation.KV{K: "stale_adjudications",
			V: validation.VInt(int64(rep.StaleAdjudications))})
	}
	// Presence-gated like stale_adjudications: a campaign whose rows all pass
	// evalscore.Validate carries the exact key set it carried before this
	// counter existed.
	if rep.InvalidAdjudications > 0 {
		out = append(out, validation.KV{K: "invalid_adjudications",
			V: validation.VInt(int64(rep.InvalidAdjudications))})
	}
	out = append(out, goldPackKV(led.goldPath, led.goldDigest,
		led.goldVerified)...)
	return validation.VObj(out...)
}

func init() {
	register(command{ord: 80, name: "adjudicate",
		line: "adjudicate <campaign> [finding]  record or list non-gold verdicts",
		run:  runAdjudicate})
}
