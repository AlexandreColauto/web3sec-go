// cmd_scorecard: `webv2 scorecard <campaign> [--json] [--no-surface]
// [--gold FILE]` — one read-only view of a campaign: what was audited, what
// was found, what it cost, and what it scores.
//
// WHY this view exists (and is not `brief` or `report`): those two answer
// OUTCOME (recall, precision, cost). A reviewer cannot tell from them whether
// a campaign that found the bug did so by reasoning or by luck, how much work
// it took, or how much of the pinned tree it actually read. And the advertised
// audit surface ("153 files, ~31k lines") is arithmetically right and
// materially misleading: it silently includes foundry test doubles, vendored
// libraries, and every config, document and data file in the tree. The surface
// section walks the pinned tree through srcclass.Classify so the composition,
// not the total, is what the operator reads.
//
// READ-ONLY: every row is derived from what is already on disk — campaign
// state, the hash-chained event log, the exec ledgers, findings/,
// campaign_state["eval_adjudications"] and the pinned snapshot record. Nothing
// here writes, logs, scores or mutates; a section whose data source is absent
// says so in words rather than printing a zero that reads as a measurement.
package cli

import (
	"fmt"
	"time"

	"websec/internal/evalscore"
	"websec/internal/srcclass"
	"websec/internal/state"
	"websec/internal/validation"
)

const scorecardUsage = "usage: webv2 scorecard [-h] [--json] [--no-surface] [--gold FILE] campaign\n"

// scorecardHelp is the argparse-style help block. The verb is Go-only, so the
// prose is ours; the wrapping follows argparse's 80-column house style.
const scorecardHelp = scorecardUsage + `
one read-only view of a campaign, in six sections: the campaign identity; the
audit SURFACE (the pinned tree split into implementation / test-double /
library / interface / other by srcclass, so "153 files" cannot pass for 153
files of product code — a config, a README or a data file is other, never
surface); the live findings by status and by evidence rung; the PROCESS
that produced them (events, execs, repro attempts, passes, wall time); the
EVAL join against the gold suite, with the non-gold adjudication accounting;
and a containment warning when the campaign directory sat inside the very
tree the pin staged from.

positional arguments:
  campaign              campaign id

options:
  -h, --help            show this help message and exit
  --json                emit the six sections as one object, keys in the
                        printed order, the same numbers typed
  --no-surface          skip the surface walk (the section is omitted, not
                        emptied) — for a large pin on a slow filesystem
  --gold FILE           grade the eval section against an operator-supplied
                        gold pack (a JSON array of evaluation_case rows, plus
                        its sha256 sidecar when one sits beside it) instead of
                        the embedded suite — an ANSWER KEY.
                        grading-time; not part of a campaign run
`

// scorecardView is the collected view: the sections in print order, each
// already carrying the numbers the text renderer and the JSON projection both
// use, so the two can never disagree.
type scorecardView struct {
	// campaign
	id, program, phase, createdAt, updatedAt string

	// surface
	surfaceOff  bool // --no-surface: the section is omitted entirely
	hasPin      bool // an active snapshot resolves to a tree on disk
	pinnedRoot  string
	surfaceRows []scClassRow

	// findings
	liveFindings      []validation.Value
	live              int
	byStatus          []scCount
	byRung            []scCount
	floorOverrides    int
	floorRows         int
	blankAttestations int

	// process
	events        int
	phaseHistory  int
	execRecords   int
	hasRepro      bool
	reproAttempts int
	reproCap      int
	reproPerFind  int
	reproFindings int
	hasMaxPasses  bool
	passes        int
	maxPasses     int
	hasWall       bool
	wall          time.Duration

	// eval
	evalMatched bool
	evalReport  evalscore.Report
	// gold is the operator-supplied pack used for this run: goldPath == ""
	// means the embedded suite, and the provenance line (and the JSON
	// gold_pack key) is absent — presence-gated, so a run without --gold is
	// byte-identical to the run that had no such flag.
	goldPath     string
	goldDigest   string
	goldVerified bool

	// containment: the flag the PIN recorded (source.campaign_inside_target),
	// plus the campaign dir for the JSON — never a re-derived comparison
	contained   bool
	campaignDir string
}

// scClassRow is one composition row of the audit surface.
type scClassRow struct {
	Class srcclass.Class
	Files int
	Lines int
}

// scCount is one (name, count) row of the findings tallies.
type scCount struct {
	Key   string
	Count int
}

func runScorecard(root string, args []string, r *Runner) int {
	return t14Dispatch(root, r, func() error { return scorecardCmd(root, args, r) })
}

func scorecardCmd(root string, args []string, r *Runner) error {
	sp := &argSpec{
		prog:  "scorecard",
		usage: scorecardUsage,
		vals:  []*valOpt{{name: "--gold"}},
		flags: []*boolOpt{{name: "--json"}, {name: "--no-surface"}},
		pos:   []*posOpt{{name: "campaign"}},
	}
	if err := sp.parse(args); err != nil {
		return err
	}
	if sp.helpSeen {
		fmt.Fprint(r.Out, scorecardHelp)
		return nil
	}
	asJSON, noSurface := sp.flags[0].set, sp.flags[1].set
	c, err := t14Open(root, sp.pos[0].val)
	if err != nil {
		return err
	}
	v, err := scCollect(c, noSurface, sp.vals[0].val)
	if err != nil {
		return err
	}
	if asJSON {
		t14PrintJSON(r.Out, v.value())
		return nil
	}
	v.print(r.Out)
	return nil
}

// scCollect builds the whole view. The order of the collectors is the order of
// the sections, and the only shared state is the live-finding slice (read once
// and used by both the findings and the process section).
func scCollect(c *state.Campaign, noSurface bool, goldPath string) (*scorecardView, error) {
	st, err := c.State()
	if err != nil {
		return nil, err
	}
	v := &scorecardView{
		id:        validation.ObjStr(st, "campaign_id"),
		program:   validation.ObjStr(st, "program"),
		phase:     validation.ObjStr(st, "phase"),
		createdAt: validation.ObjStr(st, "created_at"),
		updatedAt: validation.ObjStr(st, "updated_at"),
		goldPath:  goldPath,
	}
	if err := v.collectSurface(c, noSurface); err != nil {
		return nil, err
	}
	if err := v.collectFindings(c); err != nil {
		return nil, err
	}
	if err := v.collectProcess(c, st); err != nil {
		return nil, err
	}
	if err := v.collectEval(c); err != nil {
		return nil, err
	}
	return v, nil
}

func init() {
	register(command{ord: 81, name: "scorecard",
		line: "scorecard <campaign>            surface, findings, process, eval",
		run:  runScorecard})
}
