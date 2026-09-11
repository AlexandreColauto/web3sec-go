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
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"websec/assets"
	"websec/internal/evalscore"
	"websec/internal/findings"
	"websec/internal/floors"
	"websec/internal/probes"
	"websec/internal/snapshot"
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
		id:        objStr(st, "campaign_id"),
		program:   objStr(st, "program"),
		phase:     objStr(st, "phase"),
		createdAt: objStr(st, "created_at"),
		updatedAt: objStr(st, "updated_at"),
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

// --- 2. surface -------------------------------------------------------------

// scPinnedSnapshot reads the campaign's active snapshot record. root is
// source.root — the immutable COPY the pin staged, not the target the
// operator passed to `snap` (the same path internal/snapshot's
// deployment/chain attach paths use). contained is the RECORDED
// source.campaign_inside_target flag: the pin decided, where the absolute
// target was still known, whether the campaign directory sat inside the
// target being pinned, and wrote that boolean only when it was true. An
// absent key means "not the containment case".
//
// ok=false means there is no active snapshot record to read at all (no
// pin, or the record is gone): the section says so in words rather than
// fabricating a status, and containment is then simply not a fact.
func scPinnedSnapshot(c *state.Campaign) (root string, contained, ok bool, err error) {
	sid, err := c.ActiveSnapshotIDOrNone()
	if err != nil {
		return "", false, false, err
	}
	if sid == nil {
		return "", false, false, nil
	}
	raw, err := os.ReadFile(filepath.Join(c.Dir, "snapshots", *sid, "snapshot.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, false, nil
		}
		return "", false, false, err
	}
	snap, err := validation.ParseOrdered(raw)
	if err != nil {
		return "", false, false, err
	}
	src := objAt(snap, "source")
	root = objStr(src, "root")
	if flag := objAt(src, "campaign_inside_target"); flag.Kind == validation.Bool {
		contained = flag.B
	}
	return root, contained, true, nil
}

func (v *scorecardView) collectSurface(c *state.Campaign, noSurface bool) error {
	root, contained, recorded, err := scPinnedSnapshot(c)
	if err != nil {
		return err
	}
	// Containment is reported from the record, so it survives a walk that
	// --no-surface skipped and a copy that has since moved.
	v.contained = contained
	if contained {
		if dir, derr := filepath.Abs(c.Dir); derr == nil {
			v.campaignDir = filepath.Clean(dir)
		}
	}
	v.surfaceOff = noSurface
	// A pin whose copy is no longer on disk has nothing to walk: the
	// section says so in words (the same absent-data path as no pin).
	if !recorded || root == "" {
		return nil
	}
	if st, serr := os.Stat(root); serr != nil || !st.IsDir() {
		return nil
	}
	v.hasPin, v.pinnedRoot = true, root
	if noSurface {
		return nil
	}
	rows, err := scComposition(root)
	if err != nil {
		return err
	}
	v.surfaceRows = rows
	return nil
}

// scComposition walks the pinned tree and buckets every file by
// srcclass.Classify. The file set is snapshot.PinnedFiles — the files the
// pin's own digests cover, so the pin's metadata (snapshot.json) and the hash
// excludes (build output, caches, VCS state) stay out and the surface cannot
// disagree with the content hash. One accumulator per file: no second pass,
// no re-derivation of the class rules.
func scComposition(root string) ([]scClassRow, error) {
	files, err := snapshot.PinnedFiles(root)
	if err != nil {
		return nil, err
	}
	type acc struct{ files, lines int }
	counts := map[srcclass.Class]*acc{}
	for _, rel := range files {
		cls := srcclass.Classify(rel)
		a := counts[cls]
		if a == nil {
			a = &acc{}
			counts[cls] = a
		}
		a.files++
		n, err := scLines(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return nil, err
		}
		a.lines += n
	}
	rows := make([]scClassRow, 0, len(srcclass.Classes))
	for _, cls := range srcclass.Classes {
		row := scClassRow{Class: cls}
		if a := counts[cls]; a != nil {
			row.Files, row.Lines = a.files, a.lines
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// scLines is the editor line count: one line per newline, plus the trailing
// unterminated line. A file that ends without a newline is still one line long,
// and an empty file is zero lines — the reading an operator expects from a
// line count, not the byte count of '\n' characters.
func scLines(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	n := bytes.Count(data, []byte("\n"))
	if len(data) > 0 && data[len(data)-1] != '\n' {
		n++
	}
	return n, nil
}

// --- 3. findings ------------------------------------------------------------

func (v *scorecardView) collectFindings(c *state.Campaign) error {
	live, err := findings.LoadLiveFindings(c)
	if err != nil {
		return err
	}
	v.liveFindings, v.live = live, len(live)
	statuses := map[string]int{}
	rungs := map[string]int{}
	for _, f := range live {
		if s := objStr(f, "status"); s != "" {
			statuses[s]++
		}
		// FindingLevel is finding_level: the highest evidence rung, E0 when
		// the finding holds no parseable evidence. One rung per finding, so
		// this tally and the gate's own floor comparison cannot drift.
		lvl, err := findings.FindingLevel(f)
		if err != nil {
			return err
		}
		rungs[lvl]++
	}
	v.byStatus = scCounts(statuses, nil)
	v.byRung = scCounts(rungs, findings.EVIDENCE_ORDER)
	// The floor table is the ladder as it applies to THIS campaign: every
	// known class with its default floor and any instance-level override. The
	// count asked for here is "how many rows of the evidence ladder the
	// operator overrode", not a restatement of the floor rules.
	rep, err := floors.FloorTableReport(c)
	if err != nil {
		return err
	}
	for _, row := range objListAt(rep, "rows") {
		v.floorRows++
		if objAt(row, "override").Kind == validation.Obj {
			v.floorOverrides++
		}
	}
	v.blankAttestations = len(probes.BlankEntries(c))
	return nil
}

// scCounts orders a tally: the given order first (for the E0-E7 ladder, whose
// order is contractual), everything else alphabetical, so the same campaign
// always prints the same rows in the same order.
func scCounts(counts map[string]int, order []string) []scCount {
	seen := map[string]bool{}
	out := make([]scCount, 0, len(counts))
	for _, k := range order {
		if n, ok := counts[k]; ok {
			out = append(out, scCount{Key: k, Count: n})
			seen[k] = true
		}
	}
	rest := make([]string, 0, len(counts))
	for k := range counts {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	for _, k := range rest {
		out = append(out, scCount{Key: k, Count: counts[k]})
	}
	return out
}

// --- 4. process -------------------------------------------------------------

func (v *scorecardView) collectProcess(c *state.Campaign, st validation.Value) error {
	n, err := c.NextSeq()
	if err != nil {
		return err
	}
	v.events = n
	v.phaseHistory = len(objAt(st, "phase_history").A)
	execs, err := state.AllExecs(c)
	if err != nil {
		return err
	}
	v.execRecords = len(execs)

	budget, err := c.Budget()
	if err != nil {
		return err
	}
	if p := objAt(budget, "pass"); p.Kind == validation.Int {
		v.passes = int(p.I)
	}
	if m := objAt(budget, "max_passes"); m.Kind == validation.Int {
		v.maxPasses, v.hasMaxPasses = int(m.I), true
	}
	// The reproduction budget is PER FINDING (max_repro_attempts_per_finding),
	// so the aggregate ceiling only exists once there is a live finding to
	// spend it on: with no live finding the row is left out rather than
	// printed as "0 / 0".
	perFinding := int(objInt(budget, "max_repro_attempts_per_finding"))
	if len(v.liveFindings) > 0 && perFinding > 0 {
		total := 0
		for _, f := range v.liveFindings {
			repro := objAt(objAt(f, "verification"), "reproduction")
			total += len(objAt(repro, "attempts").A)
		}
		v.hasRepro = true
		v.reproAttempts = total
		v.reproPerFind = perFinding
		v.reproFindings = len(v.liveFindings)
		v.reproCap = perFinding * len(v.liveFindings)
	}
	// Wall time is only a measurement when both stamps parse; an unparseable
	// stamp leaves the row out instead of inventing an elapsed time.
	if v.createdAt != "" && v.updatedAt != "" {
		start, e1 := time.Parse(time.RFC3339, v.createdAt)
		end, e2 := time.Parse(time.RFC3339, v.updatedAt)
		if e1 == nil && e2 == nil && !end.Before(start) {
			v.wall, v.hasWall = end.Sub(start), true
		}
	}
	return nil
}

// --- 5. eval ----------------------------------------------------------------

// goldPackProvenance is the one provenance sentence both verbs print for an
// operator-supplied pack: the hash the pack was verified against, or the
// explicit "unverified" fact — never silence about a missing sidecar, which
// would let a hand-edited answer key read as a verified one.
func goldPackProvenance(path, digest string, verified bool) string {
	if verified {
		short := digest
		if len(short) > 12 {
			short = short[:12]
		}
		return fmt.Sprintf("gold pack: %s (sha256 %s)", path, short)
	}
	return fmt.Sprintf("gold pack: %s (unverified - no sha256 sidecar found)", path)
}

// goldPackKV is the presence-gated JSON projection of the same fact: absent
// entirely without --gold, `verified: false` and no hash when the pack had
// no sidecar (an empty sha256 string would read as a measured hash).
func goldPackKV(path, digest string, verified bool) []validation.KV {
	if path == "" {
		return nil
	}
	obj := []validation.KV{scKV("path", validation.VStr(path))}
	if verified {
		obj = append(obj, scKV("sha256", validation.VStr(digest)))
	}
	obj = append(obj, scKV("verified", validation.VBool(verified)))
	return []validation.KV{scKV("gold_pack", validation.VObj(obj...))}
}

// collectEval scores the campaign's program through the one eval ledger
// (evalscore.Score). With --gold the operator's pack REPLACES the embedded
// suite — never merged: the operator is grading one held-out target, and a
// synthetic dev row would otherwise score against a real held-out campaign.
// ok=false means no suite case matches the program: a normal state, reported
// in words, never an error and never a zeroed score.
func (v *scorecardView) collectEval(c *state.Campaign) error {
	var cases []validation.Value
	if v.goldPath != "" {
		pack, err := evalscore.OpenGoldPack(v.goldPath)
		if err != nil {
			return err
		}
		cases, v.goldDigest, v.goldVerified = pack.Cases, pack.Digest, pack.Verified
	} else {
		var err error
		cases, err = assets.LoadEvalCases()
		if err != nil {
			return err
		}
	}
	rep, ok := evalscore.Score(c, cases)
	v.evalReport, v.evalMatched = rep, ok
	return nil
}

// --- 6. containment ---------------------------------------------------------

// The containment section reports the boolean the pin recorded (source.
// campaign_inside_target), never a path comparison: the only path a reader
// can compare against is source.root, the staged COPY under the campaign
// directory, from which the geometry is unrepresentable — that comparison
// could never fire. The fact is decided once, in internal/snapshot, where
// the absolute target is still known.
//
// WHAT the section says is snapshot.ContainmentWarning: one sentence,
// identical to the one `snap` prints, so the two surfaces cannot drift.
// Presence-gated like every other section: the heading and the warning
// exist only when the recorded flag is true.

// --- rendering --------------------------------------------------------------

// scRow is one indented row under a section heading (the cmd_brief idiom).
func scRow(w io.Writer, format string, a ...any) {
	fmt.Fprintf(w, "  "+format+"\n", a...)
}

// scPlural is "1 file" / "2 files".
func scPlural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func (v *scorecardView) print(w io.Writer) {
	fmt.Fprintln(w, "campaign")
	scRow(w, "id: %s", v.id)
	scRow(w, "program: %s", v.program)
	scRow(w, "phase: %s", v.phase)
	scRow(w, "created_at: %s", v.createdAt)
	scRow(w, "updated_at: %s", v.updatedAt)

	if !v.surfaceOff {
		fmt.Fprintln(w, "surface")
		if !v.hasPin {
			scRow(w, "no pinned snapshot yet — `webv2 snap %s <target>` pins "+
				"one", v.id)
		} else {
			scRow(w, "pinned root: %s", v.pinnedRoot)
			files, lines := 0, 0
			for _, r := range v.surfaceRows {
				files += r.Files
				lines += r.Lines
				scRow(w, "%s: %s, %s", r.Class, scPlural(r.Files, "file"),
					scPlural(r.Lines, "line"))
			}
			scRow(w, "TOTAL: %s, %s", scPlural(files, "file"),
				scPlural(lines, "line"))
		}
	}

	fmt.Fprintln(w, "findings")
	scRow(w, "live findings: %d", v.live)
	if v.live == 0 {
		scRow(w, "no live findings yet")
	} else {
		for _, r := range v.byStatus {
			scRow(w, "status %s: %d", r.Key, r.Count)
		}
		for _, r := range v.byRung {
			scRow(w, "evidence rung %s: %d", r.Key, r.Count)
		}
	}
	scRow(w, "floor-overridden ladder rows: %d of %d", v.floorOverrides,
		v.floorRows)
	scRow(w, "blank attestations: %d", v.blankAttestations)

	fmt.Fprintln(w, "process")
	scRow(w, "events: %d", v.events)
	scRow(w, "phase history: %d", v.phaseHistory)
	scRow(w, "exec records: %d", v.execRecords)
	if v.hasRepro {
		scRow(w, "repro attempts: %d / %d (cap %d per finding, %d live "+
			"finding%s)", v.reproAttempts, v.reproCap, v.reproPerFind,
			v.reproFindings, scS(v.reproFindings))
	}
	if v.hasMaxPasses {
		scRow(w, "passes: %d / %d", v.passes, v.maxPasses)
	} else {
		scRow(w, "passes: %d", v.passes)
	}
	if v.hasWall {
		scRow(w, "wall time (created_at -> updated_at): %s", v.wall)
	}

	fmt.Fprintln(w, "eval")
	if v.goldPath != "" {
		scRow(w, "%s", goldPackProvenance(v.goldPath, v.goldDigest,
			v.goldVerified))
	}
	if !v.evalMatched {
		scRow(w, "no gold case matches program %s", v.program)
	} else {
		r := v.evalReport
		scRow(w, "gold cases: %d", r.GoldTotal)
		scRow(w, "%s", r.RecallLine)
		scRow(w, "%s", r.PrecisionLine)
		scRow(w, "false positives (raw unanchored live findings): %d", r.FP)
		scRow(w, "additional true positives: %d", r.Additional)
		scRow(w, "adjudicated false positives: %d", r.FalsePositives)
		scRow(w, "assumption-gated: %d", r.Gated)
		scRow(w, "unadjudicated: %d", r.Unadjudicated)
		scRow(w, "stale adjudication rows: %d", r.StaleAdjudications)
		// AdjustedPrecisionLine is wilson.Format's own "precision: k/n (...)"
		// line; the adjusted row names the noun itself, so the format's
		// leading noun is dropped and the definition follows in words.
		scRow(w, "adjusted precision: %s — adjudicated true positives and "+
			"assumption-gated findings are removed from the penalty "+
			"denominator",
			strings.TrimPrefix(r.AdjustedPrecisionLine, "precision: "))
	}

	if v.contained {
		fmt.Fprintln(w, "containment")
		scRow(w, "WARNING: %s", snapshot.ContainmentWarning)
	}
}

// scS is the empty string for 1 (so the repro row reads "1 live finding", not
// "1 live findings").
func scS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// scKV is the vet-clean keyed KV constructor for the JSON projection.
func scKV(k string, val validation.Value) validation.KV {
	return validation.KV{K: k, V: val}
}

// value is the ordered JSON projection: the same sections in the same order,
// carrying the same numbers as typed values. A section that prints as prose
// because its data is absent carries a note field instead of fabricated
// zeros, and --no-surface leaves the surface KEY out rather than emitting an
// empty object.
func (v *scorecardView) value() validation.Value {
	out := []validation.KV{
		scKV("campaign", validation.VObj(
			scKV("id", validation.VStr(v.id)),
			scKV("program", validation.VStr(v.program)),
			scKV("phase", validation.VStr(v.phase)),
			scKV("created_at", validation.VStr(v.createdAt)),
			scKV("updated_at", validation.VStr(v.updatedAt)))),
	}
	if !v.surfaceOff {
		out = append(out, scKV("surface", v.surfaceValue()))
	}
	out = append(out,
		scKV("findings", v.findingsValue()),
		scKV("process", v.processValue()),
		scKV("eval", v.evalValue()))
	if v.contained {
		// Only the paths that actually resolve are named: an empty string
		// would read as a measurement of something.
		obj := []validation.KV{scKV("contained", validation.VBool(true))}
		if v.campaignDir != "" {
			obj = append(obj, scKV("campaign_dir", validation.VStr(v.campaignDir)))
		}
		if v.pinnedRoot != "" {
			obj = append(obj, scKV("pinned_root", validation.VStr(v.pinnedRoot)))
		}
		out = append(out, scKV("containment", validation.VObj(obj...)))
	}
	return validation.VObj(out...)
}

func (v *scorecardView) surfaceValue() validation.Value {
	if !v.hasPin {
		return validation.VObj(
			scKV("pinned", validation.VBool(false)),
			scKV("note", validation.VStr("no pinned snapshot yet")))
	}
	files, lines := 0, 0
	rows := make([]validation.Value, 0, len(v.surfaceRows))
	byClass := make([]validation.KV, 0, len(v.surfaceRows))
	for _, r := range v.surfaceRows {
		files += r.Files
		lines += r.Lines
		rows = append(rows, validation.VObj(
			scKV("class", validation.VStr(string(r.Class))),
			scKV("files", validation.VInt(int64(r.Files))),
			scKV("lines", validation.VInt(int64(r.Lines)))))
		byClass = append(byClass, scKV(string(r.Class), validation.VObj(
			scKV("files", validation.VInt(int64(r.Files))),
			scKV("lines", validation.VInt(int64(r.Lines))))))
	}
	return validation.VObj(
		scKV("pinned", validation.VBool(true)),
		scKV("pinned_root", validation.VStr(v.pinnedRoot)),
		scKV("classes", validation.VObj(byClass...)),
		scKV("rows", validation.VArr(rows...)),
		scKV("total", validation.VObj(
			scKV("files", validation.VInt(int64(files))),
			scKV("lines", validation.VInt(int64(lines))))))
}

func (v *scorecardView) findingsValue() validation.Value {
	byStatus := make([]validation.KV, 0, len(v.byStatus))
	for _, r := range v.byStatus {
		byStatus = append(byStatus, scKV(r.Key, validation.VInt(int64(r.Count))))
	}
	byRung := make([]validation.KV, 0, len(v.byRung))
	for _, r := range v.byRung {
		byRung = append(byRung, scKV(r.Key, validation.VInt(int64(r.Count))))
	}
	return validation.VObj(
		scKV("live", validation.VInt(int64(v.live))),
		scKV("by_status", validation.VObj(byStatus...)),
		scKV("by_evidence_rung", validation.VObj(byRung...)),
		scKV("floor_overrides", validation.VInt(int64(v.floorOverrides))),
		scKV("floor_rows", validation.VInt(int64(v.floorRows))),
		scKV("blank_attestations", validation.VInt(int64(v.blankAttestations))))
}

func (v *scorecardView) processValue() validation.Value {
	out := []validation.KV{
		scKV("events", validation.VInt(int64(v.events))),
		scKV("phase_history", validation.VInt(int64(v.phaseHistory))),
		scKV("exec_records", validation.VInt(int64(v.execRecords))),
	}
	if v.hasRepro {
		out = append(out,
			scKV("repro_attempts", validation.VInt(int64(v.reproAttempts))),
			scKV("repro_cap", validation.VInt(int64(v.reproCap))))
	}
	out = append(out, scKV("passes", validation.VInt(int64(v.passes))))
	if v.hasMaxPasses {
		out = append(out, scKV("max_passes", validation.VInt(int64(v.maxPasses))))
	}
	if v.hasWall {
		out = append(out, scKV("wall_seconds", validation.VFloat(v.wall.Seconds())))
	}
	return validation.VObj(out...)
}

func (v *scorecardView) evalValue() validation.Value {
	out := goldPackKV(v.goldPath, v.goldDigest, v.goldVerified)
	if !v.evalMatched {
		out = append(out,
			scKV("matched", validation.VBool(false)),
			scKV("note", validation.VStr("no gold case matches program "+
				v.program)))
		return validation.VObj(out...)
	}
	r := v.evalReport
	out = append(out,
		scKV("matched", validation.VBool(true)),
		scKV("gold_cases", validation.VInt(int64(r.GoldTotal))),
		scKV("recall", validation.VStr(r.RecallLine)),
		scKV("precision", validation.VStr(r.PrecisionLine)),
		scKV("false_positives", validation.VInt(int64(r.FP))),
		scKV("additional_true_positives", validation.VInt(int64(r.Additional))),
		scKV("adjudicated_false_positives",
			validation.VInt(int64(r.FalsePositives))),
		scKV("assumption_gated", validation.VInt(int64(r.Gated))),
		scKV("unadjudicated", validation.VInt(int64(r.Unadjudicated))),
		scKV("stale_adjudications", validation.VInt(int64(r.StaleAdjudications))),
		scKV("adjusted_precision", validation.VStr(r.AdjustedPrecisionLine)))
	return validation.VObj(out...)
}

func init() {
	register(command{ord: 81, name: "scorecard",
		line: "scorecard <campaign>            surface, findings, process, eval",
		run:  runScorecard})
}
