// cmd_scorecard_collect: the collectors for the scorecard's data
// sections — surface, findings, process and eval.
package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
	src := validation.ObjAt(snap, "source")
	root = validation.ObjStr(src, "root")
	if flag := validation.ObjAt(src, "campaign_inside_target"); flag.Kind == validation.Bool {
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
		if s := validation.ObjStr(f, "status"); s != "" {
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
		if validation.ObjAt(row, "override").Kind == validation.Obj {
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
	v.phaseHistory = len(validation.ObjAt(st, "phase_history").A)
	execs, err := state.AllExecs(c)
	if err != nil {
		return err
	}
	v.execRecords = len(execs)

	budget, err := c.Budget()
	if err != nil {
		return err
	}
	if p := validation.ObjAt(budget, "pass"); p.Kind == validation.Int {
		v.passes = int(p.I)
	}
	if m := validation.ObjAt(budget, "max_passes"); m.Kind == validation.Int {
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
			repro := validation.ObjAt(validation.ObjAt(f, "verification"), "reproduction")
			total += len(validation.ObjAt(repro, "attempts").A)
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
