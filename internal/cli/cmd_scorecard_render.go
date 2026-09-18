// cmd_scorecard_render: the scorecard's two projections — the printed
// six-section view and the ordered JSON value.
package cli

import (
	"fmt"
	"io"
	"strings"

	"websec/internal/snapshot"
	"websec/internal/validation"
)

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

// printCampaign is the "campaign" section of print.
func (v *scorecardView) printCampaign(w io.Writer) {
	fmt.Fprintln(w, "campaign")
	scRow(w, "id: %s", v.id)
	scRow(w, "program: %s", v.program)
	scRow(w, "phase: %s", v.phase)
	scRow(w, "created_at: %s", v.createdAt)
	scRow(w, "updated_at: %s", v.updatedAt)
}

// printSurface is the "surface" section of print.
func (v *scorecardView) printSurface(w io.Writer) {
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
}

// printFindings is the "findings" section of print.
func (v *scorecardView) printFindings(w io.Writer) {
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
}

// printProcess is the "process" section of print.
func (v *scorecardView) printProcess(w io.Writer) {
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
}

// printEval is the "eval" section of print.
func (v *scorecardView) printEval(w io.Writer) {
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
		if r.ConfirmedPrecisionLine != "" {
			scRow(w, "false positives (CONFIRMED-only, the eval-spec budget): %d",
				r.ConfirmedLive-r.ConfirmedAnchored)
			scRow(w, "%s (CONFIRMED claims only)", r.ConfirmedPrecisionLine)
		}
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
}

// printContainment is the "containment" section of print.
func (v *scorecardView) printContainment(w io.Writer) {
	if v.contained {
		fmt.Fprintln(w, "containment")
		scRow(w, "WARNING: %s", snapshot.ContainmentWarning)
	}
}

func (v *scorecardView) print(w io.Writer) {
	v.printCampaign(w)
	v.printSurface(w)
	v.printFindings(w)
	v.printProcess(w)
	v.printEval(w)
	v.printContainment(w)
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
	if r.ConfirmedPrecisionLine != "" {
		out = append(out,
			scKV("confirmed_live", validation.VInt(int64(r.ConfirmedLive))),
			scKV("confirmed_precision", validation.VStr(r.ConfirmedPrecisionLine)))
	}
	return validation.VObj(out...)
}
