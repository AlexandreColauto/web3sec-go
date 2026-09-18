package forkdiff

import (
	"fmt"
	"path/filepath"

	"websec/internal/state"
	"websec/internal/validation"
)

// ForkdiffReport is forkdiff_report: match the target tree against every
// registered baseline; write the fork_diff artifact (consumed by findings and
// the critic bundle).
func ForkdiffReport(c *state.Campaign, snapshotRoot string) (validation.Value, error) {
	fp, err := FingerprintTree(snapshotRoot)
	if err != nil {
		return validation.VNull(), err
	}
	baselines, err := ListBaselines()
	if err != nil {
		return validation.VNull(), err
	}
	matches := make([]validation.Value, 0, len(baselines))
	for _, b := range baselines {
		matches = append(matches, Match(fp, validation.ObjAt(b, "fingerprint"),
			validation.ObjStr(b, "name")))
	}
	var best validation.Value
	hasBest := false
	for _, m := range matches {
		if !hasBest || scoreOf(m) > scoreOf(best) {
			best, hasBest = m, true
		}
	}
	snap, err := c.ActiveSnapshotIDOrNone()
	if err != nil {
		return validation.VNull(), err
	}
	snapID := "unpinned"
	if snap != nil {
		snapID = *snap
	}
	var matchedBaseline validation.Value = validation.VNull()
	diffSummary := "no baselines registered"
	extraSel, missingSel := validation.VArr(), validation.VArr()
	if hasBest {
		extraSel = validation.ObjAt(best, "extra_selectors")
		missingSel = validation.ObjAt(best, "missing_selectors")
		diffSummary = fmt.Sprintf("score %s (%s) vs %s",
			pyFixed2(scoreOf(best)), validation.ObjStr(best, "verdict"),
			validation.ObjStr(best, "baseline"))
		if validation.ObjStr(best, "verdict") != "none" {
			matchedBaseline = validation.ObjAt(best, "baseline")
		}
	}
	report := validation.VObj(
		validation.KV{K: "generated_at", V: validation.VStr(state.NowIso())},
		validation.KV{K: "snapshot_id", V: validation.VStr(snapID)},
		validation.KV{K: "matched_baseline", V: matchedBaseline},
		validation.KV{K: "diff_summary", V: validation.VStr(diffSummary)},
		validation.KV{K: "extra_selectors", V: extraSel},
		validation.KV{K: "missing_selectors", V: missingSel},
		validation.KV{K: "all_matches", V: validation.VArr(matches...)},
	)
	out := filepath.Join(c.ArtifactsDir, "fork_diff.json")
	if err := validation.WriteJson(out, report, ""); err != nil {
		return validation.VNull(), err
	}
	if _, err := c.RegisterOrRefresh("fork-diff", out, "", nil, diffSummary); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(
		validation.KV{K: "matched_baseline", V: matchedBaseline},
		validation.KV{K: "baselines", V: validation.VInt(int64(len(matches)))},
	)
	if _, err := c.Log("forkdiff.computed", nil, &data); err != nil {
		return validation.VNull(), err
	}
	return report, nil
}

func scoreOf(m validation.Value) float64 {
	x := validation.ObjAt(m, "score")
	if x.Kind == validation.Flt {
		return x.F
	}
	return 0
}

// pyFixed2 is Python's f"{x:.2f}".
func pyFixed2(f float64) string {
	return fmt.Sprintf("%.2f", f)
}
