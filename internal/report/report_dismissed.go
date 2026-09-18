// The dismissed-with-strong-reaching subsection and its helpers: the
// terminal-dismissal set, the file-overlap join between high-risk
// probe rows and dismissed findings, and the class alias suffix.
package report

import (
	"fmt"
	"sort"
	"strings"
	"websec/internal/classweights"
	"websec/internal/planner"
	"websec/internal/probes"
	"websec/internal/state"
	"websec/internal/validation"
)

// dismissedTerminalStatuses are the dismissal-side terminal states: the
// finding was looked at and set aside. SUPERSEDED is deliberately absent —
// supersession is correction, not dismissal, so it never arms gate (a).
var dismissedTerminalStatuses = []string{"DISPROVED", "OUT_OF_SCOPE",
	"INFORMATIONAL", "DUPLICATE"}

// dismissedWithReach renders the "Dismissed with strong reaching"
// subsection: every terminal-dismissal finding a high-risk probe row
// reaches, sorted by finding id then row ref (the determinism law: every
// map iteration output is sorted). It returns nil when the presence gate is
// closed — no terminal dismissals, no surface, no high-risk rows, or no
// reach — so the campaign gains no bytes.
func dismissedWithReach(campaign *state.Campaign,
	all []validation.Value) []string {
	dismissed := []validation.Value{}
	for _, f := range all {
		if dismissalTerminal(validation.ObjStr(f, "status")) {
			dismissed = append(dismissed, f)
		}
	}
	if len(dismissed) == 0 {
		return nil
	}
	surfacePtr, err := probes.CampaignSurface(campaign)
	if err != nil || surfacePtr == nil {
		return nil
	}
	indexPtr, err := probes.CampaignIndex(campaign)
	if err != nil {
		return nil
	}
	type hit struct {
		fid, status, class, row string
		tier, gap               int64
	}
	hits := []hit{}
	for _, row := range listAt(*surfacePtr, "rows") {
		if !planner.HighRiskRow(row) {
			continue
		}
		files := reachRowFiles(row, indexPtr)
		if len(files) == 0 {
			continue
		}
		rid := validation.ObjStr(row, "row_id")
		for _, f := range dismissed {
			ff := reachFindingFiles(f)
			overlap := false
			for name := range files {
				if _, ok := ff[name]; ok {
					overlap = true
					break
				}
			}
			if !overlap {
				continue
			}
			hits = append(hits, hit{fid: validation.ObjStr(f, "finding_id"),
				status: validation.ObjStr(f, "status"),
				class:  reachFindingClass(f), row: rid,
				tier: reachInt(row, "tier"),
				gap:  reachInt(row, "assertion_gap")})
		}
	}
	if len(hits) == 0 {
		return nil
	}
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].fid != hits[j].fid {
			return hits[i].fid < hits[j].fid
		}
		return hits[i].row < hits[j].row
	})
	L := []string{"### Dismissed with strong reaching", ""}
	for _, h := range hits {
		L = append(L, fmt.Sprintf("- `%s` (%s, class %s): reached by "+
			"high-risk row `%s` (tier %d, assertion_gap %d)",
			h.fid, h.status, h.class, h.row, h.tier, h.gap))
	}
	L = append(L, "reach joined by file overlap (no id-level link exists).")
	L = append(L, "")
	return L
}

// dismissalTerminal reports whether a finding status arms gate (a) of
// the dismissed-with-reach section.
func dismissalTerminal(status string) bool {
	for _, s := range dismissedTerminalStatuses {
		if status == s {
			return true
		}
	}
	return false
}

// reachRowFiles is the row side of the file-overlap join: the basenames of
// the row's anchor files (RowAnchorPairs resolves contracts through the
// index, falling back to bare contract names without one), plus the row's
// own contract names for findings whose affected entry carries no path.
func reachRowFiles(row validation.Value,
	index *validation.Value) map[string]struct{} {
	out := map[string]struct{}{}
	for _, pair := range probes.RowAnchorPairs(row, index) {
		file := pair
		if i := strings.LastIndex(file, "#L"); i >= 0 {
			file = file[:i]
		}
		if b := pathBase(file); b != "" {
			out[b] = struct{}{}
		}
	}
	for _, key := range []string{"contract", "base"} {
		if v := validation.ObjStr(row, key); v != "" {
			out[v] = struct{}{}
		}
	}
	for _, s := range listAt(row, "siblings") {
		if v := validation.ObjStr(s, "contract"); v != "" {
			out[v] = struct{}{}
		}
	}
	return out
}

// reachFindingFiles is the finding side of the join: the basenames of the
// affected paths (or files), plus contract names for entries without one.
func reachFindingFiles(f validation.Value) map[string]struct{} {
	out := map[string]struct{}{}
	for _, a := range listAt(f, "affected") {
		p := validation.ObjStr(a, "path")
		if p == "" {
			p = validation.ObjStr(a, "file")
		}
		if p != "" {
			if b := pathBase(p); b != "" {
				out[b] = struct{}{}
			}
		}
		if c := validation.ObjStr(a, "contract"); c != "" {
			out[c] = struct{}{}
		}
	}
	return out
}

// reachFindingClass is the finding's root-cause class (bug_class, then
// unclassified when neither is set).
func reachFindingClass(f validation.Value) string {
	if c := validation.ObjStr(validation.ObjAt(f, "root_cause"), "class"); c != "" {
		return c
	}
	if c := validation.ObjStr(f, "bug_class"); c != "" {
		return c
	}
	return "unclassified"
}

// classAliasSuffixSpaced is the G12 display suffix with its leading space
// (" [OWASP SC05]") or "" when the class carries no alias — the empty string
// keeps unmapped render sites byte-identical.
func classAliasSuffixSpaced(class string) string {
	if sfx := classweights.ClassAliasSuffix(class); sfx != "" {
		return " " + sfx
	}
	return ""
}

// reachInt reads an integer row field across the Int/Flt shapes (0 when
// absent — the HighRiskRow caution reads the same way).
func reachInt(row validation.Value, key string) int64 {
	switch v := validation.ObjAt(row, key); v.Kind {
	case validation.Int:
		return v.I
	case validation.Flt:
		return int64(v.F)
	}
	return 0
}
