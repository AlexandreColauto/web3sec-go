// Verification helpers for the finding section: the immunization waiver
// check, the G11 post-patch verdict label and the in-code-ack source
// quote resolver.
package report

import (
	"os"
	"path/filepath"
	"strings"

	"websec/internal/completion"
	"websec/internal/state"
	"websec/internal/validation"
)

// immunizationWaived reports whether an explicit immunization waiver covers
// this finding (subject '*' waives the whole stage). B1: mirrors the
// fork-PoC waiver check so a waived immunization renders as a caveat.
func immunizationWaived(campaign *state.Campaign, f validation.Value) bool {
	waivers, err := completion.Waivers(campaign, "immunization")
	if err != nil {
		return false
	}
	for _, w := range waivers {
		subj := validation.ObjStr(w, "subject")
		if subj == "*" || subj == validation.ObjStr(f, "finding_id") {
			return true
		}
	}
	return false
}

// patchRegressionMark renders the G11 post-patch verdict label. Unknown
// verdicts fail open to INDETERMINATE, never to a fix claim.
func patchRegressionMark(verdict string) string {
	switch verdict {
	case "fixed":
		return "**FIXED**"
	case "still_reproducible":
		return "**STILL REPRODUCIBLE**"
	default:
		return "**INDETERMINATE**"
	}
}

// reportAckQuote re-reads the acknowledged source line for the report quote:
// the record stores the file relative to the finding's source pin root. The
// quote is the trimmed line; any failure to resolve the pin, the file or the
// line yields (empty, false) and the caller prints the record without a quote.
func reportAckQuote(campaign *state.Campaign, f validation.Value,
	ack validation.Value) (string, bool) {
	sid := validation.ObjStr(validation.ObjAt(f, "snapshot_ids"), "source")
	if sid == "" || sid == "unpinned" {
		return "", false
	}
	snap, err := validation.ReadJson(filepath.Join(campaign.Dir, "snapshots",
		sid, "snapshot.json"))
	if err != nil {
		return "", false
	}
	root := validation.ObjStr(validation.ObjAt(snap, "source"), "root")
	file := validation.ObjStr(ack, "file")
	p := file
	if !filepath.IsAbs(p) {
		p = filepath.Join(root, p)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return "", false
	}
	lines := strings.Split(string(raw), "\n")
	n := int(validation.ObjAt(ack, "line").I)
	if n < 1 || n > len(lines) {
		return "", false
	}
	q := strings.TrimRight(strings.TrimLeft(lines[n-1], " \t"), " \t")
	if q == "" {
		return "", false
	}
	return `"` + q + `"`, true
}
