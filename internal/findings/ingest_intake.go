// ingest_intake.go: intake_checkpoint's pre-admission warnings and the
// affected-path discipline enforced at intake (webv2.findings).
package findings

import (
	"fmt"
	"strings"
	"websec/internal/state"
	"websec/internal/validation"
)

// IntakeCheckpoint is intake_checkpoint: pre-admission sanity checks —
// WARNINGS, not rejections. campaignID names the campaign in the repair hint;
// an empty id (a direct call with no campaign in hand) keeps the documented
// metavariable rather than an empty hole.
func IntakeCheckpoint(payload validation.Value, trajectory,
	campaignID string, campaign *state.Campaign) []string {
	if campaignID == "" {
		campaignID = "<campaign>"
	}
	var warnings []string
	if adv := classAdvisoryFunc(rootClassPtr(payload), campaign); adv != "" {
		warnings = append(warnings, adv)
	}
	if trajectory == "economic" &&
		!validation.PyTruthy(validation.ObjAt(validation.ObjAt(payload, "risk"), "economic")) {
		warnings = append(warnings,
			"trajectory 'economic' but no risk.economic block recorded yet — "+
				"the CONFIRMED gate for economic classes requires an E7 "+
				"quantification artifact (balance-delta or manual evidence), or "+
				"the NAMED DECISION that no figure is defensible "+
				"(`webv2 impact "+campaignID+" <finding> --unpriceable "+
				"--ceiling '<capacity basis>' --reason R --actor A`)")
	}
	return warnings
}

// checkAffectedPath is the intake's path discipline: relative, no empty
// segments, no . or .. anywhere, no drive-letter or backslash windows.
func checkAffectedPath(i int, path string) error {
	if path == "" || strings.HasPrefix(path, "/") ||
		strings.HasPrefix(path, "\\") || strings.Contains(path, "\\") ||
		len(path) > 1 && path[1] == ':' &&
			((path[0] >= 'a' && path[0] <= 'z') ||
				(path[0] >= 'A' && path[0] <= 'Z')) {
		return fmt.Errorf(
			"affected[%d].path %q is not a path INSIDE the pinned tree: "+
				"absolute and backslash paths are refused (make it relative "+
				"to the repository root)", i, path)
	}
	for _, seg := range strings.Split(path, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return fmt.Errorf(
				"affected[%d].path %q walks outside the pinned tree (empty, "+
					". or .. segment) — name the in-tree path exactly",
				i, path)
		}
	}
	return nil
}
