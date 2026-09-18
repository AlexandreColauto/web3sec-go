package cli

import (
	"fmt"
	"io"
	"strings"

	"websec/internal/findings"
	"websec/internal/validation"
)

// warnDyingGrants is the shared disclosure behind BOTH doors into a
// terminal status — `supersede` (r13) and `move` (r14): a TERMINAL row
// answers nothing (the r12 sweep law): no capability grants, no chain
// seeding. Retiring a granter that way is correct but was SILENT, and
// silence is how proposals disappear without anyone deciding it. This
// names the exact labels that died with the row — every successor or
// later finding must re-record them through the capabilities surface.
//
// dyingStatus is the status the granting row just acquired (must be
// terminal — the caller's move/supersede decided it); survivor is the
// row that may carry the grants onward (a supersede successor — pass
// nil when the dying row itself is the endpoint, as after a move into
// a terminal). Labels the survivor re-grants are not reported lost.
func warnDyingGrants(stderr io.Writer, oldID, dyingStatus string,
	before validation.Value, survivor *validation.Value) {
	if stderr == nil || !findings.IsTerminal(dyingStatus) {
		return
	}
	granted := func(v validation.Value) map[string]bool {
		out := map[string]bool{}
		for _, g := range objListAt(validation.ObjAt(v, "capabilities"), "granted") {
			if g.Kind == validation.Str {
				out[g.S] = true
			}
		}
		return out
	}
	var lost []string
	for l := range granted(before) {
		if survivor != nil && granted(*survivor)[l] {
			continue
		}
		lost = append(lost, l)
	}
	if len(lost) == 0 {
		return
	}
	fmt.Fprintf(stderr, "note: %s granted %s — %s rows no longer grant "+
		"capabilities or seed chain proposals (the terminal law). "+
		"Re-record any that still hold via the capabilities amend "+
		"surface, or chains through a successor will not appear.\n",
		oldID, strings.Join(lost, ", "), dyingStatus)
}
