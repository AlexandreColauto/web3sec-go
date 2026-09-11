// autotune.go (G17 tactic batting average): the policy gate for planner
// auto-deprioritization. `auto_tune` is a top-level bounty_policy boolean,
// default false — the same absent-means-off posture as acceptance_priors,
// so every campaign that predates this field (and the golden fixtures, and
// the pinned queue vectors) behaves byte-for-byte as before. The planner
// resolves this flag; the queue only demotes what it is handed.
package bounty

import (
	"path/filepath"

	"websec/internal/state"
	"websec/internal/validation"
)

// AutoTuneEnabled is the campaign's answer to "may the planner
// auto-deprioritize a statistically dead lens?" A non-boolean or absent key
// is false — the schema refuses non-booleans at load time, and this is the
// last line of defense for hand-built policies in tests.
func AutoTuneEnabled(policy validation.Value) bool {
	v := objAt(policy, "auto_tune")
	return v.Kind == validation.Bool && v.B
}

// AutoTuneForCampaign resolves the G17 gate for a campaign: true only when
// <campaign.dir>/bounty_policy.json exists, parses, and carries
// auto_tune:true. Absent, unreadable, or unparseable degrades to false —
// the queue then behaves exactly as before (fail-closed to today's order).
func AutoTuneForCampaign(c *state.Campaign) bool {
	if c == nil {
		return false
	}
	raw, err := validation.ReadJson(
		filepath.Join(c.Dir, "bounty_policy.json"))
	if err != nil {
		return false
	}
	return AutoTuneEnabled(raw)
}
