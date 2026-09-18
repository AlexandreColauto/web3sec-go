// metrics_safe.go: the guarded read primitives split out of metrics.go —
// findings/events readers that append notes instead of raising.
package metrics

import (
	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// ---- small guarded primitives -------------------------------------------

// rate is _rate: None when the denominator is zero.
func rate(numerator, denominator int) validation.Value {
	if denominator == 0 {
		return validation.VNull()
	}
	return validation.VFloat(float64(numerator) / float64(denominator))
}

func tierIndex(tier string) (int, bool) {
	for i, t := range findings.EVIDENCE_ORDER {
		if t == tier {
			return i, true
		}
	}
	return 0, false
}

// safeFindings is _safe_findings: reporter, never raiser.
func safeFindings(c *state.Campaign, notes *[]string) []validation.Value {
	all, err := findings.LoadAllFindings(c)
	if err != nil {
		*notes = append(*notes, "findings unreadable in "+c.CampaignID+
			": "+err.Error())
		return nil
	}
	out := []validation.Value{}
	for _, f := range all {
		if f.Kind == validation.Obj {
			out = append(out, f)
		}
	}
	return out
}

// safeEvents is _safe_events.
func safeEvents(c *state.Campaign, notes *[]string) []validation.Value {
	events, err := c.Events()
	if err != nil {
		*notes = append(*notes, "event log unreadable in "+c.CampaignID+
			": "+err.Error())
		return nil
	}
	out := []validation.Value{}
	for _, e := range events {
		if e.Kind == validation.Obj {
			out = append(out, e)
		}
	}
	return out
}

// maxTierOf is _max_tier_of: E0 when there is none or it is unreadable.
func maxTierOf(f validation.Value) string {
	tier, err := findings.FindingLevel(f)
	if err != nil {
		return "E0"
	}
	if _, ok := tierIndex(tier); !ok {
		return "E0"
	}
	return tier
}
