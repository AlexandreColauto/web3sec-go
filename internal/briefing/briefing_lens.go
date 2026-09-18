package briefing

import (
	"fmt"
	"strings"

	"websec/internal/classweights"
	"websec/internal/planner"
	"websec/internal/state"
	"websec/internal/validation"
	"websec/internal/version"
)

// lensMechanicalTable is the M6 map: lens id -> the mechanical table verb
// that reads the structural index directly, with one %s slot for the
// campaign id. L-02 (trust-assumption) has no table verb and stays out —
// its rows are worked per-row. L-01 routes to enforce because cursors,
// sentinels and accumulators are storage variables: the enforcement table
// shows where each is written, read and guarded, by stage.
var lensMechanicalTable = map[string]string{
	"L-01": "webv2 enforce %s <cursor-variable>",
	"L-03": "webv2 enforce %s <variable>",
	"L-04": "webv2 symmetry %s",
}

// lensDispositioned is the lens-status half of
// planner.ProbeRowDispositioned: a lens entry closes under the same
// terminal dispositions as a probe row.
func lensDispositioned(status string) bool {
	for _, d := range planner.ProbeRowDispositioned {
		if status == d {
			return true
		}
	}
	return false
}

// lensActionCampaign is the campaign id for mechanical-table commands: the
// live campaign when present, else the brief's own record, else the same
// placeholder the gate uses for an unknown campaign.
func lensActionCampaign(brief validation.Value, campaign *state.Campaign) string {
	if campaign != nil && campaign.CampaignID != "" {
		return campaign.CampaignID
	}
	if id := validation.ObjStr(validation.ObjAt(brief, "campaign"), "campaign_id"); id != "" {
		return id
	}
	return "<campaign>"
}

// skewAction is the DEFECT-2 line: the active snapshot's pin event records
// the framework build that produced it, and the running binary names its
// own via internal/version. Both known and different is the only loud
// case. A silent "" covers every honest unknown: old campaigns without the
// key, no active snapshot, no event log to read, and unstamped builds.
func skewAction(brief validation.Value, campaign *state.Campaign) string {
	if !version.Known() {
		return ""
	}
	running := version.Commit()
	sid := validation.ObjStr(validation.ObjAt(brief, "campaign"), "active_snapshot")
	if sid == "" {
		return ""
	}
	pinned := pinBuild(campaign, sid)
	if pinned == "" || pinned == running {
		return ""
	}
	return webv2Action("webv2 snap "+campaign.CampaignID+" <target>",
		fmt.Sprintf("framework skew: snapshot %s pinned with build %s "+
			"but running build %s — probe-surface semantics may differ; "+
			"re-pin or run the pinning build", sid, pinned, running))
}

// pinBuild is the framework_build the snapshot's pin event recorded, or ""
// when the campaign predates the key (or the log cannot be read).
func pinBuild(campaign *state.Campaign, sid string) string {
	events, err := campaign.Events()
	if err != nil {
		return ""
	}
	for _, e := range events {
		if validation.ObjStr(e, "type") != "snapshot.pinned" || validation.ObjStr(e, "ref") != sid {
			continue
		}
		if b := validation.ObjStr(validation.ObjAt(e, "data"), "framework_build"); b != "" {
			return b
		}
	}
	return ""
}

// aliasSuffixLabels maps aliasSuffixLabel over a label list (G12 display:
// the stored corpus_recall.discounted keys are never rewritten, only the
// rendered line gains the pinned OWASP id).
func aliasSuffixLabels(labels []string) []string {
	out := make([]string, 0, len(labels))
	for _, l := range labels {
		out = append(out, aliasSuffixLabel(l))
	}
	return out
}

// aliasSuffixLabel renders one discounted class label for display: the bare
// machine key ("bug_class=reentrancy") plus its pinned OWASP id when the
// class carries an alias ("bug_class=reentrancy [OWASP SC05]"), bare
// otherwise (presence-gated, zero byte move for unmapped classes).
func aliasSuffixLabel(label string) string {
	if cls, ok := strings.CutPrefix(label, "bug_class="); ok {
		if sfx := classweights.ClassAliasSuffix(cls); sfx != "" {
			return label + " " + sfx
		}
	}
	return label
}
