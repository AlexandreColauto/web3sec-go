// v16coverage.go is the v1.6 record-coverage section: the eight fields
// Tasks 2-8 added are written by five different code paths and read by none of
// them, so this section is the one place that notices when one of them stops
// being populated. All eight are counted — including the two that are NOT
// finding fields (review_sessions lives in campaign_state; the input-artifact
// declaration lives on model.request events) — because a field with no reader
// is the failure this section exists to catch, and a section that reads six of
// eight just moves the problem one level up.
//
// The counts are reported, not judged: a campaign with no deployment reads is
// a campaign with no deployment reads. `problems` therefore carries only the
// three states that CANNOT be true — the §2.2 tier ordering, the §2.4 replay
// profitability law, and a deployment fact read at no pinned block — which the
// write paths refuse by construction and which survive only in bytes written
// before those guards existed or edited by hand.
package sections

import (
	"fmt"
	"sort"

	"websec/internal/findings"
	"websec/internal/risk"
	"websec/internal/state"
	"websec/internal/validation"
)

// v16CoverageKeys is the coverage object's report order. A map has no order
// and this object is read by humans first, so the counters are rendered in the
// order the fields were introduced.
var v16CoverageKeys = []string{
	"findings", "confirmed",
	"fork_dependence_set", "origin_stage", "contributing_stages",
	"deployment_facts", "replay_recorded",
	"poc_tier_existence", "poc_tier_maximized",
	"review_sessions", "review_sessions_closed",
	"model_requests", "requests_declared", "model_rejections",
}

// V16Coverage is the v1.6 record-coverage section: {checked, problems, ok,
// coverage}. `checked` counts the findings walked — the meaning the ported
// sections give it — and every coverage counter is reported whether or not it
// is zero, so "the field stopped being written" is a visible 0 rather than a
// missing key.
func V16Coverage(c *state.Campaign) (validation.Value, error) {
	rows, err := listedFindings(c)
	if err != nil {
		return validation.VNull(), err
	}
	proj, err := c.State()
	if err != nil {
		return validation.VNull(), err
	}
	events, err := c.Events()
	if err != nil {
		return validation.VNull(), err
	}
	v := &v16Coverage{
		rows:   rows,
		counts: map[string]int64{"findings": int64(len(rows))},
	}
	for _, f := range rows {
		v.countFinding(f)
	}
	v.countCampaign(proj, events)
	return v.section(), nil
}

// v16Coverage carries one run's accumulators: the findings walked, the
// counters, and the impossible states found.
type v16Coverage struct {
	rows     []validation.Value
	counts   map[string]int64
	problems []validation.Value
}

// bump counts one field's presence.
func (v *v16Coverage) bump(key string) { v.counts[key]++ }

// countFinding counts one finding's six v1.6 fields and checks its
// impossible states.
func (v *v16Coverage) countFinding(f validation.Value) {
	if validation.ObjStr(f, "status") == "CONFIRMED" {
		v.bump("confirmed")
	}
	v.countAttribution(f)
	v.countEvidence(f)
	v.checkImpossible(f)
}

// countAttribution counts the finding's authoring attribution (v1.6 C2):
// the origin stage and the stages that contributed to it.
func (v *v16Coverage) countAttribution(f validation.Value) {
	if validation.ObjStr(f, "fork_dependence") != "" {
		v.bump("fork_dependence_set")
	}
	if validation.ObjStr(f, "origin_stage") != "" {
		v.bump("origin_stage")
	}
	if len(validation.ObjAt(f, "contributing_stages").A) > 0 {
		v.bump("contributing_stages")
	}
}

// countEvidence counts the finding's recorded evidence-side fields: its
// deployment-fact reads, its replay block, and its PoC tier.
func (v *v16Coverage) countEvidence(f validation.Value) {
	if len(validation.ObjAt(f, "deployment_facts").A) > 0 {
		v.bump("deployment_facts")
	}
	if validation.ObjAt(f, "replay").Kind == validation.Obj {
		v.bump("replay_recorded")
	}
	switch findings.PocTierOf(f) {
	case "existence":
		v.bump("poc_tier_existence")
	case "maximized":
		v.bump("poc_tier_maximized")
	}
}

// checkImpossible appends a problem for each state the write paths refuse, read
// back off the stored record: a maximized tier with no existence tier under it
// (§2.2), an unprofitable replay with no recorded blocker (§2.4), and a
// deployment fact read at no pinned block (Part 8). The laws are the setters'
// own — ValidatePocTierOrder and ValidateReplayProfitability — so the audit
// cannot drift from the writers it polices.
func (v *v16Coverage) checkImpossible(f validation.Value) {
	if findings.PocTierOf(f) == "maximized" {
		if err := findings.ValidatePocTierOrder(f, "maximized"); err != nil {
			v.problem(f, err.Error())
		}
	}
	if rec := validation.ObjAt(f, "replay"); rec.Kind == validation.Obj {
		if err := risk.ValidateReplayProfitability(rec); err != nil {
			v.problem(f, err.Error())
		}
	}
	if block, unpinned := unpinnedFactBlock(f); unpinned {
		v.problem(f, fmt.Sprintf("a deployment fact read is pinned at block %d — "+
			"an unpinned read is an assumption, not a fact", block))
	}
}

// problem appends one finding-scoped problem, prefixed so a report reader can
// tell which section raised it.
func (v *v16Coverage) problem(f validation.Value, why string) {
	v.problems = append(v.problems, validation.VStr(fmt.Sprintf(
		"v16_coverage: finding %s: %s", validation.ObjStr(f, "finding_id"), why)))
}

// unpinnedFactBlock returns the first deployment-fact row pinned at no block.
func unpinnedFactBlock(f validation.Value) (int64, bool) {
	for _, row := range validation.ObjAt(f, "deployment_facts").A {
		if block := validation.ObjAt(row, "block").I; block <= 0 {
			return block, true
		}
	}
	return 0, false
}

// countCampaign counts the two fields that are NOT finding fields:
// review_sessions is a campaign_state array — the field most likely to stop
// being written, because nothing produces one unless an operator runs the verb
// — and the input-artifact declaration rides the ledger's model.request events.
func (v *v16Coverage) countCampaign(proj validation.Value, events []validation.Value) {
	sessions := validation.ObjAt(proj, "review_sessions")
	v.counts["review_sessions"] = int64(len(sessions.A))
	closed := int64(0)
	for _, s := range sessions.A {
		if !validation.ObjAt(s, "open").B {
			closed++
		}
	}
	v.counts["review_sessions_closed"] = closed
	for _, e := range events {
		v.countEvent(e)
	}
}

// countEvent counts one ledger event's contribution: requests that declared
// their input artifact set, and the model refusals beside them.
func (v *v16Coverage) countEvent(e validation.Value) {
	switch validation.ObjStr(e, "type") {
	case "model.request":
		v.bump("model_requests")
		if len(validation.ObjAt(validation.ObjAt(e, "data"),
			"input_artifacts").A) > 0 {
			v.bump("requests_declared")
		}
	case "model.rejected":
		v.bump("model_rejections")
	}
}

// section is the standard section shape: checked, problems, ok, coverage.
func (v *v16Coverage) section() validation.Value {
	return validation.VObj(
		KV("checked", validation.VInt(int64(len(v.rows)))),
		KV("problems", validation.VArr(v.problems...)),
		KV("ok", validation.VBool(len(v.problems) == 0)),
		KV("coverage", v.coverageValue()),
	)
}

// coverageValue renders the counters in report order. Every declared key is
// emitted even at zero: an absent key and a stopped writer look the same in a
// report, which is the ambiguity this section exists to remove.
func (v *v16Coverage) coverageValue() validation.Value {
	out := make([]validation.KV, 0, len(v16CoverageKeys))
	for _, key := range v16CoverageKeys {
		out = append(out, KV(key, validation.VInt(v.counts[key])))
	}
	return validation.VObj(out...)
}

// listedFindings is the set of findings the coverage counts read: the ids the
// ledger's finding.ingested events recorded — the projection, not a directory
// glob — loaded through findings.LoadFinding in id order. Rows in a terminal
// junk state are skipped: a SUPERSEDED row is bookkeeping noise, and counting
// it would inflate coverage its successor already carries.
func listedFindings(c *state.Campaign) ([]validation.Value, error) {
	events, err := c.Events()
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(events))
	for id := range refsOf(events, "finding.ingested") {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]validation.Value, 0, len(ids))
	for _, id := range ids {
		f, err := findings.LoadFinding(c, id)
		if err != nil {
			continue // the projection section reports the missing file
		}
		if v16JunkStatus(validation.ObjStr(f, "status")) {
			continue
		}
		out = append(out, f)
	}
	return out, nil
}

// v16JunkStatus is the terminal junk set findings.LoadLiveFindings skips:
// bookkeeping rows, not claims the coverage should count.
func v16JunkStatus(status string) bool {
	return status == "DUPLICATE" || status == "OUT_OF_SCOPE" ||
		status == "SUPERSEDED"
}
