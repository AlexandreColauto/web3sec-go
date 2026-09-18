// Package learning is a 1:1 port of webv2/learning.py: spec-drift
// detection and the reflection/learning subsystem (memory queue + human
// gate, reflection inbox, planner hints, benchmark cases). The Python twin was retired 2026-09-09; this package is the source of truth.
//
// Nothing enters long-term memory automatically: every memory candidate
// waits for recorded human approval (K5). Disproved hypotheses are
// first-class negative memory.
package learning

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// RecordDrifts is record_drifts: persist a drift report. `drifts` come from
// the G-trajectory agent; ids and timestamps are assigned here.
func RecordDrifts(c *state.Campaign, snapshotID string,
	drifts []validation.Value) (validation.Value, error) {
	numbered := make([]validation.Value, 0, len(drifts))
	for i, d := range drifts {
		row := d
		if row.Kind != validation.Obj {
			row = validation.VObj()
		}
		row.O = validation.SetDefault(row.O, "id",
			validation.VStr(fmt.Sprintf("DRIFT-%03d", i+1)))
		numbered = append(numbered, row)
	}
	report := validation.VObj(
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("snapshot_id", validation.VStr(snapshotID)),
		kv("created_at", validation.VStr(state.NowIso())),
		kv("drifts", validation.VArr(numbered...)))
	if err := validation.Validate(report, "drift_report", 1); err != nil {
		return validation.VNull(), err
	}
	out := filepath.Join(c.ArtifactsDir, "drift_report.json")
	if err := validation.WriteJson(out, report, ""); err != nil {
		return validation.VNull(), err
	}
	// drift report is a living document (re-recorded per snapshot pass)
	reason := fmt.Sprintf("drift report recorded (%d drifts, %s)",
		len(numbered), snapshotID)
	if _, err := c.RegisterOrRefresh("drift-report", out, "", nil, reason); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(kv("count", validation.VInt(int64(len(numbered)))))
	if _, err := c.Log("drift.recorded", nil, &data); err != nil {
		return validation.VNull(), err
	}
	return report, nil
}

// DriftHypotheses is drift_hypotheses: convert drifts into prioritized
// hunting questions. Implementation-weaker drifts (code does less than
// promised) rank first.
func DriftHypotheses(report validation.Value) []validation.Value {
	drifts := validation.ObjAt(report, "drifts")
	out := make([]validation.Value, 0, len(drifts.A))
	for _, d := range drifts.A {
		risk := driftRisk(d)
		question := validation.ObjStr(d, "claim") + " is promised, but reality is: " +
			validation.ObjStr(d, "reality") +
			". What attacker-position does the gap create?"
		out = append(out, validation.VObj(
			kv("source", validation.VStr("drift:"+validation.ObjStr(d, "id"))),
			kv("layer", validation.ObjAt(d, "layer")),
			kv("question", validation.VStr(question)),
			kv("risk", risk)))
	}
	sort.SliceStable(out, func(i, j int) bool {
		return riskOf(out[i]) > riskOf(out[j])
	})
	return out
}

// driftRisk is `d.get("risk", 0.5 if direction == "divergent" else 0.8)`.
func driftRisk(d validation.Value) validation.Value {
	if r, ok := fieldAt(d, "risk"); ok {
		return r
	}
	if validation.ObjStr(d, "direction") == "divergent" {
		return validation.VFloat(0.5)
	}
	return validation.VFloat(0.8)
}

// riskOf reads the numeric risk a hypothesis carries (built above).
func riskOf(h validation.Value) float64 {
	r := validation.ObjAt(h, "risk")
	switch r.Kind {
	case validation.Flt:
		return r.F
	case validation.Int:
		return float64(r.I)
	default:
		return 0
	}
}

// fieldAt is Python's `key in d` + d[key].
func fieldAt(v validation.Value, key string) (validation.Value, bool) {
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V, true
		}
	}
	return validation.VNull(), false
}

// kv is the vet-clean keyed KV constructor.
func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

// pyRepr is validation.PyRepr for the error texts.
func pyRepr(v validation.Value) string { return validation.PyRepr(v) }

// pyReprStr is validation.PyReprStr for the error texts.
func pyReprStr(s string) string { return validation.PyReprStr(s) }

// joinComma is ", ".join(items).
func joinComma(items []string) string { return strings.Join(items, ", ") }
