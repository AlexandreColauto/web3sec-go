// v2 memory-row construction for ingest_record: the negative/prior row
// selection and the validated memory row shape.
package ingest

import (
	"fmt"

	"websec/internal/learning"
	"websec/internal/state"
	"websec/internal/taxonomy"
	"websec/internal/validation"
)

type memoryArgs struct {
	rid         string
	dataset     string
	caseID      string
	negative    bool
	prior       bool
	canonical   string
	partition   string
	pattern     validation.Value
	description string
	outcome     string
}

func memoryRows(record validation.Value, a memoryArgs) ([]validation.Value, error) {
	rows := []validation.Value{}
	stamp := state.NowIso()
	if a.negative {
		if a.outcome == "confirmed-exploitable" {
			return nil, fmt.Errorf("record %s: outcome "+
				"'confirmed-exploitable' is not a non-issue — negative=True "+
				"contradicts it", validation.PyReprStr(a.rid))
		}
		spec := negativeByOutcome[a.outcome]
		row, err := memoryRow(memoryRowArgs{
			recordID: a.rid, dataset: a.dataset, caseID: a.caseID,
			kind: "disproved", status: spec.Status,
			rejectionClass: spec.Rejection, pattern: a.pattern.S,
			bugClass: a.canonical, partition: a.partition,
			evidence: a.description, at: stamp})
		if err != nil {
			return nil, err
		}
		rows = append(rows, row)
	} else if a.prior && a.canonical != taxonomy.UNMAPPED {
		// A classless prior is useless as a prior (nothing to match on).
		row, err := memoryRow(memoryRowArgs{
			recordID: a.rid, dataset: a.dataset, caseID: a.caseID,
			kind: "confirmed", status: "CONFIRMED", pattern: a.pattern.S,
			bugClass: a.canonical, partition: a.partition,
			evidence: a.description, at: stamp})
		if err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
	return rows, nil
}

type memoryRowArgs struct {
	recordID       string
	dataset        string
	caseID         string
	kind           string
	status         string
	rejectionClass *string
	pattern        string
	bugClass       string
	partition      string
	evidence       string
	at             string
}

// memoryRow is _memory_row: one v2 memory row, validated. Provenance rides
// the schema's own source fields: campaign_id names the ingestion origin.
func memoryRow(a memoryRowArgs) (validation.Value, error) {
	rejection := validation.VNull()
	if a.rejectionClass != nil {
		rejection = validation.VStr(*a.rejectionClass)
	}
	row := validation.VObj(
		validation.KV{K: "memory_id", V: validation.VStr("MEM-" +
			validation.Sha12Hex([]byte(a.caseID+"|"+a.kind+"|"+a.status)))},
		validation.KV{K: "campaign_id", V: validation.VStr(
			"ingest:" + a.dataset + ":" + a.recordID)},
		validation.KV{K: "finding_id", V: validation.VNull()},
		validation.KV{K: "snapshot_id", V: validation.VNull()},
		validation.KV{K: "created_at", V: validation.VStr(a.at)},
		validation.KV{K: "kind", V: validation.VStr(a.kind)},
		validation.KV{K: "status", V: validation.VStr(a.status)},
		validation.KV{K: "pattern", V: validation.VStr(a.pattern)},
		validation.KV{K: "bug_class", V: validation.VStr(a.bugClass)},
		validation.KV{K: "cwe", V: validation.VNull()},
		validation.KV{K: "evidence_summary", V: validation.VStr(a.evidence)},
		validation.KV{K: "partition", V: validation.VStr(a.partition)},
		validation.KV{K: "schema_version", V: validation.VInt(
			learning.MemorySchemaVersion)},
		validation.KV{K: "rejection_class", V: rejection},
		// Ingested rows carry class/pattern matching only — proposition
		// matching is for campaign-learned rows.
		validation.KV{K: "deciding_propositions", V: validation.VArr()},
		validation.KV{K: "promotion_status", V: validation.VStr("promoted")},
		validation.KV{K: "approved_by", V: validation.VStr("dataset-ingestion")},
		validation.KV{K: "approved_at", V: validation.VStr(a.at)})
	if err := validation.Validate(row, "memory", 1); err != nil {
		return validation.VNull(), err
	}
	return row, nil
}
