// Evaluation-case construction helpers for ingest_record: locations, code
// block, and the assembled/validated evaluation case.
package ingest

import (
	"fmt"

	"websec/internal/state"
	"websec/internal/validation"
)

func buildLocations(record validation.Value, rid string) ([]validation.Value, error) {
	out := []validation.Value{}
	for _, loc := range valsOf(validation.ObjAt(record, "locations")) {
		file := validation.ObjStr(loc, "file")
		if loc.Kind != validation.Obj || file == "" {
			return nil, fmt.Errorf("record %s: each location needs a 'file'",
				validation.PyReprStr(rid))
		}
		entry := []validation.KV{{K: "file", V: validation.VStr(file)}}
		if line := validation.ObjAt(loc, "line"); line.Kind != validation.Null {
			entry = append(entry, validation.KV{K: "line", V: line})
		}
		out = append(out, validation.VObj(entry...))
	}
	return out, nil
}

func buildCode(codeIn validation.Value, repo string) (validation.Value, error) {
	out := []validation.KV{{K: "repo", V: validation.VStr(repo)}}
	if v := validation.ObjAt(codeIn, "commit"); truthy(v) {
		out = append(out, validation.KV{K: "commit", V: v})
	}
	if v := validation.ObjAt(codeIn, "files"); truthy(v) {
		out = append(out, validation.KV{K: "files", V: validation.VArr(
			valsOf(v)...)})
	}
	if v := validation.ObjAt(codeIn, "snapshot_note"); truthy(v) {
		out = append(out, validation.KV{K: "snapshot_note", V: v})
	}
	return validation.VObj(out...), nil
}

type evalCaseArgs struct {
	caseID      string
	source      []validation.KV
	partition   string
	program     validation.Value
	programName string
	outcome     string
	canonical   string
	severity    validation.Value
	rootCause   string
	locations   []validation.Value
	code        validation.Value
	notes       string
}

func buildEvalCase(a evalCaseArgs) validation.Value {
	return validation.VObj(
		validation.KV{K: "case_id", V: validation.VStr(a.caseID)},
		validation.KV{K: "source", V: validation.VObj(a.source...)},
		validation.KV{K: "partition", V: validation.VStr(a.partition)},
		validation.KV{K: "program", V: validation.VObj(
			validation.KV{K: "program", V: validation.VStr(a.programName)},
			validation.KV{K: "platform", V: nullIfAbsent(a.program, "platform")},
			validation.KV{K: "chains", V: validation.VArr(
				valsOf(validation.ObjAt(a.program, "chains"))...)})},
		validation.KV{K: "gold", V: validation.VObj(
			validation.KV{K: "outcome", V: validation.VStr(a.outcome)},
			validation.KV{K: "bug_class", V: validation.VStr(a.canonical)},
			validation.KV{K: "severity", V: a.severity},
			validation.KV{K: "root_cause", V: validation.VStr(a.rootCause)},
			validation.KV{K: "locations", V: validation.VArr(a.locations...)})},
		validation.KV{K: "code", V: a.code},
		// The schema has no title/description fields; keep them reachable
		// through notes (truncated to the schema's limit) instead of
		// dropping them — source.record_id stays the bridge back.
		validation.KV{K: "notes", V: validation.VStr(a.notes)},
		validation.KV{K: "created_at", V: validation.VStr(state.NowIso())},
		validation.KV{K: "schema_version", V: validation.VInt(2)})
}
