// ingest_payload.go: the small helpers ingest uses to build the HYPOTHESIS
// payload and the finding.ingested event data — the snapshot pin, the
// technical-signature parts, and the Python-flavoured defaults.
package findings

import (
	"websec/internal/state"
	"websec/internal/validation"
)

// SourcePinUnpinned is the pin slot's "no pin" sentinel: the value the
// framework substitutes for active_snapshot_id_or_none() when the campaign has
// no active snapshot. It is written into a finding's snapshot_ids.source
// (ingest.go:121-125) and, on the exec-evidence path, into that item's
// snapshot_id (exec_evidence.go:205-215); every consumer that RESOLVES a pin
// reads it as "not an id" (ackscan.go:183,
// report/report_finding_verify.go:53, audit/sections/snapshots.go:241).
//
// It is therefore NOT an artifact id, and the boundary's cited-set walk must
// skip it (internal/boundary/boundary.go) — otherwise an honest unpinned
// bundle is refused for citing a non-artifact. Exported so that reader
// references this one definition instead of re-spelling the literal.
const SourcePinUnpinned = "unpinned"

// sourcePinOrUnpinned is active_snapshot_id_or_none() or SourcePinUnpinned.
func sourcePinOrUnpinned(campaign *state.Campaign) validation.Value {
	id, err := campaign.ActiveSnapshotIDOrNone()
	if err != nil || id == nil {
		return validation.VStr(SourcePinUnpinned)
	}
	return validation.VStr(*id)
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// sigPath is first.get("path", "unknown") under Python str() semantics.
func sigPath(first validation.Value) string {
	v, ok := fieldAt(first, "path")
	if !ok {
		return "unknown"
	}
	return validation.PyStr(v)
}

// sigOpt is (block.get(key) or "") — absent, null, and "" all fold to "".
func sigOpt(block validation.Value, key string) string {
	v, ok := fieldAt(block, key)
	if !ok || v.Kind != validation.Str {
		return ""
	}
	return v.S
}

// classSig is the signature's class part: f"{bug_class}" (None -> "None").
func classSig(rootClass *string) string {
	if rootClass == nil {
		return "None"
	}
	return *rootClass
}

// rootClassValue is the log's bug_class: *string as a Value (nil -> null).
func rootClassValue(rootClass *string) validation.Value {
	if rootClass == nil {
		return validation.VNull()
	}
	return validation.VStr(*rootClass)
}

// rootClassPtr is (payload.get("root_cause") or {}).get("class") — the
// NO-DEFAULT flavor intake_checkpoint uses (missing -> nil, i.e. None).
func rootClassPtr(payload validation.Value) *string {
	v, ok := fieldAt(validation.ObjAt(payload, "root_cause"), "class")
	if !ok || v.Kind != validation.Str {
		return nil
	}
	return &v.S
}

// ingestLogData is the finding.ingested data dict, in Python literal order.
func ingestLogData(trajectory, stage, model string, rootClass *string,
	advisory string, warnings []string) *validation.Value {
	stageV, modelV := validation.VNull(), validation.VNull()
	if stage != "" {
		stageV = validation.VStr(stage)
	}
	if model != "" {
		modelV = validation.VStr(model)
	}
	advV := validation.VNull()
	if advisory != "" {
		advV = validation.VStr(advisory)
	}
	data := validation.VObj(
		validation.KV{K: "trajectory", V: validation.VStr(trajectory)},
		validation.KV{K: "stage", V: stageV},
		validation.KV{K: "model", V: modelV},
		validation.KV{K: "bug_class", V: rootClassValue(rootClass)},
		validation.KV{K: "class_advisory", V: advV},
		validation.KV{K: "intake_warnings", V: warningsValue(warnings)},
	)
	return &data
}

func warningsValue(warnings []string) validation.Value {
	out := make([]validation.Value, len(warnings))
	for i, w := range warnings {
		out[i] = validation.VStr(w)
	}
	return validation.VArr(out...)
}

func warningsLogData(warnings []string) *validation.Value {
	data := validation.VObj(validation.KV{K: "warnings",
		V: warningsValue(warnings)})
	return &data
}
