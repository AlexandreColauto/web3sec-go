// Package doctor is webv2/doctor.py: campaign health — repair + scope-drift
// diagnosis.
//
// `webv2 doctor` is the operator's self-check. Two jobs, both read-mostly:
//
//   - state health — the state file is re-read and re-written by every CLI
//     command, so one oversized stage note (a 2 GB index inlined by an old
//     pipeline run) made the whole campaign pay gigabytes of IO per command.
//     doctor truncates any note above the cap, IN THE PROJECTION ONLY: the
//     append-only event log is never touched, and the audit verifies the
//     chain plus content-hashed artifacts — never the state file — so the
//     repair is audit-safe.
//   - snapshot scope — the pin is the campaign's ground truth, and a pin that
//     swallowed the framework's own repository (128k files for a 122-line
//     vault) silently poisoned every derived index. doctor reports what the
//     pin actually covers and warns when it looks like scope drift.
package doctor

import (
	"websec/internal/envgo"
	"websec/internal/state"
	"websec/internal/validation"
)

// SnapshotFileWarn is SNAPSHOT_FILE_WARN: a pin this large is almost never
// "the target": real audit targets are source trees of hundreds to low
// thousands of files. Above this the operator is warned (not blocked) — some
// protocols legitimately ship large corpora, and the waiver is the operator's
// call. A package var so tests can force the drift warning (Python mutates
// DOC.SNAPSHOT_FILE_WARN).
var SnapshotFileWarn = 5000

// Doctor is doctor: the state repair, the snapshot scope report and the
// sandbox preflight (readiness BEFORE the first exec pays for it).
func Doctor(campaign *state.Campaign) (validation.Value, error) {
	st, err := StateHealth(campaign)
	if err != nil {
		return validation.VNull(), err
	}
	scope, err := SnapshotScope(campaign)
	if err != nil {
		return validation.VNull(), err
	}
	pre, err := envgo.SandboxPreflight(campaign, nil, nil)
	if err != nil {
		return validation.VNull(), err
	}
	return validation.VObj(
		validation.KV{K: "state", V: st},
		validation.KV{K: "snapshot", V: scope},
		validation.KV{K: "preflight", V: pre},
	), nil
}
