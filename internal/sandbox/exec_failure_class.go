// exec_failure_class.go: the archived failure verdict — the ONE definition of
// the failure_class event-data key, shared by both writers (exec.go,
// register_exec.go) so the two stamp an identical shape.
//
// The problem it closes. ClassifyFailure (envseam.go, default in
// envseam_classify.go) already decides WHY an exec failed, and the project
// ROUTES on that verdict — the expected-failure admission rule refuses
// anything that is not class "logic", and a critic's reasoning cites it — but
// nothing recorded it. A later reader could recover the verdict only by
// re-running the classifier over the captured output, and that input is not
// the whole story either: ExecOutput reads stdout.log/stderr.log from disk,
// which an operator can edit exactly like the record. The reliance was
// recomputational, not archival.
//
// Placement, decided. The verdict rides the EVENT's data, beside the record
// anchor, never the record: the record is the thing being verified, and the
// anchor work already established that the record's own word is not evidence.
// The anchor digest covers the RECORD, so this key must not move it.
//
// ALWAYS emitted, on every exec including successful ones. ClassifyFailure
// returns "none" for exit 0 (its own doc says it classifies a FAILED record,
// and "none" is its word for there being nothing to classify), so a uniform
// key has no absent-vs-null ambiguity to invent — which is what a field whose
// whole job is to be recoverable later needs.
//
// Determinism. ClassifyFailure is a pure function of the record's declared
// exit code and the captured output: no clock, no uuid, no ambient state, so
// the archived verdict adds no pin. It does read the captured logs, so the
// archived class is a function of the same bytes the record's artifact_hashes
// cover.
//
// What this does NOT yet do: the archive is WRITTEN but not CONSUMED. The
// expected-failure admission rule still recomputes the verdict, calling
// sandbox.ClassifyFailure(rec) itself (internal/findings/exec_evidence.go:366),
// so failure_class is not yet authoritative for admission — the reliance
// described above is removed only for readers that choose to read this key
// instead of recomputing. Rewiring admission onto the archive is a separate
// decision, deliberately not taken here.
package sandbox

import "websec/internal/validation"

// KeyFailureClass is the event-data key carrying the classifier's verdict.
const KeyFailureClass = "failure_class"

// FailureClassKV is the one data pair both writers stamp: the class
// ClassifyFailure reports for the record the event describes. The class is
// read through ObjStr, so a classifier that returns no "class" (or a
// non-string one) archives "" — visible and recoverable — rather than having
// this helper invent a verdict of its own. "" is deliberately OUTSIDE the
// classifier's vocabulary (none/logic/setup/environment/unknown), so every
// consumer that gates on a class fails closed on it instead of reading it as
// one of the real classes.
func FailureClassKV(rec validation.Value) validation.KV {
	return validation.KV{K: KeyFailureClass,
		V: validation.VStr(validation.ObjStr(ClassifyFailure(rec), "class"))}
}
