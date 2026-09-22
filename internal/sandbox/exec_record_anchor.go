// exec_record_anchor.go: the exec-record anchor — the ONE definition of the
// digest a sandbox event carries about its record, shared by both writers
// (exec.go, register_exec.go) and both admission sites (internal/findings).
//
// The problem it closes. exec_record.json is mutable JSON read straight from
// disk by the mint/ingest gate, so an operator could run a failing suite and
// then stamp expected_outcome/expected_failure (or flip exit_status) into the
// record before minting; the hash-chained sandbox.exec event carried only
// profile/exit/finding and proved nothing about the record. The digest
// anchors the WHOLE record to the event that already exists, so the same edit
// is detectable — and because it is a digest, it covers every field the
// record gains later with no maintained list.
//
// Encoding, pinned and NAMED IN THE EVENT. sha256 over
// validation.CanonSpaced(rec) — the canonicalizer the ledger already uses for
// every event hash (internal/state/chain.go), already byte-diffed against
// CPython (scripts/canon-oracle.py), so the anchor adds no second encoding to
// prove. The domain is the DECODED value, never the file bytes: WriteJson
// writes DumpIndented(data)+"\n" (internal/validation/atomicio.go), so a byte
// digest would be defeated by re-indentation alone. The label is mandatory
// because an unlabelled canonical encoding is not evidence — the project's
// own B2 collision (sha256 of a 0x-prefixed hex STRING vs of the BYTES).
//
// Backward compatibility: FAIL-OPEN on ABSENT, FAIL-CLOSED on PRESENT. The
// presence of EITHER key is the migration marker, and {digest present, label
// absent} is refused rather than read as unanchored. Fail-closed on absent
// would be red by construction: the committed Python-era fixture
// (scripts/legacy/campaigns/C-45488bdaf5) carries two sandbox.exec events
// with no anchor, and scripts/verify-full.sh step 9 asserts audit PASS over
// it; the two seeding harnesses (verify-full.sh's seed_p2_exec,
// golden-run.py's seed_exec) write records with no event of their own.
//
// The residual this does NOT close — deleting the carrier event, truncating
// the chain and editing the projection — is named in
// docs/gates/v16-exec-record-anchor-scope.md.
package sandbox

import (
	"errors"
	"fmt"

	"websec/internal/state"
	"websec/internal/validation"
)

// ExecRecordAnchorAlg names the anchor's canonical encoding. It is stamped on
// every anchored event and checked on every read: a digest whose encoding is
// not named cannot be reproduced by anyone else, which is exactly the defect
// class the label exists to close.
const ExecRecordAnchorAlg = "sha256-canon-spaced"

// The two event-data keys. Either one being present makes the event
// new-style (see EventAnchor): a half-written anchor is detectable, never
// silently unanchored.
const (
	KeyExecRecordSHA256    = "exec_record_sha256"
	KeyExecRecordSHA256Alg = "exec_record_sha256_alg"
)

// AnchorCarrierEventTypes are the event types that can carry the anchor: the
// Run path's sandbox.exec and the externally-reported path's
// sandbox.exec.registered. Anchoring only the first would leave the same
// hand-edit open through the second writer.
var AnchorCarrierEventTypes = []string{"sandbox.exec", "sandbox.exec.registered"}

// ExecRecordDigest is the anchor digest: sha256 of the record's canonical
// spaced encoding, lowercase hex. ONE definition — the writers stamp it and
// the readers recompute it, so the two cannot drift.
func ExecRecordDigest(rec validation.Value) string {
	return validation.Sha256Hex([]byte(validation.CanonSpaced(rec)))
}

// ExecRecordAnchorKVs is the two data pairs both writers stamp, so the
// written shape cannot drift from the read shape.
func ExecRecordAnchorKVs(rec validation.Value) []validation.KV {
	return []validation.KV{
		{K: KeyExecRecordSHA256, V: validation.VStr(ExecRecordDigest(rec))},
		{K: KeyExecRecordSHA256Alg, V: validation.VStr(ExecRecordAnchorAlg)},
	}
}

// IsAnchorCarrier reports whether an event type can carry the anchor.
func IsAnchorCarrier(eventType string) bool {
	for _, t := range AnchorCarrierEventTypes {
		if eventType == t {
			return true
		}
	}
	return false
}

// EventAnchor reads the anchor out of an event's data. present is true when
// EITHER key is there, so a half-written anchor is new-style and refused
// rather than read as absent. A non-string value renders through PyRepr, so
// the malformed value is visible in the refusal instead of reading as an
// empty string.
func EventAnchor(ev validation.Value) (digest, alg string, present bool) {
	data := validation.ObjAt(ev, "data")
	d, dOK := anchorKey(data, KeyExecRecordSHA256)
	a, aOK := anchorKey(data, KeyExecRecordSHA256Alg)
	return d, a, dOK || aOK
}

// anchorKey is EventAnchor's per-key read: (rendered value, key present).
func anchorKey(data validation.Value, key string) (string, bool) {
	for _, kv := range data.O {
		if kv.K != key {
			continue
		}
		if kv.V.Kind == validation.Str {
			return kv.V.S, true
		}
		return validation.PyRepr(kv.V), true
	}
	return "", false
}

// AnchorProblem is the ONE law over one anchored carrier event: given the
// event's type, its two anchor keys and the record the caller read from disk,
// it returns the refusal sentence, or "" when the anchor holds. The audit
// section and the mint gate both read their verdict from here, so the two
// cannot disagree about what an anchor violation is.
//
// Order, decided: the label is checked before the digest value — an
// unlabelled digest is the unlabelled-encoding defect, and reporting it as a
// mere mismatch would hide that. A malformed digest VALUE (not 64 lowercase
// hex, or not a string at all) is deliberately the mismatch row: it can never
// equal a recomputed digest, so the reader says so instead of shrugging at an
// unverifiable curiosity.
func AnchorProblem(eventType, execID, digest, alg string,
	rec validation.Value) string {
	if alg == "" {
		// alg == "" covers BOTH "the label key is absent" and "the label key
		// is present but holds the empty string": AnchorProblem receives the
		// RENDERED values, so it cannot tell the two apart, and the refusal
		// is identical either way (fail-closed, and an empty string is not an
		// encoding label). The sentence says which cases it covers instead of
		// claiming the key is absent.
		return fmt.Sprintf("exec %s: the %s event carries a digest with no "+
			"encoding label — an unlabelled canonical encoding is not "+
			"evidence (the %s key is absent or empty)", execID, eventType,
			KeyExecRecordSHA256Alg)
	}
	if alg != ExecRecordAnchorAlg {
		return fmt.Sprintf("exec %s: the %s event names anchor encoding %s, "+
			"not %s", execID, eventType, alg, ExecRecordAnchorAlg)
	}
	if digest == "" {
		return fmt.Sprintf("exec %s: the %s event names the anchor encoding "+
			"but carries no digest", execID, eventType)
	}
	want := ExecRecordDigest(rec)
	if digest != want {
		return fmt.Sprintf("exec %s: exec_record.json does not recompute to "+
			"the digest the %s event anchored (event %s, record %s) — the "+
			"record was edited after the run, or the stored digest is not 64 "+
			"lowercase hex; either way its declared exit/expectation cannot "+
			"be trusted", execID, eventType, digest, want)
	}
	return ""
}

// AnchorAbsentReason is the migration row's reason: an exec whose carrier
// events carry no anchor key at all. It is a COVERAGE fact, never a problem
// (fail-open, see the file header).
func AnchorAbsentReason(execID string) string {
	return fmt.Sprintf("exec %s: the sandbox.exec event carries no "+
		"exec_record_sha256 anchor — the record predates the anchor, so its "+
		"declared exit/expectation is not anchored to the ledger", execID)
}

// VerifyExecRecordAnchor is the mint-side predicate. nil when the campaign
// holds no carrier event for execID, and nil when its carriers carry no
// anchor key (fail-open: pre-anchor history and the two seeding harnesses,
// which write no event at all, admit exactly as before). Otherwise every
// anchored carrier must agree with rec: the carriers are walked in log order
// and the FIRST disagreement refuses, so the verdict is deterministic and
// never depends on map iteration.
func VerifyExecRecordAnchor(c *state.Campaign, execID string,
	rec validation.Value) error {
	events, err := c.Events()
	if err != nil {
		return err
	}
	for _, ev := range events {
		if !carrierFor(ev, execID) {
			continue
		}
		digest, alg, present := EventAnchor(ev)
		if !present {
			continue
		}
		if prob := AnchorProblem(validation.ObjStr(ev, "type"), execID,
			digest, alg, rec); prob != "" {
			return errors.New(prob)
		}
	}
	return nil
}

// carrierFor is (this event is an anchor carrier for execID).
func carrierFor(ev validation.Value, execID string) bool {
	return IsAnchorCarrier(validation.ObjStr(ev, "type")) &&
		validation.ObjStr(ev, "ref") == execID
}
