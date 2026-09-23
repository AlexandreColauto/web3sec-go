// unpriceable_handoff_schema_test.go: the regression_target handoff's
// UNPRICEABLE escape.
//
// The handoff required a strictly positive extractable_usd with no
// alternative, so the control target T-7e2781f96e25 — whose finding
// F-cfff3ebc0250 IS CONFIRMED while its figure was REFUSED (c5ba1048,
// docs/gates/v16-P1-10b-fork-spike.md: no attack was run, so no loss was
// measured) — could only be closed by fabricating a number. The escape is
// the SAME named-decision shape the finding's economic_impact already
// carries (internal/findings/levels.go UnpriceableDecision, the sole writer
// internal/risk/record.go RecordUnpriceable): priceable ABSENT means
// priceable, so every pre-existing handoff keeps its exact bytes and
// behaviour, and only an explicit false — carrying the ceiling basis it was
// made against — opens it.
//
// The generated golden table (schema_golden_test.go) carries no
// regression_target row, so this additive change moves none of its bytes.
package validation

import (
	"errors"
	"strings"
	"testing"
)

// unpHandoffCeiling is the capacity basis the unpriceable decision was made
// against; the tests below splice it into raw JSON via CanonCompact.
const unpHandoffCeiling = "capacity basis: no attack was run, so no loss was " +
	"measured (10b fork spike)"

const unpHandoffReason = "the 10b spike refused the figure: the target's own " +
	"suite is stale against the fork block"

// unpTargetJSON is the minimum schema-valid control target carrying the given
// handoff body, spliced verbatim (raw JSON, so the tests also pin the
// decoded-value path).
func unpTargetJSON(handoff string) string {
	return `{"target_id":"T-7e2781f96e25","campaign_id":"C-725aa2c6a8",` +
		`"kind":"control","program":"DebtManager","shape":"already-exploited",` +
		`"created_at":"2026-01-01T00:00:00Z","schema_version":1,` +
		`"handoff":` + handoff + `}`
}

// unpHandoffBody is the handoff's fixed prefix: the confirmed finding, the
// provenance and the determinism-pinned timestamp.
func unpHandoffBody(extra string) string {
	return `{"finding_id":"F-cfff3ebc0250"` + extra +
		`,"source":"10b fork spike (refusal)","recorded_at":"2026-01-01T00:00:00Z"}`
}

// unpHandoffValid asserts the handoff body validates.
func unpHandoffValid(t *testing.T, handoff string) {
	t.Helper()
	v, err := ParseOrdered([]byte(unpTargetJSON(handoff)))
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(v, "regression_target", 1); err != nil {
		t.Fatalf("handoff must be schema-valid: %v", err)
	}
}

// unpHandoffRefused asserts the handoff body is refused with a message
// carrying want, and returns that message.
func unpHandoffRefused(t *testing.T, handoff, want string) string {
	t.Helper()
	v, err := ParseOrdered([]byte(unpTargetJSON(handoff)))
	if err != nil {
		t.Fatal(err)
	}
	err = Validate(v, "regression_target", 1)
	if err == nil {
		t.Fatalf("handoff %s must be refused", handoff)
	}
	var se *SchemaError
	if !errors.As(err, &se) {
		t.Fatalf("err = %T; want *SchemaError", err)
	}
	if !strings.Contains(se.Msg, want) {
		t.Errorf("message = %q, want it to carry %q", se.Msg, want)
	}
	return se.Msg
}

// TestRegressionTargetHandoffKeepsTheFigureShape is the additive half: a
// handoff with a figure and NO priceable key is byte-for-byte the record the
// schema accepted before, and an explicit priceable:true changes nothing.
func TestRegressionTargetHandoffKeepsTheFigureShape(t *testing.T) {
	unpHandoffValid(t, unpHandoffBody(`,"extractable_usd":900000`))
	unpHandoffValid(t, unpHandoffBody(`,"extractable_usd":900000,"priceable":true`))
}

// unpDecision is the unpriceable decision's body suffix: the named decision,
// the actor who made it, and the ceiling basis and reason it was made against.
// Each leaf is a named argument so a test can drift exactly one, and the keys
// are spliced raw so the tests pin the decoded-value path too.
func unpDecision(ceiling, reason string) string {
	return `,"recorded_by":"operator","priceable":false,"ceiling":` +
		CanonCompact(VStr(ceiling)) + `,"reason":` + CanonCompact(VStr(reason))
}

// TestRegressionTargetHandoffAcceptsAnUnpriceableDecision is the escape: the
// decision names the ceiling basis it was made against, the written reason and
// the actor who decided, and carries no figure.
func TestRegressionTargetHandoffAcceptsAnUnpriceableDecision(t *testing.T) {
	unpHandoffValid(t, unpHandoffBody(unpDecision(unpHandoffCeiling, unpHandoffReason)))
}

// TestRegressionTargetHandoffRejectsAFigureOnAnUnpriceableDecision: the
// escape is not a way to keep the number as well. The schema's `false`
// subschema renders as the ported jsonschema template does.
func TestRegressionTargetHandoffRejectsAFigureOnAnUnpriceableDecision(t *testing.T) {
	msg := unpHandoffRefused(t, unpHandoffBody(
		unpDecision(unpHandoffCeiling, unpHandoffReason)+`,"extractable_usd":900000`),
		"False schema does not allow 900000")
	if !strings.Contains(msg, "handoff/extractable_usd") {
		t.Errorf("message = %q, want the refusal to point at handoff/extractable_usd", msg)
	}
}

// TestRegressionTargetHandoffRejectsAHandoffWithNeitherForm: the escape cannot
// be used to omit the figure silently — a handoff must record one of the two
// honest states. Neither body carries `priceable`, so the else branch applies;
// the ceiling and reason are long enough that only the missing figure is at
// fault.
func TestRegressionTargetHandoffRejectsAHandoffWithNeitherForm(t *testing.T) {
	unpHandoffRefused(t, unpHandoffBody(""),
		"'extractable_usd' is a required property")
	unpHandoffRefused(t, unpHandoffBody(`,"ceiling":"a real ceiling basis",`+
		`"reason":"a real reason, long enough"`),
		"'extractable_usd' is a required property")
}

// TestRegressionTargetHandoffRejectsAnUnattributedDecision is D3: the decision
// is ATTRIBUTED, and the schema is where that is required — an unpriceable
// handoff with every other leaf present but no recorded_by is refused, because
// an unattributed decision is nobody's (and the audit reconciles the actor
// against the ledger's).
func TestRegressionTargetHandoffRejectsAnUnattributedDecision(t *testing.T) {
	unpHandoffRefused(t, unpHandoffBody(`,"priceable":false,"ceiling":`+
		CanonCompact(VStr(unpHandoffCeiling))+`,"reason":`+
		CanonCompact(VStr(unpHandoffReason))),
		"'recorded_by' is a required property")
}

// TestRegressionTargetHandoffRejectsABlankUnpriceableBasis: "a bare flag is
// not a decision" — the ceiling and the reason must be present AND non-blank,
// so a whitespace-only basis cannot stand in for one. The whitespace reason is
// TEN characters long on purpose, so only the pattern is at fault (the length
// floor is the next test's business).
func TestRegressionTargetHandoffRejectsABlankUnpriceableBasis(t *testing.T) {
	unpHandoffRefused(t, unpHandoffBody(unpDecision("   ", unpHandoffReason)),
		"does not match")
	unpHandoffRefused(t, unpHandoffBody(unpDecision(unpHandoffCeiling, "          ")),
		"does not match")
	unpHandoffRefused(t, unpHandoffBody(`,"recorded_by":"operator",`+
		`"priceable":false,"ceiling":`+CanonCompact(VStr(unpHandoffCeiling))),
		"'reason' is a required property")
}

// TestRegressionTargetHandoffRejectsAShortReason is D2: the reason's floor is
// the SAME >=10-character floor the write path applies
// (regression.checkUnpriceableHandoff, mirroring risk.RecordUnpriceable). With
// minLength 1 a one-character reason was schema-valid, so the audit trail the
// escape exists for was unenforceable the moment the write path was bypassed.
func TestRegressionTargetHandoffRejectsAShortReason(t *testing.T) {
	msg := unpHandoffRefused(t, unpHandoffBody(unpDecision(unpHandoffCeiling, "y")),
		"is too short")
	if !strings.Contains(msg, "'y' is too short") {
		t.Errorf("message = %q, want the floor reported as a too-short reason", msg)
	}
	// Exactly ten characters is the floor, not a hair above it.
	unpHandoffValid(t, unpHandoffBody(unpDecision(unpHandoffCeiling, "0123456789")))
}

// TestRegressionTargetHandoffRejectsAPriceableWithoutAFigure is D8b: an
// explicit priceable true is a claim that a figure exists, so the else branch
// requires one — `priceable` is not a way to drop the number.
func TestRegressionTargetHandoffRejectsAPriceableWithoutAFigure(t *testing.T) {
	unpHandoffRefused(t, unpHandoffBody(`,"priceable":true`),
		"'extractable_usd' is a required property")
}
