// regressionsuite_handoff_test.go: the P1 handoff's UNPRICEABLE escape as the
// SECTION must read it — the projection, the ledger behind it, and the
// hand-edits only a hand can produce.
//
// The section is a READER, so every record here is written by hand on purpose:
// the write path and the schema refuse these shapes, and a section that only
// re-reads what the writer guarantees checks nothing (the discipline
// internal/audit/unpriceable_test.go applies to a hand-edited
// economic_impact.priceable: false).
package sections

import (
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/regression"
	"websec/internal/state"
	"websec/internal/validation"
)

// The decision's own text, spelled once: the ledger reconciliation compares
// the projection's bytes against these, so a test that drifts one of them is
// testing the drift.
const (
	handoffCeiling = "capacity basis: no attack was run, so no loss was measured"
	handoffReason  = "the 10b spike refused the figure: no attack was run"
)

// handoffFixture is a finished control target whose handoff the REAL writer
// recorded (a priceable figure), so everything around the handoff is
// schema-valid and only the handoff block itself can be at fault.
func handoffFixture(t *testing.T, id string) (*state.Campaign, string, string) {
	t.Helper()
	c := regressSectionCampaign(t, id)
	target := controlSectionTarget(t, c)
	tid := validation.ObjStr(target, "target_id")
	recordSectionControl(t, c, tid)
	fid := confirmedSectionFinding(t, c)
	if _, err := regression.RecordHandoff(c, regression.HandoffSpec{
		TargetID: tid, FindingID: fid, ExtractableUSD: 900000,
		Source: "reproduction on the pre-patch commit", RecordedBy: "operator",
	}); err != nil {
		t.Fatal(err)
	}
	return c, tid, fid
}

// recordUnpriceableHandoff records the NAMED DECISION through the real writer,
// so the ledger holds its event.
func recordUnpriceableHandoff(t *testing.T, c *state.Campaign, tid, fid string) {
	t.Helper()
	if _, err := regression.RecordHandoff(c, regression.HandoffSpec{
		TargetID: tid, FindingID: fid, Source: "10b fork spike (refusal)",
		Unpriceable: true, Ceiling: handoffCeiling, Reason: handoffReason,
		RecordedBy: "operator",
	}); err != nil {
		t.Fatal(err)
	}
}

// editHandoff replaces the target's handoff block with a raw JSON body and
// returns the record the section will read. WriteJson is called with NO schema
// name: a hand-edit is exactly what the write path refuses, and the section's
// job is to read what is on disk regardless.
func editHandoff(t *testing.T, c *state.Campaign, tid, body string) validation.Value {
	t.Helper()
	doc, ok, err := regression.Target(c, tid)
	if err != nil || !ok {
		t.Fatalf("reload target %s: ok=%v err=%v", tid, ok, err)
	}
	ho, err := validation.ParseOrdered([]byte(strings.ReplaceAll(body, "FID", "F-cfff3ebc0250")))
	if err != nil {
		t.Fatal(err)
	}
	doc.O = validation.SetOrAppend(doc.O, "handoff", ho)
	path := filepath.Join(regression.TargetsDir(c), tid+".json")
	if err := validation.WriteJson(path, doc, ""); err != nil {
		t.Fatal(err)
	}
	return doc
}

// q is a JSON string literal, so a body can splice the decision's text.
func q(s string) string { return validation.CanonCompact(validation.VStr(s)) }

// decisionBody is the honest unpriceable handoff body, with each of the three
// attribution leaves a named argument so a test can drift exactly one.
func decisionBody(ceiling, reason, actor string) string {
	return `{"finding_id":"FID","source":"10b fork spike (refusal)",` +
		`"recorded_at":"2026-01-01T00:00:00Z","recorded_by":` + q(actor) +
		`,"priceable":false,"ceiling":` + q(ceiling) + `,"reason":` + q(reason) + `}`
}

// suiteProblems runs the section and returns its problems, failing when the
// section is not RED — the whole point of every record in this file.
func suiteProblems(t *testing.T, c *state.Campaign) []validation.Value {
	t.Helper()
	sec, err := RegressionSuite(c)
	if err != nil {
		t.Fatal(err)
	}
	problems := validation.ObjAt(sec, "problems")
	if ok := validation.ObjAt(sec, "ok"); ok.Kind != validation.Bool || ok.B {
		t.Fatalf("the section is GREEN; problems=%v", problems.A)
	}
	return problems.A
}

// problemMentions reports whether one problem string carries want.
func problemMentions(problems []validation.Value, want string) bool {
	for _, p := range problems {
		if strings.Contains(p.S, want) {
			return true
		}
	}
	return false
}

// D1's measured records, verbatim in shape. Each is a hand edit the shipped
// schema REFUSES, which is why the section has to refuse it too. Each isolates
// exactly one defect — the attribution is present where the attribution is not
// the thing under test — so the validator's message names the defect and not a
// companion.
var (
	noReasonHandoff = `{"finding_id":"FID","source":"hand-edited",` +
		`"recorded_at":"2026-01-01T00:00:00Z","recorded_by":"operator",` +
		`"priceable":false,"ceiling":"` + handoffCeiling + `"}`
	blankCeilingHandoff = `{"finding_id":"FID","source":"hand-edited",` +
		`"recorded_at":"2026-01-01T00:00:00Z","recorded_by":"operator",` +
		`"priceable":false,"ceiling":"   ","reason":"` + handoffReason + `"}`
	contradictoryHandoff = `{"finding_id":"FID","source":"hand-edited",` +
		`"recorded_at":"2026-01-01T00:00:00Z","recorded_by":"operator",` +
		`"priceable":false,"ceiling":"` + handoffCeiling + `","reason":"` +
		handoffReason + `","extractable_usd":900000}`
	bareFlagHandoff = `{"finding_id":"FID","source":"hand-edited",` +
		`"recorded_at":"2026-01-01T00:00:00Z","priceable":false}`
)

// badHandoff is one hand-edited record: where it lands, what it is called, and
// whether the section must ALSO call it "no P1 handoff" — a record the
// decision's own rule refuses is not one of the two honest forms.
type badHandoff struct {
	id, name, body string
	noP1           bool
}

// TestRegressionSuiteRejectsSchemaInvalidHandoffs is D1's measured matrix:
// three hand-edited records were schema-INVALID and the section was GREEN on
// all three. Each must be RED, and each must say why.
func TestRegressionSuiteRejectsSchemaInvalidHandoffs(t *testing.T) {
	for _, rec := range []badHandoff{
		{"C-regsectbad001", "priceable:false with no reason", noReasonHandoff, true},
		{"C-regsectbad002", "priceable:false with a blank ceiling", blankCeilingHandoff, true},
		{"C-regsectbad003", "priceable:false carrying a figure", contradictoryHandoff, true},
	} {
		t.Run(rec.name, func(t *testing.T) { assertBadHandoffIsRed(t, rec) })
	}
}

// assertBadHandoffIsRed asserts the two halves D1 measured: the SHIPPED
// validator refuses the bytes, and the section is RED for them.
func assertBadHandoffIsRed(t *testing.T, rec badHandoff) {
	t.Helper()
	c, tid, _ := handoffFixture(t, rec.id)
	doc := editHandoff(t, c, tid, rec.body)
	if err := validation.Validate(doc, "regression_target", 1); err == nil {
		t.Errorf("the shipped validator ACCEPTS %s — the section cannot be "+
			"expected to catch what the schema does not", rec.name)
	}
	problems := suiteProblems(t, c)
	if !problemMentions(problems, "validation failed") {
		t.Errorf("%s: no problem reports the schema refusal; problems=%v",
			rec.name, problems)
	}
	if rec.noP1 && !problemMentions(problems, "carries no P1 handoff") {
		t.Errorf("%s: the record carries neither honest form, but no problem "+
			"says so; problems=%v", rec.name, problems)
	}
}

// TestRegressionSuiteRejectsABareUnpriceableFlag is D8a: the branch the
// reviewer's mutation M4 (a ceiling check that returns true unconditionally)
// survived. priceable:false alone is a bare flag, and a bare flag is not a
// decision — the section must say it carries no P1 handoff, not merely that
// the record is schema-invalid.
func TestRegressionSuiteRejectsABareUnpriceableFlag(t *testing.T) {
	assertBadHandoffIsRed(t, badHandoff{
		"C-regsectbad004", "bare priceable:false", bareFlagHandoff, true})
}

// TestRegressionSuiteDoesNotRenderAFigureTheDecisionRefused: D1's third record
// carries priceable:false AND a figure. The decision supersedes the figure
// (risk.RecordUnpriceable pops it for exactly this reason), so the row must
// not print a number the record's own decision refuses.
func TestRegressionSuiteDoesNotRenderAFigureTheDecisionRefused(t *testing.T) {
	c, tid, _ := handoffFixture(t, "C-regsectbad005")
	editHandoff(t, c, tid, contradictoryHandoff)
	sec, err := RegressionSuite(c)
	if err != nil {
		t.Fatal(err)
	}
	row := validation.ObjAt(sec, "targets").A[0]
	if got := validation.ObjStr(row, "handoff_extractable_usd"); got != "" {
		t.Fatalf("row renders figure %q for a decision that refuses one", got)
	}
}

// TestRegressionSuiteReadsAnIntegerFigure is D4: a schema-VALID hand-edited
// extractable_usd: 900000 parses as an Int (F=0), and reading .F made the
// section call the handoff missing and print a fabricated 0. The audit must be
// GREEN and the cell must carry the figure.
func TestRegressionSuiteReadsAnIntegerFigure(t *testing.T) {
	c, tid, _ := handoffFixture(t, "C-regsectint001")
	editHandoff(t, c, tid, `{"finding_id":"FID","source":"hand-edited",`+
		`"recorded_at":"2026-01-01T00:00:00Z","extractable_usd":900000}`)
	sec, err := RegressionSuite(c)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjAt(sec, "problems"); len(got.A) != 0 {
		t.Fatalf("problems = %v, want none: an integer figure is a figure", got.A)
	}
	assertSectionBool(t, sec, true)
	row := validation.ObjAt(sec, "targets").A[0]
	if got := validation.ObjStr(row, "handoff_extractable_usd"); got != "900000" {
		t.Fatalf("integer figure renders %q, want 900000", got)
	}
}

// assertHandoffDriftIsRed asserts a record the SCHEMA ACCEPTS is still RED:
// the ledger cross-check is the only thing that can catch it, so a test here
// that the schema would have caught would prove nothing.
func assertHandoffDriftIsRed(t *testing.T, c *state.Campaign, doc validation.Value, want string) {
	t.Helper()
	if err := validation.Validate(doc, "regression_target", 1); err != nil {
		t.Fatalf("this record must be SCHEMA-VALID, else the schema check "+
			"masks the ledger check: %v", err)
	}
	if problems := suiteProblems(t, c); !problemMentions(problems, want) {
		t.Fatalf("no problem names %q; problems=%v", want, problems)
	}
}

// TestRegressionSuiteCatchesADecisionTheLedgerNeverRecorded is D1c's first
// direction: the projection carries a COMPLETE, SCHEMA-VALID unpriceable
// decision the log never recorded — the target's last handoff event is the
// priced one the fixture wrote. Nothing but the ledger cross-check can see it.
func TestRegressionSuiteCatchesADecisionTheLedgerNeverRecorded(t *testing.T) {
	c, tid, _ := handoffFixture(t, "C-regsectled001")
	doc := editHandoff(t, c, tid, decisionBody(handoffCeiling, handoffReason, "operator"))
	assertHandoffDriftIsRed(t, c, doc, "priced one")
}

// TestRegressionSuiteCatchesADecisionWithNoEventAtAll is the same direction's
// other branch: the log holds NO handoff event for this target, so the decision
// was written straight onto the record. It is the exact shape D1c names — "the
// regression.control.handoff event reconciles nothing" — and it must be caught
// by the missing event, not by a companion problem.
func TestRegressionSuiteCatchesADecisionWithNoEventAtAll(t *testing.T) {
	c := regressSectionCampaign(t, "C-regsectled006")
	target := controlSectionTarget(t, c)
	tid := validation.ObjStr(target, "target_id")
	recordSectionControl(t, c, tid)
	doc := editHandoff(t, c, tid, decisionBody(handoffCeiling, handoffReason, "operator"))
	assertHandoffDriftIsRed(t, c, doc, "no regression.control.handoff event")
}

// TestRegressionSuiteCatchesACeilingTheLedgerDisagreesWith: the projection's
// ceiling is not the one the decision was logged against.
func TestRegressionSuiteCatchesACeilingTheLedgerDisagreesWith(t *testing.T) {
	c, tid, fid := handoffFixture(t, "C-regsectled002")
	recordUnpriceableHandoff(t, c, tid, fid)
	doc := editHandoff(t, c, tid, decisionBody("a ceiling nobody logged", handoffReason, "operator"))
	assertHandoffDriftIsRed(t, c, doc, "ceiling")
}

// TestRegressionSuiteCatchesAReasonTheLedgerDisagreesWith: the projection's
// written reason is not the one the decision was logged against.
func TestRegressionSuiteCatchesAReasonTheLedgerDisagreesWith(t *testing.T) {
	c, tid, fid := handoffFixture(t, "C-regsectled003")
	recordUnpriceableHandoff(t, c, tid, fid)
	doc := editHandoff(t, c, tid, decisionBody(handoffCeiling, "a reason nobody logged", "operator"))
	assertHandoffDriftIsRed(t, c, doc, "reason")
}

// TestRegressionSuiteCatchesAnActorTheLedgerDisagreesWith is D3: the decision
// is attributed, and the attribution is checked against the ledger — a
// hand-edited decision cannot lose or swap its actor in silence.
func TestRegressionSuiteCatchesAnActorTheLedgerDisagreesWith(t *testing.T) {
	c, tid, fid := handoffFixture(t, "C-regsectled004")
	recordUnpriceableHandoff(t, c, tid, fid)
	doc := editHandoff(t, c, tid, decisionBody(handoffCeiling, handoffReason, "someone-else"))
	assertHandoffDriftIsRed(t, c, doc, "actor")
}

// TestRegressionSuiteCatchesADecisionErasedFromTheRecord is D1c's mirror
// direction: the log's last word is a recorded unpriceable, but the record no
// longer carries it. The projection is schema-valid (a plain figure), so the
// erasure is invisible without the log.
func TestRegressionSuiteCatchesADecisionErasedFromTheRecord(t *testing.T) {
	c, tid, fid := handoffFixture(t, "C-regsectled005")
	recordUnpriceableHandoff(t, c, tid, fid)
	doc := editHandoff(t, c, tid, `{"finding_id":"FID","source":"re-edited",`+
		`"recorded_at":"2026-01-01T00:00:00Z","extractable_usd":900000}`)
	assertHandoffDriftIsRed(t, c, doc, "erased by hand-edit")
}
