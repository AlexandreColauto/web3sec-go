package harness

// zz_r33_test.go — the r33 shared-decision pins, at the unit level.
//
// Three of r33's five findings are "the bind decided it, the audit never
// re-derived it", and the fix for each is to move the decision into the ONE
// entry point both halves run. These tests pin the new API directly:
//
//	F3  the schema_version gate is DecideReportSchema, and it is DecideReport's
//	    FIRST gate (so a "2.0" report refuses on the schema, not on a later
//	    gate the bytes also violate);
//	F4  the REPORT-<digest12> label rule is ReportExecLabel (the verb writes
//	    with it, section 11 re-derives with it) and the label/kind pairing is
//	    ReportProvenanceReason;
//	F5  the pairing rail itself: a REPORT- provenance may only wear
//	    harness.ReportKind.
//
// F2's fold (SamePropertyName) is pinned here too: it is the bind's own
// property comparison moved to one home, and section 11's duplicate-
// attribution rail calls it.
//
// The bind-vs-audit half of every finding lives in internal/cli/zz_r33_test.go
// and internal/audit/sections/zz_r33_test.go; these tests cannot fail before
// the change in the "the audit blessed a forgery" sense — the functions did
// not exist — they pin the shared contract the other two files exercise.

import (
	"strings"
	"testing"

	"websec/internal/validation"
)

// r33Rep is reports/report.json with the fields DecideReport reads, built
// directly (validation values, not JSON text) so a test can move ONE field.
func r33Rep(prop string, over ...validation.KV) validation.Value {
	rep := validation.VObj(
		validation.KV{K: "schema_version", V: validation.VStr("1.0")},
		validation.KV{K: "published", V: validation.VBool(true)},
		validation.KV{K: "publish_problems", V: validation.VArr()},
		validation.KV{K: "review_findings", V: validation.VArr()},
		validation.KV{K: "flags", V: validation.VObj(
			validation.KV{K: "loop_bound", V: validation.VInt(4)})},
		validation.KV{K: "property_outcomes", V: validation.VObj(
			validation.KV{K: prop, V: validation.VObj(
				validation.KV{K: "outcome", V: validation.VStr("PROVEN")},
				validation.KV{K: "per_rule", V: validation.VObj(
					validation.KV{K: "inv_1",
						V: validation.VStr("PROVEN")})})})},
	)
	for _, kv := range over {
		rep.O = validation.SetOrAppend(rep.O, kv.K, kv.V)
	}
	return rep
}

// r33SchemaRefusal is the ONE sentence the schema gate refuses with, for a
// named state — built here from the same words DecideReportSchema renders so
// the pin is readable, and asserted byte-for-byte for both a version and the
// ABSENT state.
func r33SchemaRefusal(name string) string {
	return "report schema_version " + validation.PyReprStr(name) +
		" is not understood (this build speaks " + ReportSchemaMajor +
		"0.x) — refusing to best-effort a contract change\n"
}

// TestR33SchemaGateRefusesAndNamesTheState is F3's unit pin: the gate lives
// in the shared decision, refuses the two states the verb refused ("2.0" and
// an ABSENT version) and passes the two it accepted ("1.0", a "1.0.3" patch
// form). Before the change harness had no schema gate at all, so every one of
// these decided the same way — an audit blessed what the verb refused.
func TestR33SchemaGateRefusesAndNamesTheState(t *testing.T) {
	cases := []struct {
		name     string
		override []validation.KV
		gate     ReportGate
		refusal  string
	}{
		{"2.0", []validation.KV{{K: "schema_version",
			V: validation.VStr("2.0")}}, GateSchemaVersion,
			r33SchemaRefusal("2.0")},
		{"absent", []validation.KV{{K: "schema_version",
			V: validation.VNull()}}, GateSchemaVersion,
			r33SchemaRefusal("ABSENT (pre-1.0 report)")},
		{"2.1.next", []validation.KV{{K: "schema_version",
			V: validation.VStr("2.1")}}, GateSchemaVersion,
			r33SchemaRefusal("2.1")},
		{"non-string", []validation.KV{{K: "schema_version",
			V: validation.VInt(2)}}, GateSchemaVersion,
			r33SchemaRefusal("ABSENT (pre-1.0 report)")},
		{"1.0", nil, GateNone, ""},
		{"1.0.3 patch form", []validation.KV{{K: "schema_version",
			V: validation.VStr("1.0.3")}}, GateNone, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := r33Rep("p1", tc.override...)
			dec := DecideReportSchema(rep)
			if dec.Gate != tc.gate {
				t.Fatalf("DecideReportSchema gate = %q, want %q",
					dec.Gate, tc.gate)
			}
			if dec.Refusal != tc.refusal {
				t.Fatalf("refusal\n got %q\nwant %q", dec.Refusal,
					tc.refusal)
			}
			// And the SAME answer through the whole decision, which is
			// what both halves call.
			full := DecideReport(rep, "p1")
			if full.Gate != tc.gate {
				t.Fatalf("DecideReport gate = %q, want %q",
					full.Gate, tc.gate)
			}
		})
	}
}

// TestR33SchemaGateIsTheFirstGate is F3's ORDER pin: a report that violates
// the schema AND a later gate (a SUSPECT finding on the property) must refuse
// on the SCHEMA — the bind checks the contract before it reads anything in
// it, and the audit's sentence must be the same sentence. Before this, the
// only schema check was the verb's own early return, which section 11 never
// ran.
func TestR33SchemaGateIsTheFirstGate(t *testing.T) {
	suspect := validation.VArr(validation.VObj(
		validation.KV{K: "property", V: validation.VStr("p1")},
		validation.KV{K: "verdict", V: validation.VStr("SUSPECT")},
		validation.KV{K: "reason", V: validation.VStr("vacuous rule")}))
	rep := r33Rep("p1",
		validation.KV{K: "schema_version", V: validation.VStr("2.0")},
		validation.KV{K: "review_findings", V: suspect})
	dec := DecideReport(rep, "p1")
	if dec.Gate != GateSchemaVersion {
		t.Fatalf("the schema gate must decide first, got gate %q (%s)",
			dec.Gate, dec.Refusal)
	}
	if dec.Refusal != r33SchemaRefusal("2.0") {
		t.Fatalf("refusal = %q", dec.Refusal)
	}
	// Control: the same bytes with a 1.x schema still refuse on the review
	// gate, so the ordering pin above is about the schema gate and not
	// about the suspect arm having been switched off.
	rep.O = validation.SetOrAppend(rep.O, "schema_version",
		validation.VStr("1.0"))
	if dec := DecideReport(rep, "p1"); dec.Gate != GateSuspect {
		t.Fatalf("control: want the SUSPECT gate, got %q", dec.Gate)
	}
}

// TestR33ReportExecLabelIsTheBindsLabelRule is F4(b)'s unit pin: the label
// the verb writes and the label section 11 re-derives come from ONE function
// ("REPORT-" + the digest's first 12 hex characters), and a short digest
// (a hand-edited registry row) yields a label instead of a panic.
func TestR33ReportExecLabelIsTheBindsLabelRule(t *testing.T) {
	const dig = "89889f8cf3601122334455667788990011223344556677889900aabbccddeeff"
	if got, want := ReportExecLabel(dig), "REPORT-89889f8cf360"; got != want {
		t.Fatalf("ReportExecLabel = %q, want %q", got, want)
	}
	if got := ReportExecLabel("abc"); got != "REPORT-abc" {
		t.Fatalf("a short digest must yield its own label, got %q", got)
	}
	if got := ReportExecLabel(""); got != "REPORT-" {
		t.Fatalf("an empty digest must not panic, got %q", got)
	}
}

// TestR33ReportProvenanceReason is F4(b)/F5's unit pin: the label must name
// the pinned bytes, and a REPORT- provenance may only wear the report kind.
// Every refusal must NAME both sides of the mismatch it reports.
func TestR33ReportProvenanceReason(t *testing.T) {
	const dig = "89889f8cf3601122334455667788990011223344556677889900aabbccddeeff"
	label := ReportExecLabel(dig)
	cases := []struct {
		name string
		kind Kind
		exec string
		// want is the empty string for an honest pairing, else the
		// fragments the refusal must name.
		want []string
	}{
		{"honest report label", ReportKind, label, nil},
		{"wrong label", ReportKind, "REPORT-000000000000",
			[]string{"REPORT-000000000000", dig, label}},
		{"report rung wearing an exec kind", Halmos, label,
			[]string{"halmos", string(ReportKind)}},
		{"forge kind over report provenance", ForgeFuzz, label,
			[]string{"forge-fuzz", string(ReportKind)}},
		{"minicertora kind over report provenance", MiniCertora, label,
			[]string{"minicertora", string(ReportKind)}},
		{"ledger exec provenance", ReportKind, "EXEC-7", nil},
		{"exec rung under an exec kind", Halmos, "EXEC-7", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ReportProvenanceReason(tc.kind, tc.exec, dig)
			if len(tc.want) == 0 {
				if got != "" {
					t.Fatalf("honest pairing must not be refused: %q",
						got)
				}
				return
			}
			if got == "" {
				t.Fatalf("pairing (%s, %s) must be refused",
					tc.kind, tc.exec)
			}
			for _, frag := range tc.want {
				if !strings.Contains(got, frag) {
					t.Fatalf("the refusal must name %q, got %q", frag,
						got)
				}
			}
		})
	}
}

// TestR33SamePropertyNameIsTheBindsFold is F2's fold pin: the comparison the
// bind's holder scan makes is the comparison section 11 must collide on. Case
// and surrounding edge whitespace fold; everything else is identity.
func TestR33SamePropertyNameIsTheBindsFold(t *testing.T) {
	same := [][2]string{
		{"p1", "p1"}, {"p1", "P1"}, {" P1 ", "p1"},
		{"total_never_wraps", " TOTAL_NEVER_WRAPS "}, {"", " "},
	}
	for _, tc := range same {
		if !SamePropertyName(tc[0], tc[1]) {
			t.Fatalf("SamePropertyName(%q, %q) must fold",
				tc[0], tc[1])
		}
		if !rpSameName(tc[0], tc[1]) {
			t.Fatalf("rpSameName(%q, %q) must agree with the shared fold",
				tc[0], tc[1])
		}
	}
	for _, tc := range [][2]string{{"p1", "p2"}, {"p1", "p1x"},
		{"p1", "p 1"}, {"total", "totals"}} {
		if SamePropertyName(tc[0], tc[1]) {
			t.Fatalf("SamePropertyName(%q, %q) must NOT fold",
				tc[0], tc[1])
		}
	}
}
