package harness

import (
	"fmt"
	"strings"

	"websec/internal/validation"
)

// ReportKind is the fourth kind a bind writes: cli.verifyAutoprove's
// report-bound rung, whose mapper is MapReport over the registered report
// bytes (never MapRun/MapMinicertoraInvoc over a run's captured stdout).
// It is written on the slot and on the event by
// cmd_verify_autoprove.go, so the pairing below is the bind's own.
//
// r33 F4/F5: this was package sections' harnessReportKind. The kind/
// evidence pairing is a property of the BIND's write path, so its one home
// is the decision package both halves share.
const ReportKind = Kind("miniprover")

// ReportExecLabel is the provenance label a report-bound bind writes for its
// own pin: "REPORT-" + the first 12 hex digits of the report digest
// (cli.verifyAutoprove). Both halves call it — the verb to write the label,
// section 11 to check that a stored label names the bytes it is pinned to
// (r33 F4(b)) — so the label rule cannot drift into two spellings.
//
// The truncation is defensive about a SHORT digest: a real digest is 64 hex
// characters (validation.Sha256Hex) and never hits the guard, but a
// hand-edited registry row could carry a shorter sha, and a label rule that
// panicked on it would take the audit down instead of burning the row.
func ReportExecLabel(digest string) string {
	if len(digest) > 12 {
		digest = digest[:12]
	}
	return "REPORT-" + digest
}

// ReportProvenanceReason is the ONE reading of the (kind, exec, report pin)
// triple a report-bound rung carries, and returns "" when the pairing is one
// the bind could have written, else the sentence that says why not.
//
// The bind's report path writes exactly two shapes (cmd_verify_autoprove.go):
//
//   - no --exec: kind ReportKind and exec ReportExecLabel(pin) — the digest
//     NAMES the bytes that were mapped, and it is the only label the verb
//     invents;
//   - --exec EXEC-x: kind ReportKind and exec = that ledger exec id, after
//     harnessExecRecord proved the ledger holds it (that half needs the
//     ledger and lives in section 11).
//
// So:
//
//   - a REPORT- provenance under any kind but ReportKind is a pairing no
//     mapper produces: the report arm re-derives from the pinned report
//     bytes with MapReport, and an exec-shaped kind (halmos, forge-fuzz,
//     minicertora) claims the rung came from a captured stdout that was
//     never read. r33 F5. NOTE the report arm still RUNS for such a pairing
//     — the audit re-derives from the bytes first and burns the mismatch
//     after (r29b F1(a): a kind-shaped skip is the hole r29 closed, and the
//     digest/registry burns must keep firing first so a report row that is
//     missing from the store still says so);
//   - a REPORT- label whose digest prefix is not the pin's is a label that
//     does not name the bytes on record: the DISPLAY prints it as the
//     witness ("INV-1: PROVEN-BOUNDED (miniprover, k=4, REPORT-…)"), so a
//     label free to disagree with the pin is a printed lie about which
//     report was mapped. r33 F4(b).
func ReportProvenanceReason(kind Kind, exec, digest string) string {
	if !strings.HasPrefix(exec, "REPORT-") {
		return ""
	}
	if kind != ReportKind {
		return fmt.Sprintf("the run is pinned to report bytes "+
			"(%s) with REPORT- provenance, but the stored kind is %s — "+
			"the report-bound bind writes kind %s for a report rung, and "+
			"%s is an exec-bound kind whose mapper reads the run's own "+
			"captured stdout; no mapper produced this pairing, so the "+
			"rung is not backed", validation.PyReprStr(digest),
			validation.PyReprStr(string(kind)),
			validation.PyReprStr(string(ReportKind)),
			validation.PyReprStr(string(kind)))
	}
	if want := ReportExecLabel(digest); exec != want {
		return fmt.Sprintf("the rung's exec label is %s but the pinned "+
			"report bytes hash to %s (the bind writes %s) — the printed "+
			"provenance does not name the evidence on record, so the "+
			"rung is not backed", validation.PyReprStr(exec),
			validation.PyReprStr(digest), validation.PyReprStr(want))
	}
	return ""
}

// SamePropertyName is the ONE property-title comparison of the autoprove
// rail (r33 F2). Property titles are AGENT-authored strings, so identity
// folds case and surrounding whitespace while display keeps the first
// spelling. Three call sites share it:
//
//   - cli.autoprovePropertyHolder (the bind's one-property-one-invariant
//     rail) via cli.autoproveSameName;
//   - ReportSuspects' SUSPECT attribution;
//   - section 11's duplicate-attribution rail, which must collide on exactly
//     the pairs the bind's holder scan collides on — if the bind folds, the
//     audit folds.
//
// It was rpSameName (and, separately, an identical cli helper): two
// implementations of one law is the shape this round is about, so both are
// now spellings of this function.
func SamePropertyName(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}
