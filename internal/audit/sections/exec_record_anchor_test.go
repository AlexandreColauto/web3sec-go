package sections

// v1.6 — the exec_record_anchor section.
//
// The section is the consumer that makes the anchor load-bearing: it
// recomputes each anchored record's digest and compares it with the digest the
// ledger event committed to. These tests pin the payload's counting rule
// (`checked` counts anchor-carrying EVENTS, `anchored` counts only
// digest-VERIFIED matches, a problem row counts in `checked` only), the
// presence gate, and the migration row — the step-9 property, unit-tested:
// an unanchored event is a COVERAGE fact, `ok` stays true.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/sandbox"
	"websec/internal/state"
	"websec/internal/validation"
)

// anchorCamp is a bare campaign (no snapshot, no findings: the section reads
// the ledger and execs/ only).
func anchorCamp(t *testing.T, id string) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "Acme", state.InitOpts{CampaignID: id})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// anchorRecord writes a minimal exec record for execID and returns it.
func anchorRec(t *testing.T, c *state.Campaign, execID string,
	exit int64) validation.Value {
	t.Helper()
	rec := validation.VObj(
		KV("exec_id", validation.VStr(execID)),
		KV("exit_status", validation.VInt(exit)),
		KV("command", validation.VStr("forge test")),
	)
	writeAnchorRecord(t, c, execID, rec)
	return rec
}

// writeAnchorRecord rewrites the on-disk record for execID.
func writeAnchorRecord(t *testing.T, c *state.Campaign, execID string,
	rec validation.Value) {
	t.Helper()
	dir := filepath.Join(c.ExecsDir, execID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := validation.WriteJson(filepath.Join(dir, "exec_record.json"),
		rec, ""); err != nil {
		t.Fatal(err)
	}
}

// logCarrier appends one carrier event for execID with exactly kvs.
func logCarrier(t *testing.T, c *state.Campaign, typ, execID string,
	kvs ...validation.KV) {
	t.Helper()
	ref := execID
	data := validation.VObj(kvs...)
	if _, err := c.Log(typ, &ref, &data); err != nil {
		t.Fatal(err)
	}
}

// anchoredCarrier logs a carrier event carrying rec's own anchor.
func anchoredCarrier(t *testing.T, c *state.Campaign, typ, execID string,
	rec validation.Value) {
	t.Helper()
	logCarrier(t, c, typ, execID, sandbox.ExecRecordAnchorKVs(rec)...)
}

// anchorSection runs the section over c.
func anchorSection(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	sec, err := ExecRecordAnchor(c)
	if err != nil {
		t.Fatal(err)
	}
	return sec
}

// secInt is one integer key of the section payload.
func secInt(t *testing.T, sec validation.Value, key string) int {
	t.Helper()
	v := validation.ObjAt(sec, key)
	if v.Kind != validation.Int {
		t.Fatalf("section %s = %s, want an int", key,
			validation.CanonCompact(v))
	}
	return int(v.I)
}

// secStrs is one string-list key of the section payload.
func secStrs(t *testing.T, sec validation.Value, key string) []string {
	t.Helper()
	v := validation.ObjAt(sec, key)
	if v.Kind != validation.Arr {
		t.Fatalf("section %s = %s, want a list", key,
			validation.CanonCompact(v))
	}
	out := make([]string, 0, len(v.A))
	for _, e := range v.A {
		out = append(out, e.S)
	}
	return out
}

// secOK is the section's own ok flag.
func secOK(t *testing.T, sec validation.Value) bool {
	t.Helper()
	return validation.ObjAt(sec, "ok").B
}

func TestExecRecordAnchorReportsAMatch(t *testing.T) {
	c := anchorCamp(t, "C-anchormatch01")
	rec := anchorRec(t, c, "EXEC-0000000001", 0)
	anchoredCarrier(t, c, "sandbox.exec", "EXEC-0000000001", rec)
	sec := anchorSection(t, c)
	if got := secInt(t, sec, "checked"); got != 1 {
		t.Fatalf("checked = %d, want 1", got)
	}
	if got := secInt(t, sec, "anchored"); got != 1 {
		t.Fatalf("anchored = %d, want 1", got)
	}
	if got := len(secStrs(t, sec, "problems")); got != 0 {
		t.Fatalf("problems = %d, want 0", got)
	}
	if got := len(secStrs(t, sec, "unanchored")); got != 0 {
		t.Fatalf("unanchored = %d, want 0", got)
	}
	if !secOK(t, sec) {
		t.Fatal("ok = false on a verified anchor")
	}
}

func TestExecRecordAnchorReportsDrift(t *testing.T) {
	c := anchorCamp(t, "C-anchordrift01")
	rec := anchorRec(t, c, "EXEC-0000000001", 0)
	anchoredCarrier(t, c, "sandbox.exec", "EXEC-0000000001", rec)
	// The hand-edit: exit 0 -> 7 after the event.
	edited := validation.VObj(
		KV("exec_id", validation.VStr("EXEC-0000000001")),
		KV("exit_status", validation.VInt(7)),
		KV("command", validation.VStr("forge test")),
	)
	writeAnchorRecord(t, c, "EXEC-0000000001", edited)
	assertAnchorDrift(t, anchorSection(t, c), sandbox.ExecRecordDigest(rec), edited)
}

// assertAnchorDrift pins the drift row: the digest the event anchored and the
// digest the record now recomputes to are BOTH named, and the row is a
// problem (checked 1, anchored 0, unanchored 0, ok false).
func assertAnchorDrift(t *testing.T, sec validation.Value, stored string,
	edited validation.Value) {
	t.Helper()
	if got := secInt(t, sec, "checked"); got != 1 {
		t.Fatalf("checked = %d, want 1", got)
	}
	if got := secInt(t, sec, "anchored"); got != 0 {
		t.Fatalf("anchored = %d, want 0 (a problem row counts in checked "+
			"only)", got)
	}
	problems := secStrs(t, sec, "problems")
	if len(problems) != 1 {
		t.Fatalf("problems = %v, want exactly the drift row", problems)
	}
	if got := len(secStrs(t, sec, "unanchored")); got != 0 {
		t.Fatalf("unanchored = %d, want 0", got)
	}
	if secOK(t, sec) {
		t.Fatal("ok = true on a drifted record")
	}
	for _, want := range []string{stored, sandbox.ExecRecordDigest(edited)} {
		if !strings.Contains(problems[0], want) {
			t.Fatalf("the drift row must name both digests; %q lacks %q",
				problems[0], want)
		}
	}
}

func TestExecRecordAnchorReportsANewStyleEventWithoutADigest(t *testing.T) {
	c := anchorCamp(t, "C-anchornodig01")
	rec := anchorRec(t, c, "EXEC-0000000001", 0)
	logCarrier(t, c, "sandbox.exec", "EXEC-0000000001",
		validation.KV{K: sandbox.KeyExecRecordSHA256Alg,
			V: validation.VStr(sandbox.ExecRecordAnchorAlg)})
	sec := anchorSection(t, c)
	if got := secInt(t, sec, "checked"); got != 1 {
		t.Fatalf("checked = %d, want 1 (the label is an anchor key)", got)
	}
	if got := secInt(t, sec, "anchored"); got != 0 {
		t.Fatalf("anchored = %d, want 0", got)
	}
	problems := secStrs(t, sec, "problems")
	if len(problems) != 1 || !strings.Contains(problems[0],
		"names the anchor encoding but carries no digest") {
		t.Fatalf("problems = %v, want the missing-digest row", problems)
	}
	_ = rec
}

func TestExecRecordAnchorReportsAMissingRecord(t *testing.T) {
	c := anchorCamp(t, "C-anchormiss01")
	rec := anchorRec(t, c, "EXEC-0000000001", 0)
	anchoredCarrier(t, c, "sandbox.exec", "EXEC-0000000001", rec)
	if err := os.RemoveAll(filepath.Join(c.ExecsDir, "EXEC-0000000001")); err != nil {
		t.Fatal(err)
	}
	sec := anchorSection(t, c)
	if got := secInt(t, sec, "checked"); got != 1 {
		t.Fatalf("checked = %d, want 1", got)
	}
	if got := secInt(t, sec, "anchored"); got != 0 {
		t.Fatalf("anchored = %d, want 0", got)
	}
	problems := secStrs(t, sec, "problems")
	if len(problems) != 1 || !strings.Contains(problems[0],
		"anchors a record that is not on disk") {
		t.Fatalf("problems = %v, want the not-on-disk row", problems)
	}
	// The stated overlap: Execs reports the same deletion independently.
	ex, err := Execs(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(secStrs(t, ex, "problems")) == 0 {
		t.Fatal("Execs no longer reports an exec event whose record is gone")
	}
}

func TestExecRecordAnchorReportsAnUnparseableRecord(t *testing.T) {
	c := anchorCamp(t, "C-anchorparse01")
	rec := anchorRec(t, c, "EXEC-0000000001", 0)
	anchoredCarrier(t, c, "sandbox.exec", "EXEC-0000000001", rec)
	if err := os.WriteFile(filepath.Join(c.ExecsDir, "EXEC-0000000001",
		"exec_record.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The report is still PRODUCED — a section error would abort the whole
	// audit (AuditCampaign treats any non-ErrSkip error as fatal).
	sec := anchorSection(t, c)
	if got := secInt(t, sec, "checked"); got != 1 {
		t.Fatalf("checked = %d, want 1", got)
	}
	if got := secInt(t, sec, "anchored"); got != 0 {
		t.Fatalf("anchored = %d, want 0", got)
	}
	problems := secStrs(t, sec, "problems")
	if len(problems) != 1 || !strings.Contains(problems[0],
		"anchors a record that cannot be parsed") {
		t.Fatalf("problems = %v, want the unparseable row", problems)
	}
}

func TestExecRecordAnchorReportsDisagreeingCarriers(t *testing.T) {
	c := anchorCamp(t, "C-anchordisag01")
	rec := anchorRec(t, c, "EXEC-0000000001", 0)
	other := anchorRec(t, c, "EXEC-0000000002", 1)
	anchoredCarrier(t, c, "sandbox.exec", "EXEC-0000000001", rec)
	anchoredCarrier(t, c, "sandbox.exec.registered", "EXEC-0000000001", other)
	sec := anchorSection(t, c)
	if got := secInt(t, sec, "anchored"); got != 0 {
		t.Fatalf("anchored = %d, want 0 (the carriers disagree)", got)
	}
	problems := secStrs(t, sec, "problems")
	if len(problems) != 1 || !strings.Contains(problems[0],
		"the carriers disagree about the record") {
		t.Fatalf("problems = %v, want the disagreeing-carriers row", problems)
	}
	for _, want := range []string{sandbox.ExecRecordDigest(rec),
		sandbox.ExecRecordDigest(other)} {
		if !strings.Contains(problems[0], want) {
			t.Fatalf("the row must name both digests; %q lacks %q",
				problems[0], want)
		}
	}
}

func TestExecRecordAnchorCountsOnlyVerifiedMatches(t *testing.T) {
	c := anchorCamp(t, "C-anchorcount01")
	ok := anchorRec(t, c, "EXEC-0000000001", 0)
	drift := anchorRec(t, c, "EXEC-0000000002", 0)
	anchoredCarrier(t, c, "sandbox.exec", "EXEC-0000000001", ok)
	anchoredCarrier(t, c, "sandbox.exec", "EXEC-0000000002", drift)
	writeAnchorRecord(t, c, "EXEC-0000000002", validation.VObj(
		KV("exec_id", validation.VStr("EXEC-0000000002")),
		KV("exit_status", validation.VInt(7)),
		KV("command", validation.VStr("forge test"))))

	sec := anchorSection(t, c)
	if got := secInt(t, sec, "checked"); got != 2 {
		t.Fatalf("checked = %d, want 2", got)
	}
	if got := secInt(t, sec, "anchored"); got != 1 {
		t.Fatalf("anchored = %d, want 1 (verified matches only)", got)
	}
	if got := len(secStrs(t, sec, "problems")); got != 1 {
		t.Fatalf("problems = %d, want 1", got)
	}
}

// TestExecRecordAnchorTreatsAnUnanchoredEventAsACoverageFact is the step-9
// property, unit-tested: the legacy fixture's two unanchored sandbox.exec
// events must render as coverage — `unanchored: 2`, `ok: true`, no problems —
// or verify-full step 9 goes red by construction.
func TestExecRecordAnchorTreatsAnUnanchoredEventAsACoverageFact(t *testing.T) {
	c := anchorCamp(t, "C-anchorlegacy01")
	rec := anchorRec(t, c, "EXEC-0000000001", 0)
	// The pre-anchor event shape: profile/exit/finding, no anchor key.
	logCarrier(t, c, "sandbox.exec", "EXEC-0000000001",
		validation.KV{K: "exit", V: validation.ObjAt(rec, "exit_status")})
	sec := anchorSection(t, c)
	if got := secInt(t, sec, "checked"); got != 0 {
		t.Fatalf("checked = %d, want 0 (an unanchored event carries no "+
			"anchor to check)", got)
	}
	if got := secInt(t, sec, "anchored"); got != 0 {
		t.Fatalf("anchored = %d, want 0", got)
	}
	if got := len(secStrs(t, sec, "problems")); got != 0 {
		t.Fatalf("an unanchored event is a coverage fact, never a problem: %v",
			secStrs(t, sec, "problems"))
	}
	unanchored := secStrs(t, sec, "unanchored")
	if len(unanchored) != 1 || !strings.Contains(unanchored[0], "EXEC-0000000001") {
		t.Fatalf("unanchored = %v, want the one ref with its reason", unanchored)
	}
	if !secOK(t, sec) {
		t.Fatal("ok = false on an unanchored event: step 9 would go red")
	}
}

func TestExecRecordAnchorSkipsACampaignWithNoExecEvents(t *testing.T) {
	c := anchorCamp(t, "C-anchorskip01")
	if _, err := ExecRecordAnchor(c); !errors.Is(err, ErrSkip) {
		t.Fatalf("a campaign with no carrier event must ErrSkip, got %v", err)
	}
	// A record with NO event of its own does not render the section either:
	// the two seeding harnesses must stay invisible to it.
	anchorRec(t, c, "EXEC-0000000001", 0)
	if _, err := ExecRecordAnchor(c); !errors.Is(err, ErrSkip) {
		t.Fatalf("a seeded record with no carrier event must ErrSkip, got %v",
			err)
	}
}

// twoCarrierMissingLabel is the D1 fixture: one complete, valid carrier plus a
// second carrier for the same ref carrying the RIGHT digest with NO encoding
// label. Returns the campaign, the ref and the record.
func twoCarrierMissingLabel(t *testing.T, id string) (*state.Campaign,
	string, validation.Value) {
	t.Helper()
	c := anchorCamp(t, id)
	rec := anchorRec(t, c, "EXEC-0000000001", 0)
	anchoredCarrier(t, c, "sandbox.exec", "EXEC-0000000001", rec)
	logCarrier(t, c, "sandbox.exec.registered", "EXEC-0000000001",
		validation.KV{K: sandbox.KeyExecRecordSHA256,
			V: validation.VStr(sandbox.ExecRecordDigest(rec))})
	return c, "EXEC-0000000001", rec
}

// TestExecRecordAnchorChecksEveryCarrierLabel is the D1 pin: a second carrier
// that carries the CORRECT digest but NO encoding label must be refused by the
// section exactly as the mint gate refuses it. Before the fix the section ran
// sandbox.AnchorProblem only against anchored[0] and compared carriers by
// digest alone, so this fixture rendered {checked: 2, anchored: 2, ok: true}
// while VerifyExecRecordAnchor refused it — the audit and the mint gate
// disagreeing about the same data, and `anchored` counting a carrier whose
// label was never checked.
func TestExecRecordAnchorChecksEveryCarrierLabel(t *testing.T) {
	c, _, _ := twoCarrierMissingLabel(t, "C-anchorcarrier01")
	sec := anchorSection(t, c)
	if got := secInt(t, sec, "checked"); got != 2 {
		t.Fatalf("checked = %d, want 2 (both anchored carriers examined)", got)
	}
	if got := secInt(t, sec, "anchored"); got != 0 {
		t.Fatalf("anchored = %d, want 0 (a problem row counts in checked "+
			"only)", got)
	}
	if got := len(secStrs(t, sec, "unanchored")); got != 0 {
		t.Fatalf("unanchored = %d, want 0", got)
	}
	problems := secStrs(t, sec, "problems")
	if len(problems) != 1 || !strings.Contains(problems[0],
		"carries a digest with no encoding label") {
		t.Fatalf("problems = %v, want the unlabelled-digest row", problems)
	}
	if secOK(t, sec) {
		t.Fatal("ok = true while a carrier's label was never checked")
	}
}

// TestExecRecordAnchorRefusesTheSameFixtureAtMint closes the D1 loop: the
// fixture the section reports as a problem is REFUSED at mint by the same
// predicate, so the audit and the mint gate cannot disagree about it.
func TestExecRecordAnchorRefusesTheSameFixtureAtMint(t *testing.T) {
	c, ref, rec := twoCarrierMissingLabel(t, "C-anchorcarrier02")
	err := sandbox.VerifyExecRecordAnchor(c, ref, rec)
	if err == nil {
		t.Fatal("mint admitted a carrier carrying a digest with no label")
	}
	if !strings.Contains(err.Error(), "carries a digest with no encoding label") {
		t.Fatalf("mint refusal = %v, want the unlabelled-digest sentence", err)
	}
}

// TestExecRecordAnchorFoldsAnUnreadableLedgerIntoAProblemRow is the D2 pin:
// the section has no aborting path. c.Events() failing was returned as a plain
// error, which AuditCampaign treats as fatal (internal/audit/audit.go), so the
// section could suppress every other section's verdict. It is now a
// report-shaped red row — the same "degrade into problems" shape the event_log
// section uses for an unusable ledger.
func TestExecRecordAnchorFoldsAnUnreadableLedgerIntoAProblemRow(t *testing.T) {
	c := anchorCamp(t, "C-anchorledger01")
	// EISDIR: events.jsonl replaced by a directory. This shape is a read
	// failure under any uid (no chmod needed).
	if err := os.Remove(c.EventsPath); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(c.EventsPath, 0o755); err != nil {
		t.Fatal(err)
	}
	sec, err := ExecRecordAnchor(c)
	if err != nil {
		t.Fatalf("an unreadable ledger must degrade to a problem row, not "+
			"abort the audit: %v", err)
	}
	if got := secInt(t, sec, "checked"); got != 0 {
		t.Fatalf("checked = %d, want 0", got)
	}
	if got := secInt(t, sec, "anchored"); got != 0 {
		t.Fatalf("anchored = %d, want 0", got)
	}
	problems := secStrs(t, sec, "problems")
	if len(problems) != 1 ||
		!strings.Contains(problems[0], "the campaign ledger cannot be read") ||
		!strings.Contains(problems[0], c.EventsPath) {
		t.Fatalf("problems = %v, want the unreadable-ledger row naming %s",
			problems, c.EventsPath)
	}
	if secOK(t, sec) {
		t.Fatal("ok = true over a ledger that could not be read")
	}
}

func TestExecRecordAnchorIsDeterministic(t *testing.T) {
	c := anchorCamp(t, "C-anchordet01")
	first := anchorRec(t, c, "EXEC-0000000001", 0)
	drift := anchorRec(t, c, "EXEC-0000000002", 0)
	anchoredCarrier(t, c, "sandbox.exec", "EXEC-0000000001", first)
	anchoredCarrier(t, c, "sandbox.exec", "EXEC-0000000002", drift)
	logCarrier(t, c, "sandbox.exec", "EXEC-0000000003")
	writeAnchorRecord(t, c, "EXEC-0000000002", validation.VObj(
		KV("exec_id", validation.VStr("EXEC-0000000002")),
		KV("exit_status", validation.VInt(7)),
		KV("command", validation.VStr("forge test"))))

	a := anchorSection(t, c)
	b := anchorSection(t, c)
	if validation.CanonCompact(a) != validation.CanonCompact(b) {
		t.Fatalf("two runs differ:\n%s\n%s", validation.CanonCompact(a),
			validation.CanonCompact(b))
	}
}
