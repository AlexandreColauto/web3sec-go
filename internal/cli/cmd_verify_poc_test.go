package cli

// Wave M task 3 — cmd_verify_poc_test.go: `verify --harness-result` writes
// the runnable bridged PoC artifact for a minicertora counterexample.
//
// The artifact contract pinned here:
//
//   - a counterexample whose witness bridges cleanly lands
//     artifacts/harness/<INV>/poc-<INV>.json, holding
//     validation.CanonCompact(doc) — bytes that LoadSequenceSpec +
//     BuildCommand accept (the T1 run-path legality, consumed end to end);
//   - the file is registered in the campaign's artifact registry as a
//     sequence-poc row through the SAME write/commit path verify --scaffold
//     uses (harnessArtifactWrite), so no parallel store appears;
//   - presence-gating: nothing is written without a clean bridge, and the
//     refusal is named on stderr while the rung stays recorded;
//   - OVERWRITE determinism: a re-verify rewrites the same path with
//     identical bytes and records no second registration;
//   - the operator's artifacts/harness/<INV>/layout.json sidecar grounds
//     final_storage readings as final_assertions (A1… in sorted-key order);
//     a malformed sidecar is ignored with one stderr note and the PoC is
//     written exactly as it would have been without it.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/sequencepoc"
	"websec/internal/state"
	"websec/internal/validation"
)

// pocRegistrations counts the artifact registry events whose data names the
// sequence-poc kind: the scaffold's own registration (kind "harness") is not
// this artifact and must not be counted as one.
func pocRegistrations(t *testing.T, c *state.Campaign, typ string) int {
	t.Helper()
	n := 0
	for _, ev := range harnessEventsOf(t, c, typ) {
		if data, _ := ev["data"].(map[string]any); data != nil &&
			data["kind"] == "sequence-poc" {
			n++
		}
	}
	return n
}

// assertAuditOK runs the full integrity audit and requires it green: the
// derived artifact (and, where present, the operator's unregistered sidecar
// beside it) must not redden the campaign.
func assertAuditOK(t *testing.T, root string, c *state.Campaign) {
	t.Helper()
	code, out, errS := run(t, "--root", root, "audit", c.CampaignID,
		"--json")
	if code != 0 {
		t.Fatalf("audit exit %d err=%q", code, errS)
	}
	rep, err := validation.ParseOrdered([]byte(out))
	if err != nil {
		t.Fatalf("audit --json: %v", err)
	}
	if ok := objAt(rep, "ok"); ok.Kind != validation.Bool || !ok.B {
		t.Fatalf("audit not ok: %s", validation.CanonCompact(ok))
	}
}

// artifactsOfKind returns the campaign's REGISTERED artifact rows of one
// kind (read back from the state file, not from an in-memory handle).
func artifactsOfKind(t *testing.T, c *state.Campaign,
	kind string) []validation.Value {
	t.Helper()
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	var out []validation.Value
	for _, a := range objAt(st, "artifacts").A {
		if objStr(a, "kind") == kind {
			out = append(out, a)
		}
	}
	return out
}

// mcSymbolicSenderLine is a counterexample whose single call sends from a
// free symbol: the witness is real but cannot be replayed on a chain, so the
// bridge refuses it (the refusal text is the guidance).
const mcSymbolicSenderLine = `{"tool_version":"0.4.2","contract":"V.sol",` +
	`"rule":"inv_1","verdict":"VIOLATED","confidence":"unconfirmed",` +
	`"reason":"assertion-violated","details":"",` +
	`"bounds":{"loop_bound":4,"path_cap":64,"solver_timeout_ms":30000},` +
	`"failed_assertion":{"expression":"total >= before"},"params":{"x":"2"},` +
	`"calls":[{"step":1,"function":"withdraw","target":` +
	`"0x1111111111111111111111111111111111111111","args":["1000"],` +
	`"env":{"msg.sender":"attacker","msg.value":"0"},"reverted":false,` +
	`"reentrant":false,"overrides":{}}],"final_storage":{"total":"0"}}` + "\n"

// mcTwoReadingLine is the layout-door fixture: two concrete final_storage
// readings, so the bridge has two candidate assertions and the ids A1/A2
// have to be assigned in ITS order (sorted layout key), not the report's.
const mcTwoReadingLine = `{"tool_version":"0.4.2","contract":"V.sol",` +
	`"rule":"inv_1","verdict":"VIOLATED","confidence":"unconfirmed",` +
	`"reason":"assertion-violated","details":"",` +
	`"bounds":{"loop_bound":4,"path_cap":64,"solver_timeout_ms":30000},` +
	`"failed_assertion":{"expression":"total >= before"},"params":{"x":"2"},` +
	`"calls":[{"step":1,"function":"withdraw","target":` +
	`"0x1111111111111111111111111111111111111111","args":["1000"],` +
	`"env":{"msg.sender":"0x2222222222222222222222222222222222222222",` +
	`"msg.value":"0"},"reverted":false,"reentrant":false,"overrides":{}}],` +
	`"final_storage":{"total":"0","supply":"7"}}` + "\n"

// pocPath is the artifact path under test.
func pocPath(campaignDir string) string {
	return filepath.Join(campaignDir, "artifacts", "harness", "INV-1",
		"poc-INV-1.json")
}

// layoutPath is the operator sidecar's path under test.
func layoutPath(campaignDir string) string {
	return filepath.Join(campaignDir, "artifacts", "harness", "INV-1",
		"layout.json")
}

// writeLayout places the operator's layout sidecar (raw bytes verbatim, so a
// malformed row can be written too).
func writeLayout(t *testing.T, campaignDir, raw string) {
	t.Helper()
	p := layoutPath(campaignDir)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
}

// readPoc reads the artifact and fails when it is absent.
func readPoc(t *testing.T, campaignDir string) string {
	t.Helper()
	raw, err := os.ReadFile(pocPath(campaignDir))
	if err != nil {
		t.Fatalf("poc artifact: %v", err)
	}
	return string(raw)
}

// assertPocIsRunnable parses the stored FILE bytes, validates them against
// the embedded sequence_poc schema (proving the embedded copy is byte-equal
// to the shipped asset, exactly as the harness package's own row does) and
// requires the run path to accept the document: LoadSequenceSpec plus
// BuildCommand, the two stages `webv2 sequence run` executes. A file that
// validates but does not load (or load but does not build) is not runnable.
func assertPocIsRunnable(t *testing.T, path string) validation.Value {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read poc: %v", err)
	}
	doc, err := validation.ParseOrdered(raw)
	if err != nil {
		t.Fatalf("poc is not JSON: %v", err)
	}
	embedded, err := validation.ReadSchemaFile("sequence_poc")
	if err != nil {
		t.Fatalf("read embedded sequence_poc schema: %v", err)
	}
	disk, err := os.ReadFile("../../assets/schema/sequence_poc.schema.json")
	if err != nil {
		t.Fatalf("read shipped schema: %v", err)
	}
	if !bytes.Equal(embedded, disk) {
		t.Fatal("the embedded sequence_poc schema is not the shipped asset")
	}
	if err := validation.Validate(doc, "sequence_poc", 1); err != nil {
		t.Fatalf("stored poc is not a sequence_poc: %v", err)
	}
	loaded, err := sequencepoc.LoadSequenceSpec(path)
	if err != nil {
		t.Fatalf("the stored poc does not load: %v", err)
	}
	if _, err := sequencepoc.BuildCommand(loaded, "/wd"); err != nil {
		t.Fatalf("the stored poc does not build a driver: %v", err)
	}
	return doc
}

// pocLayoutlessBytes is the exact artifact body for mcViolatedCallsLine with
// NO layout grounding: two distinct senders (actor_1/actor_2), the second
// step reverted, and an empty final_assertions — the bytes the layout rows
// below compare against.
const pocLayoutlessBytes = `{"actors":{"actor_1":` +
	`"0x2222222222222222222222222222222222222222","actor_2":` +
	`"0x3333333333333333333333333333333333333333"},"final_assertions":[],` +
	`"finding_id":"INV-1","spec_id":"SEQ-INV1-POC","steps":[` +
	`{"actor":"actor_1","args":["1000"],"function":"withdraw","step":1,` +
	`"target":"0x1111111111111111111111111111111111111111"},` +
	`{"actor":"actor_2","args":["2000"],"expect_revert":true,` +
	`"function":"withdraw","step":2,` +
	`"target":"0x1111111111111111111111111111111111111111"}]}`

// TestVerifyHarnessResultWritesBridgedPoc is the happy path end to end: the
// counterexample's witness lands as poc-INV-1.json with byte-pinned content,
// the file is schema-valid AND runnable (LoadSequenceSpec + BuildCommand),
// the registry carries one sequence-poc row, and the audit's derived poc
// line still renders from stored state.
func TestVerifyHarnessResultWritesBridgedPoc(t *testing.T) {
	c, root := mcCamp(t, "mc-poc")
	execID := "EXEC-20"
	mcHarnessExec(t, c, execID, mcViolatedCallsLine,
		"minicertora --rule inv_1 --loop-bound 4",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c)}, 1)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 0 {
		t.Fatalf("exit %d out=%q err=%q", code, out, errS)
	}
	if out != "INV-1: counterexample (minicertora, EXEC-20)\n" {
		t.Fatalf("stdout = %q", out)
	}
	// A clean bridge is silent: no refusal note, no sidecar note.
	if errS != "" {
		t.Fatalf("stderr = %q, want empty", errS)
	}
	if got := readPoc(t, c.Dir); got != pocLayoutlessBytes {
		t.Fatalf("poc bytes =\n%s\nwant\n%s", got, pocLayoutlessBytes)
	}
	assertPocIsRunnable(t, pocPath(c.Dir))
	// The artifact row: kind sequence-poc, one row, the same path.
	rows := artifactsOfKind(t, c, "sequence-poc")
	if len(rows) != 1 {
		t.Fatalf("sequence-poc rows = %d, want 1", len(rows))
	}
	if p := objStr(rows[0], "path"); !strings.HasSuffix(p,
		filepath.Join("artifacts", "harness", "INV-1", "poc-INV-1.json")) {
		t.Fatalf("artifact row path = %q", p)
	}
	if n := pocRegistrations(t, c, "artifact.registered"); n != 1 {
		t.Fatalf("sequence-poc registrations = %d, want 1", n)
	}
	// The audit is green with the new artifact registered, and its poc line
	// is derived from the STORED rung + proof.calls.
	assertAuditOK(t, root, c)
	code, out, errS = run(t, "--root", root, "audit", c.CampaignID, "--json")
	if code != 0 {
		t.Fatalf("audit exit %d err=%q", code, errS)
	}
	rep, err := validation.ParseOrdered([]byte(out))
	if err != nil {
		t.Fatalf("audit --json: %v", err)
	}
	runs := objAt(objAt(objAt(rep, "sections"), "invariant_verification"),
		"harness_runs")
	if runs.Kind != validation.Arr || len(runs.A) == 0 ||
		runs.A[0].S != "INV-1: counterexample (minicertora, EXEC-20) | "+
			"poc: 2 calls bridged" {
		t.Fatalf("audit harness_runs = %s", validation.CanonCompact(runs))
	}
}

// TestVerifyHarnessResultBridgedPocNoCalls is the empty-witness gate: a
// counterexample whose calls array is empty is a counterexample (the rung
// stands) but nothing is bridgable, so NO file appears and stderr names why.
func TestVerifyHarnessResultBridgedPocNoCalls(t *testing.T) {
	c, root := mcCamp(t, "mc-poc-nocalls")
	execID := "EXEC-21"
	mcHarnessExec(t, c, execID, mcViolatedLine, "minicertora --rule inv_1",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c)}, 1)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 0 {
		t.Fatalf("exit %d out=%q err=%q", code, out, errS)
	}
	if out != "INV-1: counterexample (minicertora, EXEC-21)\n" {
		t.Fatalf("stdout = %q", out)
	}
	want := "verify: poc for 'INV-1' not written: no calls to bridge\n"
	if errS != want {
		t.Fatalf("stderr = %q, want %q", errS, want)
	}
	if _, err := os.Stat(pocPath(c.Dir)); !os.IsNotExist(err) {
		t.Fatalf("poc artifact exists (stat err = %v): a refused bridge "+
			"writes no file", err)
	}
	// The rung is untouched by the refusal — that is the whole point.
	if r := objStr(mcHarness(t, c), "rung"); r != "counterexample" {
		t.Fatalf("rung = %q, want counterexample", r)
	}
	if rows := artifactsOfKind(t, c, "sequence-poc"); len(rows) != 0 {
		t.Fatalf("sequence-poc rows = %d, want 0", len(rows))
	}
}

// TestVerifyHarnessResultBridgedPocUnbridgable is the negative witness lane:
// a symbolic sender cannot be replayed on a fork, so the bridge refuses, no
// file appears, and the refusal text itself is the operator guidance. The
// rung still lands, exactly as for the empty witness.
func TestVerifyHarnessResultBridgedPocUnbridgable(t *testing.T) {
	c, root := mcCamp(t, "mc-poc-symbolic")
	execID := "EXEC-22"
	mcHarnessExec(t, c, execID, mcSymbolicSenderLine,
		"minicertora --rule inv_1",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c)}, 1)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 0 {
		t.Fatalf("exit %d out=%q err=%q", code, out, errS)
	}
	if out != "INV-1: counterexample (minicertora, EXEC-22)\n" {
		t.Fatalf("stdout = %q", out)
	}
	want := "verify: poc for 'INV-1' not written: symbolic senders cannot " +
		"be fork-repro'd\n"
	if errS != want {
		t.Fatalf("stderr = %q, want %q", errS, want)
	}
	if _, err := os.Stat(pocPath(c.Dir)); !os.IsNotExist(err) {
		t.Fatalf("poc artifact exists (stat err = %v)", err)
	}
	if r := objStr(mcHarness(t, c), "rung"); r != "counterexample" {
		t.Fatalf("rung = %q, want counterexample", r)
	}
	// A refused bridge is a counterexample WITHOUT a witness: the audit's
	// derived line is absent (proof.calls empty), and no artifact row was
	// minted — the two views agree with the file's absence.
	if n := pocRegistrations(t, c, "artifact.registered"); n != 0 {
		t.Fatalf("sequence-poc registrations = %d, want 0", n)
	}
	if rows := artifactsOfKind(t, c, "sequence-poc"); len(rows) != 0 {
		t.Fatalf("sequence-poc rows = %d, want 0", len(rows))
	}
}

// TestVerifyHarnessResultBridgedPocIdempotent pins the OVERWRITE law: the
// same run re-verified rewrites the same path with IDENTICAL bytes, prints
// the same line, and records NO second registration — byte-identical bytes
// are a no-op in the shared write path, so a re-verify cannot churn the
// registry or the event log.
func TestVerifyHarnessResultBridgedPocIdempotent(t *testing.T) {
	c, root := mcCamp(t, "mc-poc-idem")
	execID := "EXEC-23"
	mcHarnessExec(t, c, execID, mcViolatedCallsLine,
		"minicertora --rule inv_1",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c)}, 1)
	code, firstOut, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 0 {
		t.Fatalf("exit %d out=%q err=%q", code, firstOut, errS)
	}
	first := readPoc(t, c.Dir)
	code, secondOut, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 0 {
		t.Fatalf("re-run exit %d out=%q err=%q", code, secondOut, errS)
	}
	if secondOut != firstOut {
		t.Fatalf("re-run stdout = %q, want %q", secondOut, firstOut)
	}
	if second := readPoc(t, c.Dir); second != first {
		t.Fatalf("re-run poc bytes =\n%s\nwant the first run's\n%s",
			second, first)
	}
	if n := pocRegistrations(t, c, "artifact.registered"); n != 1 {
		t.Fatalf("sequence-poc registrations after re-run = %d, want 1", n)
	}
	if n := pocRegistrations(t, c, "artifact.refreshed"); n != 0 {
		t.Fatalf("sequence-poc refreshes after re-run = %d, want 0 "+
			"(identical bytes are not a refresh)", n)
	}
}

// TestVerifyHarnessResultBridgedPocLayoutSidecar is the layout door end to
// end: the operator's sidecar grounds BOTH concrete final_storage readings as
// storage assertions on the sequence's own target, with ids assigned in
// sorted-layout-key order (supply before total, NOT the report's order), and
// the resulting document is schema-valid and loadable.
func TestVerifyHarnessResultBridgedPocLayoutSidecar(t *testing.T) {
	c, root := mcCamp(t, "mc-poc-layout")
	writeLayout(t, c.Dir, `{"V":"0x1111111111111111111111111111111111111111",`+
		`"V.total":"3","V.supply":"4"}`)
	execID := "EXEC-24"
	mcHarnessExec(t, c, execID, mcTwoReadingLine,
		"minicertora --rule inv_1",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c)}, 1)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 0 {
		t.Fatalf("exit %d out=%q err=%q", code, out, errS)
	}
	if errS != "" {
		t.Fatalf("stderr = %q, want empty (a well-shaped sidecar is silent)",
			errS)
	}
	want := `{"actors":{"actor_1":` +
		`"0x2222222222222222222222222222222222222222"},"final_assertions":[` +
		`{"id":"A1","kind":"storage","op":"==","slot":"4",` +
		`"target":"0x1111111111111111111111111111111111111111","value":"7"},` +
		`{"id":"A2","kind":"storage","op":"==","slot":"3",` +
		`"target":"0x1111111111111111111111111111111111111111","value":"0"}],` +
		`"finding_id":"INV-1","spec_id":"SEQ-INV1-POC","steps":[` +
		`{"actor":"actor_1","args":["1000"],"function":"withdraw","step":1,` +
		`"target":"0x1111111111111111111111111111111111111111"}]}`
	if got := readPoc(t, c.Dir); got != want {
		t.Fatalf("poc bytes =\n%s\nwant\n%s", got, want)
	}
	doc := assertPocIsRunnable(t, pocPath(c.Dir))
	fa := objAt(doc, "final_assertions")
	if fa.Kind != validation.Arr || len(fa.A) != 2 {
		t.Fatalf("final_assertions = %s, want 2", validation.CanonCompact(fa))
	}
	// The operator's sidecar is NOT a registered artifact and the audit must
	// still be green with it sitting beside the PoC.
	if rows := artifactsOfKind(t, c, "sequence-poc"); len(rows) != 1 {
		t.Fatalf("sequence-poc rows = %d, want 1", len(rows))
	}
	assertAuditOK(t, root, c)
}

// TestVerifyHarnessResultBridgedPocMalformedLayout pins the ignore lane: a
// sidecar that does not have the documented shape is ignored with ONE stderr
// note naming why, and the PoC is written with exactly the bytes it would
// have had without any sidecar — a broken operator file never blocks the
// artifact and never changes it silently.
func TestVerifyHarnessResultBridgedPocMalformedLayout(t *testing.T) {
	rows := []struct {
		name, sidecar, want string
	}{
		{"not JSON", `{"V.total":`,
			"verify: layout sidecar artifacts/harness/INV-1/layout.json " +
				"ignored: not JSON: "},
		{"top level array", `["V.total", "3"]`,
			"verify: layout sidecar artifacts/harness/INV-1/layout.json " +
				"ignored: top level must be an object mapping " +
				"\"<Contract>.<var>\" to a decimal slot string\n"},
		{"numeric slot", `{"V.total":3}`,
			"verify: layout sidecar artifacts/harness/INV-1/layout.json " +
				"ignored: key 'V.total' must map to a string, got 3\n"},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			c, root := mcCamp(t, "mc-poc-badlayout")
			writeLayout(t, c.Dir, tc.sidecar)
			execID := "EXEC-25"
			mcHarnessExec(t, c, execID, mcViolatedCallsLine,
				"minicertora --rule inv_1",
				map[string]string{"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c)}, 1)
			code, out, errS := run(t, "--root", root, "verify",
				c.CampaignID, "--harness-result", "INV-1", "--exec", execID)
			if code != 0 {
				t.Fatalf("exit %d out=%q err=%q", code, out, errS)
			}
			if out != "INV-1: counterexample (minicertora, EXEC-25)\n" {
				t.Fatalf("stdout = %q", out)
			}
			if !strings.HasPrefix(errS, tc.want) {
				t.Fatalf("stderr = %q, want the note %q", errS, tc.want)
			}
			if got := readPoc(t, c.Dir); got != pocLayoutlessBytes {
				t.Fatalf("poc bytes =\n%s\nwant the layoutless bytes\n%s",
					got, pocLayoutlessBytes)
			}
			assertPocIsRunnable(t, pocPath(c.Dir))
		})
	}
}

// TestVerifyHarnessResultBridgedPocNotWrittenForInconclusive pins the other
// half of presence-gating: a scaffold-degraded refusal (rung inconclusive)
// writes NO artifact even though the run's stdout is a witness line — the
// output was refused, so nothing derived from it may be filed.
func TestVerifyHarnessResultBridgedPocNotWrittenForInconclusive(t *testing.T) {
	c, root := mcCamp(t, "mc-poc-inconclusive")
	execID := "EXEC-26"
	mcHarnessExec(t, c, execID, mcViolatedCallsLine,
		"minicertora --rule inv_1",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": strings.Repeat("0", 64)}, 1)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 0 {
		t.Fatalf("exit %d out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(out, "inconclusive") {
		t.Fatalf("stdout = %q, want the inconclusive rung", out)
	}
	if errS != "" {
		t.Fatalf("stderr = %q, want empty (no bridge was attempted)", errS)
	}
	if _, err := os.Stat(pocPath(c.Dir)); !os.IsNotExist(err) {
		t.Fatalf("poc artifact exists (stat err = %v): a refused rung "+
			"writes nothing", err)
	}
}

// TestVerifyHarnessResultBridgedPocKindGate pins the third gate: only a
// MINICERTORA counterexample has a bridged witness. A halmos counterexample
// is prose, not a witness, so the seam must not even attempt a bridge — no
// file, and no "not written" note either (the refusal lane belongs to a
// minicertora run whose witness really could not be replayed, and noise on
// every halmos counterexample would drown that signal).
func TestVerifyHarnessResultBridgedPocKindGate(t *testing.T) {
	c, root := harnessCamp(t, "halmos", "")
	execID := "EXEC-27"
	harnessExec(t, c, execID, harnessCounterStdout,
		"halmos --root . --loop 100", nil, 1)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 0 {
		t.Fatalf("exit %d out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(out, "counterexample") {
		t.Fatalf("stdout = %q, want the counterexample rung", out)
	}
	if errS != "" {
		t.Fatalf("stderr = %q, want empty (a halmos counterexample has no "+
			"bridged witness to refuse)", errS)
	}
	if _, err := os.Stat(pocPath(c.Dir)); !os.IsNotExist(err) {
		t.Fatalf("poc artifact exists (stat err = %v)", err)
	}
	if n := pocRegistrations(t, c, "artifact.registered"); n != 0 {
		t.Fatalf("sequence-poc registrations = %d, want 0", n)
	}
}
