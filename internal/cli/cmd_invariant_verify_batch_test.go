package cli

// cmd_invariant_verify_batch_test.go — B6(b) (feedback-triage-morph-r2 §B6(b),
// plan-review F7): the `--invariants INV-1,INV-2,...` batch form.
//
// What is pinned here:
//
//   - the batch commits every id and prints one `<id>: attested` line per id
//     in ARGUMENT order, one invariant.verified event per id (never a fused
//     row), and the single operator-attestation disclosure ONCE;
//   - F7's all-or-nothing law: a refusal at ANY position prints
//     `aborted: <id> refused: <reason>; nothing written` at exit 2 and the
//     campaign's links file and event log are BYTE-IDENTICAL afterwards — no
//     earlier id in the list landed, and no `attested` line is printed for
//     state that does not exist;
//   - the list hygiene: duplicates are a usage error (exit 2, argparse
//     rendering) and an empty id (whole list or one element) is refused in
//     artifact-register's one-line shape;
//   - the conflicts: --invariants with the positional inv_id or with --exec is
//     a usage error, and the batch needs --artifact;
//   - the ABSENT case: the single-positional form's stdout, stderr, exit code
//     and its usage-error bytes are unchanged by the new flag;
//   - the read-only preflight replica agrees with the authoritative gate
//     (TestInvariantVerifyBatchGateAgreesWithSingleForm) — the drift guard for
//     the duplication documented in cmd_invariant_verify_batch.go;
//   - `-h` documents the flag (TestEveryCommandAnswersHelp stays green).

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// b6bRegisterNaming registers an artifact whose bytes name every token, the
// honest shape the relevance gate accepts (t15RegisterCheck's single-id twin,
// for lists).
func b6bRegisterNaming(t *testing.T, c *state.Campaign, name string,
	tokens ...string) string {
	t.Helper()
	path := filepath.Join(c.Root, name)
	if err := os.WriteFile(path,
		[]byte(strings.Join(tokens, " ")+" checked against src/V.sol#L40\n"),
		0o644); err != nil {
		t.Fatal(err)
	}
	aid, err := c.RegisterArtifact("other", path, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	return aid
}

// b6bReadOrEmpty reads a state file, treating absence as empty (the
// zero-write comparison must not care whether the file exists yet).
func b6bReadOrEmpty(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		t.Fatal(err)
	}
	return string(b)
}

// b6bStateBytes is the whole attestation-relevant state: the registry file and
// the append-only event log, as bytes. A refusal must leave both identical.
func b6bStateBytes(t *testing.T, c *state.Campaign) (string, string) {
	t.Helper()
	return b6bReadOrEmpty(t, filepath.Join(c.ArtifactsDir, "invariant_links.json")),
		b6bReadOrEmpty(t, c.EventsPath)
}

// b6bVerifiedEvents counts invariant.verified events per ref, so the
// one-event-per-invariant law (and "no event at all" for a refusal) is
// checkable.
func b6bVerifiedEvents(t *testing.T, c *state.Campaign) map[string]int {
	t.Helper()
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]int{}
	for _, ev := range events {
		if validation.ObjStr(ev, "type") != "invariant.verified" {
			continue
		}
		out[validation.PyStr(validation.ObjAt(ev, "ref"))]++
	}
	return out
}

// TestInvariantVerifyBatchAttestsEveryIDInArgumentOrder is the success path:
// all three ids commit, the stdout lines follow the ARGUMENT order (not the
// registry's or a sorted one), each registry entry carries the attestation
// provenance, and the log holds exactly one invariant.verified event per id.
func TestInvariantVerifyBatchAttestsEveryIDInArgumentOrder(t *testing.T) {
	c, root := t15Campaign(t, "inv")
	t15SeedInvariant(t, c, "INV-1", "totalAssets monotone except withdraw")
	t15SeedInvariant(t, c, "INV-2", "share price never decreases")
	t15SeedInvariant(t, c, "INV-3", "only the owner may pause")
	aid := b6bRegisterNaming(t, c, "inv-check.md", "INV-1", "INV-2", "INV-3")
	code, out, errS := run(t, "--root", root, "invariant-verify", c.CampaignID,
		"--artifact", aid, "--invariants", "INV-3,INV-1,INV-2")
	if code != 0 {
		t.Fatalf("exit %d, want 0 (stderr %q)", code, errS)
	}
	want := "INV-3: attested\nINV-1: attested\nINV-2: attested\n"
	if out != want {
		t.Fatalf("stdout\n%q\nwant\n%q", out, want)
	}
	if errS != verifyAttestationDisclosure {
		t.Fatalf("stderr %q, want the single disclosure %q", errS,
			verifyAttestationDisclosure)
	}
	for _, id := range []string{"INV-1", "INV-2", "INV-3"} {
		entry := invEntry(t, c, id)
		if got := validation.ObjStr(entry, "status"); got != "CHECKED_AGAINST_CODE" {
			t.Errorf("%s status %q, want CHECKED_AGAINST_CODE", id, got)
		}
		if got := validation.ObjStr(entry, "verified_by"); got != aid {
			t.Errorf("%s verified_by %q, want %q", id, got, aid)
		}
		if got := validation.ObjStr(entry, "verification_method"); got != "operator-attestation" {
			t.Errorf("%s verification_method %q", id, got)
		}
	}
	got := b6bVerifiedEvents(t, c)
	if len(got) != 3 || got["INV-1"] != 1 || got["INV-2"] != 1 || got["INV-3"] != 1 {
		t.Fatalf("invariant.verified events %v, want one per id", got)
	}
}

// TestInvariantVerifyBatchOneIDIsStillABatch: a one-element list is legal and
// attests exactly that id (the flag is a list, not a range).
func TestInvariantVerifyBatchOneIDIsStillABatch(t *testing.T) {
	c, root := t15Campaign(t, "inv")
	t15SeedInvariant(t, c, "INV-1", "totalAssets monotone except withdraw")
	aid := t15RegisterCheck(t, c, "inv-check.md", "INV-1")
	code, out, errS := run(t, "--root", root, "invariant-verify", c.CampaignID,
		"--artifact", aid, "--invariants", "INV-1")
	if code != 0 {
		t.Fatalf("exit %d (stderr %q)", code, errS)
	}
	if out != "INV-1: attested\n" {
		t.Fatalf("stdout %q", out)
	}
}

// TestInvariantVerifyBatchAppliesToAndCanonicalSpelling: the preflight's
// relevance replica accepts what the real gate accepts — an applies_to target
// and NormalizeInvID's canonical spelling of a padded registry key.
func TestInvariantVerifyBatchAppliesToAndCanonicalSpelling(t *testing.T) {
	c, root := t15Campaign(t, "inv")
	t15SeedInvariant(t, c, "INV-1", "totalAssets monotone except withdraw",
		"Vault")
	t15SeedInvariant(t, c, "INV-002", "share price never decreases")
	aid := b6bRegisterNaming(t, c, "inv-check.md", "Vault", "INV-2")
	code, out, errS := run(t, "--root", root, "invariant-verify", c.CampaignID,
		"--artifact", aid, "--invariants", "INV-1,INV-002")
	if code != 0 {
		t.Fatalf("exit %d (stderr %q)", code, errS)
	}
	if out != "INV-1: attested\nINV-002: attested\n" {
		t.Fatalf("stdout %q", out)
	}
}

// TestInvariantVerifyBatchRefusalWritesNothing is F7's core pin: the third id
// is refused by the relevance gate, so the two ids that would have passed are
// NOT written — no registry flip, no event, no `attested` line — and the whole
// state is byte-identical afterwards.
func TestInvariantVerifyBatchRefusalWritesNothing(t *testing.T) {
	c, root := t15Campaign(t, "inv")
	t15SeedInvariant(t, c, "INV-1", "totalAssets monotone except withdraw")
	t15SeedInvariant(t, c, "INV-2", "share price never decreases")
	t15SeedInvariant(t, c, "INV-3", "only the owner may pause")
	aid := b6bRegisterNaming(t, c, "inv-check.md", "INV-1", "INV-2")
	linksBefore, eventsBefore := b6bStateBytes(t, c)
	code, out, errS := run(t, "--root", root, "invariant-verify", c.CampaignID,
		"--artifact", aid, "--invariants", "INV-1,INV-2,INV-3")
	if code != 2 {
		t.Fatalf("exit %d, want 2 (stderr %q)", code, errS)
	}
	want := "aborted: INV-3 refused: artifact " + aid + " does not reference " +
		"INV-3 (nor its applies_to) — cite a check that names what it verifies " +
		"(invariant-verify with --exec <id> re-registers stdout as the artifact); " +
		"nothing written\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
	if out != "" {
		t.Fatalf("stdout %q, want empty — no attested line for unwritten state", out)
	}
	if linksAfter, eventsAfter := b6bStateBytes(t, c); linksAfter != linksBefore ||
		eventsAfter != eventsBefore {
		t.Fatalf("refusal wrote state:\nlinks %q -> %q\nevents %q -> %q",
			linksBefore, linksAfter, eventsBefore, eventsAfter)
	}
	for _, id := range []string{"INV-1", "INV-2", "INV-3"} {
		if got := validation.ObjStr(invEntry(t, c, id), "status"); got != "UNVERIFIED" {
			t.Errorf("%s status %q, want UNVERIFIED after the refusal", id, got)
		}
	}
	if got := b6bVerifiedEvents(t, c); len(got) != 0 {
		t.Fatalf("invariant.verified events %v, want none", got)
	}
}

// TestInvariantVerifyBatchUnknownInvariantRefusal: an id that is not a
// registry key is refused with the gate's own words, and the ids BEFORE it in
// the list do not land either (the half-seen batch the audit must never see).
func TestInvariantVerifyBatchUnknownInvariantRefusal(t *testing.T) {
	c, root := t15Campaign(t, "inv")
	t15SeedInvariant(t, c, "INV-1", "totalAssets monotone except withdraw")
	aid := t15RegisterCheck(t, c, "inv-check.md", "INV-1")
	linksBefore, eventsBefore := b6bStateBytes(t, c)
	code, out, errS := run(t, "--root", root, "invariant-verify", c.CampaignID,
		"--artifact", aid, "--invariants", "INV-1,INV-9")
	if code != 2 {
		t.Fatalf("exit %d, want 2 (stderr %q)", code, errS)
	}
	if errS != "aborted: INV-9 refused: unknown invariant 'INV-9'; nothing written\n" {
		t.Fatalf("stderr %q", errS)
	}
	if out != "" {
		t.Fatalf("stdout %q, want empty", out)
	}
	if got := validation.ObjStr(invEntry(t, c, "INV-1"), "status"); got != "UNVERIFIED" {
		t.Fatalf("INV-1 status %q — the id before the refusal landed", got)
	}
	if linksAfter, eventsAfter := b6bStateBytes(t, c); linksAfter != linksBefore ||
		eventsAfter != eventsBefore {
		t.Fatal("refusal wrote state")
	}
}

// TestInvariantVerifyBatchUnknownArtifactRefusal: the artifact is checked
// first (the same order the single form's gate uses), so an unregistered
// --artifact refuses the batch in state's pinned words, one line, no heal
// pointer appended (the batch's contract is the single aborted line).
func TestInvariantVerifyBatchUnknownArtifactRefusal(t *testing.T) {
	c, root := t15Campaign(t, "inv")
	t15SeedInvariant(t, c, "INV-1", "totalAssets monotone except withdraw")
	code, out, errS := run(t, "--root", root, "invariant-verify", c.CampaignID,
		"--artifact", "ART-nope", "--invariants", "INV-1")
	if code != 2 {
		t.Fatalf("exit %d, want 2 (stderr %q)", code, errS)
	}
	if errS != "aborted: INV-1 refused: unknown artifact 'ART-nope'; nothing written\n" {
		t.Fatalf("stderr %q", errS)
	}
	if out != "" {
		t.Fatalf("stdout %q, want empty", out)
	}
}

// TestInvariantVerifyBatchDuplicateIDsIsUsage: a repeated id is a usage error
// (exit 2, the argparse rendering), refused before the campaign is opened.
func TestInvariantVerifyBatchDuplicateIDsIsUsage(t *testing.T) {
	c, root := t15Campaign(t, "inv")
	code, out, errS := run(t, "--root", root, "invariant-verify", c.CampaignID,
		"--artifact", "ART-x", "--invariants", "INV-1,INV-2,INV-1")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	want := argparseUsageBlocks["invariant-verify"] +
		"webv2 invariant-verify: error: argument --invariants: duplicate " +
		"invariant id: 'INV-1'\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
	if out != "" {
		t.Fatalf("stdout %q, want empty", out)
	}
}

// TestInvariantVerifyBatchEmptyListHygiene: the empty string and an empty
// element are refused in artifact-register's one-line shape (exit 2, the
// offending value repr-quoted), before anything is opened or written.
func TestInvariantVerifyBatchEmptyListHygiene(t *testing.T) {
	c, root := t15Campaign(t, "inv")
	for _, raw := range []string{"", "INV-1,,INV-2", "INV-1,", ",INV-1",
		"INV-1, ,INV-2", " "} {
		linksBefore, eventsBefore := b6bStateBytes(t, c)
		code, out, errS := run(t, "--root", root, "invariant-verify",
			c.CampaignID, "--artifact", "ART-x", "--invariants="+raw)
		if code != 2 {
			t.Fatalf("--invariants=%q: exit %d, want 2 (%q)", raw, code, errS)
		}
		want := "invariant-verify: --invariants: empty invariant id: " +
			validation.PyReprStr(raw) + "\n"
		if errS != want {
			t.Fatalf("--invariants=%q: stderr %q, want %q", raw, errS, want)
		}
		if out != "" {
			t.Fatalf("--invariants=%q: stdout %q, want empty", raw, out)
		}
		if linksAfter, eventsAfter := b6bStateBytes(t, c); linksAfter != linksBefore ||
			eventsAfter != eventsBefore {
			t.Fatalf("--invariants=%q: refusal wrote state", raw)
		}
	}
}

// TestInvariantVerifyBatchConflictsAreUsage pins the parse-level refusals: the
// positional inv_id and --exec belong to the single form, --invariants needs a
// value, the campaign is still required, and the batch needs --artifact.
func TestInvariantVerifyBatchConflictsAreUsage(t *testing.T) {
	c, root := t15Campaign(t, "inv")
	usage := argparseUsageBlocks["invariant-verify"]
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"positional inv_id", []string{c.CampaignID, "INV-1", "--artifact",
			"ART-x", "--invariants", "INV-1"},
			usage + "webv2 invariant-verify: error: argument inv_id: not " +
				"allowed with argument --invariants\n"},
		{"--exec", []string{c.CampaignID, "--exec", "EXEC-x",
			"--invariants", "INV-1"},
			usage + "webv2 invariant-verify: error: argument --exec: not " +
				"allowed with argument --invariants\n"},
		{"no value", []string{c.CampaignID, "--artifact", "ART-x",
			"--invariants"},
			usage + "webv2 invariant-verify: error: argument --invariants: " +
				"expected one argument\n"},
		{"no campaign", []string{"--artifact", "ART-x", "--invariants",
			"INV-1"},
			usage + "webv2 invariant-verify: error: the following arguments " +
				"are required: campaign\n"},
	}
	for _, tc := range cases {
		argv := append([]string{"--root", root, "invariant-verify"}, tc.args...)
		code, out, errS := run(t, argv...)
		if code != 2 {
			t.Fatalf("%s: exit %d, want 2 (%q)", tc.name, code, errS)
		}
		if errS != tc.want {
			t.Fatalf("%s: stderr\n%q\nwant\n%q", tc.name, errS, tc.want)
		}
		if out != "" {
			t.Fatalf("%s: stdout %q, want empty", tc.name, out)
		}
	}
	// --artifact is required by the batch: a plain refusal line, after the
	// campaign is open (the single form's "one is required" placement).
	code, _, errS := run(t, "--root", root, "invariant-verify", c.CampaignID,
		"--invariants", "INV-1")
	if code != 2 || !strings.HasPrefix(errS,
		"invariant-verify: --invariants needs --artifact ART-...") ||
		strings.Count(errS, "\n") != 1 {
		t.Fatalf("no --artifact: exit %d stderr %q", code, errS)
	}
}

// TestInvariantVerifySingleFormBytesUnchangedWithoutBatchFlag is the ABSENT-case
// pin: with no --invariants the verb's success bytes and its usage-error bytes
// are exactly what they were before B6(b) — the new flag never rides the single
// form's output, and it is not smuggled into the pinned usage block.
func TestInvariantVerifySingleFormBytesUnchangedWithoutBatchFlag(t *testing.T) {
	c, root := t15Campaign(t, "inv")
	t15SeedInvariant(t, c, "INV-1", "totalAssets monotone except withdraw")
	aid := t15RegisterCheck(t, c, "inv-check.md", "INV-1")
	code, out, errS := run(t, "--root", root, "invariant-verify", c.CampaignID,
		"INV-1", "--artifact", aid)
	if code != 0 {
		t.Fatalf("exit %d (stderr %q)", code, errS)
	}
	if out != "INV-1: CHECKED_AGAINST_CODE (artifact "+aid+")\n" {
		t.Fatalf("stdout changed: %q", out)
	}
	if errS != verifyAttestationDisclosure {
		t.Fatalf("stderr changed: %q", errS)
	}
	// The usage ERROR keeps the argparse block byte-for-byte: the batch flag is
	// documented in the -h block only.
	code, _, errS = run(t, "invariant-verify")
	want := argparseUsageBlocks["invariant-verify"] +
		"webv2 invariant-verify: error: the following arguments are required: " +
		"campaign, inv_id\n"
	if code != 2 || errS != want {
		t.Fatalf("usage error exit %d stderr\n%q\nwant\n%q", code, errS, want)
	}
}

// TestInvariantVerifyBatchGateAgreesWithSingleForm is the drift guard for the
// read-only preflight replica: for each fixture the batch's verdict must be the
// single form's verdict, and a batch refusal must print the single form's own
// reason (as a substring — the single form repr-quotes the whole message).
func TestInvariantVerifyBatchGateAgreesWithSingleForm(t *testing.T) {
	// (a) honest citation: both commit.
	{
		c, root := t15Campaign(t, "inv")
		t15SeedInvariant(t, c, "INV-1", "totalAssets monotone except withdraw")
		aid := t15RegisterCheck(t, c, "inv-check.md", "INV-1")
		if code, _, errS := run(t, "--root", root, "invariant-verify",
			c.CampaignID, "INV-1", "--artifact", aid); code != 0 {
			t.Fatalf("single form refused an honest citation: %d %q", code, errS)
		}
		c2, root2 := t15Campaign(t, "inv")
		t15SeedInvariant(t, c2, "INV-1", "totalAssets monotone except withdraw")
		aid2 := t15RegisterCheck(t, c2, "inv-check.md", "INV-1")
		if code, _, errS := run(t, "--root", root2, "invariant-verify",
			c2.CampaignID, "--artifact", aid2, "--invariants",
			"INV-1"); code != 0 {
			t.Fatalf("batch refused an honest citation: %d %q", code, errS)
		}
	}
	// (b) irrelevant artifact: the batch's reason is the single form's reason.
	{
		c, root := t15Campaign(t, "inv")
		t15SeedInvariant(t, c, "INV-1", "totalAssets monotone except withdraw")
		path := filepath.Join(c.Root, "generic.md")
		if err := os.WriteFile(path, []byte("checked the withdraw path\n"),
			0o644); err != nil {
			t.Fatal(err)
		}
		aid, err := c.RegisterArtifact("other", path, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		code, _, single := run(t, "--root", root, "invariant-verify",
			c.CampaignID, "INV-1", "--artifact", aid)
		if code != 2 {
			t.Fatalf("single form exit %d, want 2", code)
		}
		code, _, batch := run(t, "--root", root, "invariant-verify",
			c.CampaignID, "--artifact", aid, "--invariants", "INV-1")
		if code != 2 {
			t.Fatalf("batch exit %d, want 2", code)
		}
		reason := batchReason(t, batch)
		if !strings.Contains(single, reason) {
			t.Fatalf("reasons disagree:\nsingle %q\nbatch  %q", single, reason)
		}
	}
	// (c) unknown invariant: same.
	{
		c, root := t15Campaign(t, "inv")
		aid := t15Register(t, c, "inv-check.md", "other", "")
		code, _, single := run(t, "--root", root, "invariant-verify",
			c.CampaignID, "INV-9", "--artifact", aid)
		if code != 2 {
			t.Fatalf("single form exit %d, want 2", code)
		}
		code, _, batch := run(t, "--root", root, "invariant-verify",
			c.CampaignID, "--artifact", aid, "--invariants", "INV-9")
		if code != 2 {
			t.Fatalf("batch exit %d, want 2", code)
		}
		reason := batchReason(t, batch)
		if !strings.Contains(single, reason) {
			t.Fatalf("reasons disagree:\nsingle %q\nbatch  %q", single, reason)
		}
	}
}

// batchReason extracts <reason> from the batch's
// `aborted: <id> refused: <reason>; nothing written` line.
func batchReason(t *testing.T, stderr string) string {
	t.Helper()
	const pre, sep, post = "aborted: ", " refused: ", "; nothing written\n"
	if !strings.HasPrefix(stderr, pre) || !strings.HasSuffix(stderr, post) {
		t.Fatalf("not an aborted line: %q", stderr)
	}
	body := strings.TrimSuffix(strings.TrimPrefix(stderr, pre), post)
	i := strings.Index(body, sep)
	if i < 0 {
		t.Fatalf("aborted line has no refusal clause: %q", stderr)
	}
	return body[i+len(sep):]
}

// TestInvariantVerifyBatchHelpDocumentsTheFlag: `-h` stays exit 0, keeps the
// pinned argparse usage block as its first lines (help and usage error cannot
// disagree about the single form's signature), and documents the batch form
// and its all-or-nothing discipline.
func TestInvariantVerifyBatchHelpDocumentsTheFlag(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Run([]string{"invariant-verify", "-h"}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d (stderr %q)", code, errOut.String())
	}
	got := out.String()
	if !strings.HasPrefix(got, argparseUsageBlocks["invariant-verify"]) {
		t.Fatalf("help does not start with the pinned usage block:\n%q", got)
	}
	for _, want := range []string{
		"webv2 invariant-verify [-h] --artifact ARTIFACT --invariants IDS campaign",
		"--invariants IDS",
		"aborted: <id> refused: <reason>; nothing written",
		"one invariant.verified event each",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("help does not document %q", want)
		}
	}
}
