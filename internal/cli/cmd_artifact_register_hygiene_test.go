package cli

// cmd_artifact_register_hygiene_test.go — B2 (feedback-triage-morph-r2):
// artifact-register hygiene.
//
// Three fixes are pinned here, each against the behavior that was wrong
// BEFORE the fix:
//
//	(a) --kind is validated EARLY, against the campaign_state schema
//	    document's artifact-row kind enum: a wrong kind is the house argparse
//	    refusal at exit 2, and it happens before state.Open, so a campaign
//	    (and its registry) is provably untouched. The enum is read from the
//	    schema FILE, not a Go literal — the SCHEMA_DIR override test proves
//	    it end to end at this layer.
//	(b) a zero-byte file is refused at the verb (exit 2, no row, no event),
//	    `/dev/null` included. Before the fix the existence check passed and a
//	    row was minted for an empty file. There is deliberately no
//	    --allow-empty bypass (pinned below).
//	(c) -h advertises [--kind KIND] [--note NOTE], names common kinds, and
//	    points at the schema document; the catalog line carries the flags too
//	    (it used to hide them).
//
// The success-path bytes are pinned by cmd_artifact_register_test.go
// (TestArtifactRegister, TestArtifactRegisterPrintsTheImmutabilityNotice) and
// are untouched by B2; TestArtifactRegisterAcceptsOneByteFile below re-checks
// the shape for the newly-legal boundary input.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/validation"
)

// b2KindValues is the artifact-row kind enum as the refusal must print it:
// read through the same exported helper the verb uses, so the expectation
// tracks the schema document rather than a copy of the list in the test.
func b2KindValues(t *testing.T) []string {
	t.Helper()
	vals, ok, err := validation.SchemaEnumValues("campaign_state",
		"artifacts[]/kind")
	if err != nil {
		t.Fatalf("read the artifact-row kind enum: %v", err)
	}
	if !ok {
		t.Fatal("campaign_state has no enum at artifacts[]/kind")
	}
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		out = append(out, validation.LegendValue(v))
	}
	return out
}

// b2ArtifactList runs artifact-list and returns its stdout, the operator's
// read of the registry.
func b2ArtifactList(t *testing.T, root, cid string) string {
	t.Helper()
	code, out, errS := run(t, "--root", root, "artifact-list", cid)
	if code != 0 {
		t.Fatalf("artifact-list exit %d: %q", code, errS)
	}
	return out
}

// b2WriteFile writes content to a file under dir and returns its path.
func b2WriteFile(t *testing.T, dir, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestArtifactRegisterInvalidKindRefusesBeforeState: a --kind outside the
// schema's enum is refused with the argparse block + the one-line error, exit
// 2, and NOTHING changes — no campaign opened (proved with a nonexistent
// campaign, where the refusal still wins over "no such campaign"), no row
// minted, artifact-list byte-identical before and after.
func TestArtifactRegisterInvalidKindRefusesBeforeState(t *testing.T) {
	c, root := t15Campaign(t, "artifact-register-b2-kind")
	good := b2WriteFile(t, root, "good.md", []byte("checked\n"))
	code, out, errS := run(t, "--root", root, "artifact-register", c.CampaignID,
		good)
	if code != 0 {
		t.Fatalf("seed register exit %d: out=%q err=%q", code, out, errS)
	}
	before := b2ArtifactList(t, root, c.CampaignID)

	kinds := b2KindValues(t)
	want := argparseUsageBlocks["artifact-register"] +
		"webv2 artifact-register: error: argument --kind: invalid kind " +
		"'bogus'; choose from: " + strings.Join(kinds, ", ") + "\n"
	for _, argv := range [][]string{
		{"--kind", "bogus"},   // space form
		{"--kind=bogus"},      // equals form
		{"--kind", ""},        // an empty kind is not a kind
		{"--kind", "Recon"},   // the enum is case-sensitive
		{"--kind", "report "}, // and whitespace is not trimmed into validity
	} {
		args := append([]string{"--root", root, "artifact-register",
			c.CampaignID, good}, argv...)
		code, out, errS = run(t, args...)
		if code != 2 {
			t.Fatalf("%v: exit %d, want 2 (out=%q err=%q)", argv, code, out,
				errS)
		}
		if out != "" {
			t.Fatalf("%v: stdout %q, want empty", argv, out)
		}
		// The message names the value as typed, then the schema's own list in
		// document order.
		wantArg := want
		if len(argv) == 2 {
			wantArg = strings.Replace(want, "'bogus'",
				"'"+argv[1]+"'", 1)
		}
		if errS != wantArg {
			t.Fatalf("%v: stderr\n%q\nwant\n%q", argv, errS, wantArg)
		}
	}
	if after := b2ArtifactList(t, root, c.CampaignID); after != before {
		t.Fatalf("the registry changed on an invalid kind:\nbefore %q\nafter  %q",
			before, after)
	}
	if rows := r34ArtifactRows(t, c); len(rows) != 1 {
		t.Fatalf("rows after five refused registers: %d, want 1", len(rows))
	}

	// Ordering proof: the kind check runs BEFORE state.Open. A campaign that
	// does not exist would otherwise be the exit-1 "no such campaign" error.
	code, _, errS = run(t, "--root", root, "artifact-register",
		"C-00000000", good, "--kind", "bogus")
	if code != 2 || !strings.Contains(errS, "invalid kind 'bogus'") {
		t.Fatalf("invalid kind must outrank the campaign open: exit %d err %q",
			code, errS)
	}
}

// TestArtifactRegisterKindAllowListFollowsTheSchemaFile: the allow-list is the
// schema DOCUMENT's enum, not a Go literal. SCHEMA_DIR points the validation
// seam at a copy whose enum has a value added and one dropped; the refusal
// must answer the copy. A hard-coded list would keep rejecting the added
// value (and keep accepting the dropped one).
func TestArtifactRegisterKindAllowListFollowsTheSchemaFile(t *testing.T) {
	c, root := t15Campaign(t, "artifact-register-b2-schemafile")
	good := b2WriteFile(t, root, "good.md", []byte("checked\n"))

	raw, err := validation.ReadSchemaFile("campaign_state")
	if err != nil {
		t.Fatal(err)
	}
	// The enum's first two entries in the document; replacing the pair keeps
	// the array order the refusal text must preserve.
	const was = `["recon", "protocol-model"`
	const now = `["b2-bogus-kind", "protocol-model"`
	mutated := bytes.Replace(raw, []byte(was), []byte(now), 1)
	if bytes.Equal(mutated, raw) {
		t.Fatalf("the schema fixture no longer starts the kind enum with %s",
			was)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "campaign_state.schema.json"),
		mutated, 0o644); err != nil {
		t.Fatal(err)
	}
	validation.SetSchemaDir(dir)
	defer validation.ResetSchemaDir()

	// The added value is now legal (the verb gets past the parse; the file is
	// refused later only if something else is wrong — here nothing is).
	code, out, errS := run(t, "--root", root, "artifact-register", c.CampaignID,
		good, "--kind", "b2-bogus-kind")
	if code != 0 {
		t.Fatalf("the schema-added kind must register: exit %d out=%q err=%q",
			code, out, errS)
	}
	// The dropped value is now refused, and the message lists the mutated
	// document in its order.
	code, _, errS = run(t, "--root", root, "artifact-register", c.CampaignID,
		good, "--kind", "recon")
	if code != 2 {
		t.Fatalf("the schema-dropped kind must refuse: exit %d err=%q", code,
			errS)
	}
	if !strings.HasPrefix(errS, argparseUsageBlocks["artifact-register"]+
		"webv2 artifact-register: error: argument --kind: invalid kind "+
		"'recon'; choose from: b2-bogus-kind, protocol-model, ") {
		t.Fatalf("the refusal must list the schema FILE's values in order: %q",
			errS)
	}
	if strings.Contains(errS, "recon,") {
		t.Fatalf("the dropped value is still in the allow-list: %q", errS)
	}
}

// TestArtifactRegisterRefusesEmptyFile: a zero-byte file is refused at the
// verb — exit 2, the documented one-line error on stderr, no stdout, no row,
// no event, and the registry reads the same afterwards. `/dev/null` is the
// spelling that made the hole visible: it EXISTS, so the pre-B2 existence
// check passed and a row was minted for it.
func TestArtifactRegisterRefusesEmptyFile(t *testing.T) {
	c, root := t15Campaign(t, "artifact-register-b2-empty")
	before := b2ArtifactList(t, root, c.CampaignID)

	empty := b2WriteFile(t, root, "empty.md", nil)
	for _, path := range []string{"/dev/null", empty} {
		code, out, errS := run(t, "--root", root, "artifact-register",
			c.CampaignID, path)
		if code != 2 {
			t.Fatalf("%s: exit %d, want 2 (out=%q err=%q)", path, code, out,
				errS)
		}
		if out != "" {
			t.Fatalf("%s: stdout %q, want empty", path, out)
		}
		if want := "artifact register failed: empty artifact: " + path + "\n"; errS != want {
			t.Fatalf("%s: stderr\n%q\nwant\n%q", path, errS, want)
		}
	}
	if after := b2ArtifactList(t, root, c.CampaignID); after != before {
		t.Fatalf("the registry changed on an empty artifact:\nbefore %q\nafter %q",
			before, after)
	}
	if rows := r34ArtifactRows(t, c); len(rows) != 0 {
		t.Fatalf("rows after two refused registers: %d, want 0", len(rows))
	}
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range events {
		if validation.ObjStr(ev, "type") == "artifact.registered" {
			t.Fatalf("an empty artifact was logged: %v", ev)
		}
	}

	// The existence refusal keeps its own bytes (it is pinned by
	// TestArtifactRegisterMissingFileExits2 and must not be shadowed by the
	// new check).
	missing := filepath.Join(root, "nope.md")
	code, _, errS := run(t, "--root", root, "artifact-register", c.CampaignID,
		missing)
	if code != 2 ||
		errS != "artifact register failed: no such file: "+missing+"\n" {
		t.Fatalf("missing file: exit %d err %q", code, errS)
	}

	// NO --allow-empty bypass: the flag does not exist, and the empty file is
	// still refused with it present.
	code, _, errS = run(t, "--root", root, "artifact-register", c.CampaignID,
		empty, "--allow-empty")
	if code != 2 || !strings.Contains(errS, "unrecognized arguments: --allow-empty") {
		t.Fatalf("--allow-empty must not exist: exit %d err %q", code, errS)
	}
}

// TestArtifactRegisterAcceptsOneByteFile: one byte is not empty. The boundary
// input registers with the pinned success shape (id line + immutability
// notice on stdout, empty stderr), and `--kind invariants` — a legal enum
// value that the old free-string parser also accepted — still works in both
// spellings.
func TestArtifactRegisterAcceptsOneByteFile(t *testing.T) {
	c, root := t15Campaign(t, "artifact-register-b2-onebyte")
	one := b2WriteFile(t, root, "one.md", []byte("x"))
	code, out, errS := run(t, "--root", root, "artifact-register", c.CampaignID,
		one, "--kind", "invariants")
	if code != 0 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	if errS != "" {
		t.Fatalf("stderr %q, want empty", errS)
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("stdout\n%q\nwant the success line plus one notice", out)
	}
	if !strings.HasPrefix(lines[0], "INV-") ||
		!strings.HasSuffix(lines[0], ": kind=invariants path="+one) {
		t.Fatalf("success line = %q", lines[0])
	}
	if want := "note: registered artifacts are immutable — to revise, register " +
		"a new artifact (the old one stays for provenance)"; lines[1] != want {
		t.Fatalf("notice\n%q\nwant\n%q", lines[1], want)
	}
	if rows := r34ArtifactRows(t, c); len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}

	// The equals spelling of a legal kind is accepted too (a second file, so
	// the first row is not merely refreshed).
	two := b2WriteFile(t, root, "two.md", []byte("y"))
	code, out, errS = run(t, "--root", root, "artifact-register", c.CampaignID,
		two, "--kind=invariants")
	if code != 0 || !strings.Contains(out, ": kind=invariants path="+two) {
		t.Fatalf("--kind=invariants: exit %d out=%q err=%q", code, out, errS)
	}
}

// TestArtifactRegisterHelpAdvertisesKindAndNote: (c) the -h block documents
// the two flags (the registry line used to hide --kind/--note), names common
// kinds, and points at the schema document for the full enum; its usage line
// is the same first line argparse renders on a usage error.
func TestArtifactRegisterHelpAdvertisesKindAndNote(t *testing.T) {
	for _, flag := range []string{"-h", "--help"} {
		code, out, errS := run(t, "artifact-register", flag)
		if code != 0 || errS != "" {
			t.Fatalf("%s: exit %d err %q", flag, code, errS)
		}
		if !strings.HasPrefix(out, argparseUsageBlocks["artifact-register"]) {
			t.Fatalf("%s: help must open with the argparse usage line:\n%q",
				flag, out)
		}
		for _, want := range []string{
			"positional arguments:",
			"options:",
			"-h, --help",
			"--kind KIND",
			"--note NOTE",
			"(default: other)",
			"recon",
			"protocol-model",
			"sequence-poc",
			"other",
			"`webv2 schema campaign_state`",
			"artifacts[]/kind",
		} {
			if !strings.Contains(out, want) {
				t.Fatalf("%s: help does not mention %q:\n%s", flag, want, out)
			}
		}
		// Every "common kind" the help names must really be legal: the help
		// must not advertise a value the parser refuses.
		kinds := b2KindValues(t)
		legal := map[string]bool{}
		for _, k := range kinds {
			legal[k] = true
		}
		for _, k := range []string{"recon", "protocol-model", "plan",
			"hypothesis", "finding", "poc", "trace", "coverage", "report",
			"harness", "detector", "sequence-poc", "disclosure", "other"} {
			if !legal[k] {
				t.Fatalf("help advertises %q, which the schema does not allow",
					k)
			}
			if !strings.Contains(out, k) {
				t.Fatalf("help must name the common kind %q:\n%s", k, out)
			}
		}
	}

	// The catalog line (register(command{line:}) → usageText) advertises the
	// flags too: the operator reading `webv2 help` must see that --kind and
	// --note exist.
	code, out, _ := run(t, "help")
	if code != 0 {
		t.Fatalf("help exit %d", code)
	}
	if !strings.Contains(out,
		"artifact-register <campaign> <path> [--kind K] [--note N]") {
		t.Fatalf("the catalog line hides the flags:\n%s", out)
	}
}
