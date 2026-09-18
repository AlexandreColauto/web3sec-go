package cli

// B6a — the unknown-artifact heal pointer on `invariant-verify`.
//
// The refusal itself is contractual and stays byte-for-byte: its inner text is
// state's KeyError copy, pinned EXACT by internal/state/artifacts_test.go
// (:339 Artifact, :497 PruneArtifact, :612 RefreshArtifact) and rendered here
// through PyReprStr. What B6a adds is a SECOND stderr line, and only for that
// one reason: the operator named an artifact the registry does not hold, and
// `artifact-register` is the only sanctioned mint. An unknown invariant, a
// relevance refusal or an unreadable store must not draw it — the advice
// would be about a different failure.
//
// The verb/flag half of the assertion reads the dispatch registry
// (cli.CommandNames) instead of grepping the sources, the precedent set by
// internal/findings/gate_remediation_guard_test.go:148 — operator-facing copy
// of a command drifts from the parser silently, and a heal line that names a
// verb the CLI does not dispatch is worse than no heal line.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/validation"
)

// b6aHealVerbs returns the verb token of every `webv2 <verb>` occurrence in a
// line: fields are split on whitespace and de-backticked first, because the
// heal line quotes its command the way the house style does
// (`webv2 artifact-register ...`).
func b6aHealVerbs(line string) []string {
	var verbs []string
	fields := strings.Fields(line)
	for i, f := range fields {
		if strings.Trim(f, "`") != "webv2" || i+1 >= len(fields) {
			continue
		}
		verbs = append(verbs, strings.Trim(fields[i+1], "`"))
	}
	return verbs
}

// b6aDispatched is CommandNames as a set.
func b6aDispatched() map[string]bool {
	out := map[string]bool{}
	for _, n := range CommandNames() {
		out[n] = true
	}
	return out
}

func TestInvariantVerifyUnknownArtifactHealsWithRegisterPointer(t *testing.T) {
	c, root := t15Campaign(t, "inv")
	t15SeedInvariant(t, c, "INV-1", "totalAssets monotone except withdraw")

	code, out, errS := run(t, "--root", root, "invariant-verify", c.CampaignID,
		"INV-1", "--artifact", "ART-nope")
	if code != 2 {
		t.Fatalf("exit %d, want 2 (%q)", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout %q, want empty — the failure path prints nothing there",
			out)
	}
	// Line 1: the pinned refusal, byte-intact (the same expression
	// cmd_invariant_verify.go renders).
	wantRefusal := "invariant verify failed: " +
		validation.PyReprStr("unknown artifact 'ART-nope'") + "\n"
	if !strings.HasPrefix(errS, wantRefusal) {
		t.Fatalf("pinned refusal line changed:\n got %q\nwant prefix %q",
			errS, wantRefusal)
	}
	lines := strings.Split(strings.TrimSuffix(errS, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("stderr %q, want the refusal plus exactly one heal line", errS)
	}
	heal := lines[1]
	// The whole heal line is pinned: it is the copy an operator acts on, and
	// the value the operator passed is reproduced as the path argument
	// (PyReprStr-quoted, so a spaced path stays copyable) beside the campaign
	// id and the real flag. `--kind invariants` is a value of the schema's
	// closed kind enum (campaign_state.schema.json:75).
	wantHeal := "invariant-verify: register it first — " +
		"`webv2 artifact-register " + c.CampaignID + " 'ART-nope' " +
		"--kind invariants` — then pass the artifact id it prints"
	if heal != wantHeal {
		t.Fatalf("heal line\n got %q\nwant %q", heal, wantHeal)
	}
	verbs := b6aHealVerbs(heal)
	if len(verbs) == 0 {
		t.Fatalf("heal line names no command: %q", heal)
	}
	dispatched := b6aDispatched()
	if len(dispatched) == 0 {
		t.Fatal("CommandNames() is empty — the guard would pass vacuously")
	}
	for _, v := range verbs {
		if !dispatched[v] {
			t.Errorf("heal line tells the operator to run %q, which the CLI "+
				"does not dispatch: %q", v, heal)
		}
	}
	// The heal's --kind value must stay a member of the schema's closed kind
	// enum, or B2's early refusal turns this pointer into a second refusal
	// (mutation-proof: deleting "invariants" from the enum fails THIS line,
	// not only the register path).
	vals, ok, err := validation.SchemaEnumValues("campaign_state",
		"artifacts[]/kind")
	if err != nil || !ok {
		t.Fatalf("kind enum unreadable at artifacts[]/kind: ok=%v err=%v",
			ok, err)
	}
	found := false
	for _, v := range vals {
		if validation.LegendValue(v) == "invariants" {
			found = true
		}
	}
	if !found {
		t.Error("the heal names --kind invariants, but the campaign_state " +
			"kind enum no longer holds it")
	}
}

// TestInvariantVerifyHealPointerReproducesAPathShapedValue: the operator who
// hits this most often passed a PATH where an id belongs (that is the whole
// point of the pointer, and of advertising --kind). The heal line must carry
// that value verbatim, repr-quoted so a spaced path stays copyable.
func TestInvariantVerifyHealPointerReproducesAPathShapedValue(t *testing.T) {
	c, root := t15Campaign(t, "inv")
	t15SeedInvariant(t, c, "INV-1", "totalAssets monotone except withdraw")

	value := filepath.Join(c.Root, "l1", "Vault.t.sol")
	code, _, errS := run(t, "--root", root, "invariant-verify", c.CampaignID,
		"INV-1", "--artifact", value)
	if code != 2 {
		t.Fatalf("exit %d, want 2 (%q)", code, errS)
	}
	if !strings.Contains(errS, validation.PyReprStr(value)) {
		t.Fatalf("heal line must name the path the operator passed: %q", errS)
	}
	if !strings.Contains(errS, "artifact-register "+c.CampaignID+" "+
		validation.PyReprStr(value)) {
		t.Fatalf("heal line must be a copyable register command: %q", errS)
	}
}

// TestInvariantVerifyHealPointerIsUnknownArtifactOnly: the two neighbouring
// exit-2 failures of this verb keep their single pinned line and draw no
// registration advice — a registered artifact that fails the relevance gate,
// and an unknown invariant beside a registered artifact.
func TestInvariantVerifyHealPointerIsUnknownArtifactOnly(t *testing.T) {
	c, root := t15Campaign(t, "inv")
	t15SeedInvariant(t, c, "INV-1", "totalAssets monotone except withdraw")
	path := filepath.Join(c.Root, "generic.md")
	if err := os.WriteFile(path, []byte("checked the withdraw path\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	aid, err := c.RegisterArtifact("other", path, "", nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		inv  string
		want string
	}{
		{"relevance refusal", "INV-1", "does not reference INV-1"},
		{"unknown invariant", "INV-NOPE", "unknown invariant 'INV-NOPE'"},
	} {
		code, _, errS := run(t, "--root", root, "invariant-verify",
			c.CampaignID, tc.inv, "--artifact", aid)
		if code != 2 {
			t.Fatalf("%s: exit %d, want 2 (%q)", tc.name, code, errS)
		}
		if !strings.Contains(errS, tc.want) {
			t.Fatalf("%s: stderr %q must name the reason", tc.name, errS)
		}
		if strings.Contains(errS, "artifact-register") {
			t.Errorf("%s: a registered artifact drew the register-it-first "+
				"pointer: %q", tc.name, errS)
		}
		if strings.Count(errS, "\n") != 1 {
			t.Errorf("%s: stderr must stay one line: %q", tc.name, errS)
		}
	}
}
