package cli

// A11 (F14): `webv2 version` is the bare-word spelling of the build stamp.
// A review reached for it and got `error: unknown command "version"`, which
// reads as a missing capability rather than a spelling mistake. The alias is
// a dispatch arm beside --version/-V, NOT a register() entry: the command
// surface (usage block, help-parity tests, remediation guard) must stay
// byte-identical, so the registry pin below is part of the contract.

import (
	"strings"
	"testing"
)

func TestVersionWordAliasMatchesFlag(t *testing.T) {
	// The override stands in for a stamped release build (test binaries
	// never carry a VCS stamp — see internal/version's tests).
	t.Setenv("WEBV2_BUILD", "aliasbuild01")

	codeFlag, outFlag, errFlag := run(t, "--version")
	if codeFlag != 0 || errFlag != "" {
		t.Fatalf("--version exit %d, stderr %q", codeFlag, errFlag)
	}
	codeWord, outWord, errWord := run(t, "version")
	if codeWord != 0 {
		t.Fatalf("`version` exit = %d, want 0 (stderr %q)", codeWord, errWord)
	}
	if errWord != "" {
		t.Fatalf("`version` wrote to stderr: %q", errWord)
	}
	if strings.Contains(errWord, "unknown command") {
		t.Fatalf("`version` still reports an unknown command: %q", errWord)
	}
	if outWord != outFlag {
		t.Fatalf("`version` stdout = %q, --version stdout = %q — the "+
			"alias must print the same stamp line", outWord, outFlag)
	}
	if !strings.HasPrefix(outWord, "webv2 ") || outWord != "webv2 aliasbuild01\n" {
		t.Fatalf("`version` stdout = %q, want the `webv2 <build>` stamp", outWord)
	}
	// The stamp goes to STDOUT, never stderr (byte discipline).
	if errWord != "" {
		t.Fatalf("`version` must keep stderr empty: %q", errWord)
	}
}

// TestVersionAliasIsNotARegisteredCommand pins the dispatch-arm design: a
// registry entry would add a usage line, a help block and a help-parity
// obligation, changing bytes the command surface has already pinned. The
// alias must therefore stay OUT of the registry.
func TestVersionAliasIsNotARegisteredCommand(t *testing.T) {
	for _, name := range CommandNames() {
		if name == "version" || name == "--version" || name == "-V" {
			t.Fatalf("%q must not be a registered command", name)
		}
	}
	code, out, _ := run(t, "help")
	if code != 0 {
		t.Fatalf("help exit = %d", code)
	}
	if strings.Contains(out, "  version ") || strings.Contains(out, "\n  version") {
		t.Fatalf("the usage block gained a version line:\n%s", out)
	}
}

// TestVersionAliasRefusesNothing: the alias takes no arguments and never
// exits 2 — like --version, extra words are ignored rather than turned into
// a usage error (the stamp is the whole answer).
func TestVersionAliasIgnoresTrailingWords(t *testing.T) {
	t.Setenv("WEBV2_BUILD", "aliasbuild01")
	code, out, errS := run(t, "version", "extra")
	if code != 0 {
		t.Fatalf("`version extra` exit = %d, want 0 (stderr %q)", code, errS)
	}
	if out != "webv2 aliasbuild01\n" {
		t.Fatalf("`version extra` stdout = %q", out)
	}
}
