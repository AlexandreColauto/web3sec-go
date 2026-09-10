// solcpin_test.go: the compiler pin read out of the TARGET repo's
// foundry.toml is untrusted input. Until 2026-09-10 it was interpolated into
// `docker run … /bin/sh -c "ls /home/foundry/.svm/<pin>"` (a pin of
// `0.8.24; <anything>` executed in the probe container, and exit 0 forged
// "solc present"), and joined into host paths for the svm-cache check.
package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/snapshot"
)

// TestSolcVersionPin is the grammar gate: a version, optionally v-prefixed and
// suffixed with foundry's nightly/commit forms, and nothing else.
func TestSolcVersionPin(t *testing.T) {
	valid := []string{
		"0.8.24", "v0.8.24", "0.8", "0.8.24-nightly.2024.1.1",
		"0.8.24+commit.e11b9ed9", "  0.8.24  ",
	}
	for _, s := range valid {
		if !SolcVersionPin(s) {
			t.Errorf("SolcVersionPin(%q) = false, want true", s)
		}
	}
	invalid := []string{
		"", "stable", "latest", "/usr/bin/solc", "../solc",
		"0.8.24; touch /tmp/pwned", "0.8.24 && ls", "0.8.24 | cat /etc/passwd",
		"$(id)", "`id`", "0.8.24\nrm -rf /", "0.8.24 /etc", "solc-0.8.24",
		"0.8.24;0.8.24", "0.8.24.", "0.8.24-",
	}
	for _, s := range invalid {
		if SolcVersionPin(s) {
			t.Errorf("SolcVersionPin(%q) = true, want false", s)
		}
	}
}

// TestSolcPinTextIsBounded: a rejected pin is echoed back to the operator in
// one bounded line (the report must not be floodable by foundry.toml).
func TestSolcPinTextIsBounded(t *testing.T) {
	long := strings.Repeat("x", 500)
	got := SolcPinText(long)
	if len([]rune(got)) > 63 {
		t.Errorf("SolcPinText(len %d) = %d runes, want <= 63",
			len(long), len([]rune(got)))
	}
	if !strings.HasPrefix(got, "'") {
		t.Errorf("SolcPinText = %q, want a quoted form", got)
	}
}

// TestSandboxPreflightRefusesHostileSolcPin: the pin is never treated as a path
// component, and the check fails with a stated reason instead of probing.
func TestSandboxPreflightRefusesHostileSolcPin(t *testing.T) {
	c := newCampaign(t, "hostile-pin")
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "foundry.toml"), []byte(
		"[profile.default]\nsol = \"0.8.24; touch /tmp/pwned\"\n"),
		0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, target, nil, nil); err != nil {
		t.Fatal(err)
	}
	withDaemon(t, true)
	svm := t.TempDir()
	t.Setenv("WEBV2_SOLC_DIR", svm)
	profile := "docker-networkless"

	pre, err := SandboxPreflight(c, nil, &profile)
	if err != nil {
		t.Fatal(err)
	}
	solc := objAt(objAt(pre, "checks"), "solc")
	if got := strAt(solc, "status"); got != "fail" {
		t.Errorf("solc status = %q, want fail", got)
	}
	if detail := strAt(solc, "detail"); !strings.Contains(detail,
		"not a solc version") {
		t.Errorf("solc detail = %q, want the refusal", detail)
	}
	if boolAt(pre, "ok") {
		t.Error("ok = true with an unusable compiler pin")
	}
	entries, err := os.ReadDir(svm)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("the pin was used as a path: %v", entries)
	}
}
