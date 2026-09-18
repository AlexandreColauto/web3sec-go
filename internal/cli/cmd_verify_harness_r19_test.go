package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// mcVersionScript writes a fake solc that answers --version with the
// banner shape of real solc (Version: X — parsed from a NON-first line
// to keep the parser honest).
func mcVersionScript(t *testing.T, dir, version string) string {
	t.Helper()
	p := filepath.Join(dir, "solc-"+version)
	body := "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'solc, the solidity compiler script'; echo 'Version: " + version + "+commit.deadbeef'; fi\n"
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestCompilerPinNoLineVersionIsUnchecked pins r19 P1 #3: a pin with
// NOTHING to compare is the THIRD state — never "checked".
func TestCompilerPinNoLineVersionIsUnchecked(t *testing.T) {
	c, root := mcCamp(t, "r19-noline")
	noVer := strings.Replace(mcProvenLine,
		`"solc_version":"0.8.36",`, "", 1)
	mcHarnessExec(t, c, "EXEC-R1", noVer, "minicertora --rule inv_1",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c)}, 0)
	recPath := filepath.Join(c.ExecsDir, "EXEC-R1", "exec_record.json")
	raw, _ := os.ReadFile(recPath)
	rec, _ := validation.ParseOrdered(raw)
	rec.O = validation.SetOrAppend(rec.O, "environment", validation.VObj(
		kvT("tool_versions", validation.VObj(kvT("solc",
			validation.VStr("0.8.36"))))))
	if err := validation.WriteJson(recPath, rec, "sandbox_execution"); err != nil {
		t.Fatal(err)
	}
	code, _, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", "EXEC-R1")
	if code != 0 {
		t.Fatalf("exit %d err %q", code, errS)
	}
	pin := validation.ObjStr(mcLinkField(t, c, "invariants", "INV-1", "verification",
		"harness", "proof"), "compiler_pin")
	if !strings.Contains(pin, "nothing was verified") ||
		strings.Contains(pin, "checked against") {
		t.Fatalf("an unmade comparison must not say checked: %q", pin)
	}
}

// TestCompilerPinEqualsFormIsHonoured pins r19 P2: --solc-path=PATH
// names the compiler as hard as --solc-path PATH; the old Fields-only
// parse dropped it and let a mismatch bind.
func TestCompilerPinEqualsFormIsHonoured(t *testing.T) {
	c, root := mcCamp(t, "r19-eqform")
	dir := t.TempDir()
	bin := mcVersionScript(t, dir, "0.8.99")
	mcHarnessExec(t, c, "EXEC-R2", mcProvenLine,
		"minicertora --solc-path="+bin+" --rule inv_1",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c)}, 0)
	code, _, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", "EXEC-R2")
	if code != 2 || !strings.Contains(errS, "toolchain-mismatch") ||
		!strings.Contains(errS, "0.8.99") {
		t.Fatalf("the =-form must resolve and mismatch: exit %d err %q",
			code, errS)
	}
}

// TestCompilerPinUnresolvableNamedBinaryRefuses pins the relative-form
// law: a run that NAMES a compiler we cannot resolve is refused, not
// silently downgraded to the record row.
func TestCompilerPinUnresolvableNamedBinaryRefuses(t *testing.T) {
	c, root := mcCamp(t, "r19-relative")
	mcHarnessExec(t, c, "EXEC-R3", mcProvenLine,
		"cd build && minicertora --solc-path ./solc-0.8.99 --rule inv_1",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c)}, 0)
	recPath := filepath.Join(c.ExecsDir, "EXEC-R3", "exec_record.json")
	raw, _ := os.ReadFile(recPath)
	rec, _ := validation.ParseOrdered(raw)
	rec.O = validation.SetOrAppend(rec.O, "environment", validation.VObj(
		kvT("tool_versions", validation.VObj(kvT("solc",
			validation.VStr("0.8.36"))))))
	if err := validation.WriteJson(recPath, rec, "sandbox_execution"); err != nil {
		t.Fatal(err)
	}
	code, _, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", "EXEC-R3")
	if code != 2 || !strings.Contains(errS, "cannot resolve") {
		t.Fatalf("named-but-unresolvable must refuse, not downgrade: exit "+
			"%d err %q", code, errS)
	}
}

var _ = state.Campaign{}
