package harness

// Compile proof (SKIP-when-unavailable): both scaffolds must compile clean
// under forge. The test runs only when the toolchain is present — docker
// functional AND forge on PATH AND both vendored libs resolvable offline —
// and SKIPs with the reason otherwise. A skip is a PASS with a message;
// a compile is never faked.

import (
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/validation"
)

// resolveForgeLibs finds a root holding BOTH forge-std/src/Test.sol and
// halmos-cheatcodes/src/SymTest.sol: an explicit T16_LIBS override, then
// this repo's scratch vendoring, then the ~/.foundry trees.
func resolveForgeLibs() (string, bool) {
	roots := []string{}
	if v := os.Getenv("T16_LIBS"); v != "" {
		roots = append(roots, v)
	}
	roots = append(roots,
		filepath.Join("..", "..", ".scratch", "t16-libs"),
	)
	if h, err := os.UserHomeDir(); err == nil {
		roots = append(roots,
			filepath.Join(h, ".foundry"),
			filepath.Join(h, ".config", ".foundry"),
		)
	}
	layouts := []string{"", "lib"}
	for _, r := range roots {
		for _, l := range layouts {
			base := filepath.Join(r, l)
			fs1 := filepath.Join(base, "forge-std", "src", "Test.sol")
			fs2 := filepath.Join(base, "halmos-cheatcodes", "src", "SymTest.sol")
			if _, err := os.Stat(fs1); err != nil {
				continue
			}
			if _, err := os.Stat(fs2); err != nil {
				continue
			}
			return base, true
		}
	}
	return "", false
}

// scratchWorkdir is a workspace-local temp dir (NOT /tmp: the docker daemon
// mounts real paths, and a redirected /tmp would be invisible to it — the
// same reason internal/reproduction stages its docker fixtures under
// .scratch).
func scratchWorkdir(t *testing.T) string {
	t.Helper()
	parent := filepath.Join("..", "..", ".scratch", "t16")
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(parent, "compile-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Name() == ".git" {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return err
		}
		defer out.Close()
		_, err = io.Copy(out, in)
		return err
	})
	if err != nil {
		t.Fatalf("copy %s: %v", src, err)
	}
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// toolchainUnavailable reports whether a forge failure is environmental
// (no network for the solc fetch, missing toolchain) rather than a real
// compile error in the scaffold.
func toolchainUnavailable(out string) bool {
	l := strings.ToLower(out)
	for _, s := range []string{
		"failed to download", "connection", "network", "offline",
		"no such host", "tls", "svm", "solc version",
	} {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

func TestScaffoldCompiles(t *testing.T) {
	if out, err := exec.Command("docker", "info").CombinedOutput(); err != nil {
		t.Skipf("docker absent: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if _, err := exec.LookPath("forge"); err != nil {
		t.Skip("forge absent from PATH")
	}
	libs, ok := resolveForgeLibs()
	if !ok {
		t.Skip("forge-std/halmos-cheatcodes not resolvable offline: " +
			"checked T16_LIBS, .scratch/t16-libs, ~/.foundry")
	}
	dir := scratchWorkdir(t)
	copyTree(t, filepath.Join(libs, "forge-std"), filepath.Join(dir, "lib", "forge-std"))
	copyTree(t, filepath.Join(libs, "halmos-cheatcodes"), filepath.Join(dir, "lib", "halmos-cheatcodes"))
	writeFile(t, filepath.Join(dir, "foundry.toml"), []byte(
		"[profile.default]\nsrc = \"src\"\ntest = \"test\"\nout = \"out\"\nlibs = [\"lib\"]\nsolc = \"0.8.24\"\n"+
			"remappings = [\"forge-std/=lib/forge-std/src/\", \"halmos-cheatcodes/=lib/halmos-cheatcodes/src/\"]\n"))
	writeFile(t, filepath.Join(dir, "src", "Stub.sol"), []byte(
		"// SPDX-License-Identifier: UNLICENSED\npragma solidity >=0.8.0;\ncontract Stub {}\n"))
	inv := validation.VObj(
		validation.KV{K: "id", V: validation.VStr("INV-007a")},
		validation.KV{K: "statement", V: validation.VStr("stub holds")},
		validation.KV{K: "source", V: validation.VStr("src/Stub.sol:1")},
	)
	halmos, err := Scaffold(Halmos, inv)
	if err != nil {
		t.Fatalf("Scaffold halmos: %v", err)
	}
	fuzz, err := Scaffold(ForgeFuzz, inv)
	if err != nil {
		t.Fatalf("Scaffold forge-fuzz: %v", err)
	}
	writeFile(t, filepath.Join(dir, "test", "H.t.sol"), halmos)
	writeFile(t, filepath.Join(dir, "test", "F.t.sol"), fuzz)

	// --no-lint: the spec-mandated snake_case harness names
	// (check_<snake>/fuzz_<snake>) trip forge's advisory mixed-case-function
	// lint by design. Lint is style, not compilation; solc warnings still
	// surface and are rejected below.
	cmd := exec.Command("forge", "build", "--no-lint")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		if toolchainUnavailable(string(out)) {
			t.Skipf("forge toolchain unavailable in this environment: %s", strings.TrimSpace(string(out)))
		}
		t.Fatalf("forge build failed:\n%s", out)
	}
	// Zero warnings tolerated.
	if strings.Contains(string(out), "Warning") {
		t.Fatalf("forge build emitted warnings (tolerated: zero):\n%s", out)
	}
	t.Logf("forge build clean for both scaffolds:\n%s", strings.TrimSpace(string(out)))
}
