package sandbox

// Port of tests/test_sandbox_solc_dir.py: WEBV2_SOLC_DIR provisioning — the
// host svm cache bind-mounted to /home/foundry/.svm and recorded on the exec
// record as container.svm_mount.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSolcDirUnsetNoMount(t *testing.T) {
	t.Setenv("WEBV2_SOLC_DIR", "")
	os.Unsetenv("WEBV2_SOLC_DIR")
	wd := t.TempDir()
	argv, meta, err := BuildContainerArgv("docker-networkless", "forge build",
		&wd, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !containsStrValue(strValueArr(argv), "-v") {
		t.Fatalf("workdir bind missing from argv: %v", argv)
	}
	for i, a := range argv {
		if a == "-v" && strings.HasSuffix(argv[i+1], ":.svm") {
			t.Fatalf("unexpected svm mount: %v", argv)
		}
	}
	if meta.SvmMount != nil {
		t.Fatalf("svm_mount = %q, want nil", *meta.SvmMount)
	}
}

func TestSolcDirExistingIsMountedAndRecorded(t *testing.T) {
	svm := t.TempDir()
	if err := os.MkdirAll(filepath.Join(svm, "0.8.24"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WEBV2_SOLC_DIR", svm)
	argv, meta, err := BuildContainerArgv("docker-networkless", "forge build",
		nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !containsStrValue(strValueArr(argv), svm+":/home/foundry/.svm") {
		t.Fatalf("svm mount missing from argv: %v", argv)
	}
	if meta.SvmMount == nil || *meta.SvmMount != resolvedPath(svm) {
		t.Fatalf("svm_mount = %v, want %q", meta.SvmMount, resolvedPath(svm))
	}
}

func TestSolcDirMissingIsTreatedAsUnset(t *testing.T) {
	t.Setenv("WEBV2_SOLC_DIR", filepath.Join(t.TempDir(), "does-not-exist"))
	argv, meta, err := BuildContainerArgv("docker-networkless", "forge build",
		nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range argv {
		if strings.HasSuffix(a, ":.svm") {
			t.Fatalf("a dangling bind source must be dropped: %v", argv)
		}
	}
	if meta.SvmMount != nil {
		t.Fatalf("svm_mount = %q, want nil", *meta.SvmMount)
	}
}

func TestSolcDirMountAppliesToForkRunner(t *testing.T) {
	svm := t.TempDir()
	t.Setenv("WEBV2_SOLC_DIR", svm)
	argv, _, err := BuildContainerArgv("fork-runner", "forge test", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !containsStrValue(strValueArr(argv), resolvedPath(svm)+":/home/foundry/.svm") {
		t.Fatalf("svm mount missing for fork-runner: %v", argv)
	}
	if !strings.Contains(strings.Join(argv, " "), "FORK_RPC_URL=") {
		t.Fatalf("fork-runner lost its RPC env: %v", argv)
	}
}

func TestSolcDirHostReadonlyUnaffected(t *testing.T) {
	svm := t.TempDir()
	t.Setenv("WEBV2_SOLC_DIR", svm)
	sb, err := NewSandbox(newCampaign(t, "svm"), "host-readonly")
	if err != nil {
		t.Fatal(err)
	}
	if sb.Profile != "host-readonly" {
		t.Fatalf("profile = %q", sb.Profile)
	}
}
