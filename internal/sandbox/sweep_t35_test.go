package sandbox

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"websec/internal/validation"
)

// Port of tests/test_review_fixes.py::test_tripwire_denies_rm_rf_home: the
// old pattern let `rm -rf /home` (user data) through host-readonly.
func TestTripwireDeniesRmRfHome(t *testing.T) {
	v, err := PolicyCheck("rm -rf /home/victim", "host-readonly")
	if err != nil {
		t.Fatal(err)
	}
	if boolAt(v, "allowed") {
		t.Error("rm -rf /home/victim must be denied")
	}
	if !containsStrValue(objAt(v, "violations"), "destructive-path") {
		t.Errorf("violations = %s, want destructive-path",
			validation.CanonCompact(objAt(v, "violations")))
	}
	ok, err := PolicyCheck("rm -rf /tmp/scratch", "host-readonly")
	if err != nil {
		t.Fatal(err)
	}
	if !boolAt(ok, "allowed") {
		t.Error("rm -rf /tmp/scratch must stay allowed")
	}
}

// dockerReady is the review-fixes `_docker_ready`: daemon answering and the
// image present locally. Integration tests skip (never fail) without them.
func dockerReady(image string) bool {
	if err := exec.Command("docker", "info").Run(); err != nil {
		return false
	}
	return exec.Command("docker", "image", "inspect", image).Run() == nil
}

func testImage() string {
	if v := os.Getenv("WEBV2_TEST_IMAGE"); v != "" {
		return v
	}
	return "alpine:3"
}

// Port of tests/test_review_fixes.py::test_docker_profile_runs_inside_a_container.
func TestDockerProfileRunsInsideAContainer(t *testing.T) {
	image := testImage()
	if !dockerReady(image) {
		t.Skipf("no live docker daemon with image %q on this host", image)
	}
	t.Setenv("WEBV2_DOCKER_IMAGE", image)
	c := newCampaign(t, "Acme Program")
	sb, err := NewSandbox(c, "docker-networkless")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := sb.Run("cat /proc/1/comm", RunOpts{Timeout: 120})
	if err != nil {
		t.Fatal(err)
	}
	if objAt(rec, "exit_status").I != 0 {
		t.Fatalf("exit_status = %v", objAt(rec, "exit_status"))
	}
	raw, err := os.ReadFile(objStr(rec, "stdout_path"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "docker-init") {
		t.Errorf("/proc/1/comm = %q, want docker-init (ran on the host?)", raw)
	}
	container := objAt(rec, "container")
	if container.Kind != validation.Obj {
		t.Fatalf("container = %v, want the isolation metadata", container)
	}
	if got := objStr(container, "image"); got != image {
		t.Errorf("container.image = %q, want %q", got, image)
	}
	if got := objStr(container, "network"); got != "none" {
		t.Errorf("container.network = %q, want none", got)
	}
	if got := objStr(objAt(rec, "environment"), "network_access"); got != "none" {
		t.Errorf("environment.network_access = %q, want none", got)
	}
}

// Port of tests/test_review_fixes.py::test_docker_network_none_blocks_egress.
func TestDockerNetworkNoneBlocksEgress(t *testing.T) {
	image := testImage()
	if !dockerReady(image) {
		t.Skipf("no live docker daemon with image %q on this host", image)
	}
	t.Setenv("WEBV2_DOCKER_IMAGE", image)
	c := newCampaign(t, "Acme Program")
	sb, err := NewSandbox(c, "docker-networkless")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := sb.Run("sh -c 'ifconfig -a 2>/dev/null | grep -c eth'",
		RunOpts{Timeout: 120})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(objStr(rec, "stdout_path"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != "0" {
		t.Errorf("eth interface count = %q, want 0 (network none)", raw)
	}
}

// Port of tests/test_review_fixes.py::test_container_env_is_isolated_from_host.
func TestContainerEnvIsolatedFromHost(t *testing.T) {
	image := testImage()
	if !dockerReady(image) {
		t.Skipf("no live docker daemon with image %q on this host", image)
	}
	t.Setenv("WEBV2_DOCKER_IMAGE", image)
	t.Setenv("WEBV2_LEAK_PROBE", "host-secret-value")
	c := newCampaign(t, "Acme Program")
	sb, err := NewSandbox(c, "docker-networkless")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := sb.Run("sh -c 'echo [${WEBV2_LEAK_PROBE:-ABSENT}]'",
		RunOpts{Timeout: 120})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(objStr(rec, "stdout_path"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "[ABSENT]") {
		t.Errorf("host env leaked into the container: %q", raw)
	}
	rec2, err := sb.Run("sh -c 'echo [${INJECTED:-MISSING}]'", RunOpts{
		Timeout: 120, Env: []EnvVar{{Key: "INJECTED", Value: "value"}}})
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := os.ReadFile(objStr(rec2, "stdout_path"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw2), "[value]") {
		t.Errorf("explicit env not injected: %q", raw2)
	}
}
