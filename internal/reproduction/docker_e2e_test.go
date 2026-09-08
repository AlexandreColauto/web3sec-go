package reproduction

// Docker e2e (WEBV2_DOCKER_TESTS=1): the whole T20 promise end to end — a
// REAL containerized forge run through the docker-networkless profile, then
// the E4 mint from that exec record. The default suite stays pure-logic.

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"websec/internal/findings"
	"websec/internal/sandbox"
	"websec/internal/validation"
)

// dockerImage is the offline solc-pinned image the e2e uses (it ships
// solc 0.8.24, so no network is needed to compile).
const dockerImage = "foundry-solc-0824:latest"

// TestDockerNetworklessMintsE4 runs `forge test` in the networkless
// container against the foundry-mini fixture and mints E4 evidence from the
// resulting exec record.
func TestDockerNetworklessMintsE4(t *testing.T) {
	if os.Getenv("WEBV2_DOCKER_TESTS") == "" {
		t.Skip("WEBV2_DOCKER_TESTS=1 to run")
	}
	t.Setenv("WEBV2_DOCKER_IMAGE", dockerImage)
	if !sandbox.ProfileAvailable("docker-networkless") {
		t.Skip("docker runtime not present on this host")
	}
	// The workdir must live OUTSIDE the test's /tmp: the DSH file sandbox
	// redirects /tmp for this process, so a bind source under it is invisible
	// to the docker daemon (which mounts the REAL path) — forge then sees an
	// empty /wd and prints only "Nothing to compile".
	workdir := copyFixtureTo(t, "foundry-mini", scratchDir(t))
	c := newCampaign(t, "docker e2e")
	fid := integrityHypo(t, c, "logic-error")
	sb, err := sandbox.NewSandbox(c, "docker-networkless")
	if err != nil {
		t.Fatalf("new sandbox: %v", err)
	}
	start := time.Now()
	rec, err := sb.Run("forge test", sandbox.RunOpts{
		Workdir: &workdir, FindingID: &fid, Timeout: 300})
	if err != nil {
		t.Fatalf("container run failed: %v", err)
	}
	elapsed := time.Since(start)
	exit := objAt(rec, "exit_status")
	out := sandbox.ExecOutput(rec)
	t.Logf("forge test exit=%s in %s", pyReprScalar(exit), elapsed)
	if !(exit.Kind == validation.Int && exit.I == 0) {
		t.Fatalf("exit %s:\n%s", pyReprScalar(exit), out)
	}
	if !strings.Contains(out, "Ran 1 test") ||
		!strings.Contains(out, "[PASS]") {
		t.Fatalf("forge output did not show a passing run:\n%s", out)
	}
	tier := "T2"
	minted, err := AttemptAndMint(c, fid, objStr(rec, "exec_id"),
		"containerized forge test proves the two() invariant", &tier, nil)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	level, err := findings.FindingLevel(minted)
	if err != nil {
		t.Fatal(err)
	}
	if level != "E4" {
		t.Fatalf("level = %q, want E4", level)
	}
}

// scratchDir is a workspace-local temp dir the docker daemon can see.
func scratchDir(t *testing.T) string {
	t.Helper()
	parent := filepath.Join("..", "..", ".scratch", "t20")
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(parent, "e2e-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// copyFixtureTo streams a testdata fixture into dst (the container
// bind-mounts it, and forge writes out/ and cache/ beside it).
func copyFixtureTo(t *testing.T, name, dst string) string {
	t.Helper()
	src := filepath.Join("testdata", name)
	err := filepath.Walk(src, func(path string, info os.FileInfo,
		err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.Create(target)
		if err != nil {
			return err
		}
		defer out.Close()
		_, err = io.Copy(out, in)
		return err
	})
	if err != nil {
		t.Fatalf("copy fixture: %v", err)
	}
	return dst
}
