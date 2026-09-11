package cli

// M1: `scope --example` prints a minimal schema-valid policy template,
// mirroring the `ingest --example` contract (pipeable stdout + a stderr
// pointer to the load command).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/validation"
)

func TestScopeExampleIsPureJSON(t *testing.T) {
	code, out, _ := run(t, "scope", "--example")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	v, err := validation.ParseOrdered([]byte(out))
	if err != nil {
		t.Fatalf("example is not JSON: %v", err)
	}
	if out != t14ExamplePolicy {
		t.Fatal("stdout is not the template verbatim (must stay pipeable)")
	}
	_ = v
}

func TestScopeExampleValidatesAsPolicy(t *testing.T) {
	v, err := validation.ParseOrdered([]byte(t14ExamplePolicy))
	if err != nil {
		t.Fatalf("template does not parse: %v", err)
	}
	if err := validation.Validate(v, "bounty_policy", 10); err != nil {
		t.Fatalf("template fails its own schema: %v", err)
	}
}

func TestScopeExampleLoadsEndToEnd(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	pol := filepath.Join(root, "policy.json")
	if err := os.WriteFile(pol, []byte(t14ExamplePolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "scope", cid, "--policy", pol)
	if code != 0 {
		t.Fatalf("scope exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "1 scope entries") {
		t.Fatalf("scope output = %q, want the template's 1 entry", out)
	}
}
