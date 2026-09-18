// artifacts_test.go pins the 2026-09-10 hash-less-row fix: the section used to
// `continue` past a registered artifact whose sha256 was null/missing while
// still reporting ok:true, so nulling the hash in the state file
// (schema-legal) and rewriting the artifact passed the integrity audit — the
// claim in internal/state/artifacts.go that "the audit already flags hash-less
// rows" was not true of any code path.
package sections

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

func artifactCamp(t *testing.T) (*state.Campaign, string) {
	t.Helper()
	root := t.TempDir()
	c, err := state.Init(root, "C-art", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(root, "src", "C.sol")
	if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("// c"), 0o644); err != nil {
		t.Fatal(err)
	}
	id, err := c.RegisterArtifact("recon", src, "fixture", nil)
	if err != nil {
		t.Fatal(err)
	}
	return c, id
}

func artifactProblems(t *testing.T, c *state.Campaign) ([]string, bool) {
	t.Helper()
	sec, err := Artifacts(c)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, p := range validation.ObjAt(sec, "problems").A {
		out = append(out, p.S)
	}
	return out, validation.ObjAt(sec, "ok").B
}

// TestArtifactsHashedRowIsClean: the happy path is unchanged — a registered
// artifact with an intact hash reports ok with no problems.
func TestArtifactsHashedRowIsClean(t *testing.T) {
	c, _ := artifactCamp(t)
	problems, ok := artifactProblems(t, c)
	if len(problems) != 0 || !ok {
		t.Errorf("problems = %v, ok = %v; want clean", problems, ok)
	}
}

// TestArtifactsHashlessRowIsAProblem: with the hash nulled the row is
// unverifiable, so the section must say so and stop reporting ok.
func TestArtifactsHashlessRowIsAProblem(t *testing.T) {
	c, id := artifactCamp(t)
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	rows := validation.ObjAt(st, "artifacts")
	if len(rows.A) != 1 {
		t.Fatalf("artifacts = %d rows, want 1", len(rows.A))
	}
	row := rows.A[0]
	row.O = validation.SetOrAppend(row.O, "sha256", validation.VNull())
	st.O = validation.SetOrAppend(st.O, "artifacts", validation.VArr(row))
	if err := validation.WriteJson(c.StatePath, st, "campaign_state"); err != nil {
		t.Fatal(err)
	}
	problems, ok := artifactProblems(t, c)
	if ok {
		t.Error("ok = true with a hash-less artifact row")
	}
	if len(problems) != 1 {
		t.Fatalf("problems = %v, want exactly the hash-less row", problems)
	}
	for _, want := range []string{id, "sha256"} {
		if !strings.Contains(problems[0], want) {
			t.Errorf("problem %q must name %q", problems[0], want)
		}
	}
}

// TestArtifactsMissingFileStillReported: the pre-existing missing-file problem
// keeps its message and does not get shadowed by the new branch.
func TestArtifactsMissingFileStillReported(t *testing.T) {
	c, _ := artifactCamp(t)
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	row := validation.ObjAt(st, "artifacts").A[0]
	if err := os.Remove(filepath.Join(
		c.Root, validation.ObjStr(row, "path"))); err != nil {
		t.Fatal(err)
	}
	problems, ok := artifactProblems(t, c)
	if ok || len(problems) != 1 ||
		!strings.Contains(problems[0], "missing file") {
		t.Errorf("problems = %v, ok = %v; want the missing-file problem",
			problems, ok)
	}
}
