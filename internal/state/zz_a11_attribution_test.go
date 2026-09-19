package state

// A11 (F14) attribution: a NEW artifact row names the framework build that
// minted it, so a later review can tell which binary's semantics produced the
// citation. The key is additive and OPTIONAL in campaign_state's schema — a
// row registered before the key existed must still validate — and a refresh
// (a re-hash, not a re-mint) preserves the stamp the mint wrote.

import (
	"os"
	"path/filepath"
	"testing"

	"websec/internal/validation"
	"websec/internal/version"
)

// a11ArtifactFile writes a file for the registry to hash.
func a11ArtifactFile(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRegisterArtifactStampsFrameworkBuild(t *testing.T) {
	// The override stands in for a stamped release build (test binaries
	// never carry a VCS stamp).
	t.Setenv("WEBV2_BUILD", "mintbuild001")
	c, err := Init(t.TempDir(), "A11 Stamp", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	p := a11ArtifactFile(t, "recon.json", "{\"ok\":true}\n")
	id, err := c.RegisterArtifact("recon", p, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	row, err := c.Artifact(id)
	if err != nil {
		t.Fatal(err)
	}
	got := validation.ObjStr(row, "framework_build")
	if got != version.Commit() {
		t.Fatalf("framework_build = %q, want the running build %q",
			got, version.Commit())
	}
	if got == version.Unknown {
		t.Fatalf("framework_build = %q: the stamp must be the RUNNING build, "+
			"not the absence marker", got)
	}
	// House style: the stamp is appended after the mint's own keys, so the
	// row's existing key order is untouched.
	want := []string{"artifact_id", "kind", "path", "registered_at", "sha256",
		"snapshot_id", "note", "framework_build"}
	names := keyNames(row)
	if len(names) != len(want) {
		t.Fatalf("row keys = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("row keys = %v, want %v", names, want)
		}
	}
}

// TestRefreshPreservesMintedFrameworkBuild: the refresh path mutates the row
// in place, so the mint-time stamp survives a re-hash under a DIFFERENT
// binary — a refresh is not a re-mint and must not restamp.
func TestRefreshPreservesMintedFrameworkBuild(t *testing.T) {
	t.Setenv("WEBV2_BUILD", "mintbuild001")
	c, err := Init(t.TempDir(), "A11 Refresh", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	p := a11ArtifactFile(t, "plan.json", "{\"v\":1}\n")
	id, err := c.RegisterArtifact("plan", p, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	// A different binary re-hashes the same row.
	t.Setenv("WEBV2_BUILD", "otherbuild02")
	if err := os.WriteFile(p, []byte("{\"v\":2}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RefreshArtifact(id, "re-hash after an external rewrite",
		"operator"); err != nil {
		t.Fatal(err)
	}
	row, err := c.Artifact(id)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(row, "framework_build"); got != "mintbuild001" {
		t.Fatalf("framework_build after refresh = %q, want the mint-time "+
			"stamp %q", got, "mintbuild001")
	}
	if rc := validation.ObjAt(row, "refresh_count"); rc.I != 1 {
		t.Fatalf("refresh_count = %v: the refresh did not run", rc.I)
	}
}

// TestArtifactRowWithoutFrameworkBuildStillValidates pins the OPTIONAL side of
// the schema edit: campaign_state's artifacts items are additionalProperties
// false, so a row minted before the key existed is only still loadable because
// framework_build is declared-but-optional (the grandfather rule).
func TestArtifactRowWithoutFrameworkBuildStillValidates(t *testing.T) {
	c, err := Init(t.TempDir(), "A11 Grandfather", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	st := mustState(t, c)
	arts := validation.ObjAt(st, "artifacts")
	arts.A = append(arts.A, validation.VObj(
		kv("artifact_id", validation.VStr("REC-old00000001")),
		kv("kind", validation.VStr("recon")),
		kv("path", validation.VStr("recon.json")),
		kv("registered_at", validation.VStr(nowIso())),
		kv("sha256", validation.VStr("deadbeef")),
		kv("snapshot_id", validation.VNull()),
		kv("note", validation.VStr("")),
	))
	st.O = validation.SetOrAppend(st.O, "artifacts", arts)
	if err := c.save(st); err != nil {
		t.Fatalf("a pre-stamp row must still validate: %v", err)
	}
}
