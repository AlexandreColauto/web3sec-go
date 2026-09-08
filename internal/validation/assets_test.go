package validation

import (
	"sort"
	"strings"
	"testing"

	"websec/assets"
)

// TestAssetsEmbeddedCount: the embedded FS exposes exactly the 27 schema
// files, each named <name>.schema.json. This is the binary-side guard that
// the sync-assets.sh copy (and the Python tree) has not drifted.
func TestAssetsEmbeddedCount(t *testing.T) {
	names, err := assets.FS.ReadDir("schema")
	if err != nil {
		t.Fatalf("read embedded schema dir: %v", err)
	}
	var files []string
	for _, d := range names {
		if !d.IsDir() {
			files = append(files, d.Name())
		}
	}
	if len(files) != 27 {
		t.Fatalf("embedded FS exposes %d files, want 27:\n%s", len(files), strings.Join(files, "\n"))
	}
	for _, f := range files {
		if !strings.HasSuffix(f, ".schema.json") {
			t.Errorf("schema file %q does not match <name>.schema.json form", f)
		}
	}
}

// TestAssetsEmbeddedParse: every embedded schema parses as ordered JSON.
func TestAssetsEmbeddedParse(t *testing.T) {
	names, _ := assets.FS.ReadDir("schema")
	for _, d := range names {
		if d.IsDir() {
			continue
		}
		raw, err := assets.FS.ReadFile("schema/" + d.Name())
		if err != nil {
			t.Errorf("read %s: %v", d.Name(), err)
			continue
		}
		if _, err := ParseOrdered(raw); err != nil {
			t.Errorf("%s does not parse: %v", d.Name(), err)
		}
	}
}

// TestAssetsEmbeddedMatchesKnown: the embedded name set is exactly the
// knownSchemas list (minus the .schema.json suffix).
func TestAssetsEmbeddedMatchesKnown(t *testing.T) {
	names, _ := assets.FS.ReadDir("schema")
	var got []string
	for _, d := range names {
		if d.IsDir() {
			continue
		}
		got = append(got, strings.TrimSuffix(d.Name(), ".schema.json"))
	}
	sort.Strings(got)

	want := append([]string(nil), knownSchemas...)
	sort.Strings(want)

	if len(got) != len(want) {
		t.Fatalf("embedded set (%d) != knownSchemas (%d)", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("embedded[%d]=%q != known[%d]=%q", i, got[i], i, want[i])
		}
	}
}

// TestAssetsRequiredSchemas: the four named schemas the rest of the system
// depends on are all present (findable and loadable).
func TestAssetsRequiredSchemas(t *testing.T) {
	for _, name := range []string{"campaign_state", "snapshot", "finding", "sandbox_execution"} {
		if _, err := loadSchema(name); err != nil {
			t.Errorf("schema %q not loadable from embedded FS: %v", name, err)
		}
	}
}
