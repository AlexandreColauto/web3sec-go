package validation

import (
	"sort"
	"strings"
	"testing"

	"websec/assets"
)

// TestAssetsEmbeddedCount: the embedded FS exposes exactly one
// <name>.schema.json per knownSchemas entry — no more, no less. This is the
// binary-side guard that the sync-assets.sh copy (and the parallel-developed
// Python tree) has not drifted. The expected count is DERIVED from
// knownSchemas, so adding a schema is a one-line change (plus sync-assets),
// never a magic number to hunt down.
func TestAssetsEmbeddedCount(t *testing.T) {
	names, err := assets.FS.ReadDir("schema")
	if err != nil {
		t.Fatalf("read embedded schema dir: %v", err)
	}
	got := map[string]bool{}
	for _, d := range names {
		if !d.IsDir() {
			got[d.Name()] = true
		}
	}
	want := map[string]bool{}
	for _, name := range knownSchemas {
		want[name+".schema.json"] = true
	}
	if len(got) != len(want) {
		t.Fatalf("embedded FS exposes %d files, want %d:\n%s", len(got), len(want),
			strings.Join(namesOf(got), "\n"))
	}
	for f := range want {
		if !got[f] {
			t.Errorf("known schema %q has no embedded file", f)
		}
	}
	for f := range got {
		if !want[f] {
			t.Errorf("embedded file %q is not in knownSchemas", f)
		}
	}
}

func namesOf(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
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
