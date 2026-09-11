// Task 6 (G9) briefing tests — the tracked-but-opaque component surfaces
// block. TDD: written BEFORE the TrackedSurfaces hookup; must FAIL
// (undefined TrackedSurfaces) until briefing.go renders it.
package briefing

import (
	"path/filepath"
	"testing"

	"websec/internal/protocolgraph"
	"websec/internal/validation"
)

func TestTrackedSurfacesAbsentWithoutModel(t *testing.T) {
	c := newCamp(t, "Opaque Program")
	if got := TrackedSurfaces(c); len(got) != 0 {
		t.Fatalf("no model must render no surfaces, got %q", got)
	}
	b, err := BuildBrief(c, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if hasKey(b, "tracked_surfaces") {
		t.Fatal("brief without components must not carry tracked_surfaces")
	}
}

func TestTrackedSurfacesRendersComponentLines(t *testing.T) {
	c := newCamp(t, "Opaque Program")
	model := validation.VObj(
		kv("protocol_id", validation.VStr("p")),
		kv("name", validation.VStr("nn")),
		kv("contracts", validation.VArr()),
		kv("actors", validation.VArr()),
		kv("assets", validation.VArr()),
		kv("relations", validation.VArr()),
		kv("components", validation.VArr(validation.VObj(
			kv("kind", validation.VStr("frontend")),
			kv("path", validation.VStr("app/")),
			kv("trust", validation.VStr("untrusted")),
			kv("in_scope", validation.VBool(true)),
			kv("paid_for", validation.VBool(true)),
		))),
	)
	if _, err := protocolgraph.SaveModel(c, model, filepath.Join(
		c.ArtifactsDir, "protocol_model.json")); err != nil {
		t.Fatal(err)
	}
	got := TrackedSurfaces(c)
	if len(got) != 1 || got[0] != "- frontend app/: in_scope, paid" {
		t.Fatalf("surfaces = %q", got)
	}
	b, err := BuildBrief(c, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	ts := objAt(b, "tracked_surfaces")
	if ts.Kind != validation.Arr || len(ts.A) != 1 ||
		ts.A[0].Kind != validation.Str ||
		ts.A[0].S != "- frontend app/: in_scope, paid" {
		t.Fatalf("tracked_surfaces = %v", ts)
	}
}
