package planner

// Task 6 (G9) planner tests — the plan view's tracked-but-opaque component
// block. TDD: written BEFORE TrackedSurfacesSection; must FAIL (undefined)
// until the planner renders it.

import (
	"testing"

	"websec/internal/validation"
)

func trackedModel(comps ...validation.Value) validation.Value {
	return validation.VObj(
		validation.KV{K: "protocol_id", V: validation.VStr("p")},
		validation.KV{K: "name", V: validation.VStr("nn")},
		validation.KV{K: "contracts", V: validation.VArr()},
		validation.KV{K: "actors", V: validation.VArr()},
		validation.KV{K: "assets", V: validation.VArr()},
		validation.KV{K: "relations", V: validation.VArr()},
		validation.KV{K: "components", V: validation.VArr(comps...)},
	)
}

func trackedComp(kind, path string, inScope, paidFor bool) validation.Value {
	return validation.VObj(
		validation.KV{K: "kind", V: validation.VStr(kind)},
		validation.KV{K: "path", V: validation.VStr(path)},
		validation.KV{K: "trust", V: validation.VStr("untrusted")},
		validation.KV{K: "in_scope", V: validation.VBool(inScope)},
		validation.KV{K: "paid_for", V: validation.VBool(paidFor)},
	)
}

func TestTrackedSurfacesSectionAbsentWithoutComponents(t *testing.T) {
	bare := validation.VObj(
		validation.KV{K: "protocol_id", V: validation.VStr("p")},
		validation.KV{K: "name", V: validation.VStr("nn")},
		validation.KV{K: "contracts", V: validation.VArr()},
		validation.KV{K: "actors", V: validation.VArr()},
		validation.KV{K: "assets", V: validation.VArr()},
		validation.KV{K: "relations", V: validation.VArr()},
	)
	if got := TrackedSurfacesSection(bare); len(got) != 0 {
		t.Fatalf("absent components must render nothing, got %q", got)
	}
	if got := TrackedSurfacesSection(trackedModel()); len(got) != 0 {
		t.Fatalf("empty components must render nothing, got %q", got)
	}
}

func TestTrackedSurfacesSectionListsComponents(t *testing.T) {
	m := trackedModel(
		trackedComp("frontend", "app/", true, true),
		trackedComp("domain", "swap.example", false, false),
	)
	got := TrackedSurfacesSection(m)
	if len(got) != 3 {
		t.Fatalf("section = %q, want header + 2 lines", got)
	}
	if got[1] != "- frontend app/: in_scope, paid" {
		t.Errorf("line 1 = %q", got[1])
	}
	if got[2] != "- domain swap.example: out-of-scope" {
		t.Errorf("line 2 = %q", got[2])
	}
}
